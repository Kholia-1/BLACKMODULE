"""Local regression tests for LOT 2B list versioning and restoration."""

import json
import gzip
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import ApprovalRequest, ImportBatch, ListVersion, ListVersionActivation, ListVersionEntry, SanctionEntry
from app.services.approval_service import (
    OP_LIST_VERSION_RESTORE,
    PENDING,
    APPROVED,
    IN_PROGRESS,
    create_approval_request,
    process_queued_restore,
    queue_restore_approval,
    review_approval_request,
)
from app.services.list_version_service import (
    ACTIVATION_RESTORE,
    ARCHIVE_PARSERS,
    ACTIVE, ENTRY_ACTIVE,
    ARCHIVED,
    CHANGE_ADDED,
    CHANGE_DELISTED,
    CHANGE_MODIFIED,
    CHANGE_REACTIVATED,
    DELISTED,
    NonRestorableVersionError,
    ObsoleteRestoreRequest,
    SourceOperationInProgress,
    SuspiciousListDropError,
    _acquire_source_lock,
    apply_version_restore,
    get_active_version,
    get_version_preview,
    is_version_restorable,
    synchronize_source_version,
)
from app.services.list_update_service import OFFICIAL_SOURCES, queue_official_update
import app.services.list_version_service as list_version_service
import app.scheduler as scheduler_service


def item(record_id, name, *, aliases=None, country="FR"):
    return {
        "source_liste": "TEST_SOURCE",
        "source_record_id": record_id,
        "type_entite": "PERSONNE_PHYSIQUE",
        "nom": name,
        "prenom": None,
        "nom_complet": name,
        "pays": country,
        "hash_signature": f"hash-{record_id}",
        "aliases": aliases or [],
    }


class Lot2BVersioningTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()
        self.previous_drop_threshold = list_version_service.LIST_MAX_ENTRY_DROP_PERCENT
        list_version_service.LIST_MAX_ENTRY_DROP_PERCENT = 60
        ARCHIVE_PARSERS["TEST_SOURCE"] = lambda content: json.loads(content.decode("utf-8"))
        ARCHIVE_PARSERS["OTHER_SOURCE"] = lambda content: json.loads(content.decode("utf-8"))

    def tearDown(self):
        list_version_service.LIST_MAX_ENTRY_DROP_PERCENT = self.previous_drop_threshold
        ARCHIVE_PARSERS.pop("TEST_SOURCE", None)
        ARCHIVE_PARSERS.pop("OTHER_SOURCE", None)
        self.db.close()
        self.engine.dispose()

    def sync(self, entries, file_hash="a" * 64, source="TEST_SOURCE"):
        entries = list(entries)
        batch = ImportBatch(source_liste=source, filename="source.xml", file_type="XML", status="PENDING")
        self.db.add(batch)
        self.db.flush()
        return synchronize_source_version(
            self.db, source_liste=source, import_batch=batch, source_url="https://official.example/list.xml",
            downloaded_at=None, published_at=None, file_hash=file_hash,
            archive_content=json.dumps(entries).encode("utf-8"), entries=entries, imported_by="TEST",
        )

    def first_two_versions(self):
        version_one, _ = self.sync([item("A", "ALPHA"), item("B", "BETA")], "1" * 64)
        self.db.flush()
        version_two, _ = self.sync([item("A", "ALPHA MODIFIED")], "2" * 64)
        self.db.flush()
        return version_one, version_two

    def test_01_creates_persistent_version_with_archive(self):
        version, _ = self.sync([item("A", "ALPHA")])
        self.assertEqual(version.status, ACTIVE)
        self.assertEqual(version.archive_compression, "gzip")
        self.assertEqual(json.loads(gzip.decompress(version.archive_content)), [item("A", "ALPHA")])

    def test_02_same_sha_does_not_create_duplicate_version(self):
        version, _ = self.sync([item("A", "ALPHA")])
        same, result = self.sync([item("A", "ALPHA")])
        self.assertEqual(version.id, same.id)
        self.assertEqual(self.db.query(ListVersion).count(), 1)
        self.assertEqual(result["inserted_records"], 0)

    def test_32_import_after_restore_uses_active_version_not_latest_created(self):
        v10, _ = self.sync([item("A", "V10"), item("B", "B")], "a" * 64)
        v11, _ = self.sync([item("A", "V11"), item("B", "B")], "b" * 64)
        v12, _ = self.sync([item("A", "V12"), item("B", "B")], "c" * 64)
        self.db.flush()
        apply_version_restore(
            self.db, target_version_id=str(v10.id), expected_current_version_id=str(v12.id),
            reviewer_username="REVIEWER", reason="Retour V10",
        )
        self.db.flush()
        self.assertEqual(get_active_version(self.db, "TEST_SOURCE").id, v10.id)

        v13, result = self.sync([item("A", "V13"), item("B", "B")], "d" * 64)
        activation = self.db.query(ListVersionActivation).filter_by(version_id=v13.id).one()
        self.assertEqual(activation.previous_version_id, v10.id)
        self.assertEqual(result["updated_records"], 1)
        self.assertEqual(v11.status, ARCHIVED)
        self.assertEqual(v12.status, ARCHIVED)

    def test_33_queued_update_is_immediately_consultable(self):
        source = OFFICIAL_SOURCES["OFAC_SDN"]
        batch = queue_official_update(self.db, "OFAC_SDN", "TEST")
        self.assertEqual(batch.status, "EN_COURS")
        self.assertEqual(batch.source_liste, source.source_liste)
        self.assertEqual(batch.source_url, source.url)
        self.assertEqual(
            self.db.query(ImportBatch).filter_by(id=batch.id).one().status,
            "EN_COURS",
        )

    def test_34_restore_approval_returns_before_background_restore(self):
        v10, v11 = self.first_two_versions()
        approval = create_approval_request(
            self.db, operation_type=OP_LIST_VERSION_RESTORE,
            initiator={"id": "initiator", "username": "INIT"}, target_entity_type="ListVersion",
            target_entity_id=str(v10.id), old_values={}, new_values={
                "target_version_id": str(v10.id), "expected_current_version_id": str(v11.id),
            }, comment="test", ip_address=None,
        )
        queue_restore_approval(
            self.db, approval=approval, reviewer={"id": "reviewer", "username": "REVIEW"},
            comment="ok", ip_address=None,
        )
        self.db.commit()
        self.assertEqual(approval.status, IN_PROGRESS)
        process_queued_restore(self.db, str(approval.id))
        self.assertEqual(self.db.query(ListVersion).filter_by(id=v10.id).one().status, ACTIVE)
        self.assertEqual(self.db.query(type(approval)).filter_by(id=approval.id).one().status, APPROVED)

    def test_35_same_source_queue_is_rejected_but_other_source_is_independent(self):
        first = queue_official_update(self.db, "OFAC_SDN", "TEST")
        with self.assertRaises(SourceOperationInProgress):
            queue_official_update(self.db, "OFAC_SDN", "TEST")
        other = queue_official_update(self.db, "ONU", "TEST")
        self.assertEqual(first.status, "EN_COURS")
        self.assertEqual(other.status, "EN_COURS")

    def test_36_restart_requeues_persisted_work(self):
        batch = queue_official_update(self.db, "OFAC_SDN", "TEST")
        v10, v11 = self.first_two_versions()
        approval = create_approval_request(
            self.db, operation_type=OP_LIST_VERSION_RESTORE,
            initiator={"id": "initiator", "username": "INIT"}, target_entity_type="ListVersion",
            target_entity_id=str(v10.id), old_values={}, new_values={
                "target_version_id": str(v10.id), "expected_current_version_id": str(v11.id),
            }, comment="test", ip_address=None,
        )
        queue_restore_approval(
            self.db, approval=approval, reviewer={"id": "reviewer", "username": "REVIEW"},
            comment="ok", ip_address=None,
        )
        self.db.commit()
        recovery_db = sessionmaker(bind=self.engine)()
        with patch.object(scheduler_service, "SessionLocal", return_value=recovery_db), \
             patch.object(scheduler_service, "enqueue_manual_update") as queued_update, \
             patch.object(scheduler_service, "enqueue_restore_approval") as queued_restore:
            self.assertEqual(scheduler_service.recover_interrupted_work(), (1, 1))
        queued_update.assert_called_once_with("OFAC_SDN", batch.id, "TEST")
        queued_restore.assert_called_once_with(str(approval.id))

    def test_03_uses_published_stable_source_identifier(self):
        self.sync([item("OFFICIAL-42", "ALPHA")])
        entry = self.db.query(SanctionEntry).one()
        self.assertEqual(entry.source_record_id, "OFFICIAL-42")

    def test_04_marks_new_entry_as_addition(self):
        version, result = self.sync([item("A", "ALPHA")])
        change = self.db.query(ListVersionEntry).filter_by(list_version_id=version.id).one()
        self.assertEqual(result["inserted_records"], 1)
        self.assertEqual(change.change_type, CHANGE_ADDED)

    def test_05_detects_modification_without_duplicate(self):
        self.sync([item("A", "ALPHA")], "1" * 64)
        _, result = self.sync([item("A", "ALPHA UPDATED")], "2" * 64)
        self.assertEqual(result["updated_records"], 1)
        self.assertEqual(self.db.query(SanctionEntry).count(), 1)

    def test_06_marks_missing_record_as_delisted(self):
        _, version = self.first_two_versions()
        entry = self.db.query(SanctionEntry).filter_by(source_record_id="B").one()
        self.assertEqual(entry.statut, DELISTED)
        self.assertEqual(version.delisted_entries, 1)

    def test_07_radiation_is_recorded_in_history(self):
        _, version_two = self.first_two_versions()
        changes = self.db.query(ListVersionEntry).filter_by(list_version_id=version_two.id).all()
        self.assertIn(CHANGE_DELISTED, {change.change_type for change in changes})

    def test_08_reappearance_reactivates_existing_entry(self):
        self.first_two_versions()
        _, result = self.sync([item("A", "ALPHA MODIFIED"), item("B", "BETA")], "3" * 64)
        entry = self.db.query(SanctionEntry).filter_by(source_record_id="B").one()
        self.assertEqual(entry.statut, ENTRY_ACTIVE)
        self.assertEqual(result["reactivated_records"], 1)

    def test_09_reactivation_does_not_duplicate_entry(self):
        self.first_two_versions()
        self.sync([item("A", "ALPHA MODIFIED"), item("B", "BETA")], "3" * 64)
        self.assertEqual(self.db.query(SanctionEntry).filter_by(source_record_id="B").count(), 1)

    def test_10_preserves_existing_aliases(self):
        self.sync([item("A", "ALPHA", aliases=["ALIAS ONE"])], "1" * 64)
        self.sync([item("A", "ALPHA", aliases=["ALIAS TWO"])], "2" * 64)
        entry = self.db.query(SanctionEntry).one()
        self.assertEqual({alias.alias for alias in entry.aliases}, {"ALIAS ONE", "ALIAS TWO"})

    def test_11_version_archives_previous_current_version(self):
        first, second = self.first_two_versions()
        self.assertEqual(first.status, ARCHIVED)
        self.assertEqual(second.status, ACTIVE)

    def test_12_preview_has_no_database_write(self):
        first, _ = self.first_two_versions()
        before = self.db.query(SanctionEntry).filter_by(source_record_id="B").one().statut
        preview = get_version_preview(self.db, first)
        after = self.db.query(SanctionEntry).filter_by(source_record_id="B").one().statut
        self.assertEqual(before, after)
        self.assertGreaterEqual(preview["reactivated"], 1)

    def test_13_preview_is_source_scoped(self):
        first, _ = self.first_two_versions()
        self.sync([item("X", "OTHER")], "4" * 64, source="OTHER_SOURCE")
        preview = get_version_preview(self.db, first)
        self.assertEqual(preview["source_liste"], "TEST_SOURCE")
        self.assertEqual(self.db.query(SanctionEntry).filter_by(source_liste="OTHER_SOURCE").count(), 1)

    def test_14_restore_reactivates_delisted_record(self):
        first, current = self.first_two_versions()
        apply_version_restore(self.db, target_version_id=str(first.id), expected_current_version_id=str(current.id), reviewer_username="reviewer")
        self.assertEqual(self.db.query(SanctionEntry).filter_by(source_record_id="B").one().statut, ENTRY_ACTIVE)

    def test_15_restore_restores_prior_values(self):
        first, current = self.first_two_versions()
        apply_version_restore(self.db, target_version_id=str(first.id), expected_current_version_id=str(current.id), reviewer_username="reviewer")
        self.assertEqual(self.db.query(SanctionEntry).filter_by(source_record_id="A").one().nom, "ALPHA")

    def test_16_restore_is_source_isolated(self):
        first, current = self.first_two_versions()
        self.sync([item("X", "OTHER")], "4" * 64, source="OTHER_SOURCE")
        apply_version_restore(self.db, target_version_id=str(first.id), expected_current_version_id=str(current.id), reviewer_username="reviewer")
        self.assertEqual(self.db.query(SanctionEntry).filter_by(source_record_id="X").one().statut, ENTRY_ACTIVE)

    def test_17_restore_request_uses_existing_approval_workflow(self):
        first, current = self.first_two_versions()
        approval = create_approval_request(
            self.db, operation_type=OP_LIST_VERSION_RESTORE, initiator={"id": "author", "username": "author"},
            target_entity_type="ListVersion", target_entity_id=str(first.id), old_values={},
            new_values={"target_version_id": str(first.id), "expected_current_version_id": str(current.id)}, comment="corriger une publication", ip_address=None,
        )
        self.assertEqual(approval.status, PENDING)

    def test_18_initiator_cannot_approve_own_restore(self):
        first, current = self.first_two_versions()
        approval = create_approval_request(
            self.db, operation_type=OP_LIST_VERSION_RESTORE, initiator={"id": "author", "username": "author"},
            target_entity_type="ListVersion", target_entity_id=str(first.id), old_values={},
            new_values={"target_version_id": str(first.id), "expected_current_version_id": str(current.id)}, comment="motif", ip_address=None,
        )
        with self.assertRaises(PermissionError):
            review_approval_request(self.db, approval=approval, reviewer={"id": "author", "username": "author"}, approved=True, comment=None, ip_address=None)

    def test_19_second_user_approval_applies_restore(self):
        first, current = self.first_two_versions()
        approval = create_approval_request(
            self.db, operation_type=OP_LIST_VERSION_RESTORE, initiator={"id": "author", "username": "author"},
            target_entity_type="ListVersion", target_entity_id=str(first.id), old_values={},
            new_values={"target_version_id": str(first.id), "expected_current_version_id": str(current.id)}, comment="motif", ip_address=None,
        )
        review_approval_request(self.db, approval=approval, reviewer={"id": "reviewer", "username": "reviewer"}, approved=True, comment="ok", ip_address=None)
        self.assertEqual(approval.status, "VALIDE")
        self.assertEqual(self.db.query(SanctionEntry).filter_by(source_record_id="B").one().statut, ENTRY_ACTIVE)

    def test_20_migration_statements_are_idempotent(self):
        main_source = Path(__file__).with_name("app").joinpath("main.py").read_text(encoding="utf-8")
        self.assertIn("source_record_id VARCHAR(255)", main_source)
        self.assertIn("ADD COLUMN IF NOT EXISTS", main_source)
        self.assertIn("delisted_records INTEGER DEFAULT 0", main_source)

    def test_21_partial_file_cannot_radiate_everything(self):
        self.sync([item(str(index), f"NAME {index}") for index in range(20)], "1" * 64)
        before = self.db.query(SanctionEntry).filter_by(statut=ENTRY_ACTIVE).count()
        with self.assertRaises(SuspiciousListDropError):
            self.sync([], "2" * 64)
        self.assertEqual(self.db.query(SanctionEntry).filter_by(statut=ENTRY_ACTIVE).count(), before)
        self.assertEqual(self.db.query(ListVersion).count(), 1)

    def test_22_massive_drop_is_blocked_before_mutation(self):
        list_version_service.LIST_MAX_ENTRY_DROP_PERCENT = 30
        self.sync([item(str(index), f"NAME {index}") for index in range(100)], "1" * 64)
        with self.assertRaisesRegex(SuspiciousListDropError, "A_VERIFIER"):
            self.sync([item(str(index), f"NAME {index}") for index in range(10)], "2" * 64)
        self.assertEqual(self.db.query(SanctionEntry).filter_by(statut=ENTRY_ACTIVE).count(), 100)

    def test_23_restore_request_becomes_obsolete_after_scheduler_update(self):
        first, _ = self.sync([item("A", "V11"), item("B", "BETA")], "1" * 64)
        current, _ = self.sync([item("A", "V12"), item("B", "BETA")], "2" * 64)
        approval = create_approval_request(
            self.db, operation_type=OP_LIST_VERSION_RESTORE,
            initiator={"id": "author", "username": "author"},
            target_entity_type="ListVersion", target_entity_id=str(first.id), old_values={},
            new_values={"target_version_id": str(first.id), "expected_current_version_id": str(current.id)},
            comment="retour V11", ip_address=None,
        )
        latest, _ = self.sync([item("A", "V13"), item("B", "BETA")], "3" * 64)
        review_approval_request(
            self.db, approval=approval, reviewer={"id": "reviewer", "username": "reviewer"},
            approved=True, comment="ok", ip_address=None,
        )
        self.assertEqual(approval.status, "OBSOLETE")
        self.assertEqual(latest.status, ACTIVE)
        self.assertEqual(self.db.query(SanctionEntry).filter_by(source_record_id="A").one().nom, "V13")

    def test_24_same_source_concurrent_operation_is_rejected(self):
        class FakeDialect:
            name = "postgresql"
        class FakeBind:
            dialect = FakeDialect()
        class Result:
            def scalar(self):
                return False
        class LockedDb:
            def get_bind(self):
                return FakeBind()
            def execute(self, _statement, _params):
                return Result()
        with self.assertRaises(SourceOperationInProgress):
            _acquire_source_lock(LockedDb(), "OFAC_SDN")

    def test_25_lock_is_scoped_and_other_source_can_continue(self):
        class FakeDialect:
            name = "postgresql"
        class FakeBind:
            dialect = FakeDialect()
        class Result:
            def __init__(self, locked):
                self.locked = locked
            def scalar(self):
                return self.locked
        class ScopedDb:
            def get_bind(self):
                return FakeBind()
            def execute(self, _statement, params):
                return Result(params["source_liste"] != "OFAC_SDN")
        db = ScopedDb()
        with self.assertRaises(SourceOperationInProgress):
            _acquire_source_lock(db, "OFAC_SDN")
        _acquire_source_lock(db, "ONU")

    def test_26_restore_keeps_all_versions_and_adds_activation_event(self):
        first, _ = self.sync([item("A", "V10"), item("B", "BETA")], "1" * 64)
        self.sync([item("A", "V11"), item("B", "BETA")], "2" * 64)
        current, _ = self.sync([item("A", "V12"), item("B", "BETA")], "3" * 64)
        apply_version_restore(
            self.db, target_version_id=str(first.id),
            expected_current_version_id=str(current.id), reviewer_username="reviewer", reason="retour V10",
        )
        self.db.flush()
        self.assertEqual(self.db.query(ListVersion).count(), 3)
        self.assertEqual(self.db.query(ListVersionActivation).count(), 4)
        latest_activation = self.db.query(ListVersionActivation).filter_by(
            activation_type=ACTIVATION_RESTORE
        ).one()
        self.assertEqual(latest_activation.activation_type, ACTIVATION_RESTORE)
        self.assertEqual(latest_activation.version_id, first.id)

    def test_27_version_without_archive_is_not_restorable(self):
        version = ListVersion(
            source_liste="TEST_SOURCE", technical_version="legacy", file_hash="f" * 64,
            archive_content=b"", archive_compression="none", status=ARCHIVED,
        )
        self.assertFalse(is_version_restorable(version))
        with self.assertRaises(NonRestorableVersionError):
            get_version_preview(self.db, version)

    def test_28_same_sha_keeps_attempt_history_but_one_business_version(self):
        self.sync([item("A", "ALPHA")], "1" * 64)
        self.sync([item("A", "ALPHA")], "1" * 64)
        self.assertEqual(self.db.query(ImportBatch).count(), 2)
        self.assertEqual(self.db.query(ListVersion).count(), 1)

    def test_29_radiation_never_crosses_source_boundary(self):
        self.sync([item("A", "ALPHA"), item("B", "BETA")], "1" * 64)
        self.sync([item("X", "OTHER")], "2" * 64, source="OTHER_SOURCE")
        self.sync([item("A", "ALPHA")], "3" * 64)
        other = self.db.query(SanctionEntry).filter_by(source_liste="OTHER_SOURCE").one()
        self.assertEqual(other.statut, ENTRY_ACTIVE)

    def test_30_fifty_thousand_entries_remains_bounded(self):
        count = 50_000
        tracemalloc.start()
        started = time.perf_counter()
        first_entries = [item(f"R{index:05d}", f"NAME {index}") for index in range(count)]
        first, _ = self.sync(first_entries, "1" * 64)
        self.db.flush()
        first_seconds = time.perf_counter() - started

        compare_started = time.perf_counter()
        second_entries = [item(f"R{index:05d}", "NAME MODIFIED" if index == 0 else f"NAME {index}") for index in range(count)]
        current, result = self.sync(second_entries, "2" * 64)
        self.db.flush()
        compare_seconds = time.perf_counter() - compare_started

        preview_started = time.perf_counter()
        preview = get_version_preview(self.db, first)
        preview_seconds = time.perf_counter() - preview_started
        restore_started = time.perf_counter()
        apply_version_restore(
            self.db, target_version_id=str(first.id), expected_current_version_id=str(current.id),
            reviewer_username="perf-reviewer", reason="test volumétrie",
        )
        self.db.flush()
        restore_seconds = time.perf_counter() - restore_started
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertEqual(result["updated_records"], 1)
        self.assertEqual(preview["total_target_entries"], count)
        self.assertLess(first_seconds, 120)
        self.assertLess(compare_seconds, 120)
        self.assertLess(preview_seconds, 120)
        self.assertLess(restore_seconds, 120)
        self.assertLess(peak_bytes, 1_500_000_000)
        print(
            "LOT2B_PERF_50K "
            f"create={first_seconds:.2f}s compare={compare_seconds:.2f}s "
            f"preview={preview_seconds:.2f}s restore={restore_seconds:.2f}s "
            f"peak_mb={peak_bytes / 1024 / 1024:.1f} "
            f"archive_mb={len(first.archive_content) / 1024 / 1024:.2f}"
        )

    def test_31_name_only_hash_is_not_accepted_as_stable_identity(self):
        name_only = item("A", "ALPHA")
        name_only.pop("source_record_id")
        with self.assertRaises(SuspiciousListDropError):
            self.sync([name_only], "9" * 64)
        self.assertEqual(self.db.query(SanctionEntry).count(), 0)


if __name__ == "__main__":
    unittest.main()
