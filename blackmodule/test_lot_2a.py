import unittest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import requests

from app.models import ImportBatch
from app.services import list_update_service as lists


class _FakeSession:
    def __init__(self):
        self.added = []
        self.rollbacks = 0
        self.commits = 0

    def add(self, item):
        self.added.append(item)

    def flush(self):
        return None

    def rollback(self):
        self.rollbacks += 1

    def commit(self):
        self.commits += 1

    def refresh(self, item):
        return None


class _SequenceQuery:
    def __init__(self, item):
        self.item = item

    def filter(self, *_args):
        return self

    def order_by(self, *_args):
        return self

    def first(self):
        return self.item


class _FreshnessSession:
    def __init__(self, attempts):
        self.attempts = iter(attempts)

    def query(self, _model):
        return _SequenceQuery(next(self.attempts))


class _AlertSession:
    def __init__(self, previous_alert=None):
        self.previous_alert = previous_alert
        self.commits = 0

    def query(self, _model):
        return _SequenceQuery(self.previous_alert)

    def commit(self):
        self.commits += 1


class Lot2AOfficialListsTests(unittest.TestCase):
    def test_ofac_uses_sanctions_list_service_not_legacy_download_urls(self):
        self.assertIn("sanctionslistservice.ofac.treas.gov", lists.OFAC_SDN_XML_URL)
        self.assertIn("sanctionslistservice.ofac.treas.gov", lists.OFAC_CONSOLIDATED_XML_URL)
        self.assertNotIn("www.treasury.gov", lists.OFAC_SDN_XML_URL)
        self.assertNotIn("www.treasury.gov", lists.OFAC_CONSOLIDATED_XML_URL)

    @patch("app.services.list_update_service.requests.get")
    def test_download_captures_hash_size_and_publication_date(self, get):
        response = Mock()
        response.content = b"<?xml version='1.0'?><sdnList/>"
        response.headers = {"Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT"}
        response.raise_for_status.return_value = None
        get.return_value = response

        downloaded = lists.download_official_file(lists.OFFICIAL_SOURCES["OFAC_SDN"])

        self.assertEqual(downloaded.file_size_bytes, len(response.content))
        self.assertEqual(downloaded.file_hash, lists.calculate_file_hash(response.content))
        self.assertEqual(downloaded.published_at, datetime(2015, 10, 21, 7, 28))
        self.assertEqual(get.call_args.kwargs["timeout"], 90)

    @patch("app.services.list_update_service.requests.get")
    def test_downloader_sends_non_empty_user_agent(self, get):
        response = Mock()
        response.content = b"<sdnList/>"
        response.headers = {}
        response.raise_for_status.return_value = None
        get.return_value = response

        lists.download_official_file(lists.OFFICIAL_SOURCES["OFAC_SDN"])

        self.assertTrue(get.call_args.kwargs["headers"]["User-Agent"])

    @patch("app.services.list_update_service.requests.get")
    def test_http_error_is_persisted_as_failed_attempt_with_source_url(self, get):
        get.side_effect = requests.HTTPError("403 Client Error")
        db = _FakeSession()

        with self.assertRaises(requests.HTTPError):
            lists.auto_update_ofac_sdn(db, imported_by="TEST")

        failed_batches = [
            item for item in db.added
            if isinstance(item, ImportBatch) and item.status == "FAILED"
        ]
        self.assertEqual(len(failed_batches), 1)
        self.assertEqual(failed_batches[0].source_liste, "OFAC_SDN")
        self.assertEqual(failed_batches[0].source_url, lists.OFAC_SDN_XML_URL)
        self.assertIsNotNone(failed_batches[0].downloaded_at)

    def test_freshness_distinguishes_fresh_late_and_failed_attempts(self):
        now = datetime(2026, 8, 26, 12, 0, 0)
        sources = list(lists.FRESHNESS_RULES)
        successes = []
        attempts = []
        for source in sources:
            success = ImportBatch(source_liste=source, status="SUCCESS")
            success.imported_at = now - timedelta(days=1)
            attempt = ImportBatch(source_liste=source, status="SUCCESS")
            attempt.imported_at = now - timedelta(hours=1)
            successes.append(success)
            attempts.append(attempt)

        late_index = sources.index("UE")
        successes[late_index].imported_at = now - timedelta(days=10)
        failed_index = sources.index("OFAC_SDN")
        attempts[failed_index].status = "FAILED"

        with patch(
            "app.services.list_update_service.get_last_success_batch",
            side_effect=successes,
        ):
            result = lists.get_list_freshness(_FreshnessSession(attempts), now=now)

        status_by_source = {item["source"]: item["status"] for item in result}
        self.assertEqual(status_by_source["OFAC_SDN"], "ECHEC")
        self.assertEqual(status_by_source["UE"], "EN_RETARD")
        self.assertEqual(status_by_source["ONU"], "FRAICHE")

    def test_stale_list_creates_one_application_alert(self):
        stale = {
            "source": "FR_GEL",
            "status": "EN_RETARD",
            "maximum_age_days": 2,
            "last_success": datetime(2026, 8, 20),
        }
        db = _AlertSession()

        with patch("app.services.list_update_service.get_list_freshness", return_value=[stale]), patch(
            "app.services.list_update_service.write_audit_log"
        ) as write_audit_log:
            alerts = lists.emit_list_freshness_alerts(db)

        self.assertEqual(alerts, [stale])
        self.assertEqual(db.commits, 1)
        self.assertEqual(write_audit_log.call_args.kwargs["action"], "LIST_UPDATE_ALERT")
        self.assertEqual(write_audit_log.call_args.kwargs["entity_id"], "FR_GEL")

    def test_stale_alert_is_not_duplicated_before_a_new_success(self):
        stale = {
            "source": "FR_GEL",
            "status": "EN_RETARD",
            "maximum_age_days": 2,
            "last_success": datetime(2026, 8, 20),
        }
        previous_alert = Mock(created_at=datetime(2026, 8, 21))
        db = _AlertSession(previous_alert=previous_alert)

        with patch("app.services.list_update_service.get_list_freshness", return_value=[stale]), patch(
            "app.services.list_update_service.write_audit_log"
        ) as write_audit_log:
            alerts = lists.emit_list_freshness_alerts(db)

        self.assertEqual(alerts, [])
        self.assertEqual(db.commits, 0)
        write_audit_log.assert_not_called()

    def test_migration_columns_are_idempotent_add_column_statements(self):
        with open("app/main.py", encoding="utf-8") as main_file:
            startup_code = main_file.read()

        for column in (
            "source_url VARCHAR(1000)",
            "downloaded_at TIMESTAMP",
            "published_at TIMESTAMP",
            "file_size_bytes INTEGER",
        ):
            self.assertIn(f'"{column}"', startup_code)
        self.assertIn(
            'ALTER TABLE import_batches ADD COLUMN IF NOT EXISTS {column_def}',
            startup_code,
        )


if __name__ == "__main__":
    unittest.main()
