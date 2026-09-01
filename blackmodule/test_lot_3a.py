"""LOT 3A regression tests for deterministic, explainable matching."""

import re
import time
import unittest
import uuid
from datetime import date

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import MatchingSetting, SanctionAlias, SanctionEntry
from app.services.approval_service import (
    OP_MATCHING_SETTINGS,
    create_approval_request,
    review_approval_request,
)
from app.services.matching_service import (
    calculate_name_score,
    calculate_name_scores_batch,
    classify_alert,
    evaluate_candidate,
    select_matching_candidates,
)
from app.services.parsers.ofac_sdn_parser import parse_ofac_sdn_xml


def _sqlite_functions(dbapi_connection, _):
    dbapi_connection.create_function("unaccent", 1, lambda value: value)
    dbapi_connection.create_function(
        "regexp_replace", 4,
        lambda value, pattern, replacement, flags: re.sub(pattern, replacement, value or ""),
    )


class Lot3AMatchingTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        event.listen(self.engine, "connect", _sqlite_functions)
        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def entry(self, *, name="JEAN DUPONT", aliases=None, **values):
        parts = name.split(" ", 1)
        entry = SanctionEntry(
            source_liste=values.pop("source_liste", "TEST"),
            type_entite="PERSONNE",
            prenom=parts[0] if len(parts) == 2 else None,
            nom=parts[-1],
            nom_complet=name,
            statut=values.pop("statut", "ACTIF"),
            **values,
        )
        entry.aliases = [SanctionAlias(alias=alias) for alias in aliases or []]
        return entry

    def evaluate(self, entry, client_name, **evidence):
        listed_name = entry.nom_complet
        score = calculate_name_score(client_name, listed_name)
        return evaluate_candidate(entry, client_name, listed_name, score, **evidence)

    def test_01_exact_name(self):
        result = self.evaluate(self.entry(), "JEAN DUPONT")
        self.assertEqual((result.score, result.matching_type), (100.0, "EXACT_NAME"))

    def test_02_exact_alias_is_selected_and_scored(self):
        entry = self.entry(aliases=["JOHNNY DUPONT"])
        self.db.add(entry)
        self.db.commit()
        candidates = select_matching_candidates(self.db, "JOHNNY DUPONT")
        self.assertEqual(len(candidates), 1)
        result = evaluate_candidate(candidates[0][0], "JOHNNY DUPONT", candidates[0][1], candidates[0][2])
        self.assertEqual((result.score, result.matching_type), (100.0, "EXACT_ALIAS"))

    def test_03_safe_abbreviation(self):
        result = self.evaluate(self.entry(), "J DUPONT")
        self.assertEqual((result.score, result.matching_type), (85.0, "NAME_ABBREVIATION"))

    def test_04_numeric_name_noise_is_ignored(self):
        entry = self.entry()
        self.db.add(entry)
        self.db.commit()
        candidates = select_matching_candidates(self.db, "JEAN DUPONT 12345")
        self.assertEqual(len(candidates), 1)
        result = evaluate_candidate(
            candidates[0][0], "JEAN DUPONT 12345", candidates[0][1], candidates[0][2],
        )
        self.assertEqual((result.score, result.matching_type), (95.0, "NORMALIZED_NAME"))
        self.assertIn("Caractères parasites ignorés", result.explanation[0])

    def test_05_same_name_with_different_birthdate_is_not_a_positive(self):
        entry = self.entry(date_naissance=date(1980, 1, 1))
        result = self.evaluate(entry, "JEAN DUPONT", date_naissance=date(1990, 1, 1))
        self.assertLess(result.score, 60.0)
        self.assertIn("Dates de naissance contradictoires", result.explanation)

    def test_06_same_name_with_different_passport_is_not_a_positive(self):
        entry = self.entry(num_passeport="PASS-001")
        result = self.evaluate(entry, "JEAN DUPONT", passport_number="PASS-999")
        self.assertLess(result.score, 60.0)
        self.assertIn("Passeports contradictoires", result.explanation)

    def test_07_exact_passport_is_decisive(self):
        entry = self.entry(name="AUTRE PERSONNE", num_passeport="AB-123")
        self.db.add(entry)
        self.db.commit()
        candidates = select_matching_candidates(self.db, "JEAN DUPONT", passport_number="AB123")
        self.assertEqual(len(candidates), 1)
        result = evaluate_candidate(
            candidates[0][0], "JEAN DUPONT", candidates[0][1], candidates[0][2],
            passport_number="AB123",
        )
        self.assertEqual((result.score, result.matching_type), (100.0, "EXACT_PASSPORT"))

    def test_08_exact_secondary_document_is_decisive(self):
        entry = self.entry(name="AUTRE PERSONNE", autres_documents="CNI : ID-7788")
        self.db.add(entry)
        self.db.commit()
        candidates = select_matching_candidates(self.db, "JEAN DUPONT", document_number="ID7788")
        self.assertEqual(len(candidates), 1)
        result = evaluate_candidate(
            candidates[0][0], "JEAN DUPONT", candidates[0][1], candidates[0][2],
            document_number="ID7788",
        )
        self.assertEqual((result.score, result.matching_type), (100.0, "EXACT_DOCUMENT"))

    def test_08b_non_document_metadata_is_never_an_exact_identifier(self):
        entry = self.entry(
            name="PAUL MALONG AWAN",
            autres_documents="GENDER : MALE / NATIONAL IDENTIFIER NUMBER: A-12345",
        )
        self.db.add(entry)
        self.db.commit()

        metadata_candidates = select_matching_candidates(
            self.db, "PAUL MALONG AWAN", document_number="MALE",
        )
        metadata_result = evaluate_candidate(
            metadata_candidates[0][0], "PAUL MALONG AWAN",
            metadata_candidates[0][1], metadata_candidates[0][2],
            document_number="MALE",
        )
        self.assertEqual(metadata_result.score, 40.0)
        self.assertNotEqual(metadata_result.matching_type, "EXACT_DOCUMENT")
        self.assertIn("Documents contradictoires", metadata_result.explanation)

        document_candidates = select_matching_candidates(
            self.db, "AUTRE PERSONNE", document_number="A12345",
        )
        document_result = evaluate_candidate(
            document_candidates[0][0], "AUTRE PERSONNE",
            document_candidates[0][1], document_candidates[0][2],
            document_number="A12345",
        )
        self.assertEqual(
            (document_result.score, document_result.matching_type),
            (100.0, "EXACT_DOCUMENT"),
        )

    def test_09_thresholds_change_only_after_second_user_approval(self):
        settings = MatchingSetting(
            exact_threshold=90.0, probable_threshold=75.0, possible_threshold=60.0,
            updated_by="SYSTEM",
        )
        self.db.add(settings)
        self.db.flush()
        approval = create_approval_request(
            self.db,
            operation_type=OP_MATCHING_SETTINGS,
            initiator={"id": "initiator-id", "username": "initiator"},
            target_entity_type="MatchingSetting",
            target_entity_id=str(settings.id),
            old_values={"exact_threshold": 90, "probable_threshold": 75, "possible_threshold": 60},
            new_values={"exact_threshold": 95, "probable_threshold": 80, "possible_threshold": 65},
            comment="Réglage contrôlé",
            ip_address=None,
        )
        self.assertEqual(settings.possible_threshold, 60.0)
        review_approval_request(
            self.db,
            approval=approval,
            reviewer={"id": "reviewer-id", "username": "reviewer"},
            approved=True,
            comment="Validé",
            ip_address=None,
        )
        self.db.flush()
        self.assertEqual(
            (settings.exact_threshold, settings.probable_threshold, settings.possible_threshold),
            (95.0, 80.0, 65.0),
        )

    def test_10_threshold_self_approval_is_forbidden(self):
        settings = MatchingSetting(exact_threshold=90, probable_threshold=75, possible_threshold=60)
        self.db.add(settings)
        self.db.flush()
        actor = {"id": "same-id", "username": "same-user"}
        approval = create_approval_request(
            self.db, operation_type=OP_MATCHING_SETTINGS, initiator=actor,
            target_entity_type="MatchingSetting", target_entity_id=str(settings.id),
            old_values={"exact_threshold": 90, "probable_threshold": 75, "possible_threshold": 60},
            new_values={"exact_threshold": 95, "probable_threshold": 80, "possible_threshold": 65},
            comment=None, ip_address=None,
        )
        with self.assertRaises(PermissionError):
            review_approval_request(
                self.db, approval=approval, reviewer=actor, approved=True,
                comment=None, ip_address=None,
            )
        self.assertEqual(settings.possible_threshold, 60)

    def test_11_result_is_explainable_and_stable(self):
        entry = self.entry(date_naissance=date(1980, 1, 1), nationalite="FRANCAISE")
        first = self.evaluate(
            entry, "JEAN DUPONT", date_naissance=date(1980, 1, 1), nationalite="FRANCAISE",
        )
        second = self.evaluate(
            entry, "JEAN DUPONT", date_naissance=date(1980, 1, 1), nationalite="FRANCAISE",
        )
        self.assertEqual(first, second)
        self.assertEqual(first.name_score, 100.0)
        self.assertIn("Nom exact", first.explanation)
        self.assertIn("Date de naissance concordante", first.explanation)
        self.assertIn("Nationalité concordante", first.explanation)

    def test_12_batch_performance_is_not_regressed(self):
        names = [f"PERSONNE TEST {index}" for index in range(50_000)]
        names[24_321] = "CIBLE UNIQUE"
        started = time.perf_counter()
        scores = calculate_name_scores_batch("CIBLE UNIQUE", names)
        elapsed = time.perf_counter() - started
        self.assertEqual(scores[24_321], 100.0)
        self.assertLess(elapsed, 5.0)

    def test_13_different_nationality_reduces_but_does_not_override_name(self):
        entry = self.entry(nationalite="FRANCAISE")
        result = self.evaluate(entry, "JEAN DUPONT", nationalite="CAMEROUNAISE")
        self.assertEqual(result.score, 85.0)
        self.assertIn("Nationalités différentes", result.explanation)

    def test_14_multi_source_entries_remain_independent(self):
        first = self.entry(source_liste="ONU")
        second = self.entry(source_liste="OFAC")
        self.db.add_all([first, second])
        self.db.commit()
        candidates = select_matching_candidates(self.db, "JEAN DUPONT")
        self.assertEqual({entry.source_liste for entry, _, _ in candidates}, {"ONU", "OFAC"})

    def test_15_paul_malong_awan_reference_variants_with_legacy_active_status(self):
        entry = self.entry(
            name="PAUL MALONG AWAN",
            aliases=["Paul Awan MALONG", "Paul MALONG"],
            source_liste="OFAC_SDN",
            statut="ACTIVE",
        )
        self.db.add(entry)
        self.db.commit()

        expected = {
            "PAUL MALONG AWAN": (100.0, "EXACT_NAME"),
            "P MALONG AWAN": (89.66, "NAME_ABBREVIATION"),
            "PAUL MALONG AWAN123": (95.0, "NORMALIZED_NAME"),
        }
        for search, expected_result in expected.items():
            with self.subTest(search=search):
                candidates = select_matching_candidates(self.db, search)
                self.assertEqual(len(candidates), 1)
                result = evaluate_candidate(
                    candidates[0][0], search, candidates[0][1], candidates[0][2],
                )
                expected_score, expected_type = expected_result
                self.assertEqual(result.matching_type, expected_type)
                self.assertAlmostEqual(result.score, expected_score, places=2)
                if result.matching_type == "NORMALIZED_NAME":
                    self.assertLess(result.score, 100.0)
                    self.assertIn("Caractères parasites ignorés", result.explanation[0])

    def test_16_alert_level_requires_exact_evidence_not_only_a_high_score(self):
        self.assertEqual(
            classify_alert(100.0, matching_type="EXACT_NAME")[0],
            "ALERTE_EXACTE",
        )
        self.assertEqual(
            classify_alert(100.0, matching_type="EXACT_DOCUMENT")[0],
            "ALERTE_EXACTE",
        )
        for matching_type, score in (
            ("NAME_ABBREVIATION", 89.66),
            ("NORMALIZED_NAME", 95.0),
            ("FUZZY_NAME", 99.0),
            ("NAME_AND_BIRTHDATE", 95.0),
        ):
            with self.subTest(matching_type=matching_type):
                self.assertEqual(
                    classify_alert(score, matching_type=matching_type),
                    ("ALERTE_PROBABLE", "REVUE_CONFORMITE"),
                )

    def test_17_ofac_passport_is_available_to_generic_document_matching(self):
        ofac_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <sdnList>
          <sdnEntry>
            <uid>12345</uid>
            <firstName>Paul</firstName>
            <lastName>Malong Awan</lastName>
            <sdnType>Individual</sdnType>
            <dateOfBirthList><dateOfBirthItem><dateOfBirth>1962-01-02</dateOfBirth></dateOfBirthItem></dateOfBirthList>
            <idList><id><idType>Passport</idType><idNumber>S00004370</idNumber></id></idList>
          </sdnEntry>
        </sdnList>"""
        parsed = parse_ofac_sdn_xml(ofac_xml)[0]
        self.assertEqual(parsed["num_passeport"], "S00004370")
        self.assertIsNone(parsed["autres_documents"])

        entry = self.entry(
            name="PAUL MALONG AWAN",
            aliases=["PAUL AWAN MALONG"],
            source_liste="OFAC_SDN",
            statut="ACTIVE",
            num_passeport=parsed["num_passeport"],
            date_naissance=parsed["date_naissance"],
        )
        self.db.add(entry)
        self.db.commit()

        name_only = self.evaluate(entry, "PAUL MALONG AWAN")
        self.assertEqual((name_only.score, name_only.matching_type), (100.0, "EXACT_NAME"))

        wrong_document = self.evaluate(
            entry, "PAUL MALONG AWAN", document_number="TEST-999999",
        )
        self.assertEqual(wrong_document.score, 40.0)
        self.assertIn("Documents contradictoires", wrong_document.explanation)

        candidates = select_matching_candidates(
            self.db, "NOM SANS RAPPORT", document_number="S00004370",
        )
        self.assertEqual(len(candidates), 1)
        exact_document = evaluate_candidate(
            candidates[0][0], "NOM SANS RAPPORT", candidates[0][1], candidates[0][2],
            document_number="S00004370",
        )
        self.assertEqual(
            (exact_document.score, exact_document.matching_type),
            (100.0, "EXACT_DOCUMENT"),
        )
        self.assertIn("Document exact", exact_document.explanation)

        exact_passport = self.evaluate(
            entry, "NOM SANS RAPPORT", passport_number="S00004370",
        )
        self.assertEqual(
            (exact_passport.score, exact_passport.matching_type),
            (100.0, "EXACT_PASSPORT"),
        )
        self.assertIn("Passeport exact", exact_passport.explanation)

        wrong_birthdate = self.evaluate(
            entry, "PAUL MALONG AWAN", date_naissance=date(1970, 1, 1),
        )
        self.assertEqual(wrong_birthdate.score, 40.0)
        self.assertIn("Dates de naissance contradictoires", wrong_birthdate.explanation)

        alias = self.evaluate(entry, "PAUL AWAN MALONG")
        abbreviation = self.evaluate(entry, "P MALONG AWAN")
        normalized = self.evaluate(entry, "PAUL MALONG AWAN123")
        self.assertEqual((alias.score, alias.matching_type), (100.0, "EXACT_ALIAS"))
        self.assertEqual((abbreviation.score, abbreviation.matching_type), (89.66, "NAME_ABBREVIATION"))
        self.assertEqual((normalized.score, normalized.matching_type), (95.0, "NORMALIZED_NAME"))


if __name__ == "__main__":
    unittest.main()
