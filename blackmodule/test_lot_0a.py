import asyncio
import os
import unittest

from openpyxl import Workbook

from app.routers.exports import _temporary_excel_response, _write_only_sheet
from app.services.matching_service import (
    _name_tokens,
    build_full_name,
    calculate_name_scores_batch,
    normalize_text,
)


class Lot0AMatchingTests(unittest.TestCase):
    def test_normalization_and_exact_name_score(self):
        client_name = build_full_name("Élodie", "D'Angers")
        self.assertEqual(client_name, "ELODIE D ANGERS")
        self.assertEqual(normalize_text("  élodie-d'angers "), client_name)
        self.assertEqual(calculate_name_scores_batch(client_name, ["ELODIE D ANGERS"]), [100.0])

    def test_candidate_tokens_are_unique_and_not_single_character(self):
        self.assertEqual(_name_tokens("A JEAN JEAN D"), ["JEAN"])


class Lot0AExportTests(unittest.TestCase):
    def test_write_only_export_uses_temporary_file_and_cleans_it_up(self):
        workbook = Workbook(write_only=True)
        sheet = _write_only_sheet(workbook, "Test", ["Colonne"])
        sheet.append(["valeur"])

        response = _temporary_excel_response(workbook, "test.xlsx")
        self.assertTrue(os.path.exists(response.path))
        asyncio.run(response.background())
        self.assertFalse(os.path.exists(response.path))


if __name__ == "__main__":
    unittest.main()
