"""Focused validation checks; run with python -m unittest discover -s tests -v."""

import csv
import tempfile
import unittest
from datetime import date
from pathlib import Path

from pydantic import ValidationError

from src.data_loader import REQUIRED_COLUMNS, load_and_validate_csv
from src.models import VulnerabilityRecord


VALID_ROW = {
    "vulnerability_id": "SYN-001",
    "scan_date": "2026-03-01",
    "tool": "QWIET-SAST",
    "application": "Fictional Portal",
    "severity": "High",
    "vulnerability_name": "SQL injection",
    "status": "Open",
    "resolved_date": "",
}


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "findings.csv"

    def write_rows(self, rows, columns=REQUIRED_COLUMNS):
        with self.path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    def test_valid_data_and_text_preservation(self):
        self.write_rows([dict(VALID_ROW, vulnerability_id="001", application="NA")])
        records, report = load_and_validate_csv(self.path)
        self.assertEqual(report.errors, [])
        self.assertEqual(records[0].vulnerability_id, "001")
        self.assertEqual(records[0].application, "NA")
        self.assertEqual(records[0].scan_date, date(2026, 3, 1))
        self.assertIsNone(records[0].resolved_date)

    def test_invalid_severity_excludes_only_invalid_row(self):
        self.write_rows([VALID_ROW, dict(VALID_ROW, vulnerability_id="SYN-002", severity="Urgent")])
        records, report = load_and_validate_csv(self.path)
        self.assertEqual(len(records), 1)
        self.assertEqual(report.invalid_rows, [3])
        self.assertEqual(report.errors[0].field, "severity")
        self.assertTrue(report.errors[0].message)

    def test_duplicate_ids_include_otherwise_invalid_rows(self):
        self.write_rows([VALID_ROW, dict(VALID_ROW, vulnerability_id=" SYN-001 ", severity="Urgent"), dict(VALID_ROW, vulnerability_id="SYN-002")])
        records, report = load_and_validate_csv(self.path)
        self.assertEqual([row.vulnerability_id for row in records], ["SYN-002"])
        self.assertEqual([e.row_number for e in report.errors if e.code == "duplicate_id"], [2, 3])

    def test_invalid_dates(self):
        for value in ("2026-02-30", "03/01/2026", "20260301", "2026-03-01T00:00:00", "", "1772323200"):
            with self.subTest(value=value):
                self.write_rows([dict(VALID_ROW, scan_date=value)])
                records, report = load_and_validate_csv(self.path)
                self.assertEqual(records, [])
                self.assertEqual(report.errors[0].field, "scan_date")

    def test_resolution_rules(self):
        cases = (("Resolved", ""), ("Open", "2026-03-02"), ("In Progress", "2026-03-02"), ("Resolved", "2026-02-28"), ("Resolved", "2026-02-30"))
        for status, resolved in cases:
            with self.subTest(status=status, resolved=resolved):
                self.write_rows([dict(VALID_ROW, status=status, resolved_date=resolved)])
                records, report = load_and_validate_csv(self.path)
                self.assertEqual(records, [])
                self.assertEqual(report.errors[0].field, "resolved_date")

    def test_valid_resolution_on_or_after_scan(self):
        for value in ("2026-03-01", "2026-03-02"):
            with self.subTest(value=value):
                self.write_rows([dict(VALID_ROW, status="Resolved", resolved_date=value)])
                records, report = load_and_validate_csv(self.path)
                self.assertEqual(len(records), 1)
                self.assertEqual(report.errors, [])

    def test_required_text_fields(self):
        for name in ("vulnerability_id", "tool", "application", "vulnerability_name"):
            with self.subTest(field=name):
                self.write_rows([dict(VALID_ROW, **{name: "   "})])
                records, report = load_and_validate_csv(self.path)
                self.assertEqual(records, [])
                self.assertEqual(report.errors[0].field, name)

    def test_invalid_status(self):
        self.write_rows([dict(VALID_ROW, status="Closed")])
        records, report = load_and_validate_csv(self.path)
        self.assertEqual(records, [])
        self.assertEqual(report.errors[0].field, "status")

    def test_omitted_resolution_for_resolved_model(self):
        row = dict(VALID_ROW, status="Resolved")
        del row["resolved_date"]
        with self.assertRaises(ValidationError):
            VulnerabilityRecord.model_validate(row)

    def test_missing_required_column(self):
        self.write_rows([VALID_ROW], columns=REQUIRED_COLUMNS[:-1])
        records, report = load_and_validate_csv(self.path)
        self.assertEqual(records, [])
        self.assertTrue(report.has_file_errors)
        self.assertEqual(report.errors[0].field, "resolved_date")

    def test_unreadable_and_empty_files(self):
        for content in (None, b"", b"\xff\xfe"):
            with self.subTest(content=content):
                if content is not None:
                    self.path.write_bytes(content)
                records, report = load_and_validate_csv(self.path)
                self.assertEqual(records, [])
                self.assertTrue(report.has_file_errors)

    def test_wrong_width_does_not_discard_good_rows(self):
        self.write_rows([VALID_ROW])
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("SYN-002,2026-03-01\n")
        records, report = load_and_validate_csv(self.path)
        self.assertEqual(len(records), 1)
        self.assertEqual(report.invalid_rows, [3])
        self.assertEqual(report.errors[0].code, "invalid_row_width")

    def test_duplicate_header_and_malformed_csv(self):
        for text in (",".join(REQUIRED_COLUMNS + ("tool",)) + "\n", ",".join(REQUIRED_COLUMNS) + '\n"unterminated'):
            with self.subTest(text=text):
                self.path.write_text(text, encoding="utf-8")
                records, report = load_and_validate_csv(self.path)
                self.assertEqual(records, [])
                self.assertTrue(report.has_file_errors)

    def test_multiline_record_reports_starting_line(self):
        self.write_rows([dict(VALID_ROW, vulnerability_name="Line one\nLine two"), dict(VALID_ROW, vulnerability_id="SYN-002", severity="Urgent")])
        records, report = load_and_validate_csv(self.path)
        self.assertEqual(len(records), 1)
        self.assertEqual(report.invalid_rows, [4])

    def test_header_only_file(self):
        self.write_rows([])
        records, report = load_and_validate_csv(self.path)
        self.assertEqual(records, [])
        self.assertEqual(report.total_rows, 0)
        self.assertEqual(report.errors, [])

    def test_synthetic_dataset_unchanged_and_valid(self):
        path = Path(__file__).resolve().parents[1] / "data" / "vulnerabilities.csv"
        before = path.read_bytes()
        records, report = load_and_validate_csv(path)
        self.assertEqual(report.errors, [])
        self.assertEqual(report.total_rows, 350)
        self.assertEqual(len(records), 350)
        self.assertEqual(len({row.vulnerability_id for row in records}), 350)
        self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
