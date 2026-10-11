"""Demonstrate rejection of intentionally invalid, entirely synthetic test data.

Run with pytest -s to display the existing loader's validation report.
The fixture is a test artifact; it never replaces the 350-record dataset.
"""

import csv
from pathlib import Path

import pytest

from src.data_loader import REQUIRED_COLUMNS, load_and_validate_csv


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "invalid_vulnerabilities.csv"


@pytest.fixture
def fixture_result():
    return load_and_validate_csv(FIXTURE)


def test_fixture_schema():
    with FIXTURE.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    assert rows[0] == list(REQUIRED_COLUMNS)
    assert len(rows) == 13
    assert all(len(row) == 8 for row in rows)


def test_fixture_summary_and_terminal_report(fixture_result):
    records, report = fixture_result
    assert report.total_rows == 12
    assert len(records) == 3
    assert len(report.invalid_rows) == 9
    assert len(report.errors) == 9
    assert not report.has_file_errors
    assert {record.vulnerability_id for record in records} == {
        "SYN-TEST-VALID-001", "SYN-TEST-VALID-002", "SYN-TEST-VALID-003",
    }
    assert report.invalid_rows == list(range(5, 14))
    print("\nIntentionally invalid SYNTHETIC test fixture (not real findings)")
    print(f"Total records: {report.total_rows}; valid: {len(records)}; invalid: {len(report.invalid_rows)}")
    print("CSV line numbers include the header on line 1.")
    for error in sorted(report.errors, key=lambda issue: (issue.row_number, issue.field)):
        print(f"Row {error.row_number} | {error.field} | {error.message}")


@pytest.mark.parametrize(
    "row_number, field, message_fragment",
    [
        (5, "severity", "Critical"),
        (6, "status", "In Progress"),
        (7, "vulnerability_id", "at least 1 character"),
        (8, "scan_date", "valid calendar date"),
        (9, "resolved_date", "on or after scan_date"),
        (10, "vulnerability_id", "Duplicate vulnerability_id"),
        (11, "vulnerability_id", "Duplicate vulnerability_id"),
        (12, "resolved_date", "required when status is Resolved"),
        (13, "resolved_date", "must be blank"),
    ],
)
def test_invalid_row_reports_field_and_reason(fixture_result, row_number, field, message_fragment):
    _, report = fixture_result
    matching = [error for error in report.errors if error.row_number == row_number and error.field == field]
    assert len(matching) == 1
    assert message_fragment in matching[0].message
    assert matching[0].code


def test_original_dataset_still_valid_and_unchanged():
    path = PROJECT_ROOT / "data" / "vulnerabilities.csv"
    before = path.read_bytes()
    # Exercise the invalid input first to check that it cannot affect the original.
    load_and_validate_csv(FIXTURE)
    records, report = load_and_validate_csv(path)
    assert report.total_rows == 350
    assert len(records) == 350
    assert len({record.vulnerability_id for record in records}) == 350
    assert report.invalid_rows == []
    assert report.errors == []
    assert path.read_bytes() == before
    print("\nOriginal synthetic CSV: 350 valid; 0 invalid; 0 errors; bytes unchanged.")
