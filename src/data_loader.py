"""Load CSV findings and isolate invalid rows before they reach analytics."""

import csv
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd
from pydantic import ValidationError

from src.models import ORIGINAL_COLUMNS, VulnerabilityRecord


REQUIRED_COLUMNS = ORIGINAL_COLUMNS


@dataclass(frozen=True)
class ValidationIssue:
    """row_number is the starting CSV line (header is line 1), or None for file errors."""

    row_number: int | None
    field: str
    message: str
    code: str


@dataclass
class ValidationReport:
    total_rows: int = 0
    errors: list[ValidationIssue] = field(default_factory=list)

    @property
    def invalid_rows(self) -> list[int]:
        return sorted({error.row_number for error in self.errors if error.row_number is not None})

    @property
    def has_file_errors(self) -> bool:
        return any(error.row_number is None for error in self.errors)


def load_and_validate_csv(path: str | Path) -> tuple[list[VulnerabilityRecord], ValidationReport]:
    """Return valid records and a structured error report without raising for bad input.

    csv.reader preserves physical row numbers and catches malformed row widths;
    pandas holds the parsed text without inferring numbers, dates, or NA values.
    Unknown columns are ignored; supplied metadata fields are validated too.
    Missing required or duplicate headers are file errors.
    All occurrences of duplicate IDs are excluded, even if a duplicate has other
    validation errors. A structurally corrupt CSV is rejected as a whole because
    its remaining record boundaries cannot be trusted.
    """
    report = ValidationReport()
    raw_rows = []
    try:
        with Path(path).open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.reader(handle, strict=True)
            header = next(reader, None)
            if not header:
                report.errors.append(ValidationIssue(None, "__file__", "CSV is empty or has no header", "empty_file"))
                return [], report
            missing = [name for name in REQUIRED_COLUMNS if name not in header]
            for name in missing:
                report.errors.append(ValidationIssue(None, name, f"Missing required column: {name}", "missing_column"))
            for name, count in Counter(header).items():
                if count > 1:
                    report.errors.append(ValidationIssue(None, name, f"Duplicate column: {name}", "duplicate_column"))
            if report.has_file_errors:
                return [], report
            while True:
                row_number = reader.line_num + 1
                row = next(reader, None)
                if row is None:
                    break
                report.total_rows += 1
                raw_rows.append((row_number, row))
    except (OSError, UnicodeError, csv.Error) as exc:
        report.errors.append(ValidationIssue(None, "__file__", f"Unable to read CSV: {exc}", "unreadable_csv"))
        return [], report

    id_index = header.index("vulnerability_id")
    # Include IDs on malformed rows too when the ID column is available.
    id_counts = Counter(
        row[id_index].strip() for _, row in raw_rows
        if len(row) > id_index and row[id_index].strip()
    )
    shaped_rows = []
    row_numbers = []
    for row_number, row in raw_rows:
        if len(row) > id_index and id_counts[row[id_index].strip()] > 1:
            report.errors.append(ValidationIssue(row_number, "vulnerability_id", "Duplicate vulnerability_id; all occurrences are excluded", "duplicate_id"))
        if len(row) != len(header):
            report.errors.append(ValidationIssue(row_number, "__row__", f"Expected {len(header)} fields, found {len(row)}", "invalid_row_width"))
            continue
        shaped_rows.append(row)
        row_numbers.append(row_number)

    frame = pd.DataFrame(shaped_rows, columns=header, dtype=str)
    validated_columns = [name for name in header if name in VulnerabilityRecord.model_fields]
    valid_records = []
    for row_number, values in zip(row_numbers, frame.loc[:, validated_columns].to_dict(orient="records")):
        try:
            record = VulnerabilityRecord.model_validate(values)
        except ValidationError as exc:
            for error in exc.errors(include_url=False, include_input=False):
                name = ".".join(str(part) for part in error["loc"]) or "__row__"
                report.errors.append(ValidationIssue(row_number, name, error["msg"], error["type"]))
            continue
        if id_counts[record.vulnerability_id] == 1:
            valid_records.append(record)
    return valid_records, report
