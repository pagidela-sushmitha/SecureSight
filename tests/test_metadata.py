"""Schema, preservation, reproducibility, and rule-based guidance checks."""

import csv
import hashlib
import io
from pathlib import Path

import pytest
from pydantic import ValidationError

from scripts.generate_synthetic_data import COLUMNS, generate_records, verify_csv
from src.data_loader import load_and_validate_csv
from src.models import METADATA_COLUMNS, ORIGINAL_COLUMNS, VulnerabilityRecord
from src.remediation import get_guidance


DATA = Path(__file__).resolve().parents[1] / "data" / "vulnerabilities.csv"


def test_original_eight_column_snapshot_preserved():
    with DATA.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == list(ORIGINAL_COLUMNS + METADATA_COLUMNS)
        rows = list(reader)
    original = io.StringIO(newline="")
    writer = csv.DictWriter(original, fieldnames=ORIGINAL_COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    # Fingerprint of the complete original eight-column CSV before enrichment.
    assert hashlib.sha256(original.getvalue().encode()).hexdigest() == "c4671b820278a8549d26ff9b991bcb47cb80dc4c0167c483b2c64dee74c2c6c3"


def test_extended_generation_is_reproducible_and_valid():
    stored = verify_csv(DATA)
    assert stored == generate_records() == generate_records()
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(generate_records())
    assert buffer.getvalue().encode() == DATA.read_bytes()
    assert b"\r" not in DATA.read_bytes()
    records, report = load_and_validate_csv(DATA)
    assert len(records) == 350 and not report.errors
    bands = {"Critical": (9, 10), "High": (7, 8.9), "Medium": (4, 6.9), "Low": (0.1, 3.9)}
    for record in records:
        assert record.description and record.remediation and record.cwe_id and record.affected_component
        low, high = bands[record.severity]
        assert low <= record.risk_score <= high
        if record.tool in ("QWIET-SAST", "QWIET-SECRETS"):
            assert record.file_path.startswith("synthetic/") and record.line_number > 0
        else:
            assert record.file_path is record.line_number is None
        if record.tool == "Tenable":
            assert record.affected_asset.endswith(".example")


@pytest.mark.parametrize("updates", [
    {"risk_score": -1}, {"risk_score": 10.1}, {"risk_score": "nan"}, {"risk_score": "inf"},
    {"cwe_id": "CWE-ABC"}, {"line_number": 0},
    {"file_path": "synthetic/source.py"}, {"line_number": 10},
    {"tool": "Tenable", "file_path": "synthetic/source.py", "line_number": 10},
])
def test_invalid_metadata_rejected(updates):
    row = dict(generate_records()[0])
    row.update(updates)
    with pytest.raises(ValidationError):
        VulnerabilityRecord.model_validate(row)


def test_loader_validates_metadata_not_just_original_columns(tmp_path):
    row = dict(generate_records()[0], risk_score="invalid")
    path = tmp_path / "bad-metadata.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerow(row)
    records, report = load_and_validate_csv(path)
    assert records == []
    assert report.errors[0].row_number == 2
    assert report.errors[0].field == "risk_score"


@pytest.mark.parametrize("name, tool, cwe, advice", [
    ("SQL injection", "QWIET-SAST", "CWE-89", "parameterized queries"),
    ("Stored cross-site scripting", "QWIET-SAST", "CWE-79", "output encoding"),
    ("Service API token", "QWIET-SECRETS", "CWE-798", "Rotate"),
    ("Remote code execution in logging dependency", "Corona SCA", "CWE-94", "Upgrade"),
    ("Legacy TLS protocol enabled", "Tenable", "CWE-326", "configuration baseline"),
    ("Unknown dependency", "Corona SCA", "CWE-1395", "Upgrade"),
    ("Unknown finding", "Other scanner", "CWE-16", "configuration baseline"),
])
def test_guidance_mapping(name, tool, cwe, advice):
    guidance = get_guidance(name, tool)
    assert guidance.cwe_id == cwe
    assert advice in guidance.remediation
    assert get_guidance(name, tool) == guidance
