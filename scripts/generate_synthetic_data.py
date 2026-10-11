"""Generate reproducible, entirely fictional SecureSight test findings."""

import calendar
import csv
import hashlib
import random
import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

# Support the documented `python scripts/generate_synthetic_data.py` invocation.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.remediation import get_guidance


SEED = 20261011
OUTPUT = Path(__file__).resolve().parents[1] / "data" / "vulnerabilities.csv"
ORIGINAL_COLUMNS = (
    "vulnerability_id",
    "scan_date",
    "tool",
    "application",
    "severity",
    "vulnerability_name",
    "status",
    "resolved_date",
)
METADATA_COLUMNS = (
    "affected_component", "cwe_id", "description", "remediation", "risk_score",
    "file_path", "line_number", "affected_asset",
)
COLUMNS = ORIGINAL_COLUMNS + METADATA_COLUMNS
# These fictional examples describe finding types, never real credentials or assets.
FINDINGS = {
    "QWIET-SAST": {
        "Critical": ("SQL injection in account search", "Unsafe object deserialization"),
        "High": ("Stored cross-site scripting", "Path traversal in file export"),
        "Medium": ("Missing authorization check", "Verbose exception disclosure"),
        "Low": ("Internal path exposed in logs", "Overly broad error message"),
    },
    "QWIET-SECRETS": {
        "Critical": ("Production administrator credential in source", "Cloud access key in configuration"),
        "High": ("Database password in build script", "Service API token in source"),
        "Medium": ("Expired service token in test fixture", "Development credential in configuration"),
        "Low": ("Inactive sandbox token in example file", "Test-only credential in documentation"),
    },
    "Tenable": {
        "Critical": ("Unpatched remote code execution vulnerability", "Exposed unauthenticated management service"),
        "High": ("Unsupported operating system release", "Outdated SSH server package"),
        "Medium": ("Legacy TLS protocol enabled", "Unnecessary network service exposed"),
        "Low": ("Verbose server version banner", "ICMP timestamp disclosure"),
    },
    "Solis DAST": {
        "Critical": ("Authentication bypass on administration endpoint", "Command injection in report endpoint"),
        "High": ("Server-side request forgery", "Session fixation vulnerability"),
        "Medium": ("Missing cross-site request forgery protection", "Overly permissive CORS policy"),
        "Low": ("Missing Content-Security-Policy header", "Missing X-Content-Type-Options header"),
    },
    "Corona SCA": {
        "Critical": ("Remote code execution in logging dependency", "Unsafe deserialization in serialization library"),
        "High": ("Denial of service in HTTP dependency", "Signature verification bypass in token library"),
        "Medium": ("Regular expression denial of service in parser", "Information disclosure in archive dependency"),
        "Low": ("Temporary file exposure in utility dependency", "Low-impact debug disclosure in dependency"),
    },
}
APPLICATIONS = (
    "AsterVale Customer Portal",
    "CedarBridge Payments API",
    "EmberHarbor Identity Service",
    "JuniperPeak Inventory Hub",
    "LumenField Analytics Gateway",
    "OrchidBay Employee Workspace",
    "SilverKite Order Service",
    "WillowForge Document Exchange",
)
SEVERITIES = ("Critical", "High", "Medium", "Low")
STATUSES = ("Open", "In Progress", "Resolved")
# Increasing scan coverage and recent unresolved findings support trend analysis.
MONTHLY_COUNTS = ((3, 35), (4, 40), (5, 45), (6, 50), (7, 55), (8, 65), (9, 60))
SNAPSHOT_DATE = date(2026, 10, 10)


def synthetic_metadata(record):
    """Derive metadata from the ID without consuming the original random stream."""
    fingerprint = int(hashlib.sha256(record["vulnerability_id"].encode()).hexdigest()[:12], 16)
    guidance = get_guidance(record["vulnerability_name"], record["tool"])
    # Tenths on a synthetic 0–10 scale, not CVSS or an exploitability estimate.
    low, high = {"Critical": (90, 100), "High": (70, 89), "Medium": (40, 69), "Low": (1, 39)}[record["severity"]]
    risk = (low + fingerprint % (high - low + 1)) / 10
    slug = record["application"].lower().replace(" ", "-")
    has_source = record["tool"] in ("QWIET-SAST", "QWIET-SECRETS")
    return {
        "affected_component": guidance.component,
        "cwe_id": guidance.cwe_id,
        "description": f"Synthetic example: {guidance.description} No actual scan was performed.",
        "remediation": guidance.remediation,
        "risk_score": f"{risk:.1f}",
        "file_path": f"synthetic/{slug}/src/{guidance.component}.py" if has_source else "",
        "line_number": str(10 + fingerprint % 390) if has_source else "",
        "affected_asset": f"host-{1 + fingerprint % 9}.{slug}.example" if record["tool"] == "Tenable" else "",
    }


def generate_records():
    """Use a local fixed seed and fixed dates, independent of the run date."""
    rng = random.Random(SEED)
    records = []
    for month, count in MONTHLY_COUNTS:
        for _ in range(count):
            scan = date(2026, month, rng.randint(1, calendar.monthrange(2026, month)[1]))
            # Later months add more infrastructure and dependency scanning.
            tool_weights = (27, 15, 20, 18, 20) if month < 7 else (20, 13, 26, 17, 24)
            tool = rng.choices(tuple(FINDINGS), weights=tool_weights, k=1)[0]
            severity_weights = (12, 31, 39, 18) if month < 7 else (8, 25, 43, 24)
            severity = rng.choices(SEVERITIES, weights=severity_weights, k=1)[0]
            status_weights = (16, 19, 65) if month < 7 else (43, 29, 28)
            status = rng.choices(STATUSES, weights=status_weights, k=1)[0]
            resolved = ""
            if status == "Resolved":
                max_delay = min(60, (SNAPSHOT_DATE - scan).days)
                resolved = (scan + timedelta(days=rng.randint(0, max_delay))).isoformat()
            records.append({
                "vulnerability_id": f"SYN-VULN-{len(records) + 1:04d}",
                "scan_date": scan.isoformat(),
                "tool": tool,
                "application": rng.choices(APPLICATIONS, weights=(20, 18, 14, 12, 10, 9, 10, 7), k=1)[0],
                "severity": severity,
                "vulnerability_name": rng.choice(FINDINGS[tool][severity]),
                "status": status,
                "resolved_date": resolved,
            })
    for record in records:
        record.update(synthetic_metadata(record))
    return sorted(records, key=lambda record: (record["scan_date"], record["vulnerability_id"]))


def verify_csv(path):
    """Check the saved artifact, including exact columns and date relationships."""
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != list(COLUMNS):
            raise ValueError("CSV columns do not match the required order")
        records = list(reader)
    if len(records) != 350 or len({row["vulnerability_id"] for row in records}) != 350:
        raise ValueError("Expected exactly 350 records with unique IDs")
    for row in records:
        required = ORIGINAL_COLUMNS[:-1] + METADATA_COLUMNS[:5]
        if set(row) != set(COLUMNS) or any(row[column] in (None, "") for column in required):
            raise ValueError("Missing or extra CSV fields")
        if not row["vulnerability_id"].startswith("SYN-VULN-"):
            raise ValueError("Missing synthetic ID prefix")
        if row["tool"] not in FINDINGS or row["severity"] not in SEVERITIES or row["status"] not in STATUSES:
            raise ValueError("Unexpected categorical value")
        if row["application"] not in APPLICATIONS or row["vulnerability_name"] not in FINDINGS[row["tool"]][row["severity"]]:
            raise ValueError("Unexpected fictional application or finding")
        scan = date.fromisoformat(row["scan_date"])
        if scan.isoformat() != row["scan_date"] or not date(2026, 3, 1) <= scan <= date(2026, 9, 30):
            raise ValueError("Invalid scan date")
        if row["status"] == "Resolved":
            resolved = date.fromisoformat(row["resolved_date"])
            if resolved.isoformat() != row["resolved_date"] or not scan <= resolved <= SNAPSHOT_DATE:
                raise ValueError("Invalid resolution date")
        elif row["resolved_date"] != "":
            raise ValueError("Unresolved findings must have a blank resolved_date")
        if {name: row[name] for name in METADATA_COLUMNS} != synthetic_metadata(row):
            raise ValueError("Synthetic metadata does not match deterministic generation")
    for column, expected in (("tool", FINDINGS), ("severity", SEVERITIES), ("status", STATUSES), ("application", APPLICATIONS)):
        if {row[column] for row in records} != set(expected):
            raise ValueError(f"Missing variation in {column}")
    return records


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(generate_records())
    records = verify_csv(OUTPUT)
    print(f"Verified {len(records)} SYNTHETIC test records: {OUTPUT}")
    for column in ("tool", "severity", "status"):
        print(f"{column}: {dict(Counter(row[column] for row in records))}")


if __name__ == "__main__":
    main()
