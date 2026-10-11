# Synthetic vulnerability test data

`vulnerabilities.csv` contains exactly 350 entirely synthetic test records, not
real security findings. All application names, findings, and identifiers are
fictional. Secret-related findings describe fictional scenarios and contain no
credentials. The `SYN-VULN-` ID prefix identifies each record as synthetic.

The original eight columns and all their values are preserved. Eight metadata
columns follow them: `affected_component`, `cwe_id`, `description`, `remediation`,
`risk_score`, `file_path`, `line_number`, and `affected_asset`. Descriptions, CWE
assignments, components, and remediation advice are deterministic illustrative
examples; they are not verified security classifications or actual scan results.

Risk uses a synthetic 0–10 scale, **not official CVSS**: Critical 9.0–10.0,
High 7.0–8.9, Medium 4.0–6.9, and Low 0.1–3.9. A stable SHA-256 digest of the ID
chooses a tenth within the severity band. It models prioritization for this demo,
not real exploitability. Metadata generation consumes none of the original seeded
random stream, so regenerating preserves the original eight-column values.

Source paths under `synthetic/` and positive line numbers appear only for SAST
and secrets findings. Infrastructure, DAST, and SCA findings have blank source
locations. Tenable rows have fictional asset names under the reserved `.example`
domain. The dashboard shows **Not available** for inapplicable locations and never
claims to have scanned those files or applied the recommended fixes.

The loader continues to accept legacy eight-column CSVs. Metadata fields are
optional for those files, but values supplied in an extended CSV are validated:
risk must be finite and within 0–10, CWE must use `CWE-<number>`, and source paths
and positive line numbers must be paired and applicable to the scanner. Legacy
findings without scores display N/A; averages include scored findings only.

The dataset covers March through September 2026, with resolutions through
October 10, 2026. Monthly volumes vary as fictional scan coverage increases.
Older findings are more likely to be resolved, while recent findings are more
likely to remain open or in progress. These patterns are simulation assumptions,
not observations about any organization or scanning tool.

From the project root, regenerate and verify the CSV with:

```sh
python3 scripts/generate_synthetic_data.py
```

The generator uses only the Python standard library, fixed seed `20261011`, and
fixed dates. This command replaces this generated CSV and prints counts by tool,
severity, and status. It checks the saved file's column order, 350 rows, unique
IDs, category coverage, ISO dates, and resolution date rules.

To verify the existing CSV without rewriting it:

```sh
python3 -B -c 'from pathlib import Path; from scripts.generate_synthetic_data import verify_csv; print(len(verify_csv(Path("data/vulnerabilities.csv"))), "verified synthetic records")'
```
