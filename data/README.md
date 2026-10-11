# Synthetic vulnerability test data

`vulnerabilities.csv` contains exactly 350 entirely synthetic test records, not
real security findings. All application names, findings, and identifiers are
fictional. Secret-related findings describe fictional scenarios and contain no
credentials. The `SYN-VULN-` ID prefix identifies each record as synthetic.

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
