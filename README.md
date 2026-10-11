# SecureSight
AI-powered cybersecurity vulnerability analytics dashboard built with Streamlit, LangChain, OpenAI, and Python to visualize security findings, track remediation.

## Run the dashboard

```sh
uv run streamlit run app.py
```

Open `http://localhost:8501`. No API key is required; AI integration remains a
future iteration. All 350 findings and source locations are synthetic examples.
See [dataset documentation](data/README.md) for the schema and synthetic risk scale.

Use the sidebar to switch between **Security Overview** and **Vulnerability
Intelligence**. Empty multiselects include all options. The scan-date interval
defines an inclusive discovery cohort; monthly resolution events use that same
cohort's resolution dates, which may extend beyond the scan interval.

The overview shows six KPIs and five interactive Plotly charts. Intelligence
supports **All Findings** and **Priority Remediation** (unresolved Critical/High),
literal ID/name search, sorting, CSV download, and finding details. Its KPIs and
download reflect the current filters, mode, and search. The sort dropdown sets
export ordering; clicking table headers sorts only the displayed table.
**Reset Filters** restores all records and clears intelligence search, mode,
sort, and finding selection. Validation diagnostics remain in the sidebar.

## Verify

```sh
uv run --frozen --with pytest python -B -m pytest -p no:cacheprovider tests -q
```

For a manual demo: select a scanner and severity, check updated KPIs/charts,
switch to Intelligence, search by an ID, select a finding, expand Technical
Details, download the matching CSV, then reset. Try a combination with no matches
and confirm the empty-state guidance. Resize the browser to check readability;
native Streamlit tables support horizontal scrolling on narrow screens.
