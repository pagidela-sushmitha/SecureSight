# SecureSight
AI-powered cybersecurity vulnerability analytics dashboard built with Streamlit, LangChain, OpenAI, and Python to visualize security findings, track remediation.

## Run the dashboard

```sh
uv run streamlit run app.py
```

Open `http://localhost:8501`. No API key is required for the dashboard. AI client
initialization is opt-in, only when submitting in **Ask SecureSight AI**.
All 350 findings and source locations are synthetic examples.
See [dataset documentation](data/README.md) for the schema and synthetic risk scale.

Use the sidebar to switch between **Security Overview**, **Vulnerability
Intelligence**, and **Ask SecureSight AI**. Empty multiselects include all options. The scan-date interval
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

## Optional OpenAI integration foundation

`src.ai_assistant.create_chat_model()` constructs a LangChain `ChatOpenAI` client
without sending a request. It reads these settings from the process environment,
falling back to the project's local `.env` file. Environment values take precedence;
the file is not searched for in parent folders or copied into the process environment.

| Variable | Default / purpose |
| --- | --- |
| `OPENAI_API_KEY` | Required only for submitted AI questions or the optional smoke test. Set privately in your environment or ignored `.env`; never commit or print it. |
| `OPENAI_MODEL` | `gpt-4.1-mini`, a small non-reasoning model suitable for this foundation. |
| `OPENAI_TIMEOUT_SECONDS` | `30`; must be a finite positive number. |

The client uses the official OpenAI endpoint, disables automatic retries, and sets
`store=False`. Temperature is 0 for known GPT-4.1, GPT-4o, and GPT-3.5 Turbo families;
other models use the provider default to avoid unsupported sampling parameters.
Model access and parameter support depend on your account and selected model.
See the [official model documentation](https://developers.openai.com/api/docs/models/gpt-4.1-mini).

Explicitly run the optional connectivity check from the project root:

```sh
uv run python -m scripts.check_openai_connection
```

This makes one real, potentially billable API request containing only a fixed
connectivity prompt, with a 32-token completion limit. It sends no vulnerability
records or source locations and does not display model output, credentials, or
raw provider errors. Success exits with status 0; sanitized failures exit with 1.
Authentication, permissions, rate limits, exhausted quota, timeouts, network
failures, and rejected requests have separate messages. The dashboard never calls
this command or the factory during startup. Automated AI tests mock requests and
do not read your `.env` or contact OpenAI.

## Ask SecureSight AI

Select **Ask SecureSight AI**, enter a question or click an example question,
and use **Clear Chat** to start over. Normal startup, navigation, filter changes,
and ordinary reruns make no API requests. The scope count and sidebar filters
apply to every calculation. Any global filter or data change clears the history,
including changes made in another workspace. Empty scopes disable submission
and never fall back to the complete dataset. History retains the last 20 turns
for this Streamlit session; only the last six messages' questions/routing metadata
are used as model context.

The bounded LangChain workflow uses `create_chat_model()` and function-calling
structured output to select one `AnalysisRequest`. An allowlist dispatches it to
existing analytics/remediation functions over the already filtered validated
frame. No model-generated code, SQL, shell commands, file access, or writes run.
The model then selects relevant explanation sentences from the calculated result.
The application renders the exact factual answer and selected sentences locally,
so the model cannot rewrite counts, IDs, CWE values, source locations, or fixes.
See [OpenAI's function-calling guidance](https://developers.openai.com/api/docs/guides/function-calling).

Explicit questions asking which application/scanner has the most Critical,
Critical/High, or High findings, optionally unresolved, are checked independently
against a small complete-question intent guard after model routing. Explicit
top-N remediation-priority questions use the same check. This prevents a valid
but incorrect model route from replacing a grouped count with an individual-risk
list. Critical means exactly Critical; Critical/High means the union of those two
severities. Unresolved includes only Open and In Progress. Highest-count ties are
always named in alphabetical order, even when only one group was requested.
Extra date/scanner qualifiers and ambiguous follow-ups remain model-routed; the
guard deliberately does not strip those qualifiers or match isolated keywords.

Each supported question makes at most two requests: a routing completion capped
at 512 tokens and an explanation selection capped at 128 tokens. The client has
no automatic retries. Unsupported questions and unknown IDs stop after routing;
empty scopes and invalid question lengths need no request. Routing receives no
raw findings, and explanation receives only the calculated answer and candidate
sentences, rather than the complete CSV. Missing credentials and provider failures
produce sanitized messages. If only explanation fails, the deterministic result
remains visible. Questions and the necessary result text are sent to OpenAI only
on submission; finding detail requests can include that one finding's synthetic
metadata. Do not enter credentials in chat.

This first version supports a single calculation per question: summaries,
scanner/application counts (optionally narrowed by severity/status/name),
unresolved Critical/High findings, top priorities (up to 10), details by ID,
rule-based guidance by ID/name, and monthly events (latest 24 months). Answers use
controlled factual wording rather than unrestricted generated prose. Arbitrary
multi-step analysis, external security research, verified fixes, and official CVSS
are outside this workflow. Routing is still model-dependent: inspect the stated
severity/status and compare with the dashboard for important questions. Live model
accuracy and account availability need manual verification with your own API key.

Manual acceptance questions, after **Reset Filters**:

| Question | Deterministic expected result |
| --- | --- |
| Which application has the most unresolved critical findings? | Tie: JuniperPeak Inventory Hub and OrchidBay Employee Workspace, 4 each. |
| What are the top five remediation priorities? | In order: SYN-VULN-0111, SYN-VULN-0303, SYN-VULN-0311, SYN-VULN-0163, SYN-VULN-0229. |
| Which scanning tool has the most High-severity findings? | Tie: Solis DAST and Tenable, 20 each. |
| What is the remediation recommendation for SYN-VULN-0008? | Rotate session IDs after authentication and privilege changes. Advice is not a verified fix. |
| Show details for UNKNOWN-ID. | Not found in the current scope; no invented details. |
| What is tomorrow's weather? | Unsupported; explains available analytics. |

Repeat after narrowing scanner, severity, application, status, and discovery dates.
Check that history clears and scope counts match the overview. Compare top IDs
with Intelligence's Priority Remediation view and highest-risk sort. Compare
recommendations with the selected finding details. Select a combination with no
findings and verify the disabled chat and empty-state message. Navigate away and
back without changing filters to verify history persists. Clear Chat should clear
messages without an API request. Automated tests independently compare counts,
priority ordering, monthly events, and combined filter scope using pandas, exercise
actual LangChain/SDK serialization with mocked HTTP, and block external network
connections in chat tests.
