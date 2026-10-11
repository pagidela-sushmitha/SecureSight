"""SecureSight dashboard: one validated dataset, shared analytics, native controls."""

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from src.analytics import (
    Filters, SEVERITY_COLORS, SEVERITY_ORDER, SORT_OPTIONS, STATUS_COLORS, STATUS_ORDER,
    calculate_kpis, category_counts, explore_findings, filter_findings, findings_csv,
    monthly_trends, records_to_frame,
)
from src.data_loader import load_and_validate_csv
from src.remediation import get_guidance
from src.chat_workspace import render_chat, sync_chat_scope


DATA_PATH = Path(__file__).resolve().parent / "data" / "vulnerabilities.csv"
FILTER_KEYS = ("filter_tool", "filter_severity", "filter_application", "filter_status")
TABLE_COLUMNS = ("vulnerability_id", "vulnerability_name", "severity", "risk_score", "application", "status", "tool")
LABELS = {
    "vulnerability_id": "ID", "vulnerability_name": "Vulnerability",
    "severity": "Severity", "risk_score": "Risk / 10", "application": "Application",
    "status": "Status", "tool": "Scanner",
}


def reset_filters(start, end):
    """Run before widgets are rendered on the next rerun."""
    for key in FILTER_KEYS:
        st.session_state[key] = []
    st.session_state["scan_range"] = (start, end)
    st.session_state["finding_search"] = ""
    st.session_state["finding_priority_only"] = False
    st.session_state["finding_sort"] = next(iter(SORT_OPTIONS))
    st.session_state["finding_normal_sort"] = next(iter(SORT_OPTIONS))
    st.session_state["finding_id"] = None


def toggle_priority_findings():
    """Start priority review by risk; restore the user's normal sort on exit."""
    if st.session_state["finding_priority_only"]:
        st.session_state["finding_normal_sort"] = st.session_state.get("finding_sort", next(iter(SORT_OPTIONS)))
        st.session_state["finding_sort"] = "Risk · highest first"
    else:
        st.session_state["finding_sort"] = st.session_state.get("finding_normal_sort", next(iter(SORT_OPTIONS)))


def render_validation(report, valid_count):
    """Keep diagnostics available without occupying the main dashboard."""
    if report.has_file_errors:
        st.error("The CSV could not be validated. Check the file and required columns; see Validation Details in the sidebar.")
    elif report.invalid_rows:
        st.warning(f"{len(report.invalid_rows)} invalid records excluded. Only validated findings are used.")
    with st.sidebar.expander("Validation Details", expanded=bool(report.errors)):
        invalid_count = "Unavailable (file/header error)" if report.has_file_errors else str(len(report.invalid_rows))
        st.write(f"Valid records: {valid_count} · Invalid records: {invalid_count}")
        if not report.errors:
            st.success(f"All {valid_count} records passed validation." if valid_count else "No data rows found.")
        else:
            st.caption("CSV row numbers include the header on line 1. File/header errors have no row number.")
            st.dataframe(pd.DataFrame([
                {"CSV row number": issue.row_number, "Field": issue.field,
                 "Validation message": issue.message, "Error code": issue.code}
                for issue in report.errors
            ]), hide_index=True, width="stretch")


def sidebar_filters(frame):
    start, end = frame["scan_date"].min().date(), frame["scan_date"].max().date()
    st.sidebar.subheader("Global filters")
    st.sidebar.caption("Leave a selection empty to include all options.")
    st.session_state.setdefault("scan_range", (start, end))
    dates = st.sidebar.date_input(
        "Scan date range", min_value=start, max_value=end,
        format="YYYY-MM-DD", key="scan_range",
        help="Inclusive discovery dates. Resolution events may occur later.",
    )
    tools = st.sidebar.multiselect("Scanning tool", sorted(frame["tool"].unique()), key="filter_tool", placeholder="All scanners")
    severities = st.sidebar.multiselect("Severity", SEVERITY_ORDER, key="filter_severity", placeholder="All severities")
    applications = st.sidebar.multiselect("Application", sorted(frame["application"].unique()), key="filter_application", placeholder="All applications")
    statuses = st.sidebar.multiselect("Remediation status", STATUS_ORDER, key="filter_status", placeholder="All statuses")
    st.sidebar.button("Reset Filters", on_click=reset_filters, args=(start, end), width="stretch")
    if len(dates) != 2:
        st.info("Select both a start and end date to apply the discovery range.")
        return None
    return Filters(dates[0], dates[1], tuple(tools), tuple(severities), tuple(applications), tuple(statuses))


def render_kpis(frame):
    values = calculate_kpis(frame)
    cards = (
        ("Total findings", f"{values['total']:,}", "Count of findings in this view."),
        ("Critical findings", f"{values['critical']:,}", "Count with Critical severity."),
        ("Unresolved findings", f"{values['unresolved']:,}", "Open plus In Progress findings."),
        ("Resolved findings", f"{values['resolved']:,}", "Count with Resolved status."),
        ("Resolution rate", f"{values['resolution_rate']:.1f}%", "Resolved findings divided by total findings; 0% for an empty view."),
        ("Average synthetic risk", "N/A" if values["average_risk"] is None else f"{values['average_risk']:.1f} / 10", f"Synthetic score, not CVSS. Average over {values['risk_count']} scored findings."),
    )
    for offset in (0, 3):
        for column, (label, value, help_text) in zip(st.columns(3), cards[offset:offset + 3]):
            column.metric(label, value, help=help_text, border=True)
    st.caption("Open: awaiting remediation · In Progress: work underway · Unresolved: Open + In Progress. Risk scores are synthetic, not CVSS.")


def show_chart(figure, key):
    figure.update_layout(
        height=330, margin=dict(l=8, r=8, t=12, b=8),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(size=12), legend_title_text="", dragmode=False,
    )
    st.plotly_chart(figure, width="stretch", key=key, config={"displaylogo": False, "responsive": True, "scrollZoom": False})


def render_overview(frame):
    st.subheader("Security Overview")
    render_kpis(frame)
    if frame.empty:
        st.info("No findings match your filters. Broaden the selections or use Reset Filters.")
        return
    left, right = st.columns(2)
    with left:
        st.markdown("#### Findings by severity")
        figure = px.bar(category_counts(frame, "severity", SEVERITY_ORDER), x="severity", y="Findings", color="severity", text="Findings",
                        color_discrete_map=SEVERITY_COLORS, category_orders={"severity": list(SEVERITY_ORDER)}, labels={"severity": "Severity"})
        figure.update_traces(hovertemplate="%{x}<br>%{y} findings<extra></extra>")
        show_chart(figure, "severity_chart")
    with right:
        st.markdown("#### Remediation status")
        figure = px.pie(category_counts(frame, "status", STATUS_ORDER), names="status", values="Findings", color="status", hole=0.65,
                        color_discrete_map=STATUS_COLORS, category_orders={"status": list(STATUS_ORDER)})
        figure.update_traces(textinfo="percent", hovertemplate="%{label}<br>%{value} findings · %{percent}<extra></extra>")
        show_chart(figure, "status_chart")
    left, right = st.columns(2)
    for column, field, title, key in (
        (left, "tool", "Findings by scanning tool", "tool_chart"),
        (right, "application", "Findings by application", "application_chart"),
    ):
        with column:
            st.markdown(f"#### {title}")
            counts = category_counts(frame, field).sort_values("Findings")
            figure = px.bar(counts, x="Findings", y=field, orientation="h", text="Findings",
                            color_discrete_sequence=["#38bdf8"], labels={field: "Scanner" if field == "tool" else "Application"})
            figure.update_traces(hovertemplate="%{y}<br>%{x} findings<extra></extra>")
            show_chart(figure, key)
    st.markdown("#### Monthly discovery and resolution events")
    st.caption("The scan-date range defines a discovery cohort. Resolution events use resolved_date for that same cohort and may occur later.")
    trends = monthly_trends(frame).melt(id_vars="Month", var_name="Event", value_name="Findings")
    figure = px.line(trends, x="Month", y="Findings", color="Event", markers=True,
                     color_discrete_map={"Discovered": "#38bdf8", "Resolved": "#4ade80"})
    figure.update_traces(hovertemplate="%{x|%b %Y}<br>%{y} findings<extra>%{fullData.name}</extra>")
    figure.update_xaxes(dtick="M1", tickformat="%b %Y")
    figure.update_yaxes(rangemode="tozero", dtick=1 if trends["Findings"].max() < 10 else None)
    show_chart(figure, "trend_chart")


def present(value):
    return "Not available" if value is None or pd.isna(value) else str(value)


def render_finding_detail(row):
    with st.container(border=True):
        st.markdown("#### Finding Overview")
        st.write(f"**{row['vulnerability_id']} · {row['vulnerability_name']}**")
        risk = "Not available" if pd.isna(row["risk_score"]) else f"{row['risk_score']:.1f} / 10 (synthetic)"
        color = {"Critical": "red", "High": "orange", "Medium": "yellow", "Low": "blue"}[row["severity"]]
        st.markdown(f":{color}-badge[{row['severity']}] · **{row['status']}** · Risk {risk}")
        st.write(present(row["description"]))
        st.caption(f"Application: {row['application']} · Scanner: {row['tool']}")
        with st.expander("Technical Details"):
            st.write(f"**CWE:** {present(row['cwe_id'])} · **Affected component:** {present(row['affected_component'])}")
            st.write(f"**Scan date:** {row['scan_date'].date().isoformat()} · **Resolved date:** {present(row['resolved_date'].date() if pd.notna(row['resolved_date']) else None)}")
            st.write(f"**Affected asset:** {present(row['affected_asset'])}")
            st.write(f"**File path:** {present(row['file_path'])}")
            line = int(row["line_number"]) if pd.notna(row["line_number"]) else None
            st.write(f"**Line number:** {present(line)}")
            st.caption("Source locations are synthetic examples, not verified code references.")
        st.markdown("#### Recommended Remediation")
        st.write(row["remediation"] or get_guidance(row["vulnerability_name"], row["tool"]).remediation)
        st.caption("Rule-based guidance only. Changes have not been applied or verified.")


def render_intelligence(frame):
    st.subheader("Vulnerability Intelligence")
    priority = st.checkbox("Priority findings only", key="finding_priority_only", on_change=toggle_priority_findings,
                           persist_state="session", help="Show only Critical/High findings with Open or In Progress status. Enabling starts with highest synthetic risk; disabling restores your previous normal sort.")
    search_column, sort_column = st.columns([2, 1])
    query = search_column.text_input("Search findings", placeholder="Search by ID or vulnerability name", key="finding_search", persist_state="session")
    sort = sort_column.selectbox("Sort findings", list(SORT_OPTIONS), key="finding_sort", persist_state="session")
    findings = explore_findings(frame, priority=priority, query=query, sort=sort)
    st.markdown(f"**{len(findings)} {'priority findings' if priority else 'matching findings'}**")
    st.caption(f"{len(frame)} findings in global analysis scope · Priority findings are Critical/High with Open or In Progress status. Local controls affect only this table and CSV export; Overview and AI use global scope.")
    ids = findings["vulnerability_id"].tolist()
    if st.session_state.get("finding_id") not in (None, *ids):
        st.session_state["finding_id"] = None
        st.caption("The previously selected finding is outside this view. Select a matching finding.")
    if findings.empty:
        st.info("No findings match this view. Clear the search, uncheck Priority findings only, or use Reset Filters.")
        return
    st.dataframe(findings.loc[:, list(TABLE_COLUMNS)], hide_index=True,
                 height=min(360, 38 + 35 * len(findings)), width="stretch", key="findings_table",
                 column_config={
                     **LABELS,
                     "vulnerability_id": st.column_config.TextColumn("ID", width="small"),
                     "vulnerability_name": st.column_config.TextColumn("Vulnerability", width="medium"),
                     "application": st.column_config.TextColumn("Application", width="medium"),
                     "risk_score": st.column_config.NumberColumn("Risk / 10", width="small", format="%.1f", help="Synthetic 0–10 scale; not CVSS"),
                 })
    st.download_button("Download filtered findings (CSV)", findings_csv(findings), file_name="securesight-synthetic-findings.csv", mime="text/csv", on_click="ignore", key="download_findings")
    names = findings.set_index("vulnerability_id")["vulnerability_name"].to_dict()
    selected = st.selectbox("Inspect vulnerability", ids, index=None, placeholder="Select a finding for details", key="finding_id", format_func=lambda item: f"{item} · {names[item]}", persist_state="session")
    if selected is not None:
        render_finding_detail(findings.loc[findings["vulnerability_id"].eq(selected)].iloc[0])


def main():
    st.set_page_config(page_title="SecureSight", layout="wide")
    st.title("SecureSight")
    st.caption("AI-Powered Vulnerability Intelligence & Analytics · Synthetic test data only. These records are not real security findings.")
    st.sidebar.markdown("## SecureSight")
    navigation = st.sidebar.radio("Workspace", ("Security Overview", "Vulnerability Intelligence", "Ask SecureSight AI"), key="navigation")
    records, report = load_and_validate_csv(DATA_PATH)
    if not records:
        render_validation(report, 0)
        st.info("No valid records are available. Check Validation Details in the sidebar.")
        return
    frame = records_to_frame(records)
    filters = sidebar_filters(frame)
    render_validation(report, len(records))
    if filters is None:
        return
    filtered = filter_findings(frame, filters)
    sync_chat_scope(st.session_state, filtered, filters)
    st.sidebar.caption(f"{len(filtered)} of {len(frame)} validated findings in discovery cohort")
    if navigation == "Security Overview":
        render_overview(filtered)
    elif navigation == "Vulnerability Intelligence":
        render_intelligence(filtered)
    else:
        render_chat(filtered)


if __name__ == "__main__":
    main()
