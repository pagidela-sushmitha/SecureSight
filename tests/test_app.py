"""Streamlit rendering and real control interactions over the validated dataset."""

import base64
import json
import io
from datetime import date
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

from src.analytics import Filters, explore_findings, filter_findings, findings_csv, records_to_frame
from src.data_loader import REQUIRED_COLUMNS, load_and_validate_csv


ROOT = Path(__file__).resolve().parents[1]


def run_app_with_csv(path, navigation=None):
    with patch("src.data_loader.load_and_validate_csv", side_effect=lambda _: load_and_validate_csv(path)):
        app = AppTest.from_file(str(ROOT / "app.py")).run(timeout=30)
        if navigation:
            app.sidebar.radio[0].set_value(navigation).run(timeout=30)
    assert not app.exception
    return app


def start_app(navigation=None):
    return run_app_with_csv(ROOT / "data" / "vulnerabilities.csv", navigation)


def metrics(app):
    return {item.label: item.value for item in app.metric}


def assert_local_summary(app, count, *, priority=False):
    assert not app.metric
    label = "priority findings" if priority else "matching findings"
    assert any(item.value == f"**{count} {label}**" for item in app.main.markdown)


def validated_frame():
    records, report = load_and_validate_csv(ROOT / "data" / "vulnerabilities.csv")
    assert not report.errors
    return records_to_frame(records)


def plot_values(values):
    # Plotly encodes numeric arrays as typed base64 in its JSON transport.
    if isinstance(values, dict) and "bdata" in values:
        return np.frombuffer(base64.b64decode(values["bdata"]), dtype=values["dtype"]).tolist()
    return values


def test_original_dataset_ui():
    path = ROOT / "data" / "vulnerabilities.csv"
    before = path.read_bytes()
    app = start_app()
    assert app.title[0].value == "SecureSight"
    assert any("Synthetic test data only" in caption.value for caption in app.caption)
    assert metrics(app) == {
        "Total findings": "350", "Critical findings": "42", "Unresolved findings": "203",
        "Resolved findings": "147", "Resolution rate": "42.0%", "Average synthetic risk": "5.6 / 10",
    }
    assert "All 350 records passed validation" in app.sidebar.success[0].value
    assert len(app.get("plotly_chart")) == 5
    assert all(not widget.value for widget in app.sidebar.multiselect)
    assert path.read_bytes() == before


def test_invalid_fixture_ui():
    app = run_app_with_csv(ROOT / "tests" / "fixtures" / "invalid_vulnerabilities.csv", "Vulnerability Intelligence")
    assert_local_summary(app, 3)
    assert app.warning
    assert not app.success
    assert app.sidebar.expander[0].label == "Validation Details"
    details = app.sidebar.dataframe[0].value
    assert len(details) == 9
    assert set(details["CSV row number"]) == set(range(5, 14))
    assert details["Validation message"].str.len().gt(0).all()
    table = app.main.dataframe[0].value
    assert table.shape == (3, 7)
    assert set(table["vulnerability_id"]) == {
        "SYN-TEST-VALID-001", "SYN-TEST-VALID-002", "SYN-TEST-VALID-003",
    }


@pytest.mark.parametrize("case", ["missing", "unreadable", "encoding", "malformed", "missing_columns"])
def test_file_errors_render_without_exception(tmp_path, case):
    path = tmp_path / "input.csv"
    header = ",".join(REQUIRED_COLUMNS) + "\n"
    if case == "unreadable":
        path.mkdir()
    elif case == "encoding":
        path.write_bytes(b"\xff")
    elif case == "malformed":
        path.write_text(header + '"unterminated', encoding="utf-8")
    elif case == "missing_columns":
        path.write_text("vulnerability_id,scan_date\n", encoding="utf-8")
    app = run_app_with_csv(path)
    assert app.error
    assert not app.success
    assert not app.metric
    assert any("Unavailable" in item.value for item in app.sidebar.markdown)
    assert len(app.sidebar.dataframe[0].value) >= 1
    assert "No valid records" in app.info[-1].value


@pytest.mark.parametrize("all_invalid", [False, True])
def test_zero_valid_records_ui(tmp_path, all_invalid):
    path = tmp_path / "input.csv"
    contents = ",".join(REQUIRED_COLUMNS) + "\n"
    if all_invalid:
        contents += "SYN-BAD,2026-03-01,Tenable,Fictional App,Extreme,Test finding,Open,\n"
    path.write_text(contents, encoding="utf-8")
    app = run_app_with_csv(path)
    assert not app.metric
    assert "No valid records" in app.info[-1].value
    assert len(app.warning) == int(all_invalid)
    assert not app.get("plotly_chart")


def test_filters_update_kpis_charts_and_navigation():
    app = start_app()
    app.sidebar.multiselect(key="filter_tool").set_value(["QWIET-SAST"]).run(timeout=30)
    app.sidebar.multiselect(key="filter_severity").set_value(["Critical"]).run(timeout=30)
    expected = filter_findings(validated_frame(), Filters(tools=("QWIET-SAST",), severities=("Critical",)))
    assert not app.exception
    assert metrics(app)["Total findings"] == str(len(expected))
    severity_chart = json.loads(app.get("plotly_chart")[0].proto.spec)
    assert sum(sum(plot_values(trace["y"])) for trace in severity_chart["data"]) == len(expected)
    app.sidebar.radio[0].set_value("Vulnerability Intelligence").run(timeout=30)
    table = app.main.dataframe[0].value
    assert set(table["vulnerability_id"]) == set(expected["vulnerability_id"])
    assert app.sidebar.multiselect(key="filter_tool").value == ["QWIET-SAST"]
    assert app.sidebar.multiselect(key="filter_severity").value == ["Critical"]
    assert len(app.get("download_button")) == 1
    assert not app.exception


def test_date_range_and_partial_selection():
    app = start_app()
    app.sidebar.date_input(key="scan_range").set_value((date(2026, 3, 1), date(2026, 3, 31))).run(timeout=30)
    assert metrics(app)["Total findings"] == "35"
    app.sidebar.date_input(key="scan_range").set_value((date(2026, 3, 1),)).run(timeout=30)
    assert not app.exception
    assert "Select both" in app.info[0].value
    assert not app.metric


def test_priority_search_sort_and_drilldown():
    app = start_app("Vulnerability Intelligence")
    app.checkbox(key="finding_priority_only").check().run(timeout=30)
    expected = explore_findings(validated_frame(), priority=True)
    table = app.main.dataframe[0].value
    assert table["vulnerability_id"].tolist() == expected["vulnerability_id"].tolist()
    assert table["risk_score"].is_monotonic_decreasing
    assert set(table["status"]) <= {"Open", "In Progress"}
    app.selectbox(key="finding_sort").set_value("Risk · lowest first").run(timeout=30)
    assert app.main.dataframe[0].value["risk_score"].is_monotonic_increasing
    selected = expected.iloc[0]["vulnerability_id"]
    app.text_input(key="finding_search").set_value(selected).run(timeout=30)
    assert_local_summary(app, 1, priority=True)
    app.selectbox(key="finding_id").set_value(selected).run(timeout=30)
    assert not app.exception
    assert any(item.label == "Technical Details" for item in app.expander)
    assert any("Recommended Remediation" in item.value for item in app.markdown)
    assert any("synthetic examples, not verified" in item.value for item in app.caption)


def test_state_survives_navigation_and_reset_restores_all_records(caplog):
    app = start_app("Vulnerability Intelligence")
    app.text_input(key="finding_search").set_value("SQL injection").run(timeout=30)
    app.sidebar.radio[0].set_value("Security Overview").run(timeout=30)
    app.sidebar.radio[0].set_value("Vulnerability Intelligence").run(timeout=30)
    assert app.text_input(key="finding_search").value == "SQL injection"
    app.sidebar.multiselect(key="filter_status").set_value(["Resolved"]).run(timeout=30)
    caplog.clear()
    app.sidebar.button[0].click().run(timeout=30)
    assert not app.exception
    assert app.text_input(key="finding_search").value == ""
    assert not app.checkbox(key="finding_priority_only").value
    assert all(not item.value for item in app.sidebar.multiselect)
    assert app.selectbox(key="finding_id").value is None
    assert_local_summary(app, 350)
    assert len(app.sidebar.date_input(key="scan_range").value) == 2
    assert "created with a default value" not in caplog.text


def test_empty_filter_and_search_results():
    app = start_app()
    app.sidebar.multiselect(key="filter_tool").set_value(["QWIET-SECRETS"]).run(timeout=30)
    # Find an application with no secrets in one discovery day, yielding a real empty intersection.
    app.sidebar.date_input(key="scan_range").set_value((date(2026, 3, 1), date(2026, 3, 1))).run(timeout=30)
    app.sidebar.multiselect(key="filter_status").set_value(["Resolved"]).run(timeout=30)
    app.sidebar.multiselect(key="filter_severity").set_value(["Critical"]).run(timeout=30)
    assert metrics(app)["Total findings"] == "0"
    assert not app.get("plotly_chart")
    assert "No findings match" in app.info[0].value
    app.sidebar.radio[0].set_value("Vulnerability Intelligence").run(timeout=30)
    assert_local_summary(app, 0)
    assert any("0 findings in global analysis scope" in item.value for item in app.main.caption)
    app.sidebar.button[0].click().run(timeout=30)
    app.sidebar.radio[0].set_value("Vulnerability Intelligence").run(timeout=30)
    app.text_input(key="finding_search").set_value("NO-SUCH-SYNTHETIC-ID").run(timeout=30)
    assert not app.exception
    assert_local_summary(app, 0)
    assert not app.main.dataframe
    assert not app.get("download_button")
    assert "No findings match" in app.info[0].value


def test_drilldown_clears_out_of_scope_selection():
    app = start_app("Vulnerability Intelligence")
    table = app.main.dataframe[0].value
    selected = table.iloc[0]["vulnerability_id"]
    app.selectbox(key="finding_id").set_value(selected).run(timeout=30)
    app.text_input(key="finding_search").set_value(table.iloc[1]["vulnerability_id"]).run(timeout=30)
    assert not app.exception
    assert app.selectbox(key="finding_id").value is None
    assert any("previously selected finding" in item.value for item in app.caption)


def test_priority_empty_when_global_status_is_resolved():
    app = start_app("Vulnerability Intelligence")
    app.sidebar.multiselect(key="filter_status").set_value(["Resolved"]).run(timeout=30)
    app.checkbox(key="finding_priority_only").check().run(timeout=30)
    assert not app.exception
    assert_local_summary(app, 0, priority=True)
    assert any("147 findings in global analysis scope" in item.value for item in app.main.caption)
    assert "No findings match" in app.info[0].value
    assert not app.main.dataframe
    assert app.sidebar.multiselect(key="filter_status").value == ["Resolved"]


def test_unified_table_defaults_and_restores_sort_across_navigation():
    app = start_app("Vulnerability Intelligence")
    assert not app.checkbox(key="finding_priority_only").value
    assert not app.get("button_group")
    assert len(app.main.dataframe[0].value) == 350
    assert_local_summary(app, 350)
    app.selectbox(key="finding_sort").set_value("Scan date · oldest first").run(timeout=30)
    app.checkbox(key="finding_priority_only").check().run(timeout=30)
    assert app.selectbox(key="finding_sort").value == "Risk · highest first"
    assert len(app.main.dataframe[0].value) == 76
    assert_local_summary(app, 76, priority=True)
    assert set(app.main.dataframe[0].value.severity) == {"Critical", "High"}
    assert set(app.main.dataframe[0].value.status) == {"Open", "In Progress"}
    app.selectbox(key="finding_sort").set_value("Risk · lowest first").run(timeout=30)
    app.run(timeout=30)
    app.sidebar.radio[0].set_value("Security Overview").run(timeout=30)
    app.sidebar.radio[0].set_value("Vulnerability Intelligence").run(timeout=30)
    assert app.checkbox(key="finding_priority_only").value
    assert app.selectbox(key="finding_sort").value == "Risk · lowest first"
    app.checkbox(key="finding_priority_only").uncheck().run(timeout=30)
    assert app.selectbox(key="finding_sort").value == "Scan date · oldest first"
    assert len(app.main.dataframe[0].value) == 350
    app.checkbox(key="finding_priority_only").check().run(timeout=30)
    assert app.selectbox(key="finding_sort").value == "Risk · highest first"
    app.sidebar.button[0].click().run(timeout=30)
    assert not app.exception
    assert not app.checkbox(key="finding_priority_only").value
    assert app.selectbox(key="finding_sort").value == "Risk · highest first"


def test_priority_global_filters_search_sort_and_csv_export():
    frame = validated_frame()
    app = start_app("Vulnerability Intelligence")
    app.sidebar.multiselect(key="filter_tool").set_value(["QWIET-SAST"]).run(timeout=30)
    app.sidebar.multiselect(key="filter_application").set_value(["AsterVale Customer Portal"]).run(timeout=30)
    app.sidebar.multiselect(key="filter_status").set_value(["In Progress"]).run(timeout=30)
    app.sidebar.multiselect(key="filter_severity").set_value(["Critical"]).run(timeout=30)
    app.sidebar.date_input(key="scan_range").set_value((date(2026, 3, 1), date(2026, 8, 31))).run(timeout=30)
    global_scope = frame.loc[
        frame.tool.eq("QWIET-SAST") & frame.application.eq("AsterVale Customer Portal")
        & frame.status.eq("In Progress") & frame.severity.eq("Critical")
        & frame.scan_date.between("2026-03-01", "2026-08-31")
    ]
    app.checkbox(key="finding_priority_only").check().run(timeout=30)
    app.text_input(key="finding_search").set_value("SQL injection").run(timeout=30)
    app.selectbox(key="finding_sort").set_value("Risk · lowest first").run(timeout=30)
    expected = global_scope.loc[
        global_scope.severity.isin(["Critical", "High"])
        & global_scope.status.isin(["Open", "In Progress"])
        & global_scope.vulnerability_name.str.contains("SQL injection", case=False, regex=False)
    ].sort_values(["risk_score", "vulnerability_id"], ascending=[True, True])
    assert not expected.empty
    with patch("src.analytics.findings_csv", wraps=findings_csv) as export:
        app.run(timeout=30)
    assert not app.exception
    assert_local_summary(app, len(expected), priority=True)
    assert any(f"{len(global_scope)} findings in global analysis scope" in item.value for item in app.main.caption)
    exported_frame = export.call_args.args[0]
    csv_frame = pd.read_csv(io.BytesIO(findings_csv(exported_frame)))
    table = app.main.dataframe[0].value
    assert table.vulnerability_id.tolist() == csv_frame.vulnerability_id.tolist() == expected.vulnerability_id.tolist()
    assert len(csv_frame.columns) == len(frame.columns)
    assert len(app.get("download_button")) == 1


def test_priority_selection_preserved_or_cleared_including_empty_table():
    frame = validated_frame()
    priority_id = frame.loc[frame.severity.eq("Critical") & frame.status.ne("Resolved")].iloc[0].vulnerability_id
    nonpriority_id = frame.loc[frame.status.eq("Resolved")].iloc[0].vulnerability_id
    app = start_app("Vulnerability Intelligence")
    app.selectbox(key="finding_id").set_value(priority_id).run(timeout=30)
    app.checkbox(key="finding_priority_only").check().run(timeout=30)
    assert app.selectbox(key="finding_id").value == priority_id
    app.selectbox(key="finding_sort").set_value("Vulnerability ID").run(timeout=30)
    assert app.selectbox(key="finding_id").value == priority_id
    app.checkbox(key="finding_priority_only").uncheck().run(timeout=30)
    app.selectbox(key="finding_id").set_value(nonpriority_id).run(timeout=30)
    app.checkbox(key="finding_priority_only").check().run(timeout=30)
    assert app.selectbox(key="finding_id").value is None
    app.selectbox(key="finding_id").set_value(priority_id).run(timeout=30)
    app.text_input(key="finding_search").set_value("NO-MATCH").run(timeout=30)
    assert not app.exception and not app.main.dataframe
    assert app.session_state["finding_id"] is None
    assert not app.get("download_button")


def test_local_priority_does_not_change_global_kpis_charts_or_ai_scope():
    from src.ai_assistant import AnalystAnswer

    app = start_app()
    app.sidebar.multiselect(key="filter_tool").set_value(["QWIET-SAST"]).run(timeout=30)
    expected_global = validated_frame().loc[lambda f: f.tool.eq("QWIET-SAST")]
    overview_metrics = metrics(app)
    chart_data = [json.loads(chart.proto.spec)["data"] for chart in app.get("plotly_chart")]
    app.session_state["chat_messages"] = [{"role": "assistant", "content": "Existing scoped answer"}]
    app.sidebar.radio[0].set_value("Vulnerability Intelligence").run(timeout=30)
    app.checkbox(key="finding_priority_only").check().run(timeout=30)
    app.text_input(key="finding_search").set_value("SQL injection").run(timeout=30)
    assert_local_summary(app, len(app.main.dataframe[0].value), priority=True)
    assert len(app.main.dataframe[0].value) < len(expected_global)
    assert all(not widget.value for widget in app.sidebar.multiselect if widget.key != "filter_tool")
    assert app.sidebar.multiselect(key="filter_tool").value == ["QWIET-SAST"]
    app.sidebar.radio[0].set_value("Security Overview").run(timeout=30)
    assert metrics(app) == overview_metrics
    assert [json.loads(chart.proto.spec)["data"] for chart in app.get("plotly_chart")] == chart_data
    app.sidebar.radio[0].set_value("Ask SecureSight AI").run(timeout=30)
    assert len(app.chat_message) == 1
    with patch("src.chat_workspace.ask_question", return_value=AnalystAnswer(True, "ok", "Mocked scoped response")) as ask:
        app.chat_input[0].set_value("Summarize findings").run(timeout=30)
    assert not app.exception
    assert set(ask.call_args.args[0].vulnerability_id) == set(expected_global.vulnerability_id)


@pytest.mark.parametrize("priority,query", [
    (False, ""), (True, ""),
    (False, "SQL injection"), (True, "SQL injection"),
    (False, "NO-MATCH"), (True, "NO-MATCH"),
])
def test_local_count_table_and_export_share_exact_scope(priority, query):
    frame = validated_frame()
    expected = frame.copy()
    if priority:
        expected = expected.loc[expected.severity.isin(["Critical", "High"]) & expected.status.isin(["Open", "In Progress"])]
    if query:
        expected = expected.loc[
            expected.vulnerability_id.str.contains(query, case=False, regex=False)
            | expected.vulnerability_name.str.contains(query, case=False, regex=False)
        ]
    expected = expected.sort_values(["risk_score", "vulnerability_id"], ascending=[False, True])
    app = start_app("Vulnerability Intelligence")
    app.checkbox(key="finding_priority_only").set_value(priority).run(timeout=30)
    app.text_input(key="finding_search").set_value(query).run(timeout=30)
    with patch("src.analytics.findings_csv", wraps=findings_csv) as export:
        app.run(timeout=30)
    assert not app.exception
    assert_local_summary(app, len(expected), priority=priority)
    assert any("350 findings in global analysis scope" in item.value for item in app.main.caption)
    if expected.empty:
        assert not app.main.dataframe and not app.get("download_button")
        assert any("No findings match" in item.value for item in app.info)
        export.assert_not_called()
    else:
        export.assert_called_once()
        table_ids = app.main.dataframe[0].value.vulnerability_id.tolist()
        csv_frame = pd.read_csv(io.BytesIO(findings_csv(export.call_args.args[0])))
        assert len(csv_frame) == len(expected)
        assert csv_frame.vulnerability_id.tolist() == table_ids == expected.vulnerability_id.tolist()
