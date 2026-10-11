"""Small, hand-calculated cohorts establish analytics and export behavior."""

import csv
import io
from datetime import date

import pytest

from src.analytics import (
    Filters, SEVERITY_ORDER, calculate_kpis, category_counts, explore_findings,
    filter_findings, findings_csv, monthly_trends, records_to_frame,
)
from src.models import VulnerabilityRecord


@pytest.fixture
def frame():
    rows = [
        ("A", "2026-01-01", "Critical", "Open", "", 9.5, "SQL injection", "QWIET-SAST", "Portal"),
        ("B", "2026-01-15", "High", "In Progress", "", 8, "Stored cross-site scripting", "QWIET-SAST", "API"),
        ("C", "2026-01-20", "Medium", "Resolved", "2026-02-05", 5, "Legacy TLS", "Tenable", "Portal"),
        ("D", "2026-02-01", "Low", "Resolved", "2026-02-01", 2, "Version banner", "Tenable", "Portal"),
    ]
    return records_to_frame([
        VulnerabilityRecord(vulnerability_id=id_, scan_date=scan, severity=severity,
                            status=status, resolved_date=resolved, risk_score=risk,
                            vulnerability_name=name, tool=tool, application=app)
        for id_, scan, severity, status, resolved, risk, name, tool, app in rows
    ])


def test_kpis(frame):
    assert calculate_kpis(frame) == {
        "total": 4, "critical": 1, "unresolved": 2, "resolved": 2,
        "resolution_rate": 50.0, "average_risk": 6.125, "risk_count": 4,
    }


def test_combined_filters_and_no_mutation(frame):
    before = frame.copy(deep=True)
    result = filter_findings(frame, Filters(
        date(2026, 1, 1), date(2026, 1, 31), ("QWIET-SAST",),
        ("Critical",), ("Portal",), ("Open",),
    ))
    assert result["vulnerability_id"].tolist() == ["A"]
    assert frame.equals(before)
    assert len(filter_findings(frame, Filters())) == 4


def test_inclusive_date_boundaries(frame):
    result = filter_findings(frame, Filters(date(2026, 1, 15), date(2026, 1, 15)))
    assert result["vulnerability_id"].tolist() == ["B"]


def test_empty_results(frame):
    empty = filter_findings(frame, Filters(tools=("Unknown",)))
    values = calculate_kpis(empty)
    assert values["total"] == values["unresolved"] == values["resolved"] == 0
    assert values["resolution_rate"] == 0
    assert values["average_risk"] is None
    assert monthly_trends(empty).empty
    assert category_counts(empty, "severity", SEVERITY_ORDER)["Findings"].tolist() == [0, 0, 0, 0]
    assert records_to_frame([]).empty


def test_severity_order_and_zero_categories(frame):
    counts = category_counts(frame.iloc[:1], "severity", SEVERITY_ORDER)
    assert counts["severity"].tolist() == list(SEVERITY_ORDER)
    assert counts["Findings"].tolist() == [1, 0, 0, 0]
    result = explore_findings(frame.iloc[::-1], sort="Severity · critical first")
    assert result["vulnerability_id"].tolist() == ["A", "B", "C", "D"]


def test_resolution_events_extend_past_discovery_range(frame):
    cohort = filter_findings(frame, Filters(date(2026, 1, 1), date(2026, 1, 31)))
    trends = monthly_trends(cohort)
    assert trends["Month"].dt.strftime("%Y-%m").tolist() == ["2026-01", "2026-02"]
    assert trends["Discovered"].tolist() == [3, 0]
    assert trends["Resolved"].tolist() == [0, 1]
    assert monthly_trends(frame)["Resolved"].tolist() == [0, 2]


def test_priority_selection_and_default_sort(frame):
    assert explore_findings(frame.iloc[::-1], priority=True)["vulnerability_id"].tolist() == ["A", "B"]
    frame.loc[frame["vulnerability_id"] == "A", "status"] = "Resolved"
    assert explore_findings(frame, priority=True)["vulnerability_id"].tolist() == ["B"]


def test_search_is_literal_and_case_insensitive(frame):
    assert explore_findings(frame, query="SQL INJECTION")["vulnerability_id"].tolist() == ["A"]
    assert explore_findings(frame, query="b")["vulnerability_id"].tolist() == ["B", "D"]
    assert explore_findings(frame, query=".*").empty


def test_csv_matches_filtered_sorted_view(frame):
    subset = explore_findings(frame, priority=True, sort="Risk · lowest first")
    raw = findings_csv(subset)
    assert b"\r" not in raw
    rows = list(csv.DictReader(io.StringIO(raw.decode())))
    assert [row["vulnerability_id"] for row in rows] == ["B", "A"]
    assert rows[0]["scan_date"] == "2026-01-15"
    assert rows[0]["resolved_date"] == ""
    assert list(rows[0]) == list(frame.columns)


def test_legacy_missing_scores_do_not_become_invented_values(frame):
    frame["risk_score"] = float("nan")
    assert calculate_kpis(frame)["average_risk"] is None
    assert calculate_kpis(frame)["risk_count"] == 0
