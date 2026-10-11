"""Shared filtering and aggregations over validated vulnerability records."""

from dataclasses import dataclass
from datetime import date
from typing import Sequence

import pandas as pd

from src.models import VulnerabilityRecord


SEVERITY_ORDER = ("Critical", "High", "Medium", "Low")
STATUS_ORDER = ("Open", "In Progress", "Resolved")
SEVERITY_COLORS = {"Critical": "#f87171", "High": "#fb923c", "Medium": "#facc15", "Low": "#38bdf8"}
STATUS_COLORS = {"Open": "#fb923c", "In Progress": "#38bdf8", "Resolved": "#4ade80"}
SORT_OPTIONS = {
    "Risk · highest first": ("risk_score", False),
    "Risk · lowest first": ("risk_score", True),
    "Severity · critical first": ("severity", True),
    "Scan date · newest first": ("scan_date", False),
    "Scan date · oldest first": ("scan_date", True),
    "Vulnerability ID": ("vulnerability_id", True),
}


@dataclass(frozen=True)
class Filters:
    """Empty selections mean all options. Date boundaries are inclusive."""

    start_date: date | None = None
    end_date: date | None = None
    tools: tuple[str, ...] = ()
    severities: tuple[str, ...] = ()
    applications: tuple[str, ...] = ()
    statuses: tuple[str, ...] = ()


def records_to_frame(records: Sequence[VulnerabilityRecord]) -> pd.DataFrame:
    frame = pd.DataFrame([record.model_dump() for record in records], columns=list(VulnerabilityRecord.model_fields))
    for column in ("scan_date", "resolved_date"):
        frame[column] = pd.to_datetime(frame[column])
    frame["risk_score"] = pd.to_numeric(frame["risk_score"])
    frame["line_number"] = pd.array(frame["line_number"], dtype="Int64")
    return frame


def filter_findings(frame: pd.DataFrame, filters: Filters) -> pd.DataFrame:
    mask = pd.Series(True, index=frame.index)
    for column, selected in (
        ("tool", filters.tools), ("severity", filters.severities),
        ("application", filters.applications), ("status", filters.statuses),
    ):
        if selected:
            mask &= frame[column].isin(selected)
    if filters.start_date is not None:
        mask &= frame["scan_date"] >= pd.Timestamp(filters.start_date)
    if filters.end_date is not None:
        mask &= frame["scan_date"] <= pd.Timestamp(filters.end_date)
    return frame.loc[mask].copy()


def calculate_kpis(frame: pd.DataFrame) -> dict:
    total = len(frame)
    resolved = int(frame["status"].eq("Resolved").sum())
    risk = frame["risk_score"].dropna()
    return {
        "total": total,
        "critical": int(frame["severity"].eq("Critical").sum()),
        "unresolved": int(frame["status"].isin(("Open", "In Progress")).sum()),
        "resolved": resolved,
        "resolution_rate": resolved / total * 100 if total else 0.0,
        "average_risk": float(risk.mean()) if len(risk) else None,
        "risk_count": len(risk),
    }


def category_counts(frame: pd.DataFrame, column: str, order=None) -> pd.DataFrame:
    counts = frame[column].value_counts()
    if order is not None:
        counts = counts.reindex(order, fill_value=0)
    return counts.rename_axis(column).reset_index(name="Findings")


def monthly_trends(frame: pd.DataFrame) -> pd.DataFrame:
    """Resolution events belong to the same discovery cohort, even in later months."""
    discovered = frame["scan_date"].dt.to_period("M").value_counts()
    resolved = frame.loc[frame["status"].eq("Resolved"), "resolved_date"].dropna().dt.to_period("M").value_counts()
    months = discovered.index.union(resolved.index)
    if months.empty:
        return pd.DataFrame(columns=["Month", "Discovered", "Resolved"])
    months = pd.period_range(months.min(), months.max(), freq="M")
    return pd.DataFrame({
        "Month": months.to_timestamp(),
        "Discovered": discovered.reindex(months, fill_value=0).to_numpy(),
        "Resolved": resolved.reindex(months, fill_value=0).to_numpy(),
    })


def explore_findings(frame: pd.DataFrame, *, priority=False, query="", sort="Risk · highest first") -> pd.DataFrame:
    """Refine a global cohort for the shared findings table and detail view."""
    result = frame.copy()
    if priority:
        result = result.loc[result["severity"].isin(("Critical", "High")) & result["status"].isin(("Open", "In Progress"))]
    query = query.strip()
    if query:
        result = result.loc[
            result["vulnerability_id"].str.contains(query, case=False, regex=False)
            | result["vulnerability_name"].str.contains(query, case=False, regex=False)
        ]
    column, ascending = SORT_OPTIONS[sort]
    if column == "severity":
        result = result.assign(_severity_rank=result["severity"].map({s: n for n, s in enumerate(SEVERITY_ORDER)}))
        return result.sort_values(["_severity_rank", "vulnerability_id"], kind="stable").drop(columns="_severity_rank")
    columns = [column] if column == "vulnerability_id" else [column, "vulnerability_id"]
    directions = ascending if column == "vulnerability_id" else [ascending, True]
    return result.sort_values(columns, ascending=directions, na_position="last", kind="stable")


def findings_csv(frame: pd.DataFrame) -> bytes:
    """Export the current view with ISO dates and LF endings, without helper columns."""
    return frame.to_csv(index=False, date_format="%Y-%m-%d", lineterminator="\n").encode("utf-8")
