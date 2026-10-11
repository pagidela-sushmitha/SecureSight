"""Allowlisted, read-only calculations and factual prose for the AI workspace."""

from dataclasses import dataclass
import re
from typing import Literal

import pandas as pd
from pydantic import BaseModel, ConfigDict, Field

from src.analytics import (
    Filters, STATUS_ORDER, calculate_kpis, category_counts, explore_findings,
    filter_findings, monthly_trends,
)
from src.remediation import get_guidance


class AnalysisRequest(BaseModel):
    """Select one supported calculation; never code, SQL, paths, or commands."""

    model_config = ConfigDict(extra="forbid")
    operation: Literal["summary", "group_counts", "unresolved", "priorities", "details", "guidance", "trends", "unsupported"]
    dimension: Literal["application", "tool"] = "application"
    severity: Literal["All", "Critical", "Critical/High", "High", "Medium", "Low"] = "All"
    status: Literal["All", "Unresolved", "Open", "In Progress", "Resolved"] = "All"
    application: str = Field(default="", max_length=120)
    tool: str = Field(default="", max_length=120)
    limit: int = Field(default=5, ge=1, le=10)
    vulnerability_id: str = Field(default="", max_length=80)
    vulnerability_name: str = Field(default="", max_length=120)


@dataclass(frozen=True)
class AnalysisResult:
    code: str
    answer: str
    # The model may select these exact sentences, but cannot rewrite facts.
    explanations: tuple[str, ...] = ()


def explicit_question_intent(question: str) -> AnalysisRequest | None:
    """Guard complete, unambiguous comparison/priority questions independently.

    Full matching is deliberate: do not discard extra qualifiers or override
    ambiguous follow-ups using keyword presence alone. Other phrasing keeps the
    existing model workflow. This guard never reads data or changes global scope.
    """
    text = " ".join(question.casefold().strip().split()).rstrip("?.!").strip()
    comparison = re.fullmatch(
        r"(?:which|what) (application|app|scanning tool|scanner|tool) "
        r"has (?:the )?(?:most|highest number of) (unresolved )?"
        r"(critical\s*(?:/|and|or|&)\s*high|critical|high)"
        r"(?:-severity| severity)? (?:findings|vulnerabilities)",
        text,
    )
    if comparison:
        entity, unresolved, severity = comparison.groups()
        return AnalysisRequest(
            operation="group_counts",
            dimension="application" if entity in ("application", "app") else "tool",
            severity="Critical/High" if "critical" in severity and "high" in severity else severity.title(),
            status="Unresolved" if unresolved else "All",
            limit=1,
        )
    priorities = re.fullmatch(
        r"(?:what are|show|list|give me) (?:the )?top (five|[1-9]|10) remediation priorities",
        text,
    )
    if priorities:
        count = priorities.group(1)
        return AnalysisRequest(operation="priorities", limit=5 if count == "five" else int(count))
    return None


def _finding_text(row, *, details=False):
    risk = "unavailable" if pd.isna(row["risk_score"]) else f"{row['risk_score']:.1f}/10 (synthetic, not CVSS)"
    text = (
        f"{row['vulnerability_id']} — {row['vulnerability_name']}; "
        f"{row['application']}; {row['tool']}; {row['severity']}; {row['status']}; risk {risk}."
    )
    if details:
        text += f" Scan date: {row['scan_date'].date().isoformat()}."
        if pd.notna(row["resolved_date"]):
            text += f" Resolved date: {row['resolved_date'].date().isoformat()}."
        for field, label in (("cwe_id", "CWE"), ("affected_component", "Component"), ("affected_asset", "Asset")):
            if pd.notna(row[field]):
                text += f" {label}: {row[field]}."
        if pd.notna(row["file_path"]):
            text += f" Illustrative source: {row['file_path']}:{int(row['line_number'])}; not a verified code reference."
    return text


def execute_analysis(frame: pd.DataFrame, request: AnalysisRequest) -> AnalysisResult:
    """Only narrow the caller's validated global scope. Never load or mutate data."""
    if frame.empty:
        return AnalysisResult("empty", "No findings are available in the current scope. Broaden the global filters or use Reset Filters.")
    if request.operation == "unsupported":
        return AnalysisResult("unsupported", "I can answer scoped finding counts, scanner/application comparisons, unresolved Critical/High findings, remediation priorities, finding details, rule-based guidance, and monthly trends. I cannot run commands, change findings, verify fixes, or answer unrelated questions.")
    statuses = ("Open", "In Progress") if request.status == "Unresolved" else (() if request.status == "All" else (request.status,))
    subset = filter_findings(frame, Filters(
        tools=(request.tool,) if request.tool else (),
        applications=(request.application,) if request.application else (),
        severities=("Critical", "High") if request.severity == "Critical/High" else ((request.severity,) if request.severity != "All" else ()),
        statuses=statuses,
    ))
    if subset.empty:
        return AnalysisResult("empty", "No findings match that question within the current global scope.")
    if request.operation == "summary":
        values = calculate_kpis(subset)
        counts = category_counts(subset, "status", STATUS_ORDER).set_index("status")["Findings"]
        answer = (
            f"There are {values['total']} findings: {int(counts['Open'])} Open, "
            f"{int(counts['In Progress'])} In Progress, and {values['resolved']} Resolved. "
            f"{values['unresolved']} are unresolved (Open + In Progress); "
            f"{values['critical']} are Critical. Resolution rate: {values['resolution_rate']:.1f}%."
        )
        risk = values["average_risk"]
        explanations = () if risk is None else (f"Average illustrative risk is {risk:.1f}/10 across {values['risk_count']} scored findings; this is not official CVSS.",)
        return AnalysisResult("ok", answer, explanations)
    if request.operation == "group_counts":
        counts = category_counts(subset, request.dimension).sort_values(
            ["Findings", request.dimension], ascending=[False, True], kind="stable",
        )
        top = counts.head(request.limit)
        qualifier = f"{request.severity} severity, {request.status} status"
        highest = int(counts.iloc[0]["Findings"])
        leaders = counts.loc[counts["Findings"].eq(highest), request.dimension].tolist()
        # Always name every highest-count tie, even when the model asks for one
        # group or chooses not to include the optional explanation sentence.
        leader_text = "; ".join(leaders)
        lead = f"Tie for most matching findings: {leader_text} — {highest} each." if len(leaders) > 1 else f"{leader_text} has the most matching findings: {highest}."
        answer = lead + f"\n\n{len(subset)} matching findings ({qualifier}), by {request.dimension}:\n\n" + "\n".join(
            f"- {row[request.dimension]}: {int(row['Findings'])}" for _, row in top.iterrows()
        )
        if len(top) < len(counts):
            answer += f"\n\nShowing {len(top)} of {len(counts)} groups, highest count first."
        tied = int(counts["Findings"].eq(counts.iloc[0]["Findings"]).sum())
        insight = f"The highest count is {int(counts.iloc[0]['Findings'])}; {tied} groups share this count." if tied > 1 else f"{counts.iloc[0][request.dimension]} has the most matching findings ({int(counts.iloc[0]['Findings'])})."
        return AnalysisResult("ok", answer, (insight, "Unresolved means Open plus In Progress; Resolved findings are excluded from unresolved counts."))
    if request.operation in ("priorities", "unresolved"):
        findings = explore_findings(subset, priority=True)
        rows = findings.head(request.limit)
        severity_label = "Critical/High" if request.severity == "All" else request.severity
        answer = f"{len(findings)} unresolved {severity_label} findings match. Showing {len(rows)}, ordered by highest synthetic risk first:\n\n" + "\n".join(
            f"- {_finding_text(row)}" for _, row in rows.iterrows()
        )
        return AnalysisResult("ok", answer, ("Priorities follow the dashboard's synthetic risk ordering, with vulnerability ID breaking ties. They are illustrative triage guidance, not verified remediation outcomes.",))
    if request.operation in ("details", "guidance"):
        if request.vulnerability_id:
            matches = subset.loc[subset["vulnerability_id"].eq(request.vulnerability_id)]
        elif request.operation == "guidance" and request.vulnerability_name:
            matches = subset.loc[subset["vulnerability_name"].str.contains(request.vulnerability_name, case=False, regex=False)]
            if matches["vulnerability_name"].nunique() > 1:
                return AnalysisResult("clarification", "Several vulnerability types match. Please provide a specific vulnerability ID from this scope.")
        else:
            return AnalysisResult("clarification", "Please provide a vulnerability ID, or a vulnerability name for rule-based guidance.")
        if matches.empty:
            return AnalysisResult("not_found", "That vulnerability ID or name was not found in the current scope. It may be unknown or excluded by the global filters.")
        row = matches.sort_values("vulnerability_id").iloc[0]
        guidance = get_guidance(row["vulnerability_name"], row["tool"])
        answer = _finding_text(row, details=True) + f"\n\nRule-based recommendation: {guidance.remediation}"
        return AnalysisResult("ok", answer, ("This recommendation has not been applied or verified. Findings, source locations, and risk scores are synthetic test examples.",))
    trends = monthly_trends(subset)
    answer = "Monthly events for the matching discovery cohort:\n\n" + "\n".join(
        f"- {row['Month']:%Y-%m}: {int(row['Discovered'])} discovered, {int(row['Resolved'])} resolved."
        for _, row in trends.tail(24).iterrows()
    )
    if len(trends) > 24:
        answer += "\n\nShowing the latest 24 months."
    return AnalysisResult("ok", answer, ("Resolution events belong to the same scan-date discovery cohort and may occur after the selected discovery range. A Resolved status records a synthetic outcome, not a verified fix.",))
