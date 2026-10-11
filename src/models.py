"""Validation rules for individual vulnerability findings."""

import re
from datetime import date
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationInfo, field_validator


NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class VulnerabilityRecord(BaseModel):
    """One finding, with dates normalized to Python date objects."""

    model_config = ConfigDict(extra="forbid", validate_default=True)

    vulnerability_id: NonEmptyText
    scan_date: date
    tool: NonEmptyText
    application: NonEmptyText
    severity: Literal["Critical", "High", "Medium", "Low"]
    vulnerability_name: NonEmptyText
    status: Literal["Open", "In Progress", "Resolved"]
    resolved_date: date | None = None

    @field_validator("scan_date", "resolved_date", mode="before")
    @classmethod
    def parse_iso_date(cls, value, info: ValidationInfo):
        if info.field_name == "resolved_date" and (value is None or value == ""):
            return None
        if type(value) is date:
            return value
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
            raise ValueError("Use an ISO date in YYYY-MM-DD format")
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("Enter a valid calendar date in YYYY-MM-DD format") from exc

    @field_validator("resolved_date")
    @classmethod
    def check_resolution(cls, value: date | None, info: ValidationInfo):
        status = info.data.get("status")
        if status == "Resolved" and value is None:
            raise ValueError("resolved_date is required when status is Resolved")
        if status in ("Open", "In Progress") and value is not None:
            raise ValueError("resolved_date must be blank when status is Open or In Progress")
        scan = info.data.get("scan_date")
        if value is not None and scan is not None and value < scan:
            raise ValueError("resolved_date must be on or after scan_date")
        return value
