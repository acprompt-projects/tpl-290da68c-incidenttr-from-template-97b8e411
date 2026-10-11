from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from typing import Optional, List

class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class Status(str, Enum):
    new = "new"
    triaging = "triaging"
    acknowledged = "acknowledged"
    resolved = "resolved"

class AlertSource(BaseModel):
    service: str
    environment: str
    host: Optional[str] = None

class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=512)
    description: str = Field(default="", max_length=4096)
    source: AlertSource
    tags: List[str] = Field(default_factory=list)
    raw_alert: Optional[dict] = None

    def deduplication_key(self) -> str:
        return f"{self.source.service}:{self.source.environment}:{self.title}"

class TriageUpdate(BaseModel):
    severity: Optional[Severity] = None
    status: Optional[Status] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None

class IncidentRead(BaseModel):
    id: str
    title: str
    description: str
    source: AlertSource
    tags: List[str]
    severity: Severity
    status: Status
    assignee: Optional[str] = None
    notes: Optional[str] = None
    correlation_count: int = 1
    dedupe_key: str
    created_at: datetime
    updated_at: datetime