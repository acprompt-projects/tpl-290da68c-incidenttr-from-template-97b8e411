import uuid
from datetime import datetime, timezone
from typing import Optional, List
from .models import IncidentCreate, IncidentRead, TriageUpdate, Severity, Status

class IncidentStore:
    def __init__(self):
        self._incidents: dict = {}

    async def init(self):
        self._incidents.clear()

    async def create(self, payload: IncidentCreate, severity: Severity, dedupe_key: str) -> IncidentRead:
        now = datetime.now(timezone.utc)
        incident = IncidentRead(
            id=str(uuid.uuid4()),
            title=payload.title,
            description=payload.description,
            source=payload.source,
            tags=payload.tags,
            severity=severity,
            status=Status.new,
            dedupe_key=dedupe_key,
            created_at=now,
            updated_at=now,
        )
        self._incidents[incident.id] = incident
        return incident

    async def get(self, incident_id: str) -> Optional[IncidentRead]:
        return self._incidents.get(incident_id)

    async def find_by_dedupe_key(self, dedupe_key: str) -> Optional[IncidentRead]:
        for inc in self._incidents.values():
            if inc.dedupe_key == dedupe_key:
                return inc
        return None

    async def increment_correlation(self, incident_id: str):
        inc = self._incidents.get(incident_id)
        if inc:
            inc.correlation_count += 1
            inc.updated_at = datetime.now(timezone.utc)

    async def update_triage(self, incident_id: str, update: TriageUpdate) -> IncidentRead:
        inc = self._incidents[incident_id]
        if update.severity is not None:
            inc.severity = update.severity
        if update.status is not None:
            inc.status = update.status
        if update.assignee is not None:
            inc.assignee = update.assignee
        if update.notes is not None:
            inc.notes = update.notes
        inc.updated_at = datetime.now(timezone.utc)
        return inc