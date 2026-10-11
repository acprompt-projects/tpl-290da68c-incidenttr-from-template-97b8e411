from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from .models import IncidentCreate, IncidentRead, TriageUpdate, Severity
from .store import IncidentStore
from .classifier import classify_severity

store = IncidentStore()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await store.init()
    yield

app = FastAPI(title="Incident Triage API", version="1.0.0", lifespan=lifespan)

@app.post("/incidents", response_model=IncidentRead, status_code=201)
async def create_incident(payload: IncidentCreate):
    dedupe_key = payload.deduplication_key()
    existing = await store.find_by_dedupe_key(dedupe_key)
    if existing:
        await store.increment_correlation(existing.id)
        return await store.get(existing.id)
    severity = await classify_severity(payload)
    incident = await store.create(payload, severity, dedupe_key)
    return incident

@app.get("/incidents/{incident_id}", response_model=IncidentRead)
async def get_incident(incident_id: str):
    incident = await store.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@app.patch("/incidents/{incident_id}/triage", response_model=IncidentRead)
async def update_triage(incident_id: str, update: TriageUpdate):
    incident = await store.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.status == "resolved":
        raise HTTPException(status_code=409, detail="Cannot triage a resolved incident")
    updated = await store.update_triage(incident_id, update)
    return updated

@app.get("/health")
async def health():
    return {"status": "healthy"}