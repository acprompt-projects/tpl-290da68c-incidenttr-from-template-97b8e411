from .models import IncidentCreate, Severity

_RULES: list[tuple[str, Severity]] = [
    ("outage", Severity.critical),
    ("down", Severity.critical),
    ("unreachable", Severity.high),
    ("degraded", Severity.high),
    ("slow", Severity.medium),
    ("warning", Severity.medium),
    ("retry", Severity.low),
    ("timeout", Severity.medium),
]

async def classify_severity(incident: IncidentCreate) -> Severity:
    text = f"{incident.title} {incident.description} {' '.join(incident.tags)}".lower()
    env_boost = incident.source.environment in ("production", "prod")
    for keyword, sev in _RULES:
        if keyword in text:
            if env_boost and sev in (Severity.medium, Severity.low):
                return Severity(Severity.high)
            return sev
    if env_boost:
        return Severity.medium
    return Severity.low