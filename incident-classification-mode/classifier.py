===
import yaml
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severity(Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"

    @property
    def rank(self) -> int:
        return {"P1": 1, "P2": 2, "P3": 3, "P4": 4}[self.value]


class Category(Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"


@dataclass
class TriageLabel:
    severity: Severity
    category: Category
    confidence: float
    rules_matched: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "confidence": round(self.confidence, 3),
            "rules_matched": self.rules_matched,
        }


@dataclass
class Incident:
    id: str
    title: str
    source: str
    tags: list[str] = field(default_factory=list)
    metric_value: Optional[float] = None
    metric_name: Optional[str] = None
    affected_services: list[str] = field(default_factory=list)
    error_rate: Optional[float] = None
    latency_ms: Optional[float] = None
    is_security_event: bool = False
    raw: dict = field(default_factory=dict)


DEFAULT_THRESHOLDS: dict = {
    "error_rate": {"P1": 50.0, "P2": 20.0, "P3": 5.0},
    "latency_ms": {"P1": 10000, "P2": 5000, "P3": 2000},
    "metric_value": {"P1": 95.0, "P2": 80.0, "P3": 60.0},
}

CATEGORY_KEYWORDS: dict[str, dict] = {
    "infra": {
        "tags": ["cpu", "memory", "disk", "host", "node", "server", "vm", "container", "pod", "infrastructure"],
        "sources": ["prometheus", "node-exporter", "cadvisor", "aws-cloudwatch", "gcp-monitoring"],
    },
    "app": {
        "tags": ["error", "exception", "crash", "timeout", "5xx", "4xx", "deploy", "release", "application"],
        "sources": ["sentry", "datadog-apm", "app-metrics", "kubernetes-events"],
    },
    "security": {
        "tags": ["auth", "breach", "malware", "intrusion", "vulnerability", "exploit", "unauthorized", "ddos", "cve"],
        "sources": ["guardduty", "crowdstrike", "waf", "siem", "security-hub"],
    },
    "network": {
        "tags": ["dns", "latency", "packet", "connection", "firewall", "routing", "bandwidth", "network", "tcp", "ssl"],
        "sources": ["ping", "traceroute", "netflow", "vpc-flow-logs", "gateway"],
    },
}


class IncidentClassifier:
    def __init__(self, config_path: Optional[str] = None):
        self.thresholds = DEFAULT_THRESHOLDS.copy()
        self.category_keywords = CATEGORY_KEYWORDS.copy()
        if config_path and Path(config_path).exists():
            self._load_config(config_path)

    def _load_config(self, path: str) -> None:
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
        if "thresholds" in cfg:
            for key, levels in cfg["thresholds"].items():
                self.thresholds.setdefault(key, {}).update(levels)
        if "category_keywords" in cfg:
            for cat, mapping in cfg["category_keywords"].items():
                self.category_keywords.setdefault(cat, {}).update(mapping)

    def classify(self, incident: Incident) -> TriageLabel:
        matched_rules: list[str] = []
        severities: list[Severity] = []
        categories: list[Category] = []

        # Security override
        if incident.is_security_event:
            categories.append(Category.SECURITY)
            matched_rules.append("security_event_flag")

        # Category from tags and source
        cat_scores = self._score_categories(incident)
        if cat_scores:
            best_cat_name, best_score = max(cat_scores.items(), key=lambda x: x[1])
            if best_score > 0:
                categories.append(Category(best_cat_name))
                matched_rules.append(f"category_keyword_{best_cat_name}")

        # Implicit category from metric name
        if incident.metric_name and not categories:
            cat = self._infer_category_from_metric(incident.metric_name)
            if cat:
                categories.append(cat)
                matched_rules.append(f"metric_inferred_{cat.value}")

        # Severity from thresholds
        sev = self._severity_from_thresholds(incident, matched_rules)
        if sev:
            severities.append(sev)

        # Default fallbacks
        final_severity = min((s for s in severities), key=lambda s: s.rank) if severities else Severity.P4
        final_category = categories[0] if categories else Category.APP

        confidence = self._compute_confidence(matched_rules, severities, categories)

        return TriageLabel(
            severity=final_severity,
            category=final_category,
            confidence=confidence,
            rules_matched=matched_rules,
        )

    def _score_categories(self, incident: Incident) -> dict[str, float]:
        scores: dict[str, float] = {"infra": 0.0, "app": 0.0, "security": 0.0, "network": 0.0}
        text_pool = [t.lower() for t in incident.tags] + [incident.title.lower()]
        for cat_name, mapping in self.category_keywords.items():
            for kw in mapping.get("tags", []):
                if any(kw in t for t in text_pool):
                    scores[cat_name] += 1.0
            if incident.source.lower() in [s.lower() for s in mapping.get("sources", [])]:
                scores[cat_name] += 2.0
        return {k: v for k, v in scores.items() if v > 0}

    def _infer_category_from_metric(self, name: str) -> Optional[Category]:
        lower = name.lower()
        for kw in ["cpu", "memory", "disk", "host"]:
            if kw in lower:
                return Category.INFRA
        for kw in ["error", "exception", "request", "latency", "duration"]:
            if kw in lower:
                return Category.APP
        for kw in ["auth", "login", "token", "certificate"]:
            if kw in lower:
                return Category.SECURITY
        for kw in ["dns", "packet", "bandwidth", "connection", "tcp"]:
            if kw in lower:
                return Category.NETWORK
        return None

    def _severity_from_thresholds(self, inc: Incident, rules: list[str]) -> Optional[Severity]:
        best = None
        if inc.error_rate is not None:
            th = self.thresholds.get("error_rate", {})
            if inc.error_rate >= th.get("P1", 50):
                candidate, rule = Severity.P1, "error_rate_P1"
            elif inc.error_rate >= th.get("P2", 20):
                candidate, rule = Severity.P2, "error_rate_P2"
            elif inc.error_rate >= th.get("P3", 5):
                candidate, rule = Severity.P3, "error_rate_P3"
            else:
                candidate, rule = None, None
            if candidate:
                rules.append(rule)
                best = candidate if best is None else min(best, candidate, key=lambda s: s.rank)

        if inc.latency_ms is not None:
            th = self.thresholds.get("latency_ms", {})
            if inc.latency_ms >= th.get("P1", 10000):
                candidate, rule = Severity.P1, "latency_P1"
            elif inc.latency_ms >= th.get("P2", 5000):
                candidate, rule = Severity.P2, "latency_P2"
            elif inc.latency_ms >= th.get("P3", 2000):
                candidate, rule = Severity.P3, "latency_P3"
            else:
                candidate, rule = None, None
            if candidate:
                rules.append(rule)
                best = candidate if best is None else min(best, candidate, key=lambda s: s.rank)

        if inc.metric_value is not None:
            th = self.thresholds.get("metric_value", {})
            if inc.metric_value >= th.get("P1", 95):
                candidate, rule = Severity.P1, "metric_P1"
            elif inc.metric_value >= th.get("P2", 80):
                candidate, rule = Severity.P2, "metric_P2"
            elif inc.metric_value >= th.get("P3", 60):
                candidate, rule = Severity.P3, "metric_P3"
            else:
                candidate, rule = None, None
            if candidate:
                rules.append(rule)
                best = candidate if best is None else min(best, candidate, key=lambda s: s.rank)

        # Security events get at least P2
        if inc.is_security_event and (best is None or best.rank > 2):
            rules.append("security_minimum_P2")
            best = Severity.P2

        return best

    def _compute_confidence(self, rules: list, sevs: list, cats: list) -> float:
        score = 0.3
        score += min(len(rules) * 0.15, 0.35)
        if sevs:
            score += 0.15
        if cats:
            score += 0.2
        return min(score, 1.0)


def classify_incident(incident: dict, config_path: Optional[str] = None) -> dict:
    inc = Incident(
        id=incident.get("id", ""),
        title=incident.get("title", ""),
        source=incident.get("source", ""),
        tags=incident.get("tags", []),
        metric_value=incident.get("metric_value"),
        metric_name=incident.get("metric_name"),
        affected_services=incident.get("affected_services", []),
        error_rate=incident.get("error_rate"),
        latency_ms=incident.get("latency_ms"),
        is_security_event=incident.get("is_security_event", False),
        raw=incident,
    )
    classifier = IncidentClassifier(config_path)
    label = classifier.classify(inc)
    return label.to_dict()