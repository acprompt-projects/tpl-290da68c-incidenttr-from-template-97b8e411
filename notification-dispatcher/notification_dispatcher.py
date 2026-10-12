===
import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Channel(str, Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


@dataclass
class Incident:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RateLimitEntry:
    tokens: float
    last_refill: float


class RateLimiter:
    """Sliding-window token-bucket rate limiter per routing key."""

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.refill_rate = max_requests / window_seconds
        self._buckets: Dict[str, RateLimitEntry] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        entry = self._buckets.get(key)
        if entry is None:
            self._buckets[key] = RateLimitEntry(tokens=self.max_requests - 1, last_refill=now)
            return True
        elapsed = now - entry.last_refill
        entry.tokens = min(self.max_requests, entry.tokens + elapsed * self.refill_rate)
        entry.last_refill = now
        if entry.tokens >= 1:
            entry.tokens -= 1
            return True
        return False


@dataclass
class RoutingRule:
    severities: List[Severity]
    categories: List[str]
    channels: List[Channel]

    def matches(self, incident: Incident) -> bool:
        sev_ok = not self.severities or incident.severity in self.severities
        cat_ok = not self.categories or incident.category in self.categories or "*" in self.categories
        return sev_ok and cat_ok


DEFAULT_ROUTING_RULES: List[RoutingRule] = [
    RoutingRule(severities=[Severity.CRITICAL], categories=["*"], channels=[Channel.SLACK, Channel.PAGERDUTY, Channel.EMAIL]),
    RoutingRule(severities=[Severity.HIGH], categories=["*"], channels=[Channel.SLACK, Channel.PAGERDUTY]),
    RoutingRule(severities=[Severity.MEDIUM, Severity.LOW], categories=["*"], channels=[Channel.SLACK, Channel.EMAIL]),
    RoutingRule(severities=[Severity.INFO], categories=["*"], channels=[Channel.SLACK]),
]


class SlackNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.client = httpx.AsyncClient(timeout=10.0)

    async def send(self, incident: Incident) -> bool:
        severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        emoji = severity_emoji.get(incident.severity.value, "⚠️")
        payload = {
            "text": f"{emoji} [{incident.severity.value.upper()}] {incident.title}",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*{emoji} Incident: {incident.title}*"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* {incident.severity.value}"},
                    {"type": "mrkdwn", "text": f"*Category:* {incident.category}"},
                    {"type": "mrkdwn", "text": f"*ID:* {incident.id}"},
                ]},
                {"type": "section", "text": {"type": "mrkdwn", "text": incident.description}},
            ],
        }
        try:
            resp = await self.client.post(self.webhook_url, json=payload)
            resp.raise_for_status()
            logger.info("Slack notification sent for incident %s", incident.id)
            return True
        except Exception as exc:
            logger.error("Slack notification failed for %s: %s", incident.id, exc)
            return False

    async def close(self):
        await self.client.aclose()


class PagerDutyNotifier:
    def __init__(self, routing_key: str, api_url: str = "https://events.pagerduty.com/v2/enqueue"):
        self.routing_key = routing_key
        self.api_url = api_url
        self.client = httpx.AsyncClient(timeout=10.0)

    def _severity_pd(self, severity: Severity) -> str:
        mapping = {Severity.CRITICAL: "critical", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "info", Severity.INFO: "info"}
        return mapping.get(severity, "warning")

    async def send(self, incident: Incident) -> bool:
        dedup_key = hashlib.sha256(f"{incident.id}:{incident.category}".encode()).hexdigest()[:32]
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": f"[{incident.severity.value.upper()}] {incident.title}",
                "severity": self._severity_pd(incident.severity),
                "source": "incident-triage-service",
                "component": incident.category,
                "custom_details": {"incident_id": incident.id, "description": incident.description, **incident.metadata},
            },
        }
        try:
            resp = await self.client.post(self.api_url, json=payload)
            resp.raise_for_status()
            logger.info("PagerDuty notification sent for incident %s", incident.id)
            return True
        except Exception as exc:
            logger.error("PagerDuty notification failed for %s: %s", incident.id, exc)
            return False

    async def close(self):
        await self.client.aclose()


class EmailNotifier:
    def __init__(self, smtp_host: str, smtp_port: int, sender: str, recipients: List[str],
                 username: Optional[str] = None, password: Optional[str] = None, use_tls: bool = True):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender = sender
        self.recipients = recipients
        self.username = username
        self.password = password
        self.use_tls = use_tls

    async def send(self, incident: Incident) -> bool:
        import aiosmtplib
        from email.mime.text import MIMEText
        subject = f"[{incident.severity.value.upper()}] {incident.title}"
        body = (
            f"Incident ID: {incident.id}\n"
            f"Severity: {incident.severity.value}\n"
            f"Category: {incident.category}\n\n"
            f"{incident.description}\n"
        )
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        try:
            await aiosmtplib.send(
                msg, hostname=self.smtp_host, port=self.smtp_port,
                username=self.username, password=self.password,
                use_tls=self.use_tls,
            )
            logger.info("Email notification sent for incident %s", incident.id)
            return True
        except Exception as exc:
            logger.error("Email notification failed for %s: %s", incident.id, exc)
            return False

    async def close(self):
        pass


class NotificationDispatcher:
    def __init__(
        self,
        slack_webhook_url: Optional[str] = None,
        pagerduty_routing_key: Optional[str] = None,
        email_config: Optional[Dict[str, Any]] = None,
        routing_rules: Optional[List[RoutingRule]] = None,
        rate_limit_max: int = 30,
        rate_limit_window: int = 60,
    ):
        self.routing_rules = routing_rules or DEFAULT_ROUTING_RULES
        self.rate_limiter = RateLimiter(max_requests=rate_limit_max, window_seconds=rate_limit_window)
        self._notifiers: Dict[Channel, Any] = {}
        if slack_webhook_url:
            self._notifiers[Channel.SLACK] = SlackNotifier(slack_webhook_url)
        if pagerduty_routing_key:
            self._notifiers[Channel.PAGERDUTY] = PagerDutyNotifier(pagerduty_routing_key)
        if email_config:
            self._notifiers[Channel.EMAIL] = EmailNotifier(**email_config)

    def _resolve_channels(self, incident: Incident) -> List[Channel]:
        channels: set = set()
        for rule in self.routing_rules:
            if rule.matches(incident):
                channels.update(rule.channels)
        return list(channels)

    async def dispatch(self, incident: Incident) -> Dict[str, bool]:
        channels = self._resolve_channels(incident)
        results: Dict[str, bool] = {}
        tasks = []
        for ch in channels:
            notifier = self._notifiers.get(ch)
            if notifier is None:
                logger.warning("No notifier configured for channel %s, skipping", ch.value)
                results[ch.value] = False
                continue
            rate_key = f"{ch.value}:{incident.severity.value}"
            if not self.rate_limiter.allow(rate_key):
                logger.warning("Rate limited on channel %s for incident %s", ch.value, incident.id)
                results[ch.value] = False
                continue
            tasks.append((ch, notifier, incident))

        async def _send(ch: Channel, notifier: Any, inc: Incident) -> tuple:
            return ch.value, await notifier.send(inc)

        outcomes = await asyncio.gather(*[_send(*t) for t in tasks], return_exceptions=True)
        for outcome in outcomes:
            if isinstance(outcome, Exception):
                logger.error("Dispatch error: %s", outcome)
                continue
            ch_name, success = outcome
            results[ch_name] = success
        logger.info("Dispatch results for incident %s: %s", incident.id, results)
        return results

    async def close(self):
        for notifier in self._notifiers.values():
            await notifier.close()