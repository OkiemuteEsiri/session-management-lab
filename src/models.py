from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Iterable

ALLOWED_ENVIRONMENTS = {"production", "staging", "development", "test"}
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def parse_utc(value: str) -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to UTC."""
    candidate = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(candidate)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class SessionPolicy:
    application: str
    environment: str
    cookie_secure: bool
    cookie_http_only: bool
    cookie_same_site: str
    idle_timeout_minutes: int
    absolute_timeout_minutes: int
    rotate_on_authentication: bool
    rotate_on_privilege_change: bool
    invalidate_on_logout: bool
    csrf_protection: bool
    session_identifier_in_url: bool
    owner: str

    def __post_init__(self) -> None:
        if not self.application.strip():
            raise ValueError("application is required")
        if self.environment not in ALLOWED_ENVIRONMENTS:
            raise ValueError("unsupported environment")
        if self.cookie_same_site not in {"Strict", "Lax", "None"}:
            raise ValueError("cookie_same_site must be Strict, Lax, or None")
        if self.idle_timeout_minutes <= 0 or self.absolute_timeout_minutes <= 0:
            raise ValueError("timeouts must be positive")
        if self.absolute_timeout_minutes < self.idle_timeout_minutes:
            raise ValueError("absolute timeout cannot be shorter than idle timeout")


@dataclass(frozen=True)
class Finding:
    control_id: str
    application: str
    title: str
    severity: str
    score: int
    evidence: str
    remediation: str
    validation: str
    attack_techniques: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError("unsupported severity")
        if not 0 <= self.score <= 100:
            raise ValueError("score must be between 0 and 100")

    @property
    def finding_id(self) -> str:
        material = f"{self.control_id}|{self.application}|{self.title}".encode()
        return sha256(material).hexdigest()[:16]


def deduplicate_techniques(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value.strip() for value in values if value.strip()}))
