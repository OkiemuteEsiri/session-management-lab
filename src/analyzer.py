from __future__ import annotations

from dataclasses import asdict
from typing import Iterable

from .models import Finding, SessionPolicy, deduplicate_techniques


def _finding(policy: SessionPolicy, control_id: str, title: str, severity: str, score: int,
             evidence: str, remediation: str, validation: str,
             techniques: Iterable[str] = ()) -> Finding:
    return Finding(
        control_id=control_id,
        application=policy.application,
        title=title,
        severity=severity,
        score=score,
        evidence=evidence,
        remediation=remediation,
        validation=validation,
        attack_techniques=deduplicate_techniques(techniques),
    )


def assess(policy: SessionPolicy) -> list[Finding]:
    """Evaluate a session-management policy against defensive control expectations."""
    findings: list[Finding] = []

    if not policy.cookie_secure:
        findings.append(_finding(
            policy, "SM-001", "Session cookie lacks Secure attribute", "high", 82,
            "cookie_secure=false",
            "Set the Secure attribute and serve authenticated traffic only over HTTPS.",
            "Re-inspect the Set-Cookie header over HTTPS and confirm Secure is present.",
            ("T1539",),
        ))

    if not policy.cookie_http_only:
        findings.append(_finding(
            policy, "SM-002", "Session cookie lacks HttpOnly", "high", 78,
            "cookie_http_only=false",
            "Set HttpOnly on session cookies unless a documented application requirement prevents it.",
            "Confirm client-side script cannot read the session cookie and regression tests still pass.",
            ("T1539",),
        ))

    if policy.cookie_same_site == "None":
        findings.append(_finding(
            policy, "SM-003", "Cross-site cookie policy requires additional scrutiny", "medium", 55,
            "SameSite=None",
            "Use Lax or Strict where business flows allow; otherwise document cross-site need and enforce CSRF defenses.",
            "Verify intended cross-site flows and confirm CSRF protections reject forged state-changing requests.",
        ))

    if policy.idle_timeout_minutes > 30:
        findings.append(_finding(
            policy, "SM-004", "Idle session timeout is longer than baseline", "medium", 48,
            f"idle_timeout_minutes={policy.idle_timeout_minutes}",
            "Reduce idle timeout based on application sensitivity and user workflow.",
            "Confirm inactive sessions are rejected after the approved timeout.",
            ("T1078",),
        ))

    if policy.absolute_timeout_minutes > 720:
        findings.append(_finding(
            policy, "SM-005", "Absolute session lifetime is excessive", "medium", 52,
            f"absolute_timeout_minutes={policy.absolute_timeout_minutes}",
            "Set a finite absolute lifetime appropriate to the application risk tier.",
            "Confirm a continuously active session is forced to re-authenticate at the configured limit.",
            ("T1078",),
        ))

    if not policy.rotate_on_authentication:
        findings.append(_finding(
            policy, "SM-006", "Session identifier is not rotated after authentication", "high", 76,
            "rotate_on_authentication=false",
            "Issue a new session identifier after authentication and invalidate the pre-authentication identifier.",
            "Compare pre/post-authentication identifiers and confirm the prior identifier is unusable.",
            ("T1078",),
        ))

    if not policy.rotate_on_privilege_change:
        findings.append(_finding(
            policy, "SM-007", "Session identifier is not rotated after privilege change", "high", 72,
            "rotate_on_privilege_change=false",
            "Rotate the session identifier when privilege or authorization context changes.",
            "Elevate privileges in an authorized test and confirm the old identifier no longer authorizes requests.",
            ("T1078",),
        ))

    if not policy.invalidate_on_logout:
        findings.append(_finding(
            policy, "SM-008", "Logout does not invalidate the server-side session", "high", 80,
            "invalidate_on_logout=false",
            "Destroy or revoke the server-side session on logout and clear client-side session material.",
            "Replay the former session identifier after logout and confirm access is denied.",
            ("T1078",),
        ))

    if not policy.csrf_protection:
        findings.append(_finding(
            policy, "SM-009", "State-changing requests lack CSRF protection", "high", 74,
            "csrf_protection=false",
            "Implement an appropriate anti-CSRF control for authenticated state-changing actions.",
            "Send an authorized negative test without the expected anti-CSRF signal and confirm rejection.",
        ))

    if policy.session_identifier_in_url:
        findings.append(_finding(
            policy, "SM-010", "Session identifier is exposed in URLs", "critical", 94,
            "session_identifier_in_url=true",
            "Remove session identifiers from URLs and use protected cookies or equivalent secure transport mechanisms.",
            "Confirm application navigation, logs, history and referrers no longer contain session identifiers.",
            ("T1539",),
        ))

    if not policy.owner.strip():
        findings.append(_finding(
            policy, "SM-011", "Session control has no accountable owner", "low", 28,
            "owner is empty",
            "Assign an accountable engineering or application-security owner for remediation and validation.",
            "Confirm ownership is recorded in the application inventory or risk register.",
        ))

    return sorted(findings, key=lambda item: (-item.score, item.control_id))


def portfolio_metrics(findings: list[Finding]) -> dict[str, object]:
    severity_counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        severity_counts[finding.severity] += 1
    affected_apps = sorted({finding.application for finding in findings})
    highest_score = max((finding.score for finding in findings), default=0)
    posture = max(0, 100 - min(100, sum(f.score for f in findings) // max(1, len(affected_apps))))
    return {
        "finding_count": len(findings),
        "affected_applications": affected_apps,
        "highest_score": highest_score,
        "posture_score": posture,
        "by_severity": severity_counts,
    }


def finding_as_dict(finding: Finding) -> dict[str, object]:
    result = asdict(finding)
    result["finding_id"] = finding.finding_id
    return result
