import unittest

from src.analyzer import assess, portfolio_metrics
from src.models import SessionPolicy


def baseline(**overrides):
    values = dict(
        application="app",
        environment="production",
        cookie_secure=True,
        cookie_http_only=True,
        cookie_same_site="Lax",
        idle_timeout_minutes=20,
        absolute_timeout_minutes=480,
        rotate_on_authentication=True,
        rotate_on_privilege_change=True,
        invalidate_on_logout=True,
        csrf_protection=True,
        session_identifier_in_url=False,
        owner="Platform Team",
    )
    values.update(overrides)
    return SessionPolicy(**values)


class SessionSecurityTests(unittest.TestCase):
    def test_secure_baseline_has_no_findings(self):
        self.assertEqual(assess(baseline()), [])

    def test_insecure_cookie_is_high(self):
        findings = assess(baseline(cookie_secure=False))
        self.assertEqual(findings[0].control_id, "SM-001")
        self.assertEqual(findings[0].severity, "high")

    def test_url_session_identifier_is_critical(self):
        findings = assess(baseline(session_identifier_in_url=True))
        self.assertEqual(findings[0].control_id, "SM-010")
        self.assertEqual(findings[0].severity, "critical")

    def test_missing_logout_invalidation_is_detected(self):
        controls = {finding.control_id for finding in assess(baseline(invalidate_on_logout=False))}
        self.assertIn("SM-008", controls)

    def test_long_timeouts_are_detected(self):
        controls = {finding.control_id for finding in assess(
            baseline(idle_timeout_minutes=60, absolute_timeout_minutes=1440)
        )}
        self.assertTrue({"SM-004", "SM-005"}.issubset(controls))

    def test_invalid_environment_fails_closed(self):
        with self.assertRaises(ValueError):
            baseline(environment="prod")

    def test_absolute_timeout_cannot_be_shorter_than_idle(self):
        with self.assertRaises(ValueError):
            baseline(idle_timeout_minutes=60, absolute_timeout_minutes=30)

    def test_finding_ids_are_deterministic(self):
        first = assess(baseline(cookie_http_only=False))[0]
        second = assess(baseline(cookie_http_only=False))[0]
        self.assertEqual(first.finding_id, second.finding_id)

    def test_metrics_are_bounded(self):
        findings = assess(baseline(cookie_secure=False, cookie_http_only=False))
        metrics = portfolio_metrics(findings)
        self.assertGreaterEqual(metrics["posture_score"], 0)
        self.assertLessEqual(metrics["posture_score"], 100)

    def test_missing_owner_is_reported(self):
        controls = {finding.control_id for finding in assess(baseline(owner=""))}
        self.assertIn("SM-011", controls)


if __name__ == "__main__":
    unittest.main()
