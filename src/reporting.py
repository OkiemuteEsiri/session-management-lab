from __future__ import annotations

from .analyzer import portfolio_metrics
from .models import Finding


def render_markdown(findings: list[Finding]) -> str:
    metrics = portfolio_metrics(findings)
    lines = [
        "# Session Management Security Assessment",
        "",
        "## Executive summary",
        f"- Findings: {metrics['finding_count']}",
        f"- Highest contextual score: {metrics['highest_score']}/100",
        f"- Posture score: {metrics['posture_score']}/100",
        f"- Affected applications: {', '.join(metrics['affected_applications']) or 'None'}",
        "",
        "## Severity distribution",
    ]
    for severity, count in metrics["by_severity"].items():
        lines.append(f"- {severity.title()}: {count}")

    lines.extend(["", "## Findings"])
    if not findings:
        lines.append("No control gaps were identified in the supplied synthetic policy set.")

    for finding in findings:
        lines.extend([
            "",
            f"### {finding.title}",
            f"- ID: `{finding.finding_id}`",
            f"- Control: `{finding.control_id}`",
            f"- Application: `{finding.application}`",
            f"- Severity: **{finding.severity.title()}**",
            f"- Contextual score: **{finding.score}/100**",
            f"- Evidence: {finding.evidence}",
            f"- ATT&CK context: {', '.join(finding.attack_techniques) or 'Not mapped'}",
            f"- Remediation: {finding.remediation}",
            f"- Validation: {finding.validation}",
        ])

    lines.extend([
        "",
        "## Interpretation",
        "ATT&CK mappings provide threat context and do not prove compromise. Findings represent configuration or control observations that require application-specific validation.",
    ])
    return "\n".join(lines) + "\n"
