# Session Management Security Lab

A defensive Web Application and API Security project for assessing session-management controls, producing explainable findings, prioritizing remediation, and validating closure using repeatable evidence.

## Problem statement

Session-management weaknesses can extend the useful lifetime of authenticated access, expose session identifiers, weaken logout behavior, or allow state-changing requests without sufficient anti-CSRF protections. In real AppSec programs, the difficult part is not only identifying a misconfiguration; it is translating the observation into defensible risk, remediation ownership, and re-test evidence.

This repository demonstrates that workflow using **synthetic application policy data only**.

## What this project demonstrates

- secure session-design review
- Web/API security engineering
- deterministic defensive control assessment
- fail-closed input validation
- explainable risk scoring
- remediation and re-test governance
- ATT&CK-aligned threat context
- synthetic-data handling
- unit testing and CI/CD security checks
- technical and executive reporting

## Architecture

```text
Synthetic policy inventory
        |
        v
Validated SessionPolicy models
        |
        v
Deterministic control assessment
        |
        +--> normalized Finding objects
        |
        +--> portfolio metrics
        |
        v
Markdown technical / executive report
        |
        v
Remediation -> re-test -> validated closure
```

Key components:

- `src/models.py` — immutable domain models and validation
- `src/analyzer.py` — session-control assessment and scoring
- `src/reporting.py` — severity metrics and Markdown reporting
- `src/cli.py` — offline assessment CLI
- `data/synthetic_session_policies.json` — realistic synthetic inventory
- `tests/test_analyzer.py` — meaningful unit coverage
- `docs/architecture-methodology.md` — architecture, methodology and governance
- `reports/example-assessment.md` — recruiter-facing example output
- `.github/workflows/ci.yml` — least-privilege CI

## Implemented controls

The assessment engine currently checks:

1. `Secure` cookie attribute
2. `HttpOnly` cookie attribute
3. SameSite policy requiring additional scrutiny
4. excessive idle-session lifetime
5. excessive absolute-session lifetime
6. session identifier rotation after authentication
7. session identifier rotation after privilege change
8. server-side invalidation on logout
9. CSRF protection for authenticated state-changing actions
10. session identifiers exposed in URLs
11. missing accountable control ownership

Each finding contains:

- deterministic finding ID
- control ID
- application
- severity
- contextual score from 0–100
- evidence
- remediation guidance
- explicit validation criteria
- MITRE ATT&CK context where appropriate

## Risk design

The repository keeps **severity**, **contextual score**, and **threat mapping** conceptually separate.

A high ATT&CK relevance does not mean compromise occurred. Likewise, a control weakness may require business-context adjustment before a final enterprise risk decision. The scoring model therefore supports prioritization rather than claiming certainty.

## MITRE ATT&CK context

Relevant defensive mappings include:

- **T1539 — Steal Web Session Cookie**
- **T1078 — Valid Accounts**

ATT&CK is used to explain why a session-management weakness matters from an adversary-behavior perspective. A mapping is not evidence that the application was exploited.

## Running the lab

The repository is intentionally dependency-light and uses the Python standard library.

```bash
python -m unittest discover -s tests -v
```

Generate a Markdown assessment from the synthetic inventory:

```bash
python -m src.cli data/synthetic_session_policies.json --output reports/generated-assessment.md
```

## Example assessment flow

```text
1. Load synthetic session policy
2. Validate schema and control values
3. Evaluate session protections
4. Generate normalized findings
5. Rank by contextual score
6. Produce management and technical output
7. Assign remediation
8. Re-test changed behavior
9. Close only with validation evidence
```

## Remediation and validation workflow

A finding is not considered complete because a ticket was closed or configuration was changed. The project uses an explicit validation standard.

Examples:

- after logout, the former session identifier must be rejected;
- after authentication, the pre-authentication session identifier must no longer be usable;
- after a privilege change, the previous identifier must not retain elevated authorization;
- cookie attributes must be observable in the resulting response headers;
- negative CSRF validation must demonstrate that forged state-changing requests are rejected.

This distinction between **remediation activity** and **validated risk reduction** is central to the design.

## Example findings

The synthetic dataset includes:

- a well-controlled customer portal baseline;
- a partner console with weak lifecycle and cookie controls;
- a legacy administrative application with URL-based session transport and missing ownership.

All names, systems, configurations, and observations are synthetic.

## Testing

`tests/test_analyzer.py` contains 10 unit tests covering:

- secure-baseline behavior
- Secure-cookie detection
- URL-based session identifiers
- logout invalidation
- timeout controls
- fail-closed environment validation
- timeout relationship validation
- deterministic finding IDs
- bounded metrics
- missing ownership

CI also performs Python compilation, unit-test discovery, and an offline CLI smoke test.

## Security engineering decisions

### Fail closed
Malformed or unsupported environment values and invalid timeout relationships raise explicit validation errors rather than being silently accepted.

### Deterministic findings
Finding IDs are derived from stable control/application material, which supports reconciliation across repeated assessments.

### Evidence preservation
Findings retain the exact policy observation that caused the control failure and pair it with remediation plus re-test guidance.

### No offensive automation
This repository does not implement session hijacking, cookie theft, credential capture, phishing, brute force, exploit delivery, or live-target testing.

## Skills demonstrated

- Application Security
- Web Security
- API Security
- Session Management
- Secure Design Review
- Python
- Security Automation
- Risk Prioritization
- Security Reporting
- Remediation Governance
- Detection/Control Engineering
- MITRE ATT&CK Mapping
- Unit Testing
- GitHub Actions

## Limitations

- synthetic data only
- no live browser or proxy interaction
- no production system access
- no framework-specific session adapters yet
- no OAuth/OIDC session correlation in the current version
- baseline timeout thresholds should be tuned to business and regulatory requirements
- the posture score is a prioritization aid, not a formal enterprise risk rating

## Roadmap

Planned extensions:

- framework-specific policy adapters for common web stacks
- structured JSON report export
- application criticality weighting
- documented exception and compensating-control workflow
- OAuth/OIDC session-lifecycle correlation
- regression fixtures for secure design baselines
- optional OWASP ASVS control mapping
- richer trend and remediation-aging metrics

## Safety and ethics

This project is intentionally defensive and uses synthetic data. It contains no real credentials, customer data, employer/client telemetry, exploit payloads, session-stealing automation, or production targeting.
