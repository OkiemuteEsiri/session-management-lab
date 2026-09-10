# Architecture and Methodology

## Purpose

This lab demonstrates a defensive, repeatable review of web and API session-management controls using synthetic application policy data. It is designed for recruiter-facing evidence of secure design review, application-security engineering, evidence handling, remediation planning, and re-test governance.

## Architecture

The project separates concerns into four layers:

1. **Domain models** — immutable policy and finding objects with fail-closed validation.
2. **Assessment engine** — deterministic control checks that convert policy observations into explainable findings.
3. **Reporting layer** — portfolio metrics and Markdown output for technical and management audiences.
4. **Validation layer** — unit tests and CI checks that exercise control logic and schema constraints.

Synthetic policy inventory -> validated `SessionPolicy` objects -> deterministic control checks -> normalized findings -> metrics and reports.

## Control methodology

The assessment evaluates whether the application demonstrates appropriate session protections, including:

- Secure and HttpOnly cookie attributes;
- SameSite policy and CSRF safeguards;
- idle and absolute session lifetime;
- session identifier rotation after authentication;
- rotation following authorization or privilege changes;
- server-side invalidation on logout;
- avoidance of session identifiers in URLs;
- accountable ownership for session controls.

The implementation intentionally evaluates configuration and design signals. It does not attempt session hijacking, credential theft, exploit delivery, brute force, or production targeting.

## Risk model

Each control observation is assigned a deterministic contextual score from 0 to 100. Severity is kept explicit rather than inferred from ATT&CK mappings. Scores support prioritization, but application-specific business context remains necessary for final risk decisions.

The portfolio posture score is a bounded summary indicator intended for comparison across synthetic applications. It is not a substitute for a formal risk assessment.

## MITRE ATT&CK context

Where relevant, findings reference:

- **T1078 — Valid Accounts** for risks that can increase the useful lifetime of an authenticated session or weaken session revalidation.
- **T1539 — Steal Web Session Cookie** for cookie and session-identifier protections.

ATT&CK mappings provide threat context only. A mapped control weakness is not evidence that an adversary exploited the application.

## Remediation workflow

1. Confirm the observation with the application owner.
2. Establish whether compensating controls or business constraints exist.
3. Prioritize the finding using severity, application sensitivity, exposure, and user population.
4. Implement the control change in a non-production environment.
5. Run regression and negative security tests.
6. Deploy through the normal change-control process.
7. Perform an explicit security re-test.
8. Close only when validation evidence demonstrates the control is effective.

## Validation standard

A remediation is considered validated only when the expected server- or client-side behavior is observed after the change. Configuration intent alone is insufficient. Examples include confirming that a prior session identifier is rejected after logout or rotation, or verifying that authenticated state-changing requests fail when the required anti-CSRF signal is absent.

## Limitations

- Input is synthetic and intentionally simplified.
- No live browser, proxy, API, or authentication-provider interaction occurs.
- Cookie behavior can depend on framework, reverse proxy, browser, and domain topology.
- SameSite requirements vary for federation and legitimate cross-site workflows.
- Timeout baselines should be adjusted for application sensitivity and regulatory requirements.
