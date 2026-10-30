# SecureLens demo checks and screenshot guide

These fixtures are synthetic examples shaped around secure software lifecycle evidence. They are intended to demonstrate the current SecureLens rules and views; they are not a complete security assessment or a substitute for organization-approved verification criteria.

## Run a phase scenario

1. Start the FastAPI API and React frontend using the root [README](../README.md).
2. In **Command center**, set the project name to `Synthetic Merchant Admin Portal`.
3. Choose the matching phase and paste the text from its `securelens-demo-*.txt` file in this folder. Each fixture has a matching phase line.
4. Select **Run assessment** and wait for the result.
5. Capture the assessment output. Then select **Assessments**, **Evidence vault**, **Control coverage**, and **Threat register** to capture the related views for the same result.
6. Repeat for the other phases. Each new run replaces the latest result in the current browser session.

The six fixtures are:

- `securelens-demo-requirements.txt` — acceptance criteria, assets, trust boundaries, and intentionally insecure prototype settings.
- `securelens-demo-design.txt` — actors, trust boundaries, an abuse case, and intentionally insecure transport settings.
- `securelens-demo-development.txt` — fake secret-like value, debug setting, and permissive CORS setting.
- `securelens-demo-testing.txt` — sanitized test evidence for TLS validation, CORS, and a fake credential-like value.
- `securelens-demo-deployment.txt` — release configuration and gate evidence with intentionally insecure settings.
- `securelens-demo-operations.txt` — synthetic incident and runbook evidence with fake values.

## Expected SecureLens signals

| Phase | Expected risk | Expected deterministic findings | Expected view signals |
|---|---|---|---|
| Requirements | Medium | Debug mode; permissive CORS | Control coverage includes the built-in NIST SSDF debug mapping. Threat register should show exposed admin surface because the evidence mentions both public and admin. |
| Design | High | Insecure HTTP; TLS verification disabled | Threat register should show transport interception and exposed admin surface. |
| Development | High | Possible hardcoded secret; debug mode; permissive CORS | Control coverage should show the configured secret, debug, and CORS mappings. Threat register should show credential exposure and exposed admin surface. |
| Testing | Critical | TLS verification disabled; permissive CORS; possible hardcoded secret | Threat register should show credential exposure and transport interception. |
| Deployment | Medium | Insecure HTTP; debug mode; permissive CORS | Threat register should show transport interception and exposed admin surface. |
| Operations | High | Possible hardcoded secret; insecure HTTP | Threat register should show credential exposure, transport interception, and exposed admin surface. |

The scanner only flags the patterns implemented in `app/scanner.py`. It does not understand the full meaning of a requirements document, test report, deployment manifest, or incident report. A phrase in a document is not proof that a control is present or absent.

## What each sidebar view currently represents

- **Assessments** displays the latest assessment created in the current browser session. The current API does not provide an assessment-history listing.
- **Evidence vault** displays the text or file currently staged in the session. It is not a persistent evidence library; assessment and knowledge uploads are stored by the API in SQLite by default.
- **Control coverage** displays only the rule-to-control mappings configured in `app/assessment.py`. It is not a full ASVS or SSDF coverage calculation.
- **Threat register** displays draft signals for credential exposure, transport interception, and an internet-facing admin surface. These are heuristic signals and require human validation.

Treat the displayed “evidence mapped” percentage as an application demo metric only; it is not a validated compliance score. The app's ASVS mapping identifiers are not pinned to a standard version. OWASP recommends versioned ASVS requirement identifiers because IDs can change between versions. Do not present these screenshots as an ASVS certification or compliance result.

## Screenshot hygiene

- Use only the included `DEMO-ONLY` placeholders; never paste real credentials, client data, or production documents.
- Keep the project name synthetic and ensure no personal information is visible.
- Capture the phase, risk level, findings, and recommendation text legibly.
- For evidence uploads, use the corresponding `.txt` fixture. The evidence view shows the selected filename and current-session input, not a permanent vault.
- Ollama is optional. If it is unavailable, the AI review should say so and the deterministic assessment should still complete.

## Industry references

- [OWASP ASVS project and current stable version](https://owasp.org/projects/asvs/)
- [NIST SP 800-218: Secure Software Development Framework (SSDF) v1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [OWASP Developer Guide: practical threat modeling](https://devguide.owasp.org/en/04-design/01-threat-modeling/07-practical-threat-modeling/)
