# Execution-Ready Specification: Minimal SAST Toy Project

## Metadata

- Profile: standard
- Interview rounds: 11
- Final ambiguity: approximately 0.07
- Threshold: 0.20
- Context type: greenfield
- Context snapshot: `.omx/context/sast-static-analysis-20260828T185453Z.md`
- Transcript: `.omx/interviews/sast-static-analysis-20260828T185453Z.md`

## Intent

Build a small runnable SAST service that accepts a project, analyzes source code before deployment, and presents actionable findings while keeping security boundaries and future rule extension visible.

## Desired outcome

A user can sign up and log in, upload a ZIP project, start an isolated analysis, and view normalized findings. An administrator can manage project access and rule activation. The system demonstrates precise Python analysis, basic Java/JavaScript analysis, and a reusable rule interface.

## In scope

- Signup and login with securely hashed passwords; role separation for administrator and regular user.
- Project registration and ZIP upload.
- Safe archive extraction into a run/project-isolated workspace.
- Analysis run lifecycle: PENDING, RUNNING, COMPLETED, FAILED.
- Python precise detectors for KISA-INPUT-01, INPUT-02, INPUT-03, INPUT-04, INPUT-05, SEC-06, SEC-12, TIME-02.
- Java and JavaScript basic detectors for KISA-INPUT-01, INPUT-02, INPUT-03, INPUT-05.
- Shared rule interface, rule registry, active/inactive state, and normalized findings.
- Finding history/detail/filter views using the design file as UI direction.
- SQLite persistence through SQLAlchemy and schema migrations.
- Tests for authentication, role/project access, archive safety, detector fixtures, run status, and result persistence.

## Out of scope / non-goals

- Full KISA 49-rule coverage or complete language parity.
- Git and internal path source integration.
- Password reset, external authentication, and production SSO.
- UI-authored detection logic; admin UI only toggles registered rules.
- Distributed workers, enterprise scalability, and production deployment hardening beyond MVP safeguards.

## Decision boundaries

- OMX may choose internal module names, API route names, HTML structure, test framework details, and exact parser implementation while preserving the stack and behavior above.
- OMX may choose SQLite migration tooling and a suitable Java/JavaScript parser implementation without adding unnecessary dependencies beyond the selected approach.
- Any expansion to full KISA coverage, new source types, external auth, or UI-authored rules requires a new scope decision.
- A detector may report conservative findings with confidence metadata; it must not silently claim complete semantic/data-flow coverage.

## Constraints

- Never store or return plaintext passwords.
- Enforce authentication, RBAC, and project membership checks server-side; do not trust request IDs alone.
- Avoid resource leaks, archive traversal, symlink escapes, and access outside the run workspace.
- Limit upload size, archive expansion, analysis duration, and analysis resources for the toy service.
- Preserve finding snapshots so later rule changes do not rewrite historical meaning.
- Keep individual rules independently testable and addable.

## Testable acceptance criteria

1. Signup creates a user with a password hash; password material is not returned.
2. Login issues a protected, expiring authentication mechanism; unauthenticated protected routes are rejected.
3. Regular users cannot create projects, run analyses, alter memberships, or toggle rules; authorized project findings are read-only.
4. ZIP files with `../`, absolute paths, symlink escapes, excessive expansion, or disallowed file types are rejected or safely contained.
5. An authorized user can create a run and observe PENDING → RUNNING → COMPLETED or FAILED, with failure information available only to authorized users.
6. `vulnerable_sample.py` produces findings for its five demonstrated vulnerabilities, including rule ID and source line.
7. `secure_sample.py` produces no findings for the implemented sample cases.
8. Each finding stores rule ID/name snapshot, severity, confidence, language, file path, line, message, evidence, and recommendation.
9. Java and JavaScript fixtures exercise the four basic INPUT rules and return normalized findings through the same result model.
10. Adding a new developer rule does not require modifying the shared run/result persistence flow; activation state controls whether it runs.

## Technical context

- Existing design frames cover login, signup, dashboard, project upload, finding detail/history, KISA guide, rule management, language management, and user/project permissions.
- Existing database proposal covers users, projects, project_members, rules, analysis_runs, and findings. Preserve its historical snapshots and relationship integrity; correct the documentation typo `refere nce_info` to `reference_info` in implementation-facing material if documentation is updated.
- Existing fixtures are `secure_sample.py` and `vulnerable_sample.py`.

## Evidence vs inference

- Evidence: requirements explicitly require Java, JavaScript, Python; KISA 49 catalog; normalized findings; statuses; RBAC; workspace/path protections.
- Evidence: design file includes signup, dashboard, upload, findings, rule/language/user management views.
- Inference resolved by user: MVP prioritizes Python precision and basic Java/JavaScript support, not complete language/rule parity.

## Optional documentation follow-up

Opt-in only: add a concise README describing local setup, seeded/admin account behavior, supported rules per language, and explicit limitations. No raw interview transcript should be published.
