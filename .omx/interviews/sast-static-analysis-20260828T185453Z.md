# Deep Interview Transcript Summary: SAST Static Analysis

- Profile: standard
- Context: greenfield; design and requirements artifacts exist, application code does not
- Rounds: 11
- Final ambiguity: approximately 0.07
- Threshold: 0.20
- Context snapshot: `.omx/context/sast-static-analysis-20260828T185453Z.md`

## Decisions

1. First deliverable is a minimum viable, runnable toy project: login, project registration/upload, analysis execution, and finding review.
2. Source input is ZIP upload only. Git integration and internal filesystem paths are out of MVP scope.
3. ZIP traversal, symbolic-link abuse, and access outside an isolated allowed workspace must be rejected.
4. Python receives precise implementations of eight rules: KISA-INPUT-01 through KISA-INPUT-05, KISA-SEC-06, KISA-SEC-12, and KISA-TIME-02.
5. Java and JavaScript receive basic detection for KISA-INPUT-01, KISA-INPUT-02, KISA-INPUT-03, and KISA-INPUT-05. Their parser/detector extension boundary is part of MVP; the other four rules are deferred.
6. Rules are developer-extensible modules registered in the database. Administrators can activate/deactivate rules but do not author rules in the UI in MVP.
7. Authentication includes login and signup. Password reset and external authentication are excluded.
8. Stack: Python FastAPI, SQLite, SQLAlchemy, simple HTML/CSS/JavaScript frontend, and Python AST-based analysis.
9. MVP acceptance uses `vulnerable_sample.py` and `secure_sample.py`: the five demonstrated vulnerabilities must be detected and the secure sample must produce no findings.
10. Findings must preserve rule ID, severity, confidence, file path, line, message, and evidence.

## Pressure-pass findings

- The initial “5–10 rules” goal was made concrete as eight Python rules plus four basic rules in Java/JavaScript; this prevents an unbounded KISA-49 implementation.
- The extensibility claim was challenged and resolved as code-level rule modules plus database registration, not arbitrary rule authoring.
- The ZIP boundary was stress-tested with traversal and symbolic-link cases and made an explicit security acceptance criterion.

## Non-goals

- Full KISA 49-rule coverage.
- Full parity of all eight Python rules in Java and JavaScript.
- Git repository integration and internal path sources.
- Password reset and external identity providers.
- Admin-authored rule logic through the UI.
- Production-scale distributed execution, advanced data-flow precision, or a polished production deployment.

## Condensed transcript

- R1: User chose runnable MVP over prototype or full product.
- R2: User chose 5–10 important/easy rules with future rule extensibility.
- R3: User selected INPUT-01~05, SEC-06, SEC-12, TIME-02.
- R4: User accepted ZIP-only source input and secure extraction boundaries.
- R5: User retained signup but excluded password reset and external auth.
- R6: User chose developer-added rule modules with admin activation control.
- R7: User accepted vulnerable/secure sample verification and normalized finding metadata.
- R8: User accepted FastAPI/SQLite/SQLAlchemy/simple frontend/Python AST stack.
- R9–R11: User clarified Python precision plus basic Java/JavaScript support for four injection/input rules.
