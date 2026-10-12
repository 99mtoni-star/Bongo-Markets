# STD-001 — Design Ready

A module may not start coding until its design note (`docs/modules/Mxx/design.md`) satisfies every item below (DEV-001).

| # | Criterion |
|---|-----------|
| 1 | Scope lists every requirement ID allocated to the module in KAR-PROJ-SA-RTM-006 v1.3, and nothing else. |
| 2 | Each requirement has at least one planned Test ID (`Mxx-Tnnn`) added to `tests/catalogue.yaml`. |
| 3 | Data model changes (tables, columns, constraints, indexes) are described; financial amounts use DECIMAL. |
| 4 | API endpoints are listed with method, path, auth requirement and permission. |
| 5 | Threats are listed (authN, authZ/IDOR, injection, XSS/CSRF, data exposure, abuse/rate limits) with the control for each. |
| 6 | Dependencies on earlier modules are named; anything borrowed from a later module is flagged as a stub. |
| 7 | Migrations touching auth, authorization, financial, audit or personal data are flagged for explicit review (SEC-SDLC-004). |
| 8 | Open questions are written down, each with an owner. |

Sign-off line at the bottom of the design note: `Design Ready: YES — <name>, <UTC date>`.
