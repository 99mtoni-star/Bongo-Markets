# Personal-Data Breach Procedure (SEC-COM-005)

| Step | Owner | Within |
|---|---|---|
| **Detect:** alerts from monitoring (M20), audit-log anomalies, reports from users or staff | On-call engineer | — |
| **Triage and escalate:** classify severity, open an incident record, notify the Incident Lead and Data Protection Officer (DPO) | On-call | 1 hour |
| **Contain:** revoke sessions, suspend affected accounts/shops, suspend payments, rotate secrets (`docs/operations/incident-response.md`) | Incident Lead | 4 hours |
| **Preserve evidence:** export the relevant audit logs (step-up, audited), snapshot logs, take a database backup; keep the chain of custody | Incident Lead | 24 hours |
| **Investigate:** scope, affected data subjects, root cause | Engineering + DPO | — |
| **Notify:** regulator and affected people as required by the Personal Data Protection Act, 2022 (Tanzania) and its regulations; Legal confirms deadlines and content | DPO + Legal | as required by law |
| **Recover and review:** fix the root cause, write a post-incident report, file findings under STD-003 | Engineering | 2 weeks |

Legal must confirm the statutory notification deadlines and authority contacts before go-live (M20 gate).
