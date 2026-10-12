# Application Logging (NFR-M09, NFR-006, ID-012)

- **Format:** structured JSON (one object per line). Fields: `ts` (UTC), `level`, `logger`, `msg`, `request_id`, plus redacted extras.
- **Redaction:** keys matching password/secret/token/authorization/cookie/api_key are replaced with `[REDACTED]`. OTPs, TOTP secrets, recovery codes and session tokens are never logged (test M04-T012).
- **Retention:** **90 days** for application logs (`deploy/logrotate/bongo-markets`: daily rotation, `rotate 90`, `maxage 90`). Audit records are not application logs: they live in `bm.audit_logs` with 7–10 year retention (M05).
- **Shipping:** in production, stdout is collected by the process manager and written to `/var/log/bongo-markets/app.log`. Centralized monitoring and alerting are configured in M20.
