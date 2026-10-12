# Rate Limits (SEC-009)

Counters live in `bm.rate_limit_buckets` and are shared by every app process. They are committed even when the request fails. IP addresses and identifiers are stored only as HMAC pseudonyms.

| Action | Per | Limit |
|---|---|---|
| Login | IP | 30 / 5 min |
| Login / password change | identifier | 10 / 15 min |
| Registration | IP | 10 / hour |
| Registration | phone number | 3 / hour |
| Code verification (phone, email, reset) | IP | 30 / 15 min |
| Resend code / email verification request | verification id / user | 3 / 15 min |
| Forgot password | IP | 10 / hour |
| Forgot password | identifier | 3 / hour |

Exceeding a limit returns `429` with `Retry-After`. Each block is written to the audit log as `security.rate_limited`.
