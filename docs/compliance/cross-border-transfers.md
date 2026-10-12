# Cross-Border Transfer of Personal Data (SEC-COM-007)

No personal data may leave Tanzania without an **approved Legal/Compliance basis** and the required safeguards.

## Register of processors (to be completed before go-live)

| Processor | Purpose | Data | Location | Legal basis | Safeguards | Approved by |
|---|---|---|---|---|---|---|
| Database hosting | Primary storage | All | *TBD (prefer in-country)* | — | Encryption at rest, access control | — |
| SMS gateway | OTP, notices | Phone number, message text | *TBD* | — | DPA contract | — |
| Payment provider | Payments (M13) | Name, phone, amount | *TBD* | — | Provider contract | — |
| Off-site backups | DR (M02/M20) | Encrypted dumps | *TBD* | — | AES-256 before transfer | — |

## Rules

1. Adding a processor, or moving a processor outside Tanzania, needs a recorded approval in this register. The M20 release gate checks that every row is approved.
2. Only the minimum data needed is sent (for example, an SMS provider receives a number and a message, not a profile).
3. Backups leave the server only after encryption (`scripts/backup.py`).
