# Password Hashing Configuration (SEC-PWD-001)

| Parameter | Value |
|---|---|
| Algorithm | Argon2id (argon2-cffi), version 19 |
| Memory | 65 536 KiB (64 MiB) |
| Iterations | 3 |
| Parallelism | 2 |
| Salt | 16 random bytes per hash |
| Output | 32 bytes |

- These parameters exceed the OWASP minimum (19 MiB, t=2, p=1). Measure login latency on production hardware (target: under 500 ms) and tune in M20.
- Hashes made with older parameters are re-hashed automatically at the next successful login.
- bcrypt is not used, so the 72-byte truncation problem does not apply (SEC-PWD-004).
- Password length: minimum 8, maximum 256. Longer input is rejected with a message, never truncated.
- Common-password screening: an offline list (global and Tanzania-specific). A breach-corpus lookup is planned for M20.
