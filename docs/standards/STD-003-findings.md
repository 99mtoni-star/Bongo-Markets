# STD-003 — Findings: Severity and Root Cause

Every defect, test failure or review comment that requires a change is logged in the module's completion note (DEV-003).

## Severity

| Level | Meaning | Rule |
|-------|---------|------|
| Critical | Money loss, auth bypass, cross-shop data exposure, data destruction | Blocks Developer Complete; fix plus a regression test |
| High | Security control weakened, wrong totals or stock, broken core flow | Blocks Developer Complete |
| Medium | Incorrect behavior with a workaround; missing validation without exposure | Fix before closure or with an approved waiver |
| Low | Cosmetic issues, wording, minor UX | May be deferred, with a ticket |

## Root-cause class

`REQ` (requirement unclear or wrong) · `DES` (design gap) · `IMP` (coding error) · `TST` (test gap) · `CFG` (configuration/environment) · `DEP` (third-party dependency) · `PRC` (process not followed)

## Log format

`F-Mxx-nnn | Severity | Root cause | Description | Fix commit | Regression Test ID | Status`
