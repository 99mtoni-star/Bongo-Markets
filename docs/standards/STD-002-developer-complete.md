# STD-002 — Developer Complete

A module is *Developer Complete* when all of the following hold (DEV-002):

1. `python scripts/gate.py Mxx` passes. The gate runs, in order: lint, test-catalogue check (DEV-004), focused module tests, protected-control regression, full regression (DEV-005).
2. An evidence bundle has been produced with `scripts/evidence.py` (DEV-006) and its bundle digest is recorded in `docs/modules/Mxx/completion.md`.
3. Every allocated requirement is marked in the completion note as **Implemented**, **Partial** (with reason), or **Deferred** (with target module).
4. All findings are classified under STD-003, and none of severity Critical or High is open.
5. The module's status in `app/core/modules.py` is set to `DEVELOPER_COMPLETE`.

**Developer Complete is not closure (DEV-007).** Closure requires an independent reviewer who did not write the code. That reviewer re-runs the gate, checks the evidence digest and signs `Closed: YES — <reviewer>, <UTC date>`. Only then may the status become `CLOSED`. Production authorization is issued only by M20.
