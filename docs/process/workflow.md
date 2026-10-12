# Module Delivery Workflow

```
NOT_STARTED ──STD-001──▶ DESIGN_READY ──code + gate──▶ DEVELOPER_COMPLETE ──independent review──▶ CLOSED
                                                                                      │
                                                         M20 final assurance ◀────────┘ (production authorization)
```

- **Order:** M01 → M20, in the sequence in KAR-PROJ-SA-RTM-006 v1.3.
- **Security and testing live inside every module.** M20 does not replace module-level tests.
- **Parallel work (DEV-008):** while Module N is being implemented, Module N+1 may undergo analysis and security pre-review only. Module N+1 coding starts only after Module N is Developer Complete *and* every dependency it relies on is stable (no open Critical/High findings).
- **Demonstration:** after each module, the running system is demonstrated to the product owner (screenshots plus test results) before the next module begins.
- **Branching:** one branch per module (`module/Mxx-<slug>`), merged to `develop` via pull request after the gate passes.
