# Test Report

Verified on 2026-08-12 with Python 3.12:

```text
35 passed, 3 warnings in 1.08s
```

The warnings are upstream deprecation notices for FastAPI's startup-event API and the TestClient/httpx compatibility layer; they do not represent test failures.

HTTP smoke test:

```text
GET /       200 (My ThreatLens title present)
GET /about  200
GET /api/setups  200 (Default Setup active)
```

Live external collectors were intentionally not exercised during the automated suite; deterministic fixtures cover alias matching, source normalization, scan completion, filtered-export parity, and hosted-demo authentication.
