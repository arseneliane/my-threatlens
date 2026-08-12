# Test Report

Verified on 2026-08-12 with Python 3.12:

```text
37 passed, 3 warnings in 0.81s
```

The warnings are upstream deprecation notices for FastAPI's startup-event API and the TestClient/httpx compatibility layer; they do not represent test failures.

HTTP smoke test:

```text
GET /       200 (My ThreatLens title present)
GET /about  200
GET /api/setups  200 (Default Setup active)
```

Live external collectors were intentionally not exercised during the automated suite; deterministic fixtures cover alias matching, source normalization, scan completion, filtered-export parity, hosted-demo authentication, browser-workspace isolation, setup-cache restoration, and Zoho HTTPS email delivery.
