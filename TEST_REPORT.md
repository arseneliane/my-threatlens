# Test Report

Verified on 2026-08-16 with Python 3.12:

```text
49 passed, 5 warnings in 11.74s
```

The warnings are upstream deprecation notices for FastAPI's startup-event API and the TestClient/httpx compatibility layer; they do not represent test failures.

HTTP smoke test:

```text
GET /login       200 (My ThreatLens slogan and account form present)
GET /             303 to /login when signed out; 200 when signed in
GET /about        200 when signed in
GET /api/setups   401 when signed out; 200 when signed in
```

Live external collectors were intentionally not exercised during the automated suite; deterministic fixtures cover alias matching, source normalization, scan completion, filtered-export parity, strong credential validation, password hashing, registration/login/logout, case-insensitive username uniqueness, account isolation, account-scoped setup-cache restoration, Zoho HTTPS email delivery, and isolated site-wide/per-finding AI conversations.
