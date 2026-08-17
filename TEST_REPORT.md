# Test Report

Verified on 2026-08-17 with Python 3.12:

```text
55 passed, 5 warnings in 6.47s
```

The warnings are upstream deprecation notices for FastAPI startup events and the TestClient compatibility layer; they are not test failures.

The suite covers account registration, password validation and hashing, login/logout, account-scoped setup persistence, scan completion, filtering, exports, imports, scheduler registration, setup-specific automatic email, Zoho delivery, and Ollama assistant fallbacks.

Local HTTP smoke verification:

```text
GET  /login          200
POST /register       303, followed by authenticated dashboard 200
GET  /api/workspace  200 with the new account and Default Setup
Listener             http://127.0.0.1:8001
```
