# Architecture

FastAPI owns HTTP routes, account authentication, scanning, email, exports, AI calls, and background jobs. Jinja2 renders the interface, and vanilla JavaScript manages selectors, polling, filters, and review interactions.

SQLAlchemy maps users, hashed sessions, account-owned setups, automation settings, and operational records to local SQLite. Passwords use salted PBKDF2-SHA256 hashes, opaque session tokens are stored only as SHA-256 hashes, and each API operation scopes setup access to the authenticated user ID. SQLite enables WAL, foreign keys, and a busy timeout.

Provider integrations are configured at runtime through `.env`. Ollama works locally without a key or through its API with a key. Email uses either Zoho Mail OAuth over HTTPS or standard SMTP. APScheduler performs daily and interval scans while the local server remains running.
