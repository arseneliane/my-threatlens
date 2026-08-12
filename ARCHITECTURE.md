# Architecture

FastAPI owns HTTP routes and background jobs; Jinja2 renders a no-build shell; vanilla JavaScript manages selectors, polling, filters, review state, and imports. SQLAlchemy 2 maps setups, scans, findings, source statuses, chats, and audit events to SQLite (or a PostgreSQL URL). Services isolate matching, enrichment, collection, import, export, and chat behavior. SQLite enables WAL, foreign keys, and a busy timeout. Stable setup-scoped fingerprints prevent duplicates.

