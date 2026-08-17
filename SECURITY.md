# Security

Local users create unique accounts. Passwords are stored as salted PBKDF2-SHA256 hashes, session tokens are stored only as SHA-256 hashes, and session cookies are HTTP-only and same-site. Setup access is authorized against the authenticated user ID.

Uploads accept only `.xlsx` and `.docx`, enforce a 5 MB limit, and are parsed without macro execution. Excel export escapes formula-leading values. HTML is escaped by Jinja2 or client-side encoding.

Keep `.env`, `data/my_threatlens.db`, email credentials, and Ollama API keys private; these files are excluded from Git. Zoho should use only the required account-read and message-create scopes. Revoke credentials when they are no longer needed.

The default listener is `127.0.0.1:8001`, which limits access to the same computer. Before permitting remote or internet access, add HTTPS, secure cookies, network restrictions, CSRF protection, rate limiting, strict outbound URL validation, monitoring, and an infrastructure/security review.
