# Security

The default build makes no arbitrary outbound requests. Uploads accept only `.xlsx` and `.docx`, enforce a 5 MB limit, and are parsed in memory without macro execution. Excel export escapes formula-leading values. HTML is escaped by Jinja2 or client-side encoding.

Internet-hosted deployments require the shared demonstration login. Its password must be stored only in the host's `SHARED_PASSWORD` secret setting; the database stores a salted PBKDF2-SHA256 hash, and session tokens are stored only as SHA-256 hashes. A simple shared password is suitable only for a limited demonstration, not for production or sensitive information. Set `SECURE_COOKIES=true` behind HTTPS, and do not deploy `.env`, passwords, SMTP credentials, AI keys, or the local SQLite database.

Browser workspaces are separated by a random, HTTP-only, same-site cookie. Setup configuration is also backed up in that browser's `localStorage` so it can be restored after temporary Render storage is reset. Findings, review notes, chat messages, credentials, and authentication secrets are never written to `localStorage`. This is convenient isolation for a demonstration, not identity-based authorization for a production multi-user system.

Hosted Zoho delivery uses OAuth with the narrow `ZohoMail.accounts.READ` and `ZohoMail.messages.CREATE` scopes. Store the client secret and refresh token only as Render secrets or local environment variables; never commit them or expose them to the browser. Revoke the Zoho self-client authorization when the hosted demo is retired.

Before enabling custom URLs, require HTTP(S), reject credentials, resolve and reject loopback/private/link-local targets before every request and redirect, cap redirects/size/time/content type, use no cookies, execute no JavaScript, sanitize extracted HTML, and log blocked attempts with correlation IDs.
