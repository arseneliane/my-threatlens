# Deployment

## Local

Local deployment remains the default: Windows, Python 3.11+, `127.0.0.1:8001`. Copy `.env.example` to `.env` and never commit local secrets.

## Password-protected Render demo

The repository includes `render.yaml` for a free supervisor demonstration. Create a private Git repository, connect it to Render as a Blueprint, and provide `DEMO_USERNAME` and a unique `DEMO_PASSWORD` of at least 12 characters when prompted. Never add the password to this repository.

The free service uses temporary SQLite storage. Each browser is isolated by an anonymous workspace cookie and keeps a local backup of its setup configuration; after Render restarts or redeploys, the browser restores those setups automatically. Clearing cookies/site data or using a private window starts a new workspace. Findings and review activity are still temporary, so this remains suitable for evaluation only, not production or durable collaboration. SMTP credentials and the local `.env` file are intentionally not deployed.

The hosted demo limits each source to 60 recent items, uses a six-second source timeout, and returns 25 findings per page. These demo-specific limits keep scans responsive on Render's smallest free instance without changing local defaults.

Render's free service blocks outbound SMTP ports. To enable email without upgrading, connect a Zoho self-client with the minimum `ZohoMail.accounts.READ` and `ZohoMail.messages.CREATE` scopes, then set the four `ZOHO_*` secrets in Render. My ThreatLens exchanges the refresh token over HTTPS and sends through the Zoho Mail API; SMTP remains an optional fallback for local or paid hosting.

For DeepSeek chat on every laptop, create an Ollama API key and set `OLLAMA_API_KEY` as a secret in Render. The Blueprint sets `OLLAMA_URL=https://ollama.com` and `OLLAMA_MODEL=deepseek-v4-flash:cloud`. Both the site-wide and finding-specific assistants call Ollama from the server, so the browser never receives the key and does not need Ollama installed.
