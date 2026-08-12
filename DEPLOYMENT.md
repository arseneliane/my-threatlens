# Deployment

## Local

Local deployment remains the default: Windows, Python 3.11+, `127.0.0.1:8001`. Copy `.env.example` to `.env` and never commit local secrets.

## Password-protected Render demo

The repository includes `render.yaml` for a free supervisor demonstration. Create a private Git repository, connect it to Render as a Blueprint, and provide `DEMO_USERNAME` and a unique `DEMO_PASSWORD` of at least 12 characters when prompted. Never add the password to this repository.

The free service uses temporary SQLite storage. Saved setup changes disappear whenever Render restarts, redeploys, or spins the service down. It is suitable for evaluation only, not production or durable collaboration. SMTP credentials and the local `.env` file are intentionally not deployed.

The hosted demo limits each source to 60 recent items, uses a six-second source timeout, and returns 25 findings per page. These demo-specific limits keep scans responsive on Render's smallest free instance without changing local defaults.
