# Local Deployment

The `codex/local-edition` branch is designed for a local Windows installation at `http://127.0.0.1:8001`. It is independent from the Render deployment on the `main` branch.

Download the branch, run `START_MY_THREATLENS.bat`, create a local account, and configure optional providers in `.env`. Never commit `.env`, provider keys, passwords, or `data/my_threatlens.db`.

The web server must remain running for scheduled scans and automatic emails. The browser may be closed. Sleep, shutdown, loss of internet access, or stopping the server pauses automation until the application runs again.

For access from other computers, do not simply expose port 8001 to the internet. Place the service behind an approved HTTPS reverse proxy, enable secure cookies, restrict network access, and obtain an infrastructure/security review.
