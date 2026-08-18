# My ThreatLens — Local Edition

My ThreatLens is a local cybersecurity-intelligence workspace. Users create accounts, save independent monitoring setups, scan approved public sources, review relevant threats, export results, and optionally configure email alerts and an AI assistant.

## Start on Windows

1. Download or clone the `codex/local-edition` branch.
2. Double-click `START_MY_THREATLENS.bat`.
3. Open `http://127.0.0.1:8001` if the browser does not open automatically.
4. Select **Create account**, then choose a unique username and strong password.
5. Email and AI are optional. Configure email after login; configure AI manually in `.env`.

On a standard Windows 10/11 installation with Windows Package Manager, the launcher installs Python when missing, creates `.venv`, installs Python packages, copies the blank `.env.example`, and starts FastAPI on port 8001. It does not install an AI provider or request credentials.

## Local persistence

SQLite stores users, password hashes, sessions, setups, search parameters, and setup-specific automatic-email settings in `data/my_threatlens.db`. Each account has an independent workspace. The local installation and the Render-hosted installation do not synchronize data.

Back up the database only while My ThreatLens is stopped. The `.env` file and database are excluded from Git.

## Optional AI providers

Local Ollama requires no API key:

```env
AI_PROVIDER=ollama
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=deepseek-r1:1.5b
OLLAMA_API_KEY=
```

Install Ollama separately and pull the configured model before using AI features. For Ollama Cloud/API:

```env
AI_PROVIDER=ollama
OLLAMA_URL=https://ollama.com
OLLAMA_MODEL=gpt-oss:20b
OLLAMA_API_KEY=
```

Place the administrator's key after `OLLAMA_API_KEY=`. For OpenAI:

```env
AI_PROVIDER=openai
OPENAI_API_KEY=
OPENAI_MODEL=
OPENAI_BASE_URL=https://api.openai.com/v1
```

OpenAI API billing is separate from ChatGPT subscriptions. The rest of the application continues to work when AI is not configured.

Restart My ThreatLens after changing AI settings. Existing Ollama switcher scripts remain available for convenience, but the startup launcher never chooses a provider automatically.

## Email configuration

All provider fields ship empty. After login, choose **Email Settings** and enter the sender address and app password. Common SMTP providers are detected automatically; other providers require their SMTP server details. The password is written only to local `.env` and is never returned to the browser. Automatic scans and emails run without an open browser, but only while the computer is powered on, connected to the internet, and `START_MY_THREATLENS.bat` is running.

The scheduler performs the configured daily 9:00 a.m. Beirut scan and the 30-minute Critical-threat checks. Each setup owns its recipients and automation settings.

## Manual start

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

AI output and public-source matching are decision support, not proof that an asset is vulnerable or compromised. Validate findings against primary advisories and the actual asset inventory.
