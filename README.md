# My ThreatLens — Local Edition

My ThreatLens is a local cybersecurity-intelligence workspace. Users create accounts, save independent monitoring setups, scan approved public sources, review relevant threats, export results, and optionally send email alerts or use Ollama assistants.

## Start on Windows

1. Download or clone the `codex/local-edition` branch.
2. Double-click `START_MY_THREATLENS.bat`.
3. Enter the sender email address and its app password when prompted. Common providers are configured automatically; uncommon providers also require their SMTP server details.
4. Open `http://127.0.0.1:8001` if the browser does not open automatically.
5. Select **Create account**, then choose a unique username and strong password.

On a standard Windows 10/11 installation with Windows Package Manager, the launcher installs Python and Ollama when missing, selects `deepseek-r1:7b` for systems with at least 16 GB RAM or `deepseek-r1:1.5b` for smaller systems, downloads the model, creates `.venv`, installs Python packages, writes the local `.env`, and starts FastAPI on port 8001. The first launch requires internet access and several gigabytes of free disk space. Company policy may require IT approval for software installation.

## Local persistence

SQLite stores users, password hashes, sessions, setups, search parameters, and setup-specific automatic-email settings in `data/my_threatlens.db`. Each account has an independent workspace. The local installation and the Render-hosted installation do not synchronize data.

Back up the database only while My ThreatLens is stopped. The `.env` file and database are excluded from Git.

## Ollama: two supported modes

Local Ollama requires no API key:

```env
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=gpt-oss:20b
OLLAMA_API_KEY=
```

Install Ollama separately and pull the configured model before using AI features. For Ollama Cloud/API:

```env
OLLAMA_URL=https://ollama.com
OLLAMA_MODEL=gpt-oss:20b
OLLAMA_API_KEY=
```

Place the administrator's key after `OLLAMA_API_KEY=`. The rest of the application continues to work if Ollama is not configured.

The first launcher prepares local DeepSeek automatically. To switch later without editing `.env`, run `USE_OLLAMA_API.bat` and enter the API key. Run `USE_LOCAL_OLLAMA.bat` to return to the automatically selected local DeepSeek model.

## Email configuration

All provider fields ship empty. The administrator may configure any compatible SMTP provider in `.env`; the optional Zoho Mail API integration also remains available. Automatic scans and emails run without an open browser, but only while the computer is powered on, connected to the internet, and `START_MY_THREATLENS.bat` is running.

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
