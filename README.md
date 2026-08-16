# My ThreatLens

## 1. Executive Summary

My ThreatLens is a local-first monitoring workspace for cybersecurity analysts. It turns a saved technology, keyword, source, and date-range scope into temporary, exportable findings.

## 2. Business Problem

Public vulnerability and threat information is fragmented across government, vendor, and news sources. Manual monitoring is slow, inconsistent, and difficult to hand off.

## 3. What My ThreatLens Does

The application normalizes approved-source items, recognizes product and attack aliases, extracts CVEs, calculates evidence-based severity and immediate relevance, then stores everything locally for review and export.

## 4. Key Capabilities

- Named setup creation, loading, saving, duplication, search, and deletion
- Username-only registration and account-isolated workspaces (no email required)
- XLSX and DOCX setup preview/import
- Non-blocking scans with progress and failure-safe behavior
- Alias-aware technology-and-keyword matching
- Server-side filters and pagination
- A hosted open model through Ollama for both a site-wide workspace assistant and grounded per-finding conversations
- Filter-consistent Excel export
- Zoho Mail API or SMTP delivery with findings shown directly in the email

## 5. How It Works

Collectors feed a normalization and enrichment pipeline. A finding is retained only when it matches at least one selected technology and one selected keyword. Deterministic relevance is available without an AI server.

## 6. Privacy and Security

Each user registers a case-insensitively unique username and a strong password; no email address is collected. Passwords are stored as salted PBKDF2-SHA256 hashes, and opaque login sessions are stored only as hashes. Setups belong to the signed-in account, so one user's changes do not affect another. The browser keeps a username-scoped local backup of setup configuration for recovery. Findings, scans, reviews, and chat messages are not placed in browser storage and remain temporary. SMTP and AI credentials remain in server environment settings and are never sent to the browser.

### Email setup

For hosted delivery, configure `ZOHO_CLIENT_ID`, `ZOHO_CLIENT_SECRET`, `ZOHO_REFRESH_TOKEN`, and `ZOHO_FROM_EMAIL`; the application uses Zoho Mail's HTTPS API so it also works on hosts that block SMTP. Local or paid deployments can instead set `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM_EMAIL`, and any required SMTP credentials. Restart after changing these values.

## 7. How to Run

On Windows, double-click `START_MY_THREATLENS.bat`. Or use PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Open http://127.0.0.1:8001, register a username and strong password, then create as many independent monitoring setups as needed.

## 8. Typical Analyst Workflow

Choose scope, save the setup, scan, filter findings, open a review, verify vendor evidence, email one or several selected threats, and export the current filtered set.

### Ollama assistants

The dashboard and About page include a site-wide assistant. Each finding also has an independent, finding-specific conversation. For local Ollama, set `OLLAMA_URL=http://127.0.0.1:11434` and install the configured model. For a hosted site that must work from any laptop on Ollama's free plan, set `OLLAMA_URL=https://ollama.com`, `OLLAMA_MODEL=gpt-oss:20b`, and store `OLLAMA_API_KEY` only in the hosting provider's secret environment variables. The API key is never sent to the browser.

## 9. AI Disclosure

AI-assisted content may be incomplete or incorrect. Verify recommendations against the cited vendor advisory, CVE record, and your own environment before taking action. This app is still under testing and can be enhanced more.

## 10. Testing

Run `.\.venv\Scripts\python.exe -m pytest -q`. See `TEST_REPORT.md` for the last verified result.

## 11. Known Limitations

The shipped collector is deterministic and offline. Live public-source adapters, DNS revalidation for custom URLs, and Ollama integration are documented extension points rather than enabled network behavior.

## 12. Roadmap

Add individually tested official API/feed adapters, cached live-source fallback, PostgreSQL deployment validation, and optional grounded Ollama analysis.
