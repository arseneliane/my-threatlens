# My ThreatLens

## 1. Executive Summary

My ThreatLens is a local-first monitoring workspace for cybersecurity analysts. It turns a saved technology, keyword, source, and date-range scope into temporary, exportable findings.

## 2. Business Problem

Public vulnerability and threat information is fragmented across government, vendor, and news sources. Manual monitoring is slow, inconsistent, and difficult to hand off.

## 3. What My ThreatLens Does

The application normalizes approved-source items, recognizes product and attack aliases, extracts CVEs, calculates evidence-based severity and immediate relevance, then stores everything locally for review and export.

## 4. Key Capabilities

- Named setup creation, loading, saving, duplication, search, and deletion
- XLSX and DOCX setup preview/import
- Non-blocking scans with progress and failure-safe behavior
- Alias-aware technology-and-keyword matching
- Server-side filters and pagination
- Grounded per-finding assistant, notes, and checklist
- Filter-consistent Excel export
- SMTP email delivery with the filtered Excel report attached

## 5. How It Works

Collectors feed a normalization and enrichment pipeline. A finding is retained only when it matches at least one selected technology and one selected keyword. Deterministic relevance is available without an AI server.

## 6. Privacy and Security

Only saved setup configuration is persisted in the local SQLite database. Findings, scans, reviews, and chat messages remain in memory, are replaced by the next scan, and disappear when the application closes. SMTP credentials are read only from the local `.env` file and are never sent to the browser. There are no accounts or analytics.

### Email setup

Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM_EMAIL`, and, when required, `SMTP_USERNAME` and `SMTP_PASSWORD` in `.env`. Port 587 normally uses `SMTP_USE_TLS=true`; port 465 normally uses `SMTP_USE_SSL=true` and `SMTP_USE_TLS=false`. Restart the application after changing these values.

## 7. How to Run

On Windows, double-click `START_MY_THREATLENS.bat`. Or use PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Open http://127.0.0.1:8001.

## 8. Typical Analyst Workflow

Choose scope, save the setup, scan, filter findings, open a review, verify vendor evidence, record notes and checklist progress, and export the current filtered set.

## 9. AI Disclosure

AI-assisted content may be incomplete or incorrect. Verify recommendations against the cited vendor advisory, CVE record, and your own environment before taking action. This app is still under testing and can be enhanced more.

## 10. Testing

Run `.\.venv\Scripts\python.exe -m pytest -q`. See `TEST_REPORT.md` for the last verified result.

## 11. Known Limitations

The shipped collector is deterministic and offline. Live public-source adapters, DNS revalidation for custom URLs, and Ollama integration are documented extension points rather than enabled network behavior.

## 12. Roadmap

Add individually tested official API/feed adapters, cached live-source fallback, PostgreSQL deployment validation, and optional grounded Ollama analysis.
