# API Reference

- `GET/POST /api/setups`, `PUT/DELETE /api/setups/{id}`
- `POST /api/setups/{id}/activate`, `POST /api/setups/{id}/duplicate`
- `POST /api/scans` (202), `GET /api/scans/{id}`
- `GET /api/findings` with `severity`, `technology`, `source`, `keyword`, `cve`, `review_state`, `ai_min`, `page`
- `PUT /api/findings/{id}/review`
- `POST/DELETE /api/findings/{id}/chat`
- `GET/POST/DELETE /api/site-chat` for the active setup's site-wide Ollama conversation
- `POST /api/import/preview`, `GET /api/import/sample/{xlsx|docx}`
- `GET /api/export` with the same finding filters
