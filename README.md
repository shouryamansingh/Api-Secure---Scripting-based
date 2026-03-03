# API Secure

**Python (Flask)** backend + **React (Vite)** frontend for API security scanning: headers, CORS, SSL/TLS, server disclosure, error handling, URL tampering. Minimalist black & white theme with light/dark toggle. Configuration via environment variables; see [SECURITY.md](./SECURITY.md) for secure coding practices.

**→ [NEXT_STEPS.md](./NEXT_STEPS.md)** — what to do now (run locally, optional config, AI/email checklist, production).  
**→ [PLAN_FROM_N8N.md](./PLAN_FROM_N8N.md)** — plan to match the n8n workflow (AI, email, optional enhancements).  
**→ [security-controls/](./security-controls/)** — modular security control definitions (prompts, config, schemas) for HTTP Header Analysis; usable in n8n or in-app AI.

## Quick start

**1. Backend**
```bash
cd "Main Project"
py -m pip install -r requirements.txt
cp .env.example .env   # optional: edit .env for CORS, limits
py app.py
```
→ **http://localhost:3001**

**2. Frontend** (separate terminal)
```bash
cd "Main Project/frontend"
npm install
npm run dev
```
→ **http://localhost:5173** (proxies `/api` to backend)

**3.** Open **http://localhost:5173**, choose testing mode, add URL(s), select methods, click **Start Testing**.

## Project structure

```
Main Project/
├── app.py                 # Flask app: /api/scan, /api/parse-urls, /api/health
├── config.py              # Config from env (CORS, limits, timeouts)
├── scanner.py             # Scan logic: headers, CORS, SSL, server, error, tampering
├── requirements.txt      # Python deps (pinned)
├── .env.example           # Example env vars (copy to .env)
├── .gitignore             # Ignore .env, __pycache__, node_modules, etc.
├── SECURITY.md            # Security practices and reporting
├── README.md
├── NEXT_STEPS.md          # What to do now (run, config, AI/email, production)
├── PLAN_FROM_N8N.md       # Plan to match n8n (AI, email, enhancements)
├── security-controls/     # Modular prompts and config (http-header-analysis, etc.)
├── public/                # Static fallback for Flask /
│   └── index.html
└── frontend/              # React (Vite)
    ├── index.html
    ├── src/
    │   ├── App.jsx
    │   ├── main.jsx
    │   └── index.css
    ├── package.json
    └── vite.config.js     # proxy /api → localhost:3001
```

## Configuration (env)

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | development | `development` or `production` |
| `PORT` | 3001 | Backend port |
| `CORS_ORIGINS` | * | Comma-separated origins or `*` (restrict in production) |
| `MAX_URLS_PER_SCAN` | 50 | Max URLs per scan request |
| `MAX_UPLOAD_SIZE_MB` | 5 | Max file size for CSV/Excel upload (MB) |
| `SCANNER_TIMEOUT` | 15 | Outbound request timeout (seconds) |

Copy `.env.example` to `.env` and set as needed. Do not commit `.env`.

## Features

- **Input:** Single URL (manual) or list (paste URLs or upload CSV/Excel)
- **Analyses:** HTTP headers, CORS (active/passive), SSL/TLS (SSL Labs), server version disclosure, improper error handling, URL tampering
- **Reports:** Per-URL tabs; batch mode with URL selector
- **API:** `POST /api/scan`, `POST /api/parse-urls`, `GET /api/health`

---

## Security controls (6)

1. **HTTP Header Analysis** — Evaluates security headers (e.g. CSP, HSTS, X-Frame-Options).
2. **SSL/TLS Analysis** — Grade and details via SSL Labs (or local fallback); certs, ciphers, protocols.
3. **Server Version Disclosure** — Headers that reveal stack/versions; stack inference, severity, recommendations, config examples.
4. **CORS Validation** — Passive (no origin) or Active (custom origin); OPTIONS preflight; Origin Accepted/Reflected; findings and full headers.
5. **Improper Error Handling** — Probes a non-existent path; scans error **body** for stack trace, DB names, tech leakage; High/Low risk.
6. **URL Tampering** — Path traversal and invalid-query probes; reports status code and body length for review.

## Security

- Only `http://` and `https://` URLs accepted; file uploads validated by extension and size.
- Security headers on all responses; CORS configurable.
- See [SECURITY.md](./SECURITY.md) for full notes.

## Build for production

```bash
cd frontend && npm run build
```
Serve `frontend/dist` and point API to your backend. Set `FLASK_ENV=production` and `CORS_ORIGINS` to your frontend origin(s).

## Tech stack

- **Backend:** Python 3.8+, Flask, requests, openpyxl, python-dotenv
- **Frontend:** React 18, Vite 5