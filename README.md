# API Secure

**Python (Flask)** backend + **React (Vite)** frontend for API security scanning: headers, CORS, SSL/TLS, server disclosure, error handling, URL tampering. Minimalist black & white theme with light/dark toggle. Configuration via environment variables; see [SECURITY.md](./SECURITY.md) for secure coding practices.

**→ [SETUP.md](./SETUP.md)** — **start here**: full step-by-step setup from scratch (Python, Node, Firebase login, Supabase, running locally, troubleshooting).  
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
cp .env.example .env   # edit .env with Firebase + Supabase keys
npm install
npm run dev
```
→ **http://localhost:5173** (proxies `/api` to backend)

**3.** Open **http://localhost:5173**, choose testing mode, add URL(s), select methods, click **Start Testing**.

## Project structure

```
Main Project/
├── app.py                 # Flask app: /api/scan, /api/parse-urls, /api/execute-curl*, /api/health
├── config.py              # Config from env (CORS, limits, timeouts, SMTP, Gmail OAuth)
├── scanner.py             # Scan logic: headers, CORS, SSL, server, error, tampering
├── email_service.py      # Send report email via SMTP or Gmail API (OAuth)
├── requirements.txt      # Python deps (pinned; optional google-* for Gmail OAuth)
├── .env.example           # Example env vars (copy to .env); includes email options
├── .gitignore             # Ignore .env, __pycache__, node_modules, etc.
├── SECURITY.md            # Security practices and reporting
├── README.md
├── NEXT_STEPS.md          # What to do now (run, config, email, production)
├── PLAN_FROM_N8N.md       # Plan to match n8n (AI, email, enhancements)
├── docs/                  # Project visualization (project-visualization.html)
├── scripts/               # One-time helpers (e.g. get_gmail_refresh_token.py)
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
| Email (optional) | — | See **Email (report recipients)** above; `.env.example` lists SMTP and Gmail OAuth vars. |
| `VITE_FIREBASE_*` | — | Firebase config for frontend auth (see `frontend/.env.example`) |
| `VITE_SUPABASE_URL` | — | Supabase URL for frontend user profiles |
| `VITE_SUPABASE_ANON_KEY` | — | Supabase anon key for frontend user profiles |

Copy `.env.example` to `.env` and set as needed. Do not commit `.env`.

### Email (report recipients)

To send security reports to the **Report Recipients** you add in the Scanner UI, configure one of:

- **SMTP** — Set `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD` (and optionally `SMTP_FROM`, `SMTP_PORT`, `SMTP_USE_TLS`). Works with Gmail (App Password), Outlook, or any SMTP server.
- **Gmail OAuth** — Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REFRESH_TOKEN`, `GOOGLE_SENDER_EMAIL` from Google Cloud Console. Add redirect URIs `http://localhost:8080/` through `http://localhost:9999/` (see `.env.example`). Run `py scripts/get_gmail_refresh_token.py` once (sign in with the Gmail that will send) to obtain the refresh token.

## Features

- **Input:** Single URL (manual) or list (paste URLs or upload CSV/Excel)
- **Analyses:** HTTP headers, CORS (active/passive), SSL/TLS (SSL Labs), server version disclosure, improper error handling, URL tampering
- **Reports:** Per-URL tabs; batch mode with URL selector; optional email to Report Recipients (SMTP or Gmail OAuth)
- **Token Generator:** Run curl commands; chain curls with token injection; scan the 2nd API with token; SSE event view
- **API:** `POST /api/scan`, `POST /api/parse-urls`, `POST /api/execute-curl`, `POST /api/execute-curl-chain`, `GET /api/health`

---

## About the analysis engine (no LLM)

Reports are produced by lightweight, rule-based scripting and basic analysis (`template_analysis.py`) — no external or locally hosted LLM is used.

- A local LLM such as BART could be integrated for AI-based analysis in the future. However, the backend is currently deployed on Render's free tier, which has resource limitations and cannot host an LLM model of 3 GB or larger.
- Using external LLM APIs would also introduce additional usage costs.
- The current implementation has therefore been intentionally built on rule-based analysis.

The existing architecture can be extended in the future to support AI-powered analysis, intelligent vulnerability interpretation, automated recommendations, and more advanced security insights once suitable infrastructure or an appropriate LLM service is available. (`ai_service.py` and the `OPENROUTER_*` settings are kept for that purpose but are not called by the app today.)

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

- **Backend:** Python 3.8+, Flask, requests, openpyxl, python-dotenv; optional google-auth, google-api-python-client for Gmail OAuth email
- **Frontend:** React 18, Vite 5