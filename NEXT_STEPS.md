# What to do now

Cleanup is done. Here’s how to run the project and what you can do next.

---

## 1. Run the project locally

**Terminal 1 – Backend**
```bash
cd "Main Project"
py -m pip install -r requirements.txt
copy .env.example .env
py app.py
```
→ Backend at **http://localhost:3001**

**Terminal 2 – Frontend**
```bash
cd "Main Project\frontend"
npm install
npm run dev
```
→ Open **http://localhost:5173** in your browser. Use the UI to add URL(s), choose methods, and click **Start Testing**.

---

## 2. Optional: environment config

- Copy `.env.example` to `.env` (if you haven’t).
- Adjust in `.env` if needed:
  - `PORT` (default 3001)
  - `CORS_ORIGINS` (e.g. `http://localhost:5173` in production)
  - `MAX_URLS_PER_SCAN`, `MAX_UPLOAD_SIZE_MB`, `SCANNER_TIMEOUT`

---

## 3. Optional: AI and email (not implemented yet)

- **AI analysis** — If you want AI summaries/recommendations, say which provider (OpenAI / Anthropic / Gemini) and that you’ll add the API key in an env var.
- **Email reports** — If you want reports sent to “Report recipients”, say SMTP or provider (e.g. SendGrid) and that you’ll set credentials via env vars.

| # | Item | Your response |
|---|------|----------------|
| 1 | AI: want it? Provider? Key via env? | |
| 2 | Email: want it? SMTP or provider? Creds via env? | |
| 3 | SSL: OK to use SSL Labs public API? | |

Once you decide, those can be wired up.

---

## 4. Production build

When you’re ready to deploy:

```bash
cd frontend && npm run build
```

Serve the `frontend/dist` folder with your web server and point the frontend to your backend API. Set `FLASK_ENV=production` and restrict `CORS_ORIGINS` to your frontend origin(s).

---

## Summary

| Step | Action |
|------|--------|
| 1 | Run backend + frontend (see section 1). |
| 2 | Optionally edit `.env` (see section 2). |
| 3 | Optionally request AI and/or email (see section 3). |
| 4 | For production, build frontend and deploy (see section 4). |
