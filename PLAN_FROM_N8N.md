# Plan: What to Add to Make This Project Match the n8n Workflow

This plan is based on the **Working API Secure.json** n8n workflow. The Main Project already implements all **scan types** and **report UI**; the gaps are **AI analysis**, **email delivery**, and a few optional enhancements.

---

## Reference: What the n8n Workflow Does

| Area | n8n behavior | Main Project status |
|------|----------------|---------------------|
| **Trigger / input** | Webhook receives: Landing Page Url, Analysis Type, CORS type, Origin, Recipient Emails | ✅ REST API + React form (same data) |
| **Security headers** | HTTP request → format headers → **AI Agent (Gemini)** for headers + **AI Agent** for HTML content → process → HTML report | ✅ Rule-based headers; ❌ No AI |
| **CORS** | Passive/Active HTTP → analyze CORS headers → **AI Agent (Gemini)** for assessment + plain-language summary → HTML report | ✅ Rule-based CORS; ❌ No AI |
| **SSL/TLS** | SSL Labs API → process → **AI Agent** for cert/TLS summary → HTML report; **SplitInBatches + Wait** for rate limit | ✅ SSL Labs + report; ❌ No AI; optional delay between URLs |
| **Server disclosure** | HTTP → detect headers → report | ✅ Done |
| **Error handling** | Probe URL → check body for stack traces → report | ✅ Done |
| **URL tampering** | Tampering tests → **AI Agent** → HTML report | ✅ Tampering tests; ❌ No AI |
| **Email** | **Gmail** “Send a message” nodes send HTML reports to Recipient Emails | ❌ Not implemented |
| **Batch** | Multiple URLs via webhook/loop; Wait between SSL calls | ✅ Batch in app; optional SSL delay |

---

## Phase 1: Run the Project (Already Possible)

You can run the app **today** without adding anything:

1. **Backend:** `cd "Main Project"` → `py -m pip install -r requirements.txt` → `copy .env.example .env` → `py app.py`
2. **Frontend:** `cd "Main Project\frontend"` → `npm install` → `npm run dev`
3. Open **http://localhost:5173**, enter URL(s), select methods, click **Start Testing**.

All scans (headers, CORS, SSL, server, error handling, URL tampering) and the report UI work. No AI and no email yet.

---

## Phase 2: Add AI-Backed Analysis (Match n8n)

The n8n workflow uses **Google Gemini** for:

- **Headers:** Analyze response headers + HTML content; return structured JSON (severity, recommendations) and a professional summary.
- **CORS:** Turn scanner output into an assessment (overall risk, executive summary, plain-language summary, findings with severity/impact/recommendation).
- **SSL/TLS:** Summarize certificate and TLS security in natural language.
- **URL tampering:** Optional AI summary of tampering test results.

**What you need to add:**

| Step | Task | Details |
|------|------|---------|
| 2.1 | Choose AI provider | n8n uses **Google Gemini**. You can use Gemini (e.g. `google-generativeai`), or OpenAI/Anthropic if you prefer. |
| 2.2 | Add API key to env | e.g. `GEMINI_API_KEY` or `OPENAI_API_KEY` in `.env` (see `.env.example`). Never commit the key. |
| 2.3 | Implement AI service in backend | New module (e.g. `ai_analysis.py`) that: takes scan output (headers, CORS, SSL summary, etc.), calls the AI API with prompts similar to n8n (structured JSON + summary), returns parsed result. |
| 2.4 | Integrate into scan flow | After each scan type (headers, CORS, SSL, tampering): if AI is enabled and key is set, call the AI service and merge result into the report (e.g. `aiHeaderNotes`, `aiAssessment`, `aiContentNotes`). |
| 2.5 | Expose “AI summary” in UI | Show AI summary and (if any) plain-language summary in the existing report tabs (e.g. Security headers, CORS, SSL/TLS). |

**n8n prompt reference (in Working API Secure.json):**

- **Headers:** “Analyze the following HTTP response headers… return ONLY valid JSON” with schema for headers array and summary (criticalCount, warningCount, okCount).
- **Content:** “Analyze the HTML content for vulnerabilities… criticalVulnerabilities, informationLeakage, clientSideWeaknesses, summary.”
- **CORS:** “Analyze CORS configuration… assessment (overallRisk, executiveSummary, plainLanguageSummary), findings (title, severity, description, impact, recommendation).”

You can copy or adapt these prompts into your AI service.

---

## Phase 3: Add Email Sending (Match n8n)

The n8n workflow sends reports via **Gmail** (“Send a message” nodes) to **Recipient Emails**.

**What you need to add:**

| Step | Task | Details |
|------|------|---------|
| 3.1 | Choose email method | **Option A:** Gmail SMTP (same as n8n). **Option B:** Generic SMTP (Outlook, etc.). **Option C:** SendGrid/Mailgun API. |
| 3.2 | Add credentials to env | e.g. `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`. For Gmail: use App Password if 2FA is on. |
| 3.3 | Implement email service in backend | New module (e.g. `email_service.py`) that: builds a plain-text or HTML body from the scan result (and optional AI summary), sends to each address in `recipientEmails` (comma-separated from the form). |
| 3.4 | Call email after scan | In `app.py`, after a successful scan: if `recipientEmails` is present and email is configured, call the email service (async or in background to avoid blocking the API response). |
| 3.5 | Optional: HTML report template | n8n builds styled HTML reports. You can add a simple HTML template (Jinja2 or string) for “Security Audit Report” (headers + CORS + SSL + summary) and send that as the email body or attachment. |

---

## Phase 4: Optional Enhancements (From n8n)

| Item | n8n behavior | Suggestion |
|------|----------------|------------|
| **SSL Labs rate limiting** | SplitInBatches + Wait between requests | Add a short delay (e.g. 2–5 s) between SSL Labs calls when scanning multiple URLs to reduce throttling. |
| **Export / Download report** | HTML reports generated for email | Add “Export to File” in the UI: generate same (or simpler) HTML or JSON and return as download (already stubbed in sidebar). |
| **Error handling** | If a node fails, workflow can still continue | Ensure one failing URL in a batch doesn’t break the whole response; you already have per-URL error handling—just keep it robust. |

---

## Summary Checklist: What to Add

| # | What to add | Needed from you | Effort |
|---|-------------|------------------|--------|
| 1 | **Run as-is** | Nothing | Done — follow Phase 1. |
| 2 | **AI analysis** | AI provider (e.g. Gemini), API key in env | Medium — Phase 2. |
| 3 | **Email reports** | SMTP or Gmail credentials in env | Medium — Phase 3. |
| 4 | **SSL delay (optional)** | None | Low — configurable delay in scanner. |
| 5 | **Export to file (optional)** | None | Low — endpoint + frontend download. |

---

## Suggested Order of Work

1. **Now:** Run the project (Phase 1) and confirm all scan types and UI work.
2. **Next:** Add **AI** (Phase 2) so reports match n8n’s summaries and recommendations.
3. **Then:** Add **email** (Phase 3) so recipients get reports like in n8n.
4. **Later:** Optional SSL delay and Export to File (Phase 4).

For the exact prompts and JSON schemas used in n8n, open **Working API Secure.json** and search for `"text":` inside the AI Agent nodes (e.g. “AI Agent - Headers2”, “AI Agent2”, “Process Audit Results2”).
