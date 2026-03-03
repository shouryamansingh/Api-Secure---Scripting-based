# HTTP and HTTPS Header Analysis — Control Module

This control evaluates HTTP/HTTPS response headers for a given API endpoint against security best practices and produces a structured report.

## Objective

When a user provides an API endpoint:

1. The system **fetches** the backend response headers (e.g. via HTTP Request node in n8n or `scanner.fetch_url` in this app).
2. **Prepares** the input: formats headers and optional context into the string expected by the AI (see `input-schema.json`).
3. **Analyzes** using the AI prompt in `prompt.md` (or rule-based logic using `config.json`).
4. **Produces** a structured report: evaluated headers, summary counts, vulnerabilities, recommendations, score and grade.

## Files in this folder

| File | Purpose |
|------|--------|
| `metadata.json` | Control id, name, description, version, inputs/outputs. |
| `config.json` | Headers to evaluate, severity rules, scoring, options. |
| `prompt.md` | Full AI prompt (role, scope, input, output, criteria) for any LLM; use in n8n by copying and replacing `INPUT_PLACEHOLDER`. |
| `input-schema.json` | Contract for input (e.g. `formattedHeaders`, `originalUrl`). |
| `output-schema.json` | Contract for AI output (headers array + summary). |

## Flow (n8n)

1. **Trigger / Webhook** — Receives `Landing Page Url` (API endpoint).
2. **HTTP Request** — GET the URL; capture full response (headers + optionally body). Output: `headers`, `body`, etc.
3. **Code (format input)** — Build `formattedHeaders`:
   - Extract `originalUrl`, `targetDomain`.
   - From response, build a string:
     - Lines: `Website: {targetDomain}`, `Target Domain: {targetDomain}`, `Original URL: {originalUrl}`.
     - Then: "Security Headers Analysis Request: … Current Headers:" and list each header as `Name: value`.
   - Pass through the 10 header names from `config.json` in the context if needed.
   - Output: `formattedHeaders`, `originalHeaders`, `siteUrl`, `targetDomain`, `originalUrl`.
4. **AI Agent** — Copy `prompt.md`, replace `INPUT_PLACEHOLDER` with `{{ $json.formattedHeaders }}`. Model: any (Gemini, OpenAI, etc.).
5. **Code (process results)** — Parse LLM response (extract JSON from string if needed). Map to your report shape: `evaluatedHeaders`, `criticalCount`, `warningCount`, `score`, `grade`, `vulnerabilities`, `recommendations`, `aiHeaderNotes`. If parsing fails, use `originalHeaders` and config to build a fallback (rule-based) result.
6. **Report / Email** — Use the processed result to generate HTML or send email.

## Flow (this app)

- **Without AI:** `scanner.run_headers_analysis(url)` uses `config` headers (see `scanner.REQUIRED_HEADERS`) and rule-based severity; returns the same logical shape as the report.
- **With AI:** Load `prompt.md`, replace `INPUT_PLACEHOLDER` with the formatted headers string (built from fetch response), call LLM, parse response with `output-schema.json`, then merge into the existing report structure.

## Input preparation (formattedHeaders)

The string passed to the prompt must look like:

```
Website: example.com
Target Domain: example.com
Original URL: https://example.com/api

Security Headers Analysis Request:

Please analyze the following HTTP response headers for security vulnerabilities:

Current Headers:
Content-Type: application/json
Strict-Transport-Security: max-age=31536000
X-Frame-Options: DENY
...
```

If there are no headers (e.g. connection failed), use: `No headers available - possible connection issue`.

## Output usage

- **headers** — Each item becomes a row in the “Security headers” table; `severity` drives styling (critical/warning/ok).
- **summary** — Used for score: `score = round(((okCount + 0.5 * warningCount) / 10) * 100)`, then grade A/B/C/D/F from `config.json` thresholds.
- From headers, build:
  - `vulnerabilities`: list of `"HeaderName: issue"` for severity critical.
  - `warnings`: same for severity warning.
  - `recommendations`: list of `"HeaderName: recommendation"` for critical and warning.

This keeps the control modular and the report format consistent across n8n and this app.
