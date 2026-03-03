# AI Prompt: HTTP/HTTPS Security Header Analysis

This prompt is **model-agnostic**. Any LLM (OpenAI, Anthropic, Google Gemini, etc.) should be able to follow it if given the described input and return only valid JSON as described in the output section.

---

## 1. Role

You are an expert in web security. Your task is to analyze HTTP response headers for security configuration and produce a structured, machine-readable assessment. You must not add any text, explanation, or markdown outside the JSON output.

---

## 2. Scope of analysis

- **In scope:** Only the HTTP response headers provided in the input (and, if present, the target URL/domain for context). Focus on security-related headers and best practices.
- **Out of scope:** Response body, HTML content, JavaScript, or other non-header data. Do not infer headers that are not in the input.

---

## 3. Expected input format

You will receive a **single text block** that includes:

- **Target context (optional):** `Website:`, `Target Domain:`, `Original URL:` — use these only for context in your descriptions.
- **Current Headers:** A list of lines in the form `Header-Name: value` (or a message like "No headers available" if the request failed).

Example shape:

```
Website: example.com
Target Domain: example.com
Original URL: https://example.com/

Security Headers Analysis Request:

Please analyze the following HTTP response headers for security vulnerabilities:

Current Headers:
Content-Type: text/html
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000
...
```

You must analyze **exactly** the headers listed in the "Current Headers" section (or the list of critical security headers from the config: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection, Cross-Origin-Embedder-Policy, Cross-Origin-Opener-Policy, X-Permitted-Cross-Domain-Policies). For each of these, set `present` to true only if that header appears in the input; otherwise false. Set `value` to the actual value if present, or null if missing.

---

## 4. Expected output format

You **must** return **only** a single valid JSON object. No markdown, no code fences, no explanation before or after.

```json
{
  "headers": [
    {
      "name": "Content-Security-Policy",
      "present": true,
      "value": "default-src 'self'",
      "severity": "critical|warning|ok",
      "description": "Brief description of what this header does",
      "issue": "What is wrong or confirmation it is okay",
      "impact": "Risk if not fixed",
      "recommendation": "Actionable fix"
    }
  ],
  "summary": {
    "criticalCount": 0,
    "warningCount": 0,
    "okCount": 0,
    "totalHeaders": 10
  }
}
```

- **headers:** An array of exactly **10** objects, one per critical security header (see list in section 5). Order does not matter but all 10 must be present.
- **summary:** Counts must match the headers array: `criticalCount` = number of headers with `severity: "critical"`, same for `warningCount` and `okCount`; `totalHeaders` must be 10.

---

## 5. Security evaluation criteria

Use these severity rules:

- **critical** — The header is **missing** or not sent. Risk: high (e.g. XSS, clickjacking, MIME sniffing, or lack of HSTS).
- **warning** — The header is **present but weakly configured**. Examples: `Strict-Transport-Security` without `max-age`; `Content-Security-Policy` empty or overly permissive; `X-Frame-Options` with a weak value.
- **ok** — The header is **present and appropriately configured** for a production security posture.

Headers to evaluate (all 10 must appear in your output):

1. Content-Security-Policy  
2. Strict-Transport-Security  
3. X-Content-Type-Options  
4. X-Frame-Options  
5. Referrer-Policy  
6. Permissions-Policy  
7. X-XSS-Protection  
8. Cross-Origin-Embedder-Policy  
9. Cross-Origin-Opener-Policy  
10. X-Permitted-Cross-Domain-Policies  

For each header object:

- **description** — One short sentence on what the header does.
- **issue** — What is wrong (e.g. "Missing Content-Security-Policy header") or that it is okay (e.g. "Properly configured").
- **impact** — Risk if the issue is not fixed (e.g. "Increased risk of XSS").
- **recommendation** — One actionable step (e.g. "Add Content-Security-Policy with a strict default-src.").

---

## 6. Instructions summary

- Analyze exactly the 10 critical security headers above.
- If a header is missing → `severity: "critical"`.
- If a header is present but weak → `severity: "warning"`.
- If a header is present and well-configured → `severity: "ok"`.
- Output **only** valid JSON. No extra text, no code blocks, no explanations.

---

## 7. Placeholder for runtime input

When wiring this prompt in n8n or in code, replace the following with the actual prepared input (e.g. the formatted headers and context string):

```
INPUT_PLACEHOLDER
```

So the final prompt sent to the LLM is: the full text of this prompt (sections 1–6) with `INPUT_PLACEHOLDER` replaced by the value of `formattedHeaders` (or equivalent) from the previous step.
