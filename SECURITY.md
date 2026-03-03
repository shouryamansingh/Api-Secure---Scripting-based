# Security

## Secure coding practices in this project

- **Configuration**: No hardcoded secrets; use environment variables (see `.env.example`). Do not commit `.env`.
- **Input validation**: Only `http://` and `https://` URLs are accepted for scanning. File uploads are restricted by extension (`.csv`, `.xlsx`, `.xls`) and size (`MAX_UPLOAD_SIZE_MB`).
- **Limits**: `MAX_URLS_PER_SCAN` caps how many URLs can be scanned per request (default 50). Upload size is capped (default 5 MB).
- **Response headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin` are set on all responses.
- **CORS**: Configurable via `CORS_ORIGINS`. In production, set specific origins instead of `*`.
- **Error handling**: Generic "Server error" messages to clients; detailed errors are logged server-side only.
- **Dependencies**: Pinned versions in `requirements.txt`; keep them updated and run `pip audit` periodically.

## Reporting vulnerabilities

If you find a security issue, please report it responsibly (e.g. private disclosure to the maintainers) rather than opening a public issue.
