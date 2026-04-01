"""
Application configuration from environment variables.
No secrets or defaults that are insecure in production.
"""
import os

# Environment
ENV = os.environ.get("FLASK_ENV", "development")
DEBUG = ENV == "development"

# Server
PORT = int(os.environ.get("PORT", "3001"))
HOST = os.environ.get("HOST", "0.0.0.0")

# CORS: restrict in production; use CORS_ORIGINS (comma-separated) or "*" for dev
_cors = os.environ.get("CORS_ORIGINS", "*").strip()
CORS_ORIGINS = [o.strip() for o in _cors.split(",") if o.strip()] if _cors != "*" else "*"

# Limits (safe defaults)
MAX_URLS_PER_SCAN = int(os.environ.get("MAX_URLS_PER_SCAN", "50"))
MAX_UPLOAD_SIZE_MB = float(os.environ.get("MAX_UPLOAD_SIZE_MB", "5"))
ALLOWED_UPLOAD_EXTENSIONS = (".csv", ".xlsx", ".xls")

# Request timeout for outbound scanner requests (seconds)
SCANNER_TIMEOUT = int(os.environ.get("SCANNER_TIMEOUT", "15"))

# Allowed URL schemes for scan targets (security: no file:, javascript:, etc.)
ALLOWED_URL_SCHEMES = ("http", "https")

# Email (SMTP) — optional; if not set, report email is disabled
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587") or "587")
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").strip()
SMTP_FROM = os.environ.get("SMTP_FROM", "").strip() or SMTP_USER
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "1").strip().lower() in ("1", "true", "yes")
SMTP_ENABLED = bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)

# Email (Gmail OAuth) — optional; use Client ID + Client Secret + Refresh Token from Google Cloud Console
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REFRESH_TOKEN = os.environ.get("GOOGLE_REFRESH_TOKEN", "").strip()
GOOGLE_SENDER_EMAIL = os.environ.get("GOOGLE_SENDER_EMAIL", "").strip()  # Gmail address that sends (must match OAuth account)
GMAIL_OAUTH_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN and GOOGLE_SENDER_EMAIL)

EMAIL_ENABLED = SMTP_ENABLED or GMAIL_OAUTH_ENABLED

# AI analysis via OpenRouter — optional
# Supports multiple keys (comma-separated in OPENROUTER_API_KEYS) for automatic rotation.
# Falls back to single OPENROUTER_API_KEY for backward compatibility.
_raw_keys = os.environ.get("OPENROUTER_API_KEYS", "").strip()
if not _raw_keys:
    _raw_keys = os.environ.get("OPENROUTER_API_KEY", "").strip()
OPENROUTER_API_KEYS = [k.strip() for k in _raw_keys.split(",") if k.strip()]
OPENROUTER_API_KEY = OPENROUTER_API_KEYS[0] if OPENROUTER_API_KEYS else ""
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "google/gemini-2.0-flash-exp:free").strip()
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1/chat/completions"
AI_ENABLED = bool(OPENROUTER_API_KEYS)
