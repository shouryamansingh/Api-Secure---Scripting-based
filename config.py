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
