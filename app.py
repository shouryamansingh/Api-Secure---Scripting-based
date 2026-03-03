"""
API Secure — API security scanning backend.
Headers, CORS, SSL/TLS, server disclosure, error handling, URL tampering.
Configuration via environment variables; see .env.example.
"""
import csv
import io
import os
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, request, jsonify, send_from_directory

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from config import (
    CORS_ORIGINS,
    MAX_URLS_PER_SCAN,
    MAX_UPLOAD_SIZE_MB,
    ALLOWED_UPLOAD_EXTENSIONS,
    PORT,
    HOST,
    ENV,
)
from scanner import (
    get_domain,
    run_headers_analysis,
    run_cors_analysis,
    run_server_disclosure_analysis,
    run_error_handling_check,
    run_url_tampering_check,
    run_ssl_analysis,
)

app = Flask(__name__, static_folder="public", static_url_path="")
MAX_UPLOAD_BYTES = int(MAX_UPLOAD_SIZE_MB * 1024 * 1024)


def _security_headers(response):
    """Add security-related response headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def _cors_headers(response):
    """Add CORS headers from config (restrict origins in production)."""
    if CORS_ORIGINS == "*":
        response.headers["Access-Control-Allow-Origin"] = "*"
    elif request.origin and request.origin in CORS_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = request.origin
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Max-Age"] = "86400"
    return response


@app.after_request
def after_request(response):
    response = _security_headers(response)
    response = _cors_headers(response)
    return response


@app.route("/", methods=["GET"])
def index():
    path = os.path.join(app.root_path, app.static_folder or "", "index.html")
    if os.path.isfile(path):
        return send_from_directory(app.static_folder, "index.html")
    return jsonify({
        "service": "API Secure",
        "message": "API is running. For the UI, run: cd frontend && npm run dev",
        "docs": "/api/health",
    }), 200


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "API Secure"})


def _normalize_url(u: str) -> str:
    """Ensure URL has a scheme (default https). Returns empty string if invalid."""
    if not u or not isinstance(u, str):
        return ""
    s = u.strip()
    if not s:
        return ""
    if not s.startswith(("http://", "https://")):
        s = "https://" + s
    return s


def _validate_url_scheme(url: str) -> bool:
    """Allow only http/https to prevent SSRF-style abuse."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def _want(analysis_types, *keys):
    at = (analysis_types or []) if isinstance(analysis_types, list) else []
    s = str(analysis_types).lower()
    for k in keys:
        klo = k.lower()
        for x in at:
            if (str(x) or "").strip().lower() == klo or klo in (str(x) or "").strip().lower():
                return True
        if klo in s:
            return True
    return False


def _safe_report(value, error_fallback):
    """Ensure we always have a dict; use fallback if value is None or has error. Frontend expects 'error' as message string."""
    if value is None or not isinstance(value, dict):
        return error_fallback
    if value.get("error"):
        msg = value.get("message") or error_fallback.get("message") or "Analysis failed"
        return {**error_fallback, "error": msg, "message": msg}
    return value


def _scan_one(normalized, data, want_headers, want_cors, want_server, want_ssl, want_error, want_tamper):
    origin = (data.get("origin") or data.get("Origin") or "").strip()
    domain = get_domain(normalized)
    result = {
        "url": normalized,
        "targetDomain": domain,
        "scannedAt": datetime.utcnow().isoformat() + "Z",
        "headersReport": None,
        "corsReport": None,
        "serverReport": None,
        "sslReport": None,
        "errorHandlingReport": None,
        "urlTamperingReport": None,
        "error": None,
    }

    if want_headers:
        try:
            result["headersReport"] = _safe_report(
                run_headers_analysis(normalized),
                {"error": True, "message": "Headers analysis failed", "score": 0, "grade": "F", "evaluatedHeaders": {}, "vulnerabilities": [], "warnings": [], "recommendations": []},
            )
        except Exception as e:
            result["headersReport"] = {"error": True, "message": str(e), "score": 0, "grade": "F", "evaluatedHeaders": {}, "vulnerabilities": [], "warnings": [], "recommendations": []}

    if want_cors:
        try:
            result["corsReport"] = _safe_report(
                run_cors_analysis(normalized, origin or None),
                {"error": True, "message": "CORS analysis failed", "riskLevel": "Unknown", "configuration": {}, "vulnerabilities": []},
            )
        except Exception as e:
            result["corsReport"] = {"error": True, "message": str(e), "riskLevel": "Unknown", "configuration": {}, "vulnerabilities": []}

    if want_server:
        try:
            result["serverReport"] = _safe_report(
                run_server_disclosure_analysis(normalized),
                {"targetDomain": domain, "error": "Server disclosure check failed", "riskLevel": "Unknown", "disclosures": []},
            )
        except Exception as e:
            result["serverReport"] = {"targetDomain": domain, "error": str(e), "riskLevel": "Unknown", "disclosures": []}

    if want_ssl:
        try:
            result["sslReport"] = run_ssl_analysis(normalized)
            if result["sslReport"] is None or not isinstance(result["sslReport"], dict):
                result["sslReport"] = {"host": domain, "error": True, "message": "SSL analysis did not complete", "scannedAt": datetime.utcnow().isoformat() + "Z"}
        except Exception as e:
            result["sslReport"] = {"host": domain, "error": True, "message": str(e), "scannedAt": datetime.utcnow().isoformat() + "Z"}

    if want_error:
        try:
            result["errorHandlingReport"] = _safe_report(
                run_error_handling_check(normalized),
                {"targetDomain": domain, "error": "Error handling check failed", "riskLevel": "Unknown"},
            )
        except Exception as e:
            result["errorHandlingReport"] = {"targetDomain": domain, "error": str(e), "riskLevel": "Unknown"}

    if want_tamper:
        try:
            result["urlTamperingReport"] = _safe_report(
                run_url_tampering_check(normalized),
                {"targetDomain": domain, "error": "URL tampering check failed", "tests": []},
            )
        except Exception as e:
            result["urlTamperingReport"] = {"targetDomain": domain, "error": str(e), "tests": []}

    if want_ssl and result.get("sslReport") is None:
        result["sslReport"] = {"host": domain, "error": True, "message": "SSL analysis did not complete", "scannedAt": datetime.utcnow().isoformat() + "Z"}
    return result


@app.route("/api/scan", methods=["POST", "OPTIONS"])
def scan():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(silent=True) or {}
        url = data.get("url") or ""
        batch_urls = data.get("batchUrls") or data.get("Batch URLs") or []
        if isinstance(batch_urls, str):
            batch_urls = [u.strip() for u in batch_urls.split(",") if u.strip()]
        raw_types = data.get("analysisTypes") or data.get("Analysis Type") or []
        if isinstance(raw_types, str):
            analysis_types = [t.strip() for t in raw_types.split(",") if t.strip()]
        elif raw_types:
            analysis_types = [str(t).strip() for t in raw_types if str(t).strip()]
        else:
            analysis_types = []
        origin = (data.get("origin") or data.get("Origin") or "").strip()
        cors_analysis_type = (data.get("corsAnalysisType") or data.get("Cors Analysis Type") or "").strip()

        if not url and not batch_urls:
            return jsonify({"error": 'Missing "url" or "batchUrls" in request body.'}), 400

        urls_to_scan = []

        def _add_url(raw, prepend=False):
            normalized = _normalize_url(raw)
            if not normalized or not _validate_url_scheme(normalized):
                return
            final = normalized.rstrip("/") or normalized
            if final in urls_to_scan:
                if prepend and urls_to_scan[0] != final:
                    urls_to_scan.remove(final)
                    urls_to_scan.insert(0, final)
                return
            if prepend:
                urls_to_scan.insert(0, final)
            else:
                urls_to_scan.append(final)

        if url and isinstance(url, str) and url.strip():
            _add_url(url, prepend=True)
        if batch_urls:
            for u in batch_urls:
                if isinstance(u, str) and u.strip():
                    _add_url(u, prepend=False)

        if not urls_to_scan:
            return jsonify({"error": "No valid URLs to scan. Use http:// or https:// only."}), 400

        if len(urls_to_scan) > MAX_URLS_PER_SCAN:
            return jsonify({"error": f"Maximum {MAX_URLS_PER_SCAN} URLs per scan allowed."}), 400

        want_headers = _want(analysis_types, "http header analysis", "headers", "HTTP Header Analysis", "m_http")
        want_cors = _want(analysis_types, "cors", "CORS Validation", "m_cors") or bool(cors_analysis_type) or bool(data.get("corsAnalysisType"))
        want_server = _want(analysis_types, "Server version Disclosure", "Server version", "m_sensitive", "server version")
        want_ssl = _want(analysis_types, "SSL / TLS analysis", "SSL", "TLS", "m_ssl", "ssl/tls", "ssl tls", "improper tls")
        want_error = _want(analysis_types, "Improper Error Handling", "Improper Error", "m_error", "error handling")
        want_tamper = _want(analysis_types, "URL Tampering Analysis", "URL Tampering", "m_url", "tampering")

        if not any([want_headers, want_cors, want_server, want_ssl, want_error, want_tamper]):
            return jsonify({"error": "Select at least one analysis type."}), 400

        results = []
        for normalized in urls_to_scan:
            results.append(_scan_one(normalized, data, want_headers, want_cors, want_server, want_ssl, want_error, want_tamper))

        if len(results) == 1:
            return jsonify(results[0])
        return jsonify({
            "batch": True,
            "results": results,
            "batchSummary": {"total": len(results), "success": len([r for r in results if not r.get("error")]), "failed": len([r for r in results if r.get("error")])},
        })
    except Exception as err:
        app.logger.exception("Scan error")
        return jsonify({"error": "Server error. Please try again."}), 500


@app.route("/api/parse-urls", methods=["POST", "OPTIONS"])
def parse_urls():
    if request.method == "OPTIONS":
        return "", 204
    try:
        f = request.files.get("file")
        if not f or (getattr(f, "filename", None) or "").strip() == "":
            return jsonify({"error": "No file uploaded."}), 400

        name = (f.filename or "").lower()
        if not any(name.endswith(ext) for ext in ALLOWED_UPLOAD_EXTENSIONS):
            return jsonify({"error": f"Unsupported file type. Allowed: {', '.join(ALLOWED_UPLOAD_EXTENSIONS)}"}), 400

        content = f.read()
        if len(content) > MAX_UPLOAD_BYTES:
            return jsonify({"error": f"File too large. Maximum size: {MAX_UPLOAD_SIZE_MB} MB."}), 400

        urls = []
        if name.endswith(".csv"):
            stream = io.StringIO(content.decode("utf-8", errors="replace"))
            reader = csv.reader(stream)
            rows = list(reader)
            if not rows:
                return jsonify({"urls": []})
            header = [h.strip().lower() for h in rows[0]]
            url_col = next((i for i, h in enumerate(header) if h in ("url", "link", "uri", "endpoint", "api", "domain")), 0)
            for row in rows[1:]:
                if row and len(row) > url_col and row[url_col].strip():
                    u = row[url_col].strip()
                    if u.startswith(("http://", "https://")):
                        urls.append(u)
            return jsonify({"urls": urls})

        if name.endswith(".xlsx") or name.endswith(".xls"):
            try:
                import openpyxl
            except ImportError:
                return jsonify({"error": "Excel support requires openpyxl. Install with: pip install openpyxl"}), 501
            wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
            ws = wb.active
            rows = list(ws.iter_rows(values_only=True))
            wb.close()
            if not rows:
                return jsonify({"urls": []})
            header = [str(h).strip().lower() if h is not None else "" for h in rows[0]]
            url_col = next((i for i, h in enumerate(header) if h in ("url", "link", "uri", "endpoint", "api", "domain")), 0)
            for row in rows[1:]:
                if row and len(row) > url_col and row[url_col]:
                    u = str(row[url_col]).strip()
                    if u.startswith(("http://", "https://")):
                        urls.append(u)
            return jsonify({"urls": urls})

        return jsonify({"error": "Unsupported file type."}), 400
    except Exception as err:
        app.logger.exception("Parse URLs error")
        return jsonify({"error": "Server error. Please try again."}), 500


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=(ENV == "development"))
