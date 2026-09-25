"""
API Secure — API security scanning backend.
Headers, CORS, SSL/TLS, server disclosure, error handling, URL tampering.
Configuration via environment variables; see .env.example.
"""
import csv
import io
import json
import os
import re
import shlex
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests as http_requests
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
    EMAIL_ENABLED,
)
from scanner import (
    get_domain,
    run_headers_analysis,
    run_cors_analysis,
    run_server_disclosure_analysis,
    run_error_handling_check,
    run_url_tampering_check,
    run_sensitive_data_check,
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


@app.errorhandler(404)
def spa_fallback(err):
    """Serve the React app for client-side routes (e.g. /scanner) on refresh or direct visit."""
    index_path = os.path.join(app.root_path, app.static_folder or "", "index.html")
    if request.method == "GET" and not request.path.startswith("/api/") and os.path.isfile(index_path):
        return send_from_directory(app.static_folder, "index.html")
    return err


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


def _scan_one(normalized, data, want_headers, want_cors, want_server, want_ssl, want_error, want_tamper, want_pii=False, extra_headers=None, extra_method=None, extra_body=None):
    origin = (data.get("origin") or data.get("Origin") or "").strip()
    domain = get_domain(normalized)
    method = (extra_method or "GET").upper() if extra_method else "GET"
    body = extra_body if extra_body is not None else None
    result = {
        "url": normalized,
        "targetDomain": domain,
        "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
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
                run_headers_analysis(normalized, extra_headers=extra_headers, method=method, body=body),
                {"error": True, "message": "Headers analysis failed", "score": 0, "grade": "F", "evaluatedHeaders": {}, "vulnerabilities": [], "warnings": [], "recommendations": []},
            )
        except Exception as e:
            result["headersReport"] = {"error": True, "message": str(e), "score": 0, "grade": "F", "evaluatedHeaders": {}, "vulnerabilities": [], "warnings": [], "recommendations": []}

    if want_cors:
        try:
            result["corsReport"] = _safe_report(
                run_cors_analysis(normalized, origin or None, extra_headers=extra_headers, method=method, body=body),
                {"error": True, "message": "CORS analysis failed", "riskLevel": "Unknown", "configuration": {}, "vulnerabilities": []},
            )
        except Exception as e:
            result["corsReport"] = {"error": True, "message": str(e), "riskLevel": "Unknown", "configuration": {}, "vulnerabilities": []}

    if want_server:
        try:
            result["serverReport"] = _safe_report(
                run_server_disclosure_analysis(normalized, extra_headers=extra_headers, method=method, body=body),
                {"targetDomain": domain, "error": "Server disclosure check failed", "riskLevel": "Unknown", "disclosures": []},
            )
        except Exception as e:
            result["serverReport"] = {"targetDomain": domain, "error": str(e), "riskLevel": "Unknown", "disclosures": []}

    if want_ssl:
        try:
            result["sslReport"] = run_ssl_analysis(normalized)
            if result["sslReport"] is None or not isinstance(result["sslReport"], dict):
                result["sslReport"] = {"host": domain, "error": True, "message": "SSL analysis did not complete", "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"}
        except Exception as e:
            result["sslReport"] = {"host": domain, "error": True, "message": str(e), "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"}

    if want_error:
        try:
            result["errorHandlingReport"] = _safe_report(
                run_error_handling_check(normalized, extra_headers=extra_headers, method=method, body=body),
                {"targetDomain": domain, "error": "Error handling check failed", "riskLevel": "Unknown"},
            )
        except Exception as e:
            result["errorHandlingReport"] = {"targetDomain": domain, "error": str(e), "riskLevel": "Unknown"}

    if want_tamper:
        try:
            result["urlTamperingReport"] = _safe_report(
                run_url_tampering_check(normalized, extra_headers=extra_headers, method=method, body=body),
                {"targetDomain": domain, "error": "URL tampering check failed", "tests": []},
            )
        except Exception as e:
            result["urlTamperingReport"] = {"targetDomain": domain, "error": str(e), "tests": []}

    if want_pii:
        try:
            result["sensitiveDataReport"] = _safe_report(
                run_sensitive_data_check(normalized, extra_headers=extra_headers, method=method, body=body),
                {"targetDomain": domain, "error": "Sensitive data check failed", "riskLevel": "Unknown"},
            )
        except Exception as e:
            result["sensitiveDataReport"] = {"targetDomain": domain, "error": str(e), "riskLevel": "Unknown"}

    if want_ssl and result.get("sslReport") is None:
        result["sslReport"] = {"host": domain, "error": True, "message": "SSL analysis did not complete", "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"}

    # ── Template-based analysis (deterministic, always consistent with scan) ──
    hr = result.get("headersReport")
    if hr is not None:
        try:
            from template_analysis import analyze_headers_template
            evaluated = hr.get("evaluatedHeaders") or {}
            extra_findings = hr.get("extraFindings") or []
            tmpl = analyze_headers_template(evaluated, domain, extra_findings=extra_findings)
            hr["aiHeaderNotes"] = tmpl["aiHeaderNotes"]
            hr["aiHeaders"] = tmpl["aiHeaders"]
            hr["aiSummary"] = tmpl["aiSummary"]
            hr["aiExecutiveSummary"] = tmpl["aiExecutiveSummary"]
            hr["aiOverallRisk"] = tmpl["aiOverallRisk"]
            hr["aiRiskExplanation"] = tmpl["aiRiskExplanation"]
            hr["aiTopRecs"] = tmpl["aiTopRecs"]
            hr["aiSource"] = "template"
            hr["aiError"] = None
            hr["extraFindings"] = tmpl.get("extraFindings", [])
            result["aiEnabled"] = True
        except Exception as ai_err:
            app.logger.warning("Template analysis failed: %s", ai_err, exc_info=True)
            result["aiEnabled"] = False
            hr["aiError"] = f"Analysis error: {ai_err}"
    else:
        result["aiEnabled"] = False

    # Overall summary — computed after all checks including AI
    try:
        hr = result.get("headersReport") or {}
        cr = result.get("corsReport") or {}
        sr = result.get("serverReport") or {}
        sl = result.get("sslReport") or {}
        er = result.get("errorHandlingReport") or {}
        tr = result.get("urlTamperingReport") or {}

        # Collect per-test data for the summary
        tests_run = []
        score_values = []

        if want_headers and not hr.get("error"):
            h_score = hr.get("score", 0) or 0
            score_values.append(h_score)
            tests_run.append({
                "name": "Security Headers",
                "icon": "🛡️",
                "score": h_score,
                "grade": hr.get("grade", "?"),
                "criticalCount": hr.get("criticalCount", 0),
                "warningCount": hr.get("warningCount", 0),
                "status": "critical" if h_score < 40 else "warning" if h_score < 70 else "ok",
            })

        if want_cors and not cr.get("error"):
            risk = (cr.get("riskLevel") or "Unknown").lower()
            c_score = {"low": 90, "informational": 80, "medium": 55, "high": 25, "critical": 10}.get(risk, 60)
            score_values.append(c_score)
            tests_run.append({
                "name": "CORS",
                "icon": "🌐",
                "score": c_score,
                "riskLevel": cr.get("riskLevel", "Unknown"),
                "status": "critical" if risk in ("critical", "high") else "warning" if risk == "medium" else "ok",
            })

        if want_server and not sr.get("error"):
            s_risk = (sr.get("riskLevel") or "Unknown").lower()
            s_score = {"low": 85, "informational": 80, "medium": 55, "high": 25, "critical": 10}.get(s_risk, 60)
            score_values.append(s_score)
            tests_run.append({
                "name": "Server Disclosure",
                "icon": "🖥️",
                "score": s_score,
                "riskLevel": sr.get("riskLevel", "Unknown"),
                "status": "critical" if s_risk in ("critical", "high") else "warning" if s_risk == "medium" else "ok",
            })

        if want_ssl and not sl.get("error"):
            ssl_grade = sl.get("grade") or "?"
            ssl_score_map = {"A+": 100, "A": 95, "A-": 90, "B": 75, "C": 55, "D": 40, "F": 20, "T": 35, "M": 30}
            sl_score = ssl_score_map.get(ssl_grade, 50)
            score_values.append(sl_score)
            tests_run.append({
                "name": "SSL/TLS",
                "icon": "🔒",
                "score": sl_score,
                "grade": ssl_grade,
                "status": "critical" if sl_score < 40 else "warning" if sl_score < 75 else "ok",
            })

        if want_error and not er.get("error"):
            e_risk = (er.get("riskLevel") or "Unknown").lower()
            e_score = {"low": 85, "informational": 80, "medium": 55, "high": 25, "critical": 10}.get(e_risk, 65)
            score_values.append(e_score)
            tests_run.append({
                "name": "Error Handling",
                "icon": "⚠️",
                "score": e_score,
                "riskLevel": er.get("riskLevel", "Unknown"),
                "status": "critical" if e_risk in ("critical", "high") else "warning" if e_risk == "medium" else "ok",
            })

        if want_tamper and not tr.get("error"):
            tamper_tests = tr.get("tests") or []
            high_risk = sum(1 for t in tamper_tests if (t.get("riskLevel") or "").lower() in ("high", "critical"))
            med_risk = sum(1 for t in tamper_tests if (t.get("riskLevel") or "").lower() == "medium")
            t_score = max(20, 100 - high_risk * 20 - med_risk * 10)
            score_values.append(t_score)
            tests_run.append({
                "name": "URL Tampering",
                "icon": "🔗",
                "score": t_score,
                "highRiskCount": high_risk,
                "status": "critical" if high_risk > 0 else "warning" if med_risk > 0 else "ok",
            })

        overall_score = round(sum(score_values) / len(score_values)) if score_values else 0
        if overall_score >= 90:
            overall_grade = "A+"
        elif overall_score >= 80:
            overall_grade = "A"
        elif overall_score >= 70:
            overall_grade = "B"
        elif overall_score >= 55:
            overall_grade = "C"
        elif overall_score >= 40:
            overall_grade = "D"
        else:
            overall_grade = "F"

        critical_tests = sum(1 for t in tests_run if t.get("status") == "critical")
        warning_tests = sum(1 for t in tests_run if t.get("status") == "warning")

        # AI notes for summary — use header AI summary if available
        ai_header_summary = ""
        if result.get("headersReport", {}).get("aiSummary"):
            ais = result["headersReport"]["aiSummary"]
            ai_header_summary = (
                f"{ais.get('criticalCount', 0)} critical, "
                f"{ais.get('warningCount', 0)} warning, "
                f"{ais.get('okCount', 0)} OK headers"
            )

        result["overallSummary"] = {
            "domain": domain,
            "scannedAt": result.get("scannedAt"),
            "testsRun": tests_run,
            "testsCount": len(tests_run),
            "overallScore": overall_score,
            "overallGrade": overall_grade,
            "criticalTests": critical_tests,
            "warningTests": warning_tests,
            "okTests": len(tests_run) - critical_tests - warning_tests,
            "aiHeaderSummary": ai_header_summary,
        }
    except Exception as summ_err:
        app.logger.warning("Overall summary failed: %s", summ_err)

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
        want_pii = _want(analysis_types, "Sensitive Data Exposure", "sensitive data", "PII", "m_pii")

        if not any([want_headers, want_cors, want_server, want_ssl, want_error, want_tamper, want_pii]):
            return jsonify({"error": "Select at least one analysis type."}), 400

        # Optional auth headers (e.g. from curl with token) so scanner can hit protected APIs
        request_headers = data.get("requestHeaders") or data.get("headers")
        if request_headers is not None and not isinstance(request_headers, dict):
            request_headers = None
        extra_headers = request_headers
        # Optional method and body so scanner can use POST (e.g. APIs that only return headers for POST)
        extra_method = data.get("method")
        if extra_method is not None and isinstance(extra_method, str) and not extra_method.strip():
            extra_method = None
        extra_body = data.get("requestBody") or data.get("body")
        if extra_body is not None and not isinstance(extra_body, str):
            extra_body = None

        results = []
        for normalized in urls_to_scan:
            results.append(_scan_one(normalized, data, want_headers, want_cors, want_server, want_ssl, want_error, want_tamper, want_pii=want_pii, extra_headers=extra_headers, extra_method=extra_method, extra_body=extra_body))

        # Build response payload
        if len(results) == 1:
            payload = results[0]
        else:
            payload = {
                "batch": True,
                "results": results,
                "batchSummary": {"total": len(results), "success": len([r for r in results if not r.get("error")]), "failed": len([r for r in results if r.get("error")])},
            }

        # Send report email if recipients provided and SMTP is configured
        recipient_emails = (data.get("recipientEmails") or data.get("recipient_emails") or "").strip()
        if recipient_emails and EMAIL_ENABLED:
            try:
                from email_service import send_report
                email_ok, email_msg = send_report(recipient_emails, payload)
                payload["emailSent"] = email_ok
                if not email_ok:
                    payload["emailError"] = email_msg
            except Exception as e:
                app.logger.exception("Email send error")
                payload["emailSent"] = False
                payload["emailError"] = str(e)
        elif recipient_emails and not EMAIL_ENABLED:
            payload["emailSent"] = False
            payload["emailError"] = "Email is not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD in .env."

        return jsonify(payload)
    except Exception as err:
        app.logger.exception("Scan error")
        return jsonify({"error": "Server error. Please try again."}), 500




@app.route("/api/download-report", methods=["POST", "OPTIONS"])
def download_report():
    """Return a styled HTML security report as a downloadable file."""
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True, silent=True) or {}
        report = data.get("report")
        if not report:
            return jsonify({"error": "No report data provided."}), 400
        from email_service import build_html_report
        html_content = build_html_report(report)
        filename = "security-report.html"
        target = report.get("url") or report.get("targetDomain") or ""
        if target:
            safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in str(target))[:40]
            filename = f"security-report-{safe}.html"
        from flask import Response
        return Response(
            html_content,
            mimetype="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "text/html; charset=utf-8",
            },
        )
    except Exception as err:
        app.logger.exception("Download report error")
        return jsonify({"error": "Failed to generate report."}), 500


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


def _parse_curl(raw_curl: str) -> dict:
    """Parse a curl command string into method, url, headers, and body.

    No shell execution — safe tokenisation only via shlex.
    Raises ValueError on invalid input.
    """
    if not raw_curl or not isinstance(raw_curl, str):
        raise ValueError("Empty curl command.")

    text = raw_curl.strip()
    # Normalise line continuations (backslash-newline)
    text = text.replace("\\\n", " ").replace("\\\r\n", " ")

    try:
        tokens = shlex.split(text, posix=True)
    except ValueError as e:
        raise ValueError(f"Failed to parse curl command: {e}")

    if not tokens:
        raise ValueError("Empty curl command after parsing.")

    # Strip leading 'curl' if present
    if tokens[0].lower() == "curl":
        tokens = tokens[1:]
    if not tokens:
        raise ValueError("No URL or options found in curl command.")

    url = None
    method = None
    headers = {}
    body = None

    skip_flags = {"--location", "-L", "--compressed", "-s", "--silent", "-k", "--insecure", "-v", "--verbose", "--http1.1", "--http2"}

    i = 0
    while i < len(tokens):
        tok = tokens[i]

        if tok in skip_flags:
            i += 1
            continue

        if tok in ("-X", "--request"):
            if i + 1 < len(tokens):
                method = tokens[i + 1].upper()
                i += 2
                continue

        if tok in ("-H", "--header"):
            if i + 1 < len(tokens):
                hval = tokens[i + 1]
                if ":" in hval:
                    key, _, val = hval.partition(":")
                    headers[key.strip()] = val.strip()
                i += 2
                continue

        if tok in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode"):
            if i + 1 < len(tokens):
                body = tokens[i + 1]
                i += 2
                continue

        if tok.startswith("-"):
            # Unknown flag — skip it (and its argument if it looks like a flag with value)
            i += 1
            continue

        # Positional argument — treat as URL if we don't have one yet
        if url is None:
            url = tok

        i += 1

    if not url:
        raise ValueError("No URL found in curl command.")

    # Default method
    if method is None:
        method = "POST" if body else "GET"

    return {"url": url, "method": method, "headers": headers, "body": body}


def _parse_sse_body(body_str):
    """Parse Server-Sent Events (SSE) body into a list of events.
    Each event: { "event": str, "data": str or dict (if JSON), "id": str or None, "retry": str or None }
    """
    if not body_str or not isinstance(body_str, str):
        return []
    # SSE: blocks separated by blank lines; lines are event:, data:, id:, retry:
    blocks = re.split(r"\n\s*\n", body_str.strip())
    events = []
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        ev = {"event": None, "data": None, "id": None, "retry": None}
        data_lines = []
        for line in block.split("\n"):
            if line.startswith("event:"):
                ev["event"] = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].strip())
            elif line.startswith("id:"):
                ev["id"] = line[3:].strip() or None
            elif line.startswith("retry:"):
                ev["retry"] = line[6:].strip() or None
        if data_lines:
            data_joined = "\n".join(data_lines)
            try:
                ev["data"] = json.loads(data_joined)
            except Exception:
                ev["data"] = data_joined
        if ev["event"] is not None or ev["data"] is not None:
            events.append(ev)
    return events


_SESSION_KEYS = [
    "sessionId", "session_id", "sessionID", "SessionId",
    "token", "accessToken", "access_token", "accesstoken",
    "id_token", "idToken", "refresh_token", "refreshToken",
    "auth_token", "authToken", "jwt", "bearer",
    "txnToken", "txn_token", "ssoToken", "sso_token",
]


def _extract_tokens_from_body(body_str):
    """Pull session/token values out of a JSON response body."""
    found = {}
    if not body_str:
        return found
    try:
        data = json.loads(body_str)
    except Exception:
        return found

    def _walk(obj, prefix=""):
        if not isinstance(obj, dict):
            return
        for key, val in obj.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(val, str) and val and any(
                k.lower() == key.lower() for k in _SESSION_KEYS
            ):
                found[key] = val
            if isinstance(val, dict):
                _walk(val, path)
    _walk(data)
    return found


def _extract_tokens_from_headers(headers_dict):
    """Pull session/token values out of response headers (e.g. X-Session-Id, Authorization).
    Uses canonical keys from _SESSION_KEYS so {{sessionId}} etc. work in the next curl."""
    found = {}
    if not headers_dict or not isinstance(headers_dict, dict):
        return found
    for hname, hval in headers_dict.items():
        if not hval or not isinstance(hval, str):
            continue
        val = hval.strip()
        if not val:
            continue
        lname = hname.lower().strip()
        # Authorization: Bearer <token> or Token <token>
        if lname == "authorization":
            m = re.match(r"(?:Bearer|Token)\s+(.+)", val, re.IGNORECASE)
            if m:
                found["bearer"] = m.group(1).strip()
                found["token"] = m.group(1).strip()
            continue
        # Map header name to a canonical session key (match _SESSION_KEYS)
        # e.g. x-session-id -> sessionId, x-auth-token -> authToken
        stripped = re.sub(r"[^a-z]", "", lname)
        for sk in _SESSION_KEYS:
            sk_stripped = re.sub(r"[^a-z]", "", sk.lower())
            if sk_stripped and sk_stripped in stripped:
                found[sk] = val
                break
    return found


def _inject_placeholders(raw_curl, token_map):
    """Replace {{key}} placeholders in a curl string with token values."""
    if not token_map or not raw_curl:
        return raw_curl

    result = raw_curl

    # Exact match: {{sessionId}} etc.
    for key, val in token_map.items():
        result = result.replace("{{" + key + "}}", val)

    # Case-insensitive match
    for key, val in token_map.items():
        pattern = re.compile(r"\{\{" + re.escape(key) + r"\}\}", re.IGNORECASE)
        result = pattern.sub(val, result)

    # {{auto}} and {{token}} → first available token
    first_val = next(iter(token_map.values()), "")
    result = re.sub(r"\{\{auto\}\}", first_val, result, flags=re.IGNORECASE)
    result = re.sub(r"\{\{token\}\}", first_val, result, flags=re.IGNORECASE)

    return result


_SESSION_KEYS_LOWER = [k.lower() for k in _SESSION_KEYS]


def _auto_inject_into_headers(headers, token_map):
    """Auto-replace token values inside parsed headers.

    - Authorization: Bearer <old>  →  Bearer <new_token>
    - Any header whose name matches a session key and has a value → replace it
    """
    if not token_map or not headers:
        return headers, []

    first_val = next(iter(token_map.values()), "")
    injected = []

    new_headers = {}
    for hname, hval in headers.items():
        lname = hname.lower()

        # Authorization: Bearer <something>  →  replace bearer value
        if lname == "authorization" and first_val:
            # Bearer xyz  →  Bearer <new>
            new_hval, count = re.subn(
                r"(Bearer\s+)\S+", r"\g<1>" + first_val, hval, flags=re.IGNORECASE
            )
            if count:
                new_headers[hname] = new_hval
                injected.append(f"Authorization Bearer → {first_val}")
                continue
            # token xyz  →  token <new>
            new_hval, count = re.subn(
                r"(token\s+)\S+", r"\g<1>" + first_val, hval, flags=re.IGNORECASE
            )
            if count:
                new_headers[hname] = new_hval
                injected.append(f"Authorization token → {first_val}")
                continue

        # Header name matches a session key (e.g. x-session-id, x-auth-token)
        stripped = re.sub(r"[^a-z]", "", lname)
        for sk in _SESSION_KEYS_LOWER:
            sk_stripped = re.sub(r"[^a-z]", "", sk)
            if sk_stripped and sk_stripped in stripped:
                matching_val = token_map.get(sk) or first_val
                if matching_val and hval != matching_val:
                    new_headers[hname] = matching_val
                    injected.append(f"{hname} → {matching_val}")
                    break
        else:
            new_headers[hname] = hval
            continue
        # if we broke out of the for loop (match found), already set, skip else
        continue

    return new_headers, injected


def _auto_inject_into_body(body, token_map):
    """Auto-replace token fields inside a JSON request body."""
    if not token_map or not body:
        return body, []

    try:
        data = json.loads(body)
    except Exception:
        return body, []

    if not isinstance(data, dict):
        return body, []

    injected = []
    first_val = next(iter(token_map.values()), "")

    def _walk_replace(obj):
        if not isinstance(obj, dict):
            return
        for key in list(obj.keys()):
            val = obj[key]
            klower = key.lower()
            # Check if this key matches any session/token key
            if any(klower == sk.lower() for sk in _SESSION_KEYS):
                # Replace if empty, placeholder, or different from the new token
                matching_val = None
                for tk, tv in token_map.items():
                    if tk.lower() == klower:
                        matching_val = tv
                        break
                if not matching_val:
                    matching_val = first_val
                if matching_val and (not val or isinstance(val, str)):
                    if val != matching_val:
                        obj[key] = matching_val
                        injected.append(f"body.{key} → {matching_val}")
            elif isinstance(val, dict):
                _walk_replace(val)

    _walk_replace(data)

    if injected:
        return json.dumps(data), injected
    return body, []


def _auto_inject_into_url(url, token_map):
    """Auto-replace token-like query parameters in the URL."""
    if not token_map or not url or "?" not in url:
        return url, []

    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    first_val = next(iter(token_map.values()), "")
    injected = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    changed = False

    for pname in list(params.keys()):
        plower = pname.lower()
        if any(plower == sk.lower() for sk in _SESSION_KEYS):
            matching_val = None
            for tk, tv in token_map.items():
                if tk.lower() == plower:
                    matching_val = tv
                    break
            if not matching_val:
                matching_val = first_val
            if matching_val:
                params[pname] = [matching_val]
                injected.append(f"url.{pname} → {matching_val}")
                changed = True

    if changed:
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        return new_url, injected

    return url, []


def _do_execute_curl(raw_curl, token_map=None):
    """Shared logic: parse curl, optionally inject tokens, execute, return dict."""
    auto_injections = []

    # Step 1: Replace {{placeholder}} syntax
    if token_map:
        raw_curl = _inject_placeholders(raw_curl, token_map)

    parsed = _parse_curl(raw_curl)
    target_url = parsed["url"]
    if not _validate_url_scheme(target_url):
        raise ValueError("Invalid URL scheme. Only http:// and https:// are allowed.")

    method = parsed["method"]
    hdrs = parsed["headers"]
    body = parsed["body"]

    # Step 2: Smart auto-injection into headers, body, URL
    if token_map:
        hdrs, h_inj = _auto_inject_into_headers(hdrs, token_map)
        auto_injections.extend(h_inj)

        if body:
            body, b_inj = _auto_inject_into_body(body, token_map)
            auto_injections.extend(b_inj)

        target_url, u_inj = _auto_inject_into_url(target_url, token_map)
        auto_injections.extend(u_inj)

    from config import SCANNER_TIMEOUT

    kwargs = {
        "url": target_url,
        "headers": hdrs,
        "timeout": SCANNER_TIMEOUT,
        "verify": False,
        "allow_redirects": True,
    }
    if body is not None:
        kwargs["data"] = body

    resp = http_requests.request(method, **kwargs)
    resp_body = resp.text
    is_json = False
    try:
        resp.json()
        is_json = True
    except Exception:
        pass

    resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    is_sse = (
        resp_headers_lower.get("content-type", "").split(";")[0].strip() == "text/event-stream"
        or ("event:" in resp_body and "data:" in resp_body)
    )
    sse_events = _parse_sse_body(resp_body) if is_sse else []

    result = {
        "success": True,
        "request": {
            "url": target_url,
            "method": method,
            "headers": {k: v for k, v in hdrs.items()},
            "hasBody": body is not None,
            "body": body,
        },
        "response": {
            "statusCode": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp_body,
            "isJson": is_json,
            "sseEvents": sse_events if sse_events else None,
        },
    }

    if auto_injections:
        result["autoInjections"] = auto_injections

    return result


@app.route("/api/execute-curl", methods=["POST", "OPTIONS"])
def execute_curl():
    """Execute a parsed curl command via requests and return the response."""
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(silent=True) or {}
        raw_curl = (data.get("curlCommand") or "").strip()
        if not raw_curl:
            return jsonify({"error": "Missing curlCommand in request body."}), 400

        token_map = data.get("previousTokens") or None

        try:
            result = _do_execute_curl(raw_curl, token_map)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except http_requests.exceptions.Timeout:
            return jsonify({"error": "Request timed out.", "statusCode": 504}), 504
        except http_requests.exceptions.ConnectionError:
            return jsonify({"error": "Connection failed. Check the URL and try again.", "statusCode": 502}), 502

        return jsonify(result)

    except Exception as err:
        app.logger.exception("Execute-curl error")
        return jsonify({"error": "Server error. Please try again."}), 500


@app.route("/api/execute-curl-chain", methods=["POST", "OPTIONS"])
def execute_curl_chain():
    """Execute multiple curls sequentially, passing tokens from each to the next."""
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(silent=True) or {}
        curls = data.get("curls")
        if not curls or not isinstance(curls, list):
            return jsonify({"error": "Missing 'curls' array in request body."}), 400

        collected_tokens = {}
        results = []

        for i, item in enumerate(curls):
            curl_id = item.get("id", i + 1)
            raw = (item.get("curlCommand") or "").strip()
            if not raw:
                results.append({"id": curl_id, "skipped": True})
                continue

            try:
                result = _do_execute_curl(raw, collected_tokens if collected_tokens else None)
                # Extract tokens from this response (body + headers) for next curls
                resp = result.get("response", {})
                resp_body = resp.get("body", "")
                resp_headers = resp.get("headers", {})
                new_tokens = _extract_tokens_from_body(resp_body)
                new_tokens.update(_extract_tokens_from_headers(resp_headers))
                collected_tokens.update(new_tokens)
                result["id"] = curl_id
                result["injectedTokens"] = list(collected_tokens.keys())
                results.append(result)
            except ValueError as e:
                results.append({"id": curl_id, "error": str(e)})
            except http_requests.exceptions.Timeout:
                results.append({"id": curl_id, "error": "Request timed out.", "statusCode": 504})
            except http_requests.exceptions.ConnectionError:
                results.append({"id": curl_id, "error": "Connection failed.", "statusCode": 502})
            except Exception as e:
                results.append({"id": curl_id, "error": f"Error: {e}"})

        return jsonify({
            "success": True,
            "results": results,
            "collectedTokens": collected_tokens,
        })

    except Exception as err:
        app.logger.exception("Execute-curl-chain error")
        return jsonify({"error": "Server error. Please try again."}), 500






if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=(ENV == "development"))
