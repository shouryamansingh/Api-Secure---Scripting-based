"""
Security scanner: headers, CORS, SSL/TLS, server disclosure, error handling, URL tampering.
Uses config for timeouts when available.
"""
import os
import re
import ssl
import socket
import time
import urllib.parse
from datetime import datetime, timezone

import requests

try:
    from config import SCANNER_TIMEOUT
except ImportError:
    SCANNER_TIMEOUT = 15

SSL_LABS_EMAIL = os.environ.get("SSL_LABS_EMAIL", "").strip()

try:
    from urllib3.exceptions import InsecureRequestWarning
    import urllib3
    urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass

# HTTP-header analysis rules live in security-controls/http-header-analysis/
# and are loaded by header_rules.py. PyYAML is a hard dependency for scanning
# — if it failed to load we want a clear error, not silent fallback drift.
import header_rules as _hr

if not _hr.LOADED:
    raise RuntimeError(
        "HTTP header analysis rules failed to load from "
        "security-controls/http-header-analysis/: "
        f"{_hr.LOAD_ERROR}. Install PyYAML (pip install PyYAML) and ensure "
        "the rule files are present."
    )

REQUIRED_HEADERS = _hr.REQUIRED_HEADERS
_DEPRECATED_HEADERS = _hr.DEPRECATED_HEADERS
_INFO_LEAK_HEADERS = _hr.INFO_LEAK_HEADERS
_PP_SENSITIVE_FEATURES = _hr.PP_SENSITIVE_FEATURES
_finding = _hr.make_finding


def get_domain(url_str: str) -> str:
    try:
        s = url_str.strip()
        s = re.sub(r"^https?://", "", s, flags=re.I)
        s = re.sub(r"^www\.", "", s, flags=re.I)
        return s.split("/")[0].split("?")[0] or "Unknown"
    except Exception:
        return "Unknown"


def _normalize_headers(raw_headers) -> dict:
    """Build a dict with lowercase keys and string values for reliable lookup.
    Pass a plain dict (e.g. dict(resp.headers)) to avoid CaseInsensitiveDict iteration issues.
    """
    if not raw_headers:
        return {}
    # Use a plain dict so iteration is reliable (requests uses CaseInsensitiveDict which can misbehave)
    try:
        if not isinstance(raw_headers, dict):
            raw_headers = dict(raw_headers)
    except Exception:
        raw_headers = {}
    out = {}
    for k, v in raw_headers.items():
        key = k.lower().strip() if isinstance(k, str) else str(k).lower().strip()
        if key in out:
            continue
        if isinstance(v, (list, tuple)):
            val = v[0] if v else ""
        else:
            val = v
        out[key] = (str(val).strip() if val is not None else "")
    return out


def get_header(headers, name: str):
    """Get a header value; headers dict should have lowercase keys (use _normalize_headers)."""
    if not headers:
        return None
    name_lower = name.lower().strip()
    val = headers.get(name_lower)
    if val is None or (isinstance(val, str) and val == ""):
        return None
    if isinstance(val, (list, tuple)):
        return val[0].strip() if val else None
    return str(val).strip() or None


def fetch_url(url: str, origin=None, follow_redirects=True, extra_headers=None, method="GET", body=None):
    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if origin and str(origin).strip():
        req_headers["Origin"] = str(origin).strip()
    if extra_headers and isinstance(extra_headers, dict):
        for k, v in extra_headers.items():
            if k and v is not None and str(v).strip():
                req_headers[k] = str(v).strip()
    method = (method or "GET").upper()
    kwargs = {
        "url": url,
        "allow_redirects": follow_redirects,
        "headers": req_headers,
        "timeout": SCANNER_TIMEOUT,
        "verify": False,
    }
    if body is not None and method in ("POST", "PUT", "PATCH"):
        kwargs["data"] = body
    resp = requests.request(method, **kwargs)
    # Use plain dict so header iteration is reliable on all platforms
    out_headers = _normalize_headers(dict(resp.headers))
    return out_headers, resp.text, resp.status_code


def fetch_options(url: str, origin: str, extra_headers=None, request_method="GET"):
    """Send OPTIONS preflight request with Origin. Returns normalized headers or None on failure."""
    if not origin or not str(origin).strip():
        return None
    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Origin": str(origin).strip(),
        "Access-Control-Request-Method": (request_method or "GET").upper(),
        "Accept": "*/*",
    }
    if extra_headers and isinstance(extra_headers, dict):
        for k, v in extra_headers.items():
            if k and v is not None and str(v).strip():
                req_headers[k] = str(v).strip()
    try:
        resp = requests.options(
            url,
            headers=req_headers,
            timeout=min(10, SCANNER_TIMEOUT),
            verify=False,
        )
        return _normalize_headers(dict(resp.headers))
    except Exception:
        return None


def _count_security_headers_present(normalized_headers: dict) -> int:
    """Count how many of REQUIRED_HEADERS are present (non-empty) in the normalized dict."""
    return sum(1 for name in REQUIRED_HEADERS if get_header(normalized_headers, name))


def _parse_csp_directives(value: str) -> dict:
    """Parse a CSP header value into a dict of directive -> list of sources."""
    directives = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


def _deep_analyze_csp(value: str) -> list:
    """Analyze Content-Security-Policy value for weaknesses. Returns list of finding dicts."""
    findings = []
    if not value or not value.strip():
        return [_finding("csp-empty")]

    directives = _parse_csp_directives(value)

    if "default-src" not in directives:
        findings.append(_finding("csp-no-default-src"))

    script_src = directives.get("script-src", directives.get("default-src", []))
    style_src = directives.get("style-src", directives.get("default-src", []))
    img_src = directives.get("img-src", directives.get("default-src", []))
    connect_src = directives.get("connect-src", directives.get("default-src", []))
    font_src = directives.get("font-src", directives.get("default-src", []))

    # ── script-src checks ──
    if "'unsafe-inline'" in script_src:
        findings.append(_finding("csp-unsafe-inline"))
    if "'unsafe-eval'" in script_src:
        findings.append(_finding("csp-unsafe-eval"))
    if "'unsafe-hashes'" in script_src:
        findings.append(_finding("csp-unsafe-hashes"))
    if "blob:" in script_src:
        findings.append(_finding("csp-blob-script"))
    if "data:" in script_src:
        findings.append(_finding("csp-data-script"))

    # ── http: mixed content in any directive ──
    for directive_name, sources in directives.items():
        if directive_name in ("report-uri", "report-to"):
            continue
        http_sources = [s for s in sources if s.startswith("http://")]
        if http_sources:
            findings.append(_finding(
                "csp-http",
                id_override=f"csp-http-{directive_name}",
                directive_name=directive_name,
                http_source=http_sources[0][:50],
            ))
            break

    # ── wildcard in ALL directives (not just first) ──
    wildcard_directives = []
    for directive_name, sources in directives.items():
        if directive_name in ("report-uri", "report-to"):
            continue
        if "*" in sources:
            wildcard_directives.append(directive_name)
    if wildcard_directives:
        directives_display = (
            ", ".join(wildcard_directives[:3])
            + (f" (+{len(wildcard_directives)-3} more)" if len(wildcard_directives) > 3 else "")
        )
        findings.append(_finding(
            "csp-wildcard",
            directives_display=directives_display,
            directives_full=", ".join(wildcard_directives),
        ))

    # ── data: in non-script directives ──
    if "data:" in img_src:
        findings.append(_finding("csp-data-img"))
    if "data:" in font_src:
        findings.append(_finding("csp-data-font"))
    if "data:" in connect_src:
        findings.append(_finding("csp-data-connect"))

    # ── missing critical directives ──
    if "base-uri" not in directives:
        findings.append(_finding("csp-no-base-uri"))
    if "object-src" not in directives and "'none'" not in directives.get("default-src", []):
        findings.append(_finding("csp-no-object-src"))
    if "form-action" not in directives:
        findings.append(_finding("csp-no-form-action"))
    if "frame-ancestors" not in directives:
        findings.append(_finding("csp-no-frame-ancestors"))
    if "upgrade-insecure-requests" not in directives:
        findings.append(_finding("csp-no-upgrade-insecure"))

    # ── style-src checks ──
    if "'unsafe-inline'" in style_src:
        findings.append(_finding("csp-unsafe-inline-style"))

    # ── deprecated reporting ──
    if "report-uri" in directives and "report-to" not in directives:
        findings.append(_finding("csp-deprecated-report-uri"))

    return findings


def _deep_analyze_hsts(value: str) -> list:
    """Analyze Strict-Transport-Security value for weaknesses."""
    findings = []
    if not value or not value.strip():
        return [_finding("hsts-empty")]

    val_lower = value.lower()
    max_age = None
    match = re.search(r"max-age\s*=\s*(\d+)", val_lower)
    if match:
        max_age = int(match.group(1))
    else:
        findings.append(_finding("hsts-no-max-age"))
        return findings

    if max_age == 0:
        findings.append(_finding("hsts-max-age-zero"))
    elif max_age < 2592000:
        findings.append(_finding("hsts-max-age-short", max_age=max_age, days=max_age // 86400))
    elif max_age < 31536000:
        findings.append(_finding("hsts-max-age-moderate", max_age=max_age, days=max_age // 86400))

    if "includesubdomains" not in val_lower:
        findings.append(_finding("hsts-no-subdomains"))
    if "preload" not in val_lower:
        findings.append(_finding("hsts-no-preload"))
    return findings


def _deep_analyze_x_frame_options(value: str) -> list:
    findings = []
    if not value or not value.strip():
        return []
    val_upper = value.strip().upper()
    if "ALLOW-FROM" in val_upper:
        findings.append(_finding("xfo-allow-from"))
    elif val_upper == "SAMEORIGIN":
        findings.append(_finding("xfo-sameorigin"))
    elif val_upper not in ("DENY", "SAMEORIGIN"):
        findings.append(_finding("xfo-invalid", value_trunc=value.strip()[:40]))
    return findings


_VALID_REFERRER_POLICIES = {
    "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
    "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url", ""
}


def _deep_analyze_referrer_policy(value: str) -> list:
    findings = []
    if not value or not value.strip():
        return []
    val_lower = value.strip().lower()
    parts = [p.strip() for p in val_lower.split(",")]
    unique_parts = list(dict.fromkeys(parts))
    if len(parts) != len(unique_parts):
        findings.append(_finding("rp-duplicate", value_trunc=value.strip()[:80]))

    invalid_values = [p for p in unique_parts if p and p not in _VALID_REFERRER_POLICIES]
    if invalid_values:
        findings.append(_finding("rp-invalid", invalid_display=", ".join(invalid_values[:2])))

    effective = unique_parts[-1] if unique_parts else val_lower
    if effective == "unsafe-url":
        findings.append(_finding("rp-unsafe-url"))
    elif effective == "no-referrer-when-downgrade":
        findings.append(_finding("rp-downgrade"))
    elif effective in ("origin-when-cross-origin", "origin"):
        findings.append(_finding("rp-origin-only", effective=effective))
    return findings


def _deep_analyze_x_xss_protection(value: str) -> list:
    findings = []
    if not value or not value.strip():
        return []
    val_lower = value.strip().lower()
    if val_lower.startswith("0"):
        findings.append(_finding("xxss-disabled"))
    elif "mode=block" not in val_lower and val_lower.startswith("1"):
        findings.append(_finding("xxss-no-block"))
    return findings


def _deep_analyze_permissions_policy(value: str) -> list:
    findings = []
    if not value or not value.strip():
        return []
    val_lower = value.strip().lower()

    for feature, desc in _PP_SENSITIVE_FEATURES.items():
        if f"{feature}=*" in val_lower:
            findings.append(_finding(
                "pp-permissive",
                id_override=f"pp-permissive-{feature}",
                feature=feature, desc=desc,
            ))
        elif f"{feature}=(self)" in val_lower:
            findings.append(_finding(
                "pp-self",
                id_override=f"pp-self-{feature}",
                feature=feature, desc=desc,
            ))

    if "interest-cohort=()" not in val_lower and "browsing-topics=()" not in val_lower:
        findings.append(_finding("pp-no-floc-block"))

    return findings


def _deep_analyze_coep(value: str) -> list:
    findings = []
    if not value or not value.strip():
        return []
    val_lower = value.strip().lower()
    if val_lower == "unsafe-none":
        findings.append(_finding("coep-unsafe-none"))
    return findings


def _deep_analyze_coop(value: str) -> list:
    findings = []
    if not value or not value.strip():
        return []
    val_lower = value.strip().lower()
    if val_lower == "unsafe-none":
        findings.append(_finding("coop-unsafe-none"))
    elif val_lower == "same-origin-allow-popups":
        findings.append(_finding("coop-allow-popups"))
    return findings


def _deep_analyze_x_content_type_options(value: str) -> list:
    findings = []
    if not value or not value.strip():
        return []
    if value.strip().lower() != "nosniff":
        findings.append(_finding("xcto-invalid", value_trunc=value.strip()[:40]))
    return findings


def _deep_analyze_x_permitted_cross_domain(value: str) -> list:
    findings = []
    if not value or not value.strip():
        return []
    val_lower = value.strip().lower()
    if val_lower not in ("none",):
        if val_lower in ("master-only", "by-content-type", "by-ftp-filename", "all"):
            findings.append(_finding("xpcd-permissive", value=value.strip()))
    return findings


_DEEP_ANALYZERS = {
    "Content-Security-Policy": _deep_analyze_csp,
    "Strict-Transport-Security": _deep_analyze_hsts,
    "X-Frame-Options": _deep_analyze_x_frame_options,
    "Referrer-Policy": _deep_analyze_referrer_policy,
    "X-XSS-Protection": _deep_analyze_x_xss_protection,
    "Permissions-Policy": _deep_analyze_permissions_policy,
    "Cross-Origin-Embedder-Policy": _deep_analyze_coep,
    "Cross-Origin-Opener-Policy": _deep_analyze_coop,
    "X-Content-Type-Options": _deep_analyze_x_content_type_options,
    "X-Permitted-Cross-Domain-Policies": _deep_analyze_x_permitted_cross_domain,
}


def build_evaluated_headers(original_headers: dict) -> dict:
    evaluated = {}
    for name in REQUIRED_HEADERS:
        value = get_header(original_headers, name)
        present = bool(value)

        findings = []
        if present:
            analyzer = _DEEP_ANALYZERS.get(name)
            if analyzer:
                findings = analyzer(str(value))

        has_high = any(f.get("severity") in ("high", "critical") for f in findings)
        has_medium = any(f.get("severity") == "medium" for f in findings)
        has_low = any(f.get("severity") in ("low", "info") for f in findings)

        if not present:
            severity = "critical"
        elif has_high:
            severity = "warning"
        elif has_medium:
            severity = "warning"
        elif has_low:
            severity = "ok"
        else:
            severity = "ok"

        total_deduction = sum(f.get("deduction", 0) for f in findings)

        finding_titles = [f["title"] for f in findings if f.get("severity") in ("high", "medium", "critical")]
        if finding_titles:
            issue_text = f"Present with issues: {'; '.join(finding_titles[:3])}"
        elif findings:
            minor_titles = [f["title"] for f in findings]
            issue_text = f"Configured (minor notes: {'; '.join(minor_titles[:2])})"
        elif present:
            issue_text = "Configured"
        else:
            issue_text = f"Missing {name} header"

        evaluated[name] = {
            "present": present,
            "value": value if value else None,
            "severity": severity,
            "findings": findings,
            "deduction": total_deduction,
            "description": f"Security header: {name}",
            "issue": issue_text,
            "impact": ("High security risk" if not present
                       else "Reduced protection" if has_high or has_medium
                       else "Low risk"),
            "recommendation": (f"Add {name} header" if not present
                               else "Review configuration — weaknesses detected" if has_high or has_medium
                               else "Review configuration" if findings
                               else "No action needed"),
        }
    return evaluated


# _DEPRECATED_HEADERS and _INFO_LEAK_HEADERS now come from
# security-controls/http-header-analysis/{deprecated,info-leak}-headers.yaml
# via header_rules.py (bound at the top of this module).

_INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)


def _detect_server_disclosure(headers: dict) -> list:
    """Comprehensive detection of server info leaks, deprecated headers, and information disclosure."""
    findings = []

    # ── Server header ──
    server_val = get_header(headers, "Server")
    if server_val:
        server_str = str(server_val).strip()
        has_version = bool(re.search(r"/[\d.]", server_str))
        if has_version:
            findings.append(_finding("server-version-disclosure", server_trunc60=server_str[:60]))
        else:
            findings.append(_finding("server-name-disclosure", server_trunc40=server_str[:40]))

    # ── Deprecated headers ──
    for hdr_name, info in _DEPRECATED_HEADERS.items():
        val = get_header(headers, hdr_name)
        if val:
            detail = info["detail"]
            if hdr_name == "X-Powered-By":
                detail = f"Value: {str(val)[:50]}. {detail}"
            findings.append({"id": f"deprecated-{hdr_name.lower()}", "severity": info["severity"],
                             "title": info["title"], "detail": detail})

    # ── Information leakage headers ──
    for hdr_name, info in _INFO_LEAK_HEADERS.items():
        val = get_header(headers, hdr_name)
        if val:
            findings.append({"id": f"info-leak-{hdr_name.lower()}", "severity": info["severity"],
                             "title": f"{info['title']} ({str(val)[:40]})", "detail": info["detail"]})

    # ── Internal IP address in any header ──
    for hdr_name in headers:
        val = str(headers.get(hdr_name, ""))
        match = _INTERNAL_IP_RE.search(val)
        if match:
            findings.append(_finding(
                "internal-ip",
                id_override=f"internal-ip-{hdr_name}",
                hdr_name=hdr_name, ip=match.group(),
            ))

    # ── Version numbers in non-standard headers ──
    skip_for_version = {"server", "content-type", "date", "etag", "content-length",
                        "content-security-policy", "strict-transport-security", "set-cookie",
                        "cache-control", "expires", "last-modified", "accept-ranges"}
    for hdr_name in headers:
        if hdr_name.lower() in skip_for_version:
            continue
        val = str(headers.get(hdr_name, ""))
        ver_match = re.search(r"(?:^|[\s/])(\d+\.\d+\.\d+)", val)
        if ver_match and hdr_name.lower() not in ("etag",):
            findings.append(_finding(
                "version-in-header",
                id_override=f"version-{hdr_name}",
                hdr_name=hdr_name, version=ver_match.group(1),
            ))
            break

    # ── Missing best-practice headers (not in REQUIRED_HEADERS but recommended) ──
    if not get_header(headers, "Cross-Origin-Resource-Policy"):
        findings.append(_finding("missing-corp"))

    cache_control = get_header(headers, "Cache-Control") or ""
    content_type = get_header(headers, "Content-Type") or ""
    is_api = "json" in content_type.lower() or "xml" in content_type.lower()
    if is_api and "no-store" not in cache_control.lower():
        cache_state = f"'{cache_control[:50]}'" if cache_control else "no Cache-Control header set"
        findings.append(_finding("cache-api-no-store", cache_state=cache_state))

    return findings


def _detect_cookie_issues(resp) -> list:
    """Analyze Set-Cookie headers for security weaknesses."""
    findings = []
    try:
        raw_headers = resp.raw.headers if hasattr(resp, "raw") and hasattr(resp.raw, "headers") else None
        if raw_headers is None:
            return findings
        cookies = []
        items = raw_headers.items() if hasattr(raw_headers, "items") else []
        for name, val in items:
            if name.lower() == "set-cookie":
                cookies.append(str(val))
        if not cookies:
            return findings

        for cookie_str in cookies:
            parts = cookie_str.split(";")
            name_val = parts[0].strip()
            cookie_name = name_val.split("=")[0].strip() if "=" in name_val else name_val
            attrs_lower = cookie_str.lower()

            if "secure" not in attrs_lower:
                findings.append({
                    "id": f"cookie-no-secure-{cookie_name[:20]}", "severity": "high",
                    "title": f"Cookie '{cookie_name[:30]}' missing Secure flag",
                    "detail": f"The cookie '{cookie_name[:30]}' can be sent over unencrypted HTTP connections, "
                              "allowing attackers on the network to intercept it. Add the Secure attribute.",
                })
            if "httponly" not in attrs_lower:
                findings.append({
                    "id": f"cookie-no-httponly-{cookie_name[:20]}", "severity": "medium",
                    "title": f"Cookie '{cookie_name[:30]}' missing HttpOnly flag",
                    "detail": f"The cookie '{cookie_name[:30]}' is accessible to JavaScript via document.cookie. "
                              "If an XSS vulnerability exists, attackers can steal this cookie. Add HttpOnly.",
                })
            if "samesite" not in attrs_lower:
                findings.append({
                    "id": f"cookie-no-samesite-{cookie_name[:20]}", "severity": "medium",
                    "title": f"Cookie '{cookie_name[:30]}' missing SameSite attribute",
                    "detail": f"Without SameSite, the cookie '{cookie_name[:30]}' is sent on all cross-site requests, "
                              "making CSRF attacks easier. Set SameSite=Strict or SameSite=Lax.",
                })
            if "samesite=none" in attrs_lower and "secure" not in attrs_lower:
                findings.append({
                    "id": f"cookie-samesite-none-no-secure-{cookie_name[:20]}", "severity": "high",
                    "title": f"Cookie '{cookie_name[:30]}': SameSite=None without Secure",
                    "detail": "SameSite=None requires the Secure flag. Browsers will reject this cookie entirely, "
                              "breaking functionality.",
                })
            if cookie_name.startswith("__Secure-") and "secure" not in attrs_lower:
                findings.append({
                    "id": f"cookie-prefix-secure-{cookie_name[:20]}", "severity": "medium",
                    "title": f"Cookie '{cookie_name[:30]}' uses __Secure- prefix without Secure flag",
                    "detail": "Cookies with the __Secure- prefix must have the Secure attribute. "
                              "Browsers will reject this cookie.",
                })
            if cookie_name.startswith("__Host-"):
                if "secure" not in attrs_lower or "path=/" not in attrs_lower.replace(" ", ""):
                    findings.append({
                        "id": f"cookie-prefix-host-{cookie_name[:20]}", "severity": "medium",
                        "title": f"Cookie '{cookie_name[:30]}' uses __Host- prefix incorrectly",
                        "detail": "Cookies with the __Host- prefix must have Secure, Path=/, and no Domain attribute. "
                                  "Browsers will reject non-conforming cookies.",
                    })

    except Exception:
        pass
    return findings


def _detect_duplicate_headers(resp) -> list:
    """Detect duplicate response headers from the raw urllib3 response."""
    findings = []
    try:
        raw_headers = resp.raw.headers if hasattr(resp, "raw") and hasattr(resp.raw, "headers") else None
        if raw_headers is None:
            return findings
        seen = {}
        items = raw_headers.items() if hasattr(raw_headers, "items") else []
        for name, _val in items:
            key = name.lower()
            if key == "set-cookie":
                continue
            if key in seen:
                seen[key] += 1
            else:
                seen[key] = 1
        for key, count in seen.items():
            if count > 1:
                findings.append({
                    "id": f"dup-{key}", "severity": "low",
                    "title": f"Duplicate header: {key} (sent {count} times)",
                    "detail": f"The '{key}' header appears {count} times in the response. "
                              "Browsers may concatenate or use only the last value, potentially "
                              "causing unexpected security behaviour. "
                              "Ensure the server sends each header exactly once.",
                })
    except Exception:
        pass
    return findings


def _headers_from_response(resp) -> dict:
    """Build normalized headers dict from a requests Response. Use plain dict for reliable iteration."""
    raw = dict(resp.headers)
    return _normalize_headers(raw)


def run_headers_analysis(url: str, extra_headers=None, method="GET", body=None) -> dict:
    target_domain = get_domain(url)
    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if extra_headers and isinstance(extra_headers, dict):
        for k, v in extra_headers.items():
            if k and v is not None and str(v).strip():
                req_headers[k] = str(v).strip()
    method = (method or "GET").upper()
    best_headers = {}
    best_resp = None
    extra_findings = []
    for follow_redirects in (True, False):
        try:
            kwargs = {
                "url": url,
                "allow_redirects": follow_redirects,
                "headers": req_headers,
                "timeout": SCANNER_TIMEOUT,
                "verify": False,
            }
            if body is not None and method in ("POST", "PUT", "PATCH"):
                kwargs["data"] = body
            resp = requests.request(method, **kwargs)
            h = _normalize_headers(dict(resp.headers))
            if _count_security_headers_present(h) > _count_security_headers_present(best_headers):
                best_headers = h
                best_resp = resp
            if best_headers and _count_security_headers_present(best_headers) == len(REQUIRED_HEADERS):
                break
        except Exception:
            continue

    if best_resp is not None:
        extra_findings.extend(_detect_duplicate_headers(best_resp))
        extra_findings.extend(_detect_cookie_issues(best_resp))
    extra_findings.extend(_detect_server_disclosure(best_headers))

    evaluated_headers = build_evaluated_headers(best_headers)

    header_list = [{"name": n, **info} for n, info in evaluated_headers.items()]
    critical_count = sum(1 for h in header_list if h["severity"] == "critical")
    warning_count = sum(1 for h in header_list if h["severity"] == "warning")
    ok_count = sum(1 for h in header_list if h["severity"] == "ok")
    total_headers = len(REQUIRED_HEADERS)

    total_deduction = sum(h.get("deduction", 0) for h in header_list)
    base_score = round(((ok_count * 10 + warning_count * 5) / total_headers) * 10)
    score = max(0, min(100, base_score - total_deduction))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

    warnings = []
    vulnerabilities = []
    recommendations = []
    for h in header_list:
        if h["severity"] == "warning":
            warnings.append(f"{h['name']}: {h['issue']}")
            recommendations.append(f"{h['name']}: {h['recommendation']}")
        elif h["severity"] == "critical":
            vulnerabilities.append(f"{h['name']}: {h['issue']}")
            recommendations.append(f"{h['name']}: {h['recommendation']}")

    ai_header_notes = f"Security Analysis Summary for {target_domain}:\n\n"
    if critical_count > 0:
        ai_header_notes += f"Critical: {critical_count} essential security headers are missing.\n\n"
    if warning_count > 0:
        ai_header_notes += f"Warnings: {warning_count} headers need attention.\n\n"
    if ok_count > 0:
        ai_header_notes += f"Good: {ok_count} security headers are properly configured.\n\n"
    if score < 60:
        ai_header_notes += f"Overall: POOR ({score}%) - Immediate action required."
    elif score < 80:
        ai_header_notes += f"Overall: MODERATE ({score}%) - Several improvements needed."
    else:
        ai_header_notes += f"Overall: GOOD ({score}%) - Well-configured security."

    return {
        "siteUrl": target_domain,
        "targetDomain": target_domain,
        "originalUrl": url,
        "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "evaluatedHeaders": evaluated_headers,
        "criticalCount": critical_count,
        "warningCount": warning_count,
        "okCount": ok_count,
        "score": score,
        "grade": grade,
        "warnings": warnings,
        "vulnerabilities": vulnerabilities,
        "recommendations": recommendations,
        "aiHeaderNotes": ai_header_notes,
        "aiContentNotes": "Content analysis is available when AI is enabled.",
        "totalHeaders": total_headers,
        "extraFindings": extra_findings,
    }


def analyze_cors_from_response(url: str, origin_sent, headers: dict) -> dict:
    hostname = get_domain(url)
    norm = _normalize_headers(headers)
    acao = norm.get("access-control-allow-origin")
    acac = norm.get("access-control-allow-credentials")
    acam = norm.get("access-control-allow-methods")
    acah = norm.get("access-control-allow-headers")
    aceh = norm.get("access-control-expose-headers")
    vary = (norm.get("vary") or "").lower()

    credentials_interpreted = str(acac or "").lower() == "true"
    configuration = {
        "allowedOrigin": acao if acao is not None else "Not Set",
        "allowedMethods": acam if acam is not None else "Not Set",
        "allowedHeaders": acah if acah is not None else "Not Set",
        "supportsCredentials": credentials_interpreted,
        "supportsCredentialsHeader": (acac or "Not Set").strip() or "Not Set",
        "exposedHeaders": aceh if aceh is not None else "Not Set",
        "varyHeader": vary or "Not Set",
    }

    # Display string for origin sent (passive = no origin)
    origin_display = (origin_sent or "None (passive)").strip() or "None (passive)"
    current_acao_val = (acao or "").strip()
    sent_origin_val = (origin_sent or "").strip()
    # Origin Accepted: when we sent an origin, was it accepted? (ACAO is * or equals sent origin)
    if not sent_origin_val:
        origin_accepted = None  # N/A for passive
    else:
        origin_accepted = bool(current_acao_val == "*" or current_acao_val == sent_origin_val)
    # Origin Reflected: server echoed back exactly the origin we sent (security concern with credentials)
    if not sent_origin_val or not current_acao_val:
        origin_reflected = None
    else:
        origin_reflected = current_acao_val == sent_origin_val

    analysis = {
        "targetDomain": hostname,
        "fullUrl": url,
        "originSent": origin_display,
        "originAccepted": origin_accepted,
        "originReflected": origin_reflected,
        "riskLevel": "Informational",
        "corsStatus": "Enabled" if acao else "Not Enabled",
        "vulnerabilities": [],
        "configuration": configuration,
        "allHeaders": headers or {},
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
    }

    highest_risk = 0
    if acao:
        current_acao = configuration["allowedOrigin"]
        current_acac = configuration["supportsCredentials"]

        if current_acao == "*" and current_acac:
            highest_risk = max(highest_risk, 3)
            analysis["vulnerabilities"].append({
                "severity": "Critical",
                "title": "Wildcard Origin with Credentials",
                "description": "The server allows any origin (`*`) to make authenticated requests. Browsers will send cookies and auth headers from any site.",
                "impact": "Attackers can perform authenticated cross-origin requests from malicious sites, leading to data theft or account takeover.",
                "recommendation": "Never use `*` with Access-Control-Allow-Credentials: true. Use a strict whitelist of origins.",
            })
        origin_hostname = None
        if origin_sent:
            origin_hostname = re.sub(r"^https?://", "", str(origin_sent), flags=re.I).split("/")[0]
        if current_acao == origin_sent and current_acac and origin_hostname and origin_hostname != hostname:
            highest_risk = max(highest_risk, 3)
            analysis["vulnerabilities"].append({
                "severity": "Critical",
                "title": "Reflected Origin with Credentials",
                "description": "The server reflects the incoming Origin header in Access-Control-Allow-Origin, allowing an attacker to bypass same-origin policy.",
                "impact": "Any site can claim an origin and receive credentialed access; attackers can steal or modify user data.",
                "recommendation": "Validate Origin against a strict whitelist; do not reflect it blindly.",
            })
        if current_acao == "*":
            highest_risk = max(highest_risk, 2)
            analysis["vulnerabilities"].append({
                "severity": "Medium",
                "title": "Permissive Wildcard Origin",
                "description": "The `Access-Control-Allow-Origin` header is set to `*`, which allows any website to access this resource in the browser.",
                "impact": "Unauthorized data access, scraping, or abuse—especially if the API serves sensitive data or has rate limits that can be bypassed from many origins.",
                "recommendation": "Replace `*` with a whitelist of trusted origins if the resource is not truly public.",
            })
        if current_acao != "*" and (not vary or "origin" not in vary):
            highest_risk = max(highest_risk, 2)
            analysis["vulnerabilities"].append({
                "severity": "Medium",
                "title": "Cache Poisoning Risk: Missing Vary: Origin",
                "description": "The response varies by Origin but does not include Vary: Origin, so caches may serve one origin's response to another.",
                "impact": "Cache poisoning: a cached CORS response for one origin could be served to a different origin, leaking or corrupting data.",
                "recommendation": "Include Vary: Origin on CORS responses that are not using `*`.",
            })
    else:
        if acac or acam or acah:
            analysis["corsStatus"] = "Misconfigured"
            highest_risk = max(highest_risk, 2)
            analysis["vulnerabilities"].append({
                "severity": "Medium",
                "title": "Ineffective CORS Headers",
                "description": "CORS-related headers are sent but Access-Control-Allow-Origin is missing. Browsers will block cross-origin requests.",
                "impact": "Cross-origin requests may fail; configuration is inconsistent and may confuse developers or mask real CORS behavior.",
                "recommendation": "Either add Access-Control-Allow-Origin or remove the other CORS headers.",
            })

    risk_map = ["Informational", "Low", "Medium", "High"]
    analysis["riskLevel"] = risk_map[highest_risk]
    if highest_risk == 0 and acao:
        analysis["riskLevel"] = "Low"

    # Build recommendations list (best practice)
    recs = [
        "Use a strict allowlist of origins; never use `*` when credentials are involved.",
        "Validate the Origin header server-side against the allowlist; do not reflect it blindly.",
        "Include Vary: Origin when ACAO is not `*` to avoid cache poisoning.",
        "Prefer sending CORS headers on both OPTIONS (preflight) and actual request responses.",
    ]
    if acao and str(acao).strip() == "*":
        recs.insert(0, "Replace wildcard `*` with explicit allowed origins if the resource is not truly public.")
    analysis["recommendations"] = recs

    # Executive summary (1-2 sentences)
    if not acao:
        analysis["executiveSummary"] = (
            f"The API at {hostname} does not send Access-Control-Allow-Origin in the response. "
            "Cross-origin requests from browsers may be blocked by default, or CORS may be configured only for preflight."
        )
    elif current_acao_val == "*" and not configuration["supportsCredentials"]:
        analysis["executiveSummary"] = (
            f"The API's CORS configuration allows any origin to access its resources due to the wildcard `*` in Access-Control-Allow-Origin. "
            "This poses a risk of unauthorized data access or abuse if the API serves sensitive information or has rate limiting."
        )
    elif current_acao_val == "*" and configuration["supportsCredentials"]:
        analysis["executiveSummary"] = (
            "The API uses Access-Control-Allow-Origin: * with credentials enabled. This is invalid and dangerous: "
            "browsers may reject it or allow any origin to make authenticated requests, leading to data theft or account compromise."
        )
    elif origin_reflected:
        analysis["executiveSummary"] = (
            "The server reflects the requested Origin header in Access-Control-Allow-Origin. "
            "With credentials enabled, any site can obtain cross-origin authenticated access; this bypasses same-origin policy and is a critical risk."
        )
    else:
        analysis["executiveSummary"] = (
            f"The API at {hostname} returns Access-Control-Allow-Origin for the tested origin. "
            "Review the configuration table and findings to ensure only trusted origins are allowed and Vary: Origin is set where needed."
        )

    # In simple terms (analogy)
    if current_acao_val == "*":
        analysis["simpleTerms"] = (
            "Think of the API as a house with an open front door (the CORS wildcard). Anyone can walk in and look around. "
            "To protect the house, restrict access to only trusted visitors (specific allowed origins)."
        )
    elif origin_reflected:
        analysis["simpleTerms"] = (
            "The API automatically lets in anyone who claims to be from a certain address (reflected Origin). "
            "An attacker can pretend to be a trusted site and get in. The server should check IDs (validate Origin) against a list of allowed addresses."
        )
    else:
        analysis["simpleTerms"] = (
            "CORS controls which websites can call this API from the browser. "
            "Ensure only your own domains are in the allowlist and that credentials are not exposed to untrusted origins."
        )

    analysis["references"] = [
        "MDN: CORS - https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
        "OWASP: Cross-Site Request Forgery / CORS Misconfiguration",
        "W3C: Fetch Standard (CORS) - https://fetch.spec.whatwg.org/#http-access-control",
    ]

    return analysis


def run_cors_analysis(url: str, origin_sent=None, extra_headers=None, method="GET", body=None) -> dict:
    # Passive: no origin sent. Active: user-provided origin.
    sent_origin = (origin_sent or "").strip() or None
    headers, _, _ = fetch_url(url, origin=sent_origin, extra_headers=extra_headers, method=method, body=body)
    options_headers = None
    cors_from_preflight = False

    # When testing with an origin, also send OPTIONS preflight; merge CORS headers if GET had none
    if sent_origin:
        options_headers = fetch_options(url, sent_origin, extra_headers=extra_headers, request_method=method or "GET")
        if options_headers:
            norm_get = headers if isinstance(headers, dict) else {}
            acao_get = (norm_get.get("access-control-allow-origin") or "").strip()
            acao_opt = options_headers.get("access-control-allow-origin")
            if not acao_get and acao_opt:
                # CORS only in preflight: use OPTIONS response for analysis
                headers = dict(norm_get)
                for k in (
                    "access-control-allow-origin",
                    "access-control-allow-credentials",
                    "access-control-allow-methods",
                    "access-control-allow-headers",
                    "access-control-expose-headers",
                ):
                    if options_headers.get(k):
                        headers[k] = options_headers[k]
                cors_from_preflight = True

    result = analyze_cors_from_response(url, sent_origin or "", headers)
    result["howWeTested"] = (
        "GET request with no Origin header (passive)."
        if not sent_origin
        else f"GET and OPTIONS requests with Origin: {sent_origin}."
    )
    result["corsFromPreflight"] = cors_from_preflight
    return result


# --- Server version disclosure (aligned with n8n: detect headers → stack/versions → risk → recommendations + config examples) ---
FINDING_ID_PREFIX = "SVD"
DISCLOSURE_HEADERS = [
    "Server", "X-Powered-By", "Via", "Link", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Runtime", "X-Version", "X-Generator", "X-Drupal-Cache", "X-Request-Id", "Alt-Svc",
]

# Severity: exact version of high-risk component = Critical; exact server version = High; product only = Medium; generic = Low; other = Info
VERSION_PATTERN = re.compile(r"\d+\.\d+(\.\d+)?(-[a-z0-9]+)?")


def _header_severity(header_name: str, value: str) -> str:
    """Classify severity of a single disclosure (Critical/High/Medium/Low/Informational).

    Severity guidelines (aligned with OWASP A05/A06):
      Critical – exact runtime/framework version (direct CVE lookup)
      High     – exact server version or WordPress REST API leak
      Medium   – server name without version / Via proxy / generic X-Powered-By
      Low      – CDN presence / informational routing headers
      Info     – request IDs, Alt-Svc, non-actionable hints
    """
    v = (value or "").strip().lower()
    has_version = bool(VERSION_PATTERN.search(v))
    name_lower = header_name.lower()

    # X-Powered-By with version → Critical (PHP/7.4, ASP.NET/4.0, etc.)
    if "x-powered-by" in name_lower:
        if has_version:
            return "Critical"
        return "Medium"  # Name-only X-Powered-By still reveals the runtime

    # Server / ASP.NET version headers
    if "server" in name_lower or "x-aspnet-version" in name_lower or "x-aspnetmvc-version" in name_lower:
        if has_version:
            return "High"
        # Name-only (e.g. "nginx", "Apache", "IIS") – technology is confirmed; Medium per OWASP A05
        return "Medium"

    # Via: reveals proxy/CDN layer
    if "via" in name_lower:
        return "Low" if "cloudflare" in v or "akamai" in v else "Medium"

    # Link: WordPress REST API endpoint exposure
    if "link" in name_lower and ("wp-json" in v or "wordpress" in v):
        return "High"

    # X-Runtime / X-Version / X-Generator
    if "x-runtime" in name_lower or "x-version" in name_lower or "x-generator" in name_lower:
        return "High" if has_version else "Medium"

    # CMS-specific cache headers
    if "x-drupal-cache" in name_lower:
        return "Medium"

    # Purely informational / non-actionable
    if "x-request-id" in name_lower or "alt-svc" in name_lower:
        return "Informational"

    return "Medium"


def _build_affected_components(possible_versions: dict) -> list:
    """Build affected components list with Component, Version, Role."""
    role_map = {
        "Web Server/CDN": "Web Server / CDN",
        "Runtime Environment": "Runtime",
        "HTTP Protocol": "Protocol",
        "AspNet Version": "Framework",
        "AspNetMvc Version": "Framework",
        "Runtime": "Runtime",
        "Version": "Application",
        "Generator": "CMS / Generator",
    }
    out = []
    for comp, ver in (possible_versions or {}).items():
        role = role_map.get(comp, "Other")
        version_str = str(ver).strip() if ver else "Not disclosed"
        out.append({"component": comp, "version": version_str, "role": role})
    return out


def _compliance_mapping() -> list:
    """Return compliance framework mapping for server disclosure."""
    return [
        {"framework": "OWASP", "controlId": "A06:2021", "requirement": "Security Misconfiguration – minimize disclosure of implementation details."},
        {"framework": "NIST SP 800-53", "controlId": "CM-6", "requirement": "Configuration settings – restrict server/version information."},
        {"framework": "NIST SP 800-53", "controlId": "SI-2", "requirement": "Flaw remediation – known vulnerable versions should not be advertised."},
        {"framework": "CIS", "controlId": "Web Server Hardening", "requirement": "Disable server tokens and version headers."},
        {"framework": "PCI-DSS", "controlId": "6.2", "requirement": "Protect against known vulnerabilities; version disclosure aids targeting."},
    ]


def _html_disclosure_checks(body: str) -> list:
    """Check response body for version/generator disclosure in HTML."""
    if not body or len(body) > 500000:
        return []
    body_lower = body.lower()
    findings = []
    # generator meta
    if 'name="generator"' in body_lower or "content=\"wordpress" in body_lower or "content='wordpress" in body_lower:
        findings.append({"type": "HTML generator meta", "description": "Generator or WordPress version may be present in HTML source.", "severity": "Medium"})
    # common version patterns in comments
    if re.search(r"<!--\s*.*(?:wordpress|drupal|joomla|v\d+\.\d+).*-->", body_lower):
        findings.append({"type": "HTML comment", "description": "CMS or version string found in HTML comments.", "severity": "Low"})
    return findings


# Configuration examples for report (same structure as n8n email)
CONFIG_EXAMPLES = {
    "PHP": """; Locate your php.ini file and set the following:
expose_php = Off""",
    "Nginx": """# Inside the http or server block:
server_tokens off;
fastcgi_hide_header X-Powered-By;
proxy_hide_header X-Powered-By;""",
    "Apache": """# Inside the main config or .htaccess:
ServerTokens Prod
ServerSignature Off
Header unset X-Powered-By
Header unset Link""",
    "WordPress": """// Add to functions.php to remove version and link headers:
remove_action('wp_head', 'wp_generator');
remove_action('template_redirect', 'rest_output_link_header', 11);""",
    "Cloudflare": """Create a 'Transform Rule' -> 'Modify Response Header':
1. Set Header 'Server' to 'cloudflare'
2. Remove Header 'X-Powered-By'
3. Remove Header 'X-AspNet-Version' (if applicable)""",
    "IIS": """<!-- In web.config -->
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <remove name="X-Powered-By" />
    </customHeaders>
  </httpProtocol>
  <security>
    <requestFiltering removeServerHeader="true" />
  </security>
</system.webServer>""",
}


def _infer_stack_and_versions(found: dict, norm: dict) -> tuple:
    """Infer stack summary and possibleVersions from disclosed header values (no AI)."""
    possible_versions = {}
    parts = []
    server_val = found.get("Server") or ""
    via_val = found.get("Via") or ""
    powered_val = found.get("X-Powered-By") or ""
    link_val = found.get("Link") or ""
    alt_svc = found.get("Alt-Svc") or ""

    if server_val:
        v = str(server_val).strip()
        possible_versions["Web Server/CDN"] = v
        parts.append(v)
    if via_val and "Web Server/CDN" not in possible_versions:
        v = str(via_val).strip()
        possible_versions["Web Server/CDN"] = v
        if v not in str(parts):
            parts.append(v)
    if powered_val:
        v = str(powered_val).strip()
        possible_versions["Runtime Environment"] = v
        parts.append(v)
    for h in ("X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime", "X-Version", "X-Generator"):
        if found.get(h):
            v = str(found[h]).strip()
            possible_versions[h.replace("X-", "").replace("-", " ")] = v
            parts.append(v)

    # HTTP protocol hint (e.g. HTTP/3 from Alt-Svc)
    if alt_svc and ("h3" in alt_svc.lower() or "quic" in alt_svc.lower()):
        possible_versions["HTTP Protocol"] = "HTTP/3 (h3)"
    elif norm.get("alt-svc"):
        possible_versions["HTTP Protocol"] = str(norm.get("alt-svc", ""))[:80]

    stack_parts = []
    is_cloudflare = "cloudflare" in (server_val + via_val).lower()
    is_wordpress = "wp-json" in link_val.lower() or "wordpress" in (link_val + powered_val).lower()
    is_php = "php" in powered_val.lower()
    if is_wordpress:
        stack_parts.append("WordPress CMS")
    if is_php:
        stack_parts.append("PHP" + (" " + powered_val.strip() if powered_val else ""))
    if is_cloudflare:
        stack_parts.append("Cloudflare CDN")
    if possible_versions.get("HTTP Protocol"):
        stack_parts.append(possible_versions["HTTP Protocol"])
    if not stack_parts:
        stack_parts = parts if parts else ["Not identified"]
    if len(stack_parts) == 1:
        stack = stack_parts[0]
    else:
        stack = stack_parts[0] + " running on " + " via ".join(stack_parts[1:])
    return stack, possible_versions


def _server_disclosure_risk(found: dict, possible_versions: dict) -> tuple:
    """Rule-based risk (Low/Medium/High), justification, and targeted recommendations.

    Risk thresholds:
      High   – 3+ headers exposed, OR version number present in 2+ headers
      Medium – any version number present, OR 2+ name-only headers
      Low    – single name-only header (server type known, no CVE correlation)
    """
    if not found:
        return "Informational", "No technology or version headers detected.", [], 5.0

    disclosure_indicators = list(found.keys())
    version_pattern = re.compile(r"\d+\.\d+(\.\d+)?")
    has_version = any(version_pattern.search(str(v)) for v in found.values())
    count = len(found)

    confidence = min(10.0, 4.0 + count * 1.2 + (2.0 if has_version else 0) + (1.5 if "X-Powered-By" in disclosure_indicators else 0))

    if count >= 3 or (has_version and count >= 2):
        risk = "High"
        justification = "Multiple headers expose technology and/or version numbers; attackers can correlate with known CVEs and craft targeted exploits."
    elif has_version or count >= 2:
        risk = "Medium"
        justification = "Version or stack details are exposed; an attacker can search CVE databases for the exact software version disclosed."
    else:
        risk = "Low"
        justification = "A single header discloses the server technology name without a version number; no direct CVE correlation is possible, but the disclosure reduces anonymity."

    server_val_r  = str(found.get("Server") or "").lower()
    via_val_r     = str(found.get("Via") or "").lower()
    powered_val_r = str(found.get("X-Powered-By") or "").lower()
    link_val_r    = str(found.get("Link") or "").lower()

    is_nginx      = "nginx"      in server_val_r
    is_apache     = "apache"     in server_val_r
    is_iis        = "iis"        in server_val_r
    is_php        = "php"        in powered_val_r
    is_wordpress  = "wp-json"    in link_val_r or "wordpress" in (link_val_r + powered_val_r)
    is_cloudflare = "cloudflare" in (server_val_r + via_val_r)

    recs = []
    if is_nginx:
        recs.append("Set `server_tokens off;` in the Nginx `http` or `server` block — this removes the version string and shows only `nginx` (or nothing if combined with `more_clear_headers 'Server';`).")
        recs.append("To hide the server name entirely, add `more_clear_headers 'Server';` via the `ngx_headers_more` module, or use a reverse proxy to rewrite the Server header to a generic value.")
    if is_apache:
        recs.append("Add `ServerTokens Prod` and `ServerSignature Off` to httpd.conf or .htaccess — this restricts the Server header to just `Apache` without any version suffix.")
        recs.append("Use `Header unset Server` in mod_headers (requires `Header always set Server ''` or header stripping via a WAF) to remove it entirely.")
    if is_iis:
        recs.append("In web.config, add `<requestFiltering removeServerHeader='true' />` under `<system.webServer><security>` to strip the IIS Server header.")
        recs.append("Also remove the `X-Powered-By: ASP.NET` header via `<remove name='X-Powered-By' />` in `<httpProtocol><customHeaders>`.")
    if is_php:
        recs.append("Set `expose_php = Off` in php.ini to prevent the PHP version from appearing in the `X-Powered-By` response header.")
    if is_wordpress:
        recs.append("Add the following to functions.php to suppress the WordPress version in the REST API Link header and the HTML generator meta tag:\n  `remove_action('wp_head', 'wp_generator');`\n  `remove_action('template_redirect', 'rest_output_link_header', 11);`")
        recs.append("Restrict access to the WordPress REST API and XML-RPC endpoints (`/wp-json/`, `/xmlrpc.php`) to authenticated users or trusted IP ranges.")
    if is_cloudflare:
        recs.append("Create a Cloudflare Transform Rule (Rules → Transform Rules → Modify Response Header): set the `Server` header to a generic value (e.g. `webserver`) and remove `X-Powered-By`.")
    if "X-Powered-By" in disclosure_indicators and not is_php:
        recs.append("Remove the `X-Powered-By` response header in your web server or application framework configuration to avoid revealing the runtime environment.")
    if not recs:
        recs.append("Configure the web server to suppress or replace the Server response header with a generic value (e.g. `webserver`) to prevent technology fingerprinting.")
    # Always append a general hardening tip
    recs.append("After removing disclosure headers, add defensive security headers (Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Content-Security-Policy) to harden the server posture further.")

    return risk, justification, recs, round(confidence, 1)


def _build_executive_summary(domain: str, found: dict, stack: str, risk_level: str, possible_versions: dict) -> str:
    """Build a concise, non-repetitive executive summary."""
    if not found:
        return (
            f"{domain} was analyzed for server version disclosure. No technology or version information "
            "was found in response headers — the server correctly conceals its identity from external observers."
        )

    version_pattern = re.compile(r"\d+\.\d+(\.\d+)?")
    has_version = any(version_pattern.search(str(v)) for v in found.values())
    header_count = len(found)
    disclosure_list = ", ".join(f"`{k}: {v}`" for k, v in found.items())

    if has_version:
        exposure_note = (
            f"The server at {domain} discloses {header_count} header{'s' if header_count > 1 else ''} "
            f"containing identifiable technology and version details: {disclosure_list}. "
            "Exact version numbers allow attackers to search CVE databases and apply known exploits directly — "
            "this is a high-value reconnaissance signal."
        )
    else:
        exposure_note = (
            f"The server at {domain} discloses {header_count} header{'s' if header_count > 1 else ''} "
            f"that reveal the technology in use: {disclosure_list}. "
            "While no version number is present (limiting direct CVE mapping), confirmed knowledge of the "
            "server type reduces attacker effort during targeted probing."
        )

    fix_note = (
        "The recommended remediation is to suppress or genericize these headers in the server configuration. "
        f"Detected stack: {stack}. Risk level: {risk_level}."
    )
    return f"{exposure_note} {fix_note}"


def _filter_config_examples(found: dict) -> dict:
    """Return only the CONFIG_EXAMPLES relevant to the technologies actually detected in headers."""
    server_v  = str(found.get("Server") or "").lower()
    via_v     = str(found.get("Via") or "").lower()
    powered_v = str(found.get("X-Powered-By") or "").lower()
    link_v    = str(found.get("Link") or "").lower()

    relevant = {}
    if "nginx"      in server_v:                                       relevant["Nginx"]      = CONFIG_EXAMPLES["Nginx"]
    if "apache"     in server_v:                                       relevant["Apache"]     = CONFIG_EXAMPLES["Apache"]
    if "iis"        in server_v:                                       relevant["IIS"]        = CONFIG_EXAMPLES["IIS"]
    if "php"        in powered_v:                                      relevant["PHP"]        = CONFIG_EXAMPLES["PHP"]
    if "wp-json"    in link_v or "wordpress" in (link_v + powered_v): relevant["WordPress"]  = CONFIG_EXAMPLES["WordPress"]
    if "cloudflare" in (server_v + via_v):                             relevant["Cloudflare"] = CONFIG_EXAMPLES["Cloudflare"]
    # Fallback: if we found headers but couldn't map to a known tech, show Nginx as a safe default
    if not relevant and found:
        relevant["Nginx"] = CONFIG_EXAMPLES["Nginx"]
    return relevant


def run_server_disclosure_analysis(url: str, extra_headers=None, method="GET", body=None) -> dict:
    headers, resp_body, status = fetch_url(url, extra_headers=extra_headers, method=method, body=body)
    target_domain = get_domain(url)
    norm = _normalize_headers(headers)
    found = {}
    for name in DISCLOSURE_HEADERS:
        key = name.lower().replace("-", "")
        for hk, hv in norm.items():
            if hk.replace("-", "").lower() == key:
                found[name] = hv
                break
    # Enrich each disclosure with severity and evidence
    disclosures = []
    for k, v in found.items():
        severity = _header_severity(k, v)
        disclosures.append({
            "header": k,
            "value": v,
            "severity": severity,
            "evidence": f"Header: {k}: {v}. Source: HTTP response headers.",
        })
    stack, possible_versions = _infer_stack_and_versions(found, norm)
    risk_level, justification, recommendations, confidence = _server_disclosure_risk(found, possible_versions)
    disclosure_indicators = list(found.keys())
    notes = f"Detected {len(found)} header(s) exposing technology or version info: {', '.join(disclosure_indicators)}." if found else "No sensitive version headers detected."
    executive_summary = _build_executive_summary(target_domain, found, stack, risk_level, possible_versions)

    # Affected components
    affected_components = _build_affected_components(possible_versions)

    # Use the same version-detection logic for attack scenario, business impact, AND summary counts
    # (avoids "version information" text appearing while stats show "0 With version")
    with_version = sum(1 for d in disclosures if VERSION_PATTERN.search(str(d.get("value") or "")))
    has_version = with_version > 0  # single source of truth

    if has_version:
        attack_scenario = (
            f"An attacker can take the exact version string{'s' if with_version > 1 else ''} disclosed here and query CVE databases "
            "(e.g. cve.mitre.org, nvd.nist.gov) for known vulnerabilities. Automated exploit frameworks such as Metasploit "
            "include modules targeting specific server and runtime versions — reducing the time-to-exploit to minutes."
        )
    elif found:
        stack_val = stack or "the identified technology"
        attack_scenario = (
            f"The server confirms it is running {stack_val}, but does not reveal a version number. "
            "Without a version, an attacker cannot directly look up applicable CVEs. However, confirmed technology "
            "knowledge enables stack-specific probing (e.g. nginx-specific misconfigurations, default path enumeration) "
            "and social-engineering attempts. Removing the header eliminates this reconnaissance advantage entirely."
        )
    else:
        attack_scenario = "No stack or version disclosure detected; direct reconnaissance value from response headers is minimal."

    business_impact = (
        "Targeted exploitation via known CVEs; compliance findings (OWASP A05, PCI-DSS 6.2); potential breach of production systems."
        if has_version else (
            "Technology fingerprinting enables stack-specific attacks; minor compliance finding; low direct exploit risk."
            if found else "Minimal — server does not disclose technology information."
        )
    )
    # Likelihood reflects whether a version was disclosed (enables direct CVE lookup)
    likelihood = "High" if (has_version and len(found) >= 2) else ("Medium" if has_version else ("Low" if found else "Informational"))

    # Remediation priority from risk
    priority_map = {"High": "P1", "Medium": "P2", "Low": "P3", "Informational": "P3"}
    remediation_priority = priority_map.get(risk_level, "P2")
    verification_step = "After changing server or application configuration, re-run this scan and confirm that the listed headers are removed or show generic values only."
    expected_state = "Server: generic value or absent; X-Powered-By: absent; Link: no version or API disclosure; other version headers removed or generic."

    html_disclosures = _html_disclosure_checks(resp_body or "")

    # Summary metrics: disclosure score 0-100, counts
    critical_high = sum(1 for d in disclosures if d.get("severity") in ("Critical", "High"))
    # with_version already computed above (single source of truth for has_version + summaryCounts)
    product_only = len(disclosures) - with_version
    # Score: higher = worse. +15 Critical, +10 High, +5 Medium, +2 Low/Info. Cap 100.
    score_weights = {"Critical": 15, "High": 10, "Medium": 5, "Low": 2, "Informational": 1}
    disclosure_score = min(100, sum(score_weights.get(d.get("severity"), 0) for d in disclosures) + (5 * len(html_disclosures)))
    summary_counts = {
        "totalHeaders": len(disclosures),
        "headersWithVersion": with_version,
        "productOnlyCount": product_only,
        "criticalHighCount": critical_high,
    }

    return {
        "targetDomain": target_domain,
        "domain": target_domain,
        "originalUrl": url,
        "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "findingId": f"{FINDING_ID_PREFIX}-001",
        "reportTitle": f"Server Version Disclosure Audit Report - {target_domain}",
        "disclosures": disclosures,
        "disclosureIndicators": disclosure_indicators,
        "stack": stack,
        "possibleVersions": possible_versions,
        "riskLevel": risk_level,
        "confidence": confidence,
        "justification": justification,
        "executiveSummary": executive_summary,
        "notes": notes,
        "recommendation": "Remove or genericize server/version headers to reduce information disclosure." if found else "No sensitive version headers detected.",
        "recommendations": recommendations,
        "configurationExamples": _filter_config_examples(found),
        "references": [
            "OWASP A06:2021 - Security Misconfiguration",
            "NIST SP 800-53 Rev.5 - CM-6 / SI-2",
            "CIS Benchmark - Web Server / Application Hardening",
        ],
        "affectedComponents": affected_components,
        "cveNote": (
            "Disclosed versions should be checked against CVE databases and vendor security advisories. "
            "Consider: https://cve.mitre.org/ or https://nvd.nist.gov/"
            if has_version else None
        ),
        "attackScenario": attack_scenario,
        "businessImpact": business_impact,
        "likelihood": likelihood,
        "complianceMapping": _compliance_mapping(),
        "remediationPriority": remediation_priority,
        "verificationStep": verification_step,
        "expectedState": expected_state,
        "htmlDisclosures": html_disclosures,
        "disclosureScore": disclosure_score,
        "summaryCounts": summary_counts,
    }


# --- Improper error handling (heuristic: stack trace / exception in body) ---
# Indicators: (phrase, category, severity)
_ERROR_INDICATORS = [
    # ── Stack traces & debug output ──
    ("stack trace", "Stack trace", "High"),
    ("stacktrace", "Stack trace", "High"),
    ("traceback", "Stack trace", "High"),
    ("traceback (most recent call last)", "Stack trace", "High"),
    ("at line", "Stack trace", "High"),
    ("syntax error", "Stack trace", "High"),
    ("parse error", "Stack trace", "High"),
    ("segmentation fault", "Stack trace", "High"),
    ("core dumped", "Stack trace", "High"),
    ("debug mode", "Debug exposure", "High"),
    ("debug = true", "Debug exposure", "High"),
    ("app_debug", "Debug exposure", "High"),
    ("django_debug", "Debug exposure", "High"),
    ("xdebug", "Debug exposure", "High"),
    ("phpinfo()", "Debug exposure", "High"),
    ("var_dump(", "Debug exposure", "High"),
    ("print_r(", "Debug exposure", "High"),
    # ── File & path disclosure ──
    ("file \"", "Path disclosure", "High"),
    ("file '", "Path disclosure", "High"),
    (" in /", "Path disclosure", "High"),
    (" in c:\\", "Path disclosure", "High"),
    (" in d:\\", "Path disclosure", "High"),
    ("/usr/", "Path disclosure", "High"),
    ("/var/", "Path disclosure", "High"),
    ("/home/", "Path disclosure", "High"),
    ("/opt/", "Path disclosure", "High"),
    ("/etc/", "Path disclosure", "High"),
    ("/srv/", "Path disclosure", "High"),
    ("c:\\inetpub", "Path disclosure", "High"),
    ("c:\\users\\", "Path disclosure", "High"),
    ("c:\\windows\\", "Path disclosure", "High"),
    ("wwwroot", "Path disclosure", "High"),
    ("htdocs", "Path disclosure", "High"),
    ("public_html", "Path disclosure", "High"),
    ("web.config", "Path disclosure", "High"),
    (".env", "Path disclosure", "High"),
    ("node_modules", "Path disclosure", "Medium"),
    ("site-packages", "Path disclosure", "Medium"),
    ("vendor/", "Path disclosure", "Medium"),
    # ── Python ──
    (".py\",", "Framework (Python)", "High"),
    (".py'", "Framework (Python)", "High"),
    (".py, line", "Framework (Python)", "High"),
    ("django", "Framework (Python)", "High"),
    ("flask", "Framework (Python)", "High"),
    ("fastapi", "Framework (Python)", "High"),
    ("gunicorn", "Framework (Python)", "Medium"),
    ("uwsgi", "Framework (Python)", "Medium"),
    ("modulenotfounderror", "Framework (Python)", "High"),
    ("importerror", "Framework (Python)", "High"),
    ("attributeerror", "Framework (Python)", "High"),
    ("typeerror", "Framework (Python)", "High"),
    ("keyerror", "Framework (Python)", "High"),
    ("valueerror", "Framework (Python)", "High"),
    ("indentationerror", "Framework (Python)", "High"),
    ("jinja2", "Framework (Python)", "High"),
    ("werkzeug", "Framework (Python)", "High"),
    ("celery", "Framework (Python)", "Medium"),
    # ── PHP ──
    (".php on line", "Framework (PHP)", "High"),
    (".php:", "Framework (PHP)", "High"),
    ("fatal error:", "Framework (PHP)", "High"),
    ("uncaught error", "Framework (PHP)", "High"),
    ("uncaught exception", "Framework (PHP)", "High"),
    ("pdoexception", "Framework (PHP)", "High"),
    ("mysqli_", "Framework (PHP)", "High"),
    ("php warning", "Framework (PHP)", "High"),
    ("php notice", "Framework (PHP)", "Medium"),
    ("php fatal", "Framework (PHP)", "High"),
    ("php parse error", "Framework (PHP)", "High"),
    ("laravel", "Framework (PHP)", "High"),
    ("symfony", "Framework (PHP)", "High"),
    ("codeigniter", "Framework (PHP)", "High"),
    ("wordpress", "Framework (PHP)", "Medium"),
    ("wp-content", "Framework (PHP)", "Medium"),
    ("wp-includes", "Framework (PHP)", "Medium"),
    ("drupal", "Framework (PHP)", "Medium"),
    ("zend_", "Framework (PHP)", "High"),
    # ── Java / JVM ──
    (".java:", "Framework (Java)", "High"),
    (".java)", "Framework (Java)", "High"),
    (".jsp:", "Framework (Java)", "High"),
    ("java.lang.", "Framework (Java)", "High"),
    ("java.io.", "Framework (Java)", "High"),
    ("java.sql.", "Framework (Java)", "High"),
    ("java.net.", "Framework (Java)", "High"),
    ("javax.", "Framework (Java)", "High"),
    ("nullpointerexception", "Framework (Java)", "High"),
    ("classnotfoundexception", "Framework (Java)", "High"),
    ("nosuchmethodexception", "Framework (Java)", "High"),
    ("arrayindexoutofboundsexception", "Framework (Java)", "High"),
    ("illegalargumentexception", "Framework (Java)", "High"),
    ("spring", "Framework (Java)", "High"),
    ("springframework", "Framework (Java)", "High"),
    ("struts", "Framework (Java)", "High"),
    ("hibernate", "Framework (Java)", "High"),
    ("tomcat", "Framework (Java)", "High"),
    ("catalina", "Framework (Java)", "High"),
    ("jetty", "Framework (Java)", "Medium"),
    ("wildfly", "Framework (Java)", "Medium"),
    ("jboss", "Framework (Java)", "Medium"),
    ("at com.", "Framework (Java)", "High"),
    ("at org.", "Framework (Java)", "High"),
    ("at java.", "Framework (Java)", "High"),
    ("at sun.", "Framework (Java)", "High"),
    # ── .NET / ASP.NET ──
    ("system.web", "Framework (.NET)", "High"),
    ("system.data", "Framework (.NET)", "High"),
    ("system.io", "Framework (.NET)", "High"),
    ("system.net", "Framework (.NET)", "High"),
    ("asp.net", "Framework (.NET)", "High"),
    ("__viewstate", "Framework (.NET)", "Medium"),
    ("nullreferenceexception", "Framework (.NET)", "High"),
    ("argumentexception", "Framework (.NET)", "High"),
    ("invalidoperationexception", "Framework (.NET)", "High"),
    ("sqlexception", "Framework (.NET)", "High"),
    ("stacktrace:", "Framework (.NET)", "High"),
    ("x-aspnet-version", "Framework (.NET)", "Medium"),
    ("x-aspnetmvc-version", "Framework (.NET)", "Medium"),
    ("microsoft.aspnetcore", "Framework (.NET)", "High"),
    ("iis ", "Framework (.NET)", "Medium"),
    ("microsoft-iis", "Framework (.NET)", "Medium"),
    # ── Node.js / JavaScript ──
    ("at object.", "Framework (Node.js)", "High"),
    ("at module.", "Framework (Node.js)", "High"),
    ("at function.", "Framework (Node.js)", "High"),
    ("at process.", "Framework (Node.js)", "High"),
    ("error: cannot find module", "Framework (Node.js)", "High"),
    ("referenceerror", "Framework (Node.js)", "High"),
    ("rangeerror", "Framework (Node.js)", "High"),
    ("syntaxerror", "Framework (Node.js)", "High"),
    ("express", "Framework (Node.js)", "Medium"),
    ("koa", "Framework (Node.js)", "Medium"),
    ("next.js", "Framework (Node.js)", "Medium"),
    ("nestjs", "Framework (Node.js)", "Medium"),
    ("handlebars", "Framework (Node.js)", "Medium"),
    ("ejs", "Framework (Node.js)", "Medium"),
    ("pug", "Framework (Node.js)", "Medium"),
    # ── Ruby ──
    (".rb:", "Framework (Ruby)", "High"),
    (".rb'", "Framework (Ruby)", "High"),
    ("actioncontroller", "Framework (Ruby)", "High"),
    ("activerecord", "Framework (Ruby)", "High"),
    ("rack::utils", "Framework (Ruby)", "High"),
    ("nomethoderror", "Framework (Ruby)", "High"),
    ("runtimeerror", "Framework (Ruby)", "High"),
    ("sinatra", "Framework (Ruby)", "Medium"),
    # ── Go ──
    ("goroutine", "Framework (Go)", "High"),
    ("runtime.gopanic", "Framework (Go)", "High"),
    ("runtime.go:", "Framework (Go)", "High"),
    (".go:", "Framework (Go)", "High"),
    # ── Database ──
    ("sqlstate", "Database", "High"),
    ("sqlstate[", "Database", "High"),
    ("odbc ", "Database", "High"),
    ("postgresql", "Database", "High"),
    ("mysql_", "Database", "High"),
    ("mysql error", "Database", "High"),
    ("mariadb", "Database", "High"),
    ("sqlite", "Database", "High"),
    ("oracle error", "Database", "High"),
    ("ora-", "Database", "High"),
    ("pg_query", "Database", "High"),
    ("pg_connect", "Database", "High"),
    ("syntax error at or near", "Database", "High"),
    ("unterminated quoted string", "Database", "High"),
    ("you have an error in your sql syntax", "Database", "High"),
    ("microsoft sql server", "Database", "High"),
    ("sql server", "Database", "High"),
    ("mssql", "Database", "High"),
    ("mongodb", "Database", "High"),
    ("mongoose", "Database", "High"),
    ("redis", "Database", "Medium"),
    ("cassandra", "Database", "Medium"),
    ("elasticsearch", "Database", "Medium"),
    ("couchdb", "Database", "Medium"),
    ("dynamodb", "Database", "Medium"),
    # ── Runtime / generic errors ──
    ("warning:", "Runtime error", "Medium"),
    ("notice:", "Runtime error", "Low"),
    ("deprecated:", "Runtime error", "Low"),
    ("undefined index", "Runtime error", "Medium"),
    ("undefined variable", "Runtime error", "Medium"),
    ("undefined property", "Runtime error", "Medium"),
    ("undefined offset", "Runtime error", "Medium"),
    ("cannot read property", "Runtime error", "Medium"),
    ("is not defined", "Runtime error", "Medium"),
    ("is not a function", "Runtime error", "Medium"),
    ("unexpected token", "Runtime error", "Medium"),
    ("unhandled promise rejection", "Runtime error", "High"),
    ("unhandledrejection", "Runtime error", "High"),
    # ── Generic server errors ──
    ("internal server error", "Generic error", "Medium"),
    ("502 bad gateway", "Generic error", "Low"),
    ("503 service unavailable", "Generic error", "Low"),
    ("504 gateway timeout", "Generic error", "Low"),
    # ── Infrastructure / environment ──
    ("connection refused", "Infrastructure", "Medium"),
    ("permission denied", "Infrastructure", "Medium"),
    ("access denied", "Infrastructure", "Medium"),
    ("connection timed out", "Infrastructure", "Low"),
    ("no such host", "Infrastructure", "Medium"),
    ("name or service not known", "Infrastructure", "Medium"),
    ("upstream", "Infrastructure", "Medium"),
    ("proxy error", "Infrastructure", "Medium"),
    ("bad gateway", "Infrastructure", "Low"),
    ("load balancer", "Infrastructure", "Medium"),
    # ── Cloud / container ──
    ("aws ", "Cloud / container", "Medium"),
    ("amazon web services", "Cloud / container", "Medium"),
    ("s3.amazonaws.com", "Cloud / container", "High"),
    ("lambda function", "Cloud / container", "Medium"),
    ("azure ", "Cloud / container", "Medium"),
    ("google cloud", "Cloud / container", "Medium"),
    ("kubernetes", "Cloud / container", "High"),
    ("docker", "Cloud / container", "Medium"),
    ("container id", "Cloud / container", "Medium"),
    # ── Config / secrets ──
    ("password", "Credential leak", "High"),
    ("passwd", "Credential leak", "High"),
    ("secret_key", "Credential leak", "High"),
    ("api_key", "Credential leak", "High"),
    ("apikey", "Credential leak", "High"),
    ("access_token", "Credential leak", "High"),
    ("private_key", "Credential leak", "High"),
    ("database_url", "Credential leak", "High"),
    ("db_password", "Credential leak", "High"),
    ("connectionstring", "Credential leak", "High"),
    # ── Template engines ──
    ("twig", "Template engine", "Medium"),
    ("blade", "Template engine", "Medium"),
    ("thymeleaf", "Template engine", "Medium"),
    ("freemarker", "Template engine", "Medium"),
    ("velocity", "Template engine", "Medium"),
    ("mustache", "Template engine", "Medium"),
]

_ERROR_CATEGORY_GUIDANCE = {
    "Stack trace": {
        "impact": "Attackers can see code paths, line numbers, and file names, making it easier to find bugs and craft exploits.",
        "remediation": "Disable stack traces and debug mode in production. Log full details server-side only; return a generic message to the client.",
    },
    "Debug exposure": {
        "impact": "Debug mode exposes internal application state, variable values, SQL queries, and environment configuration to any visitor.",
        "remediation": "Disable debug mode in production (DEBUG=False, APP_DEBUG=false). Remove all phpinfo(), var_dump(), print_r() calls.",
    },
    "Path disclosure": {
        "impact": "File or directory paths reveal OS, application structure, deployment location, and user accounts.",
        "remediation": "Never expose real paths in error responses. Configure custom error pages and log paths server-side only.",
    },
    "Framework (Python)":  {"impact": "Python framework details and exception types help attackers target framework-specific CVEs.", "remediation": "Set DEBUG=False, use custom error handlers, and suppress Werkzeug/Django debug pages in production."},
    "Framework (PHP)":     {"impact": "PHP version, paths, and error types enable targeted exploitation of PHP-specific CVEs.", "remediation": "Set display_errors=Off, log_errors=On, expose_php=Off. Use custom error pages."},
    "Framework (Java)":    {"impact": "Java stack traces reveal class hierarchy, library versions, and application architecture.", "remediation": "Configure the application server to show generic error pages. Suppress stack traces in responses."},
    "Framework (.NET)":    {"impact": "ASP.NET/IIS details expose framework version, class structure, and internal state.", "remediation": "Set customErrors mode='On', remove version headers, and configure generic error pages."},
    "Framework (Node.js)": {"impact": "Node.js error details reveal module paths, npm packages, and application logic.", "remediation": "Use Express error middleware to catch all errors and return generic responses. Set NODE_ENV=production."},
    "Framework (Ruby)":    {"impact": "Ruby/Rails stack traces expose routes, gems, file paths, and internal methods.", "remediation": "Set consider_all_requests_local=false and configure custom error pages in production."},
    "Framework (Go)":      {"impact": "Go panic traces expose goroutine stacks, function names, and file paths.", "remediation": "Use recover() in handlers and return generic error responses. Never expose panic output."},
    "Exception / runtime": {"impact": "Exception messages often contain internal state, variable names, or logic details.", "remediation": "Catch all exceptions and return generic user messages; log the real exception server-side only."},
    "Runtime error":       {"impact": "Warnings and notices reveal configuration, deprecated usage, or environment details.", "remediation": "Disable display of warnings/notices to users in production; log them server-side instead."},
    "Database":            {"impact": "Database type, version, SQL state, or query details aid SQL injection and version-specific attacks.", "remediation": "Never expose raw DB errors, SQL queries, or connection strings to clients. Use parameterized queries and generic messages."},
    "Generic error":       {"impact": "Default error pages identify the web server software and version.", "remediation": "Replace default error pages with custom, generic responses that do not identify the server."},
    "Infrastructure":      {"impact": "Connection, proxy, and permission messages reveal backend topology, internal hostnames, or OS details.", "remediation": "Handle upstream errors gracefully. Return generic messages; never forward raw infrastructure errors to clients."},
    "Cloud / container":   {"impact": "Cloud provider, container IDs, or orchestration details expose deployment architecture.", "remediation": "Strip cloud-specific details from error responses. Use error boundaries before responses reach the client."},
    "Credential leak":     {"impact": "Passwords, API keys, tokens, or connection strings in error output enable direct unauthorized access.", "remediation": "Never log or display credentials in error messages. Audit error handlers for sensitive data exposure. Rotate any leaked credentials immediately."},
    "Template engine":     {"impact": "Template engine errors expose template paths, syntax, and server-side code structure.", "remediation": "Configure template engines to use generic error messages in production. Disable template debugging."},
    "Internal IP":         {"impact": "Internal/private IP addresses expose network topology and enable lateral movement or targeted attacks.", "remediation": "Strip internal IPs from all responses. Configure reverse proxies to remove X-Forwarded-For and internal headers."},
    "Email disclosure":    {"impact": "Email addresses in error messages can be used for phishing, social engineering, or account enumeration.", "remediation": "Remove developer and admin email addresses from error responses."},
    "Version disclosure":  {"impact": "Exact software version numbers allow attackers to look up known CVEs and craft version-specific exploits.", "remediation": "Remove version numbers from Server, X-Powered-By, and custom headers. Use server_tokens off (Nginx) or ServerTokens Prod (Apache)."},
    "Error page fingerprint": {"impact": "Default error pages uniquely identify the web server or framework, aiding reconnaissance.", "remediation": "Replace all default error pages (404, 500, etc.) with custom pages that do not identify the technology stack."},
    "Sensitive header":    {"impact": "Debug or technology-revealing headers in error responses provide free reconnaissance to attackers.", "remediation": "Remove or suppress debug headers (X-Debug-*, X-Powered-By, Server version) especially in error responses."},
    "Method disclosure":   {"impact": "The Allow header in 405 responses reveals all HTTP methods accepted, aiding attack surface mapping.", "remediation": "Disable unused HTTP methods. Configure the Allow header to only list necessary methods."},
}

# Regex patterns for advanced detection: (compiled_regex, category, severity, description)
_ERROR_REGEX_PATTERNS = [
    (re.compile(r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'), "Internal IP", "High", "Internal/private IP address detected"),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "Email disclosure", "Medium", "Email address found in response"),
    (re.compile(r'(?:Apache|nginx|IIS|LiteSpeed|Tomcat|Jetty|Caddy)[/ ]\d+[\d.]*', re.I), "Version disclosure", "High", "Server software version number detected"),
    (re.compile(r'(?:PHP|Python|Ruby|Node|Java|Perl|Go)[/ ]\d+[\d.]*', re.I), "Version disclosure", "High", "Runtime/language version number detected"),
    (re.compile(r'(?:OpenSSL|OpenSSH|mod_ssl)[/ ]\d+[\d.]*', re.I), "Version disclosure", "Medium", "Library version number detected"),
    (re.compile(r'(?:WordPress|Drupal|Joomla|Magento|Shopify)[/ ]\d+[\d.]*', re.I), "Version disclosure", "High", "CMS version number detected"),
    (re.compile(r'(?:jQuery|React|Angular|Vue|Bootstrap)[/ ]\d+[\d.]*', re.I), "Version disclosure", "Low", "Client framework version detected"),
    (re.compile(r'[A-Za-z]:\\(?:Users|Windows|inetpub|Program Files)\\[^\s<>"\']+', re.I), "Path disclosure", "High", "Windows file path detected"),
    (re.compile(r'/(?:home|var|usr|opt|etc|srv|tmp)/[^\s<>"\']{3,}'), "Path disclosure", "High", "Unix file path detected"),
    (re.compile(r'\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b'), "Credential leak", "High", "AWS access key pattern detected"),
    (re.compile(r'(?:"|\')?(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key)(?:"|\')?[\s]*[:=][\s]*(?:"|\')?[A-Za-z0-9+/=_-]{8,}', re.I), "Credential leak", "High", "API key/secret assignment detected"),
    (re.compile(r'(?:mongodb|mysql|postgres|redis|amqp)://[^\s<>"\']+', re.I), "Credential leak", "High", "Database connection string detected"),
]

# Default error page fingerprints: (substring, server_identity, severity)
_ERROR_PAGE_FINGERPRINTS = [
    ("<address>apache/", "Apache default error page", "Medium"),
    ("apache server at", "Apache default error page", "Medium"),
    ("<hr><center>nginx", "Nginx default error page", "Medium"),
    ("microsoft-iis/", "IIS default error page", "Medium"),
    ("server error in '/' application", "ASP.NET default error page", "High"),
    ("runtime error</title>", "ASP.NET runtime error page", "High"),
    ("this error page might contain sensitive information", "ASP.NET detailed error", "High"),
    ("apache tomcat/", "Tomcat default error page", "Medium"),
    ("coyote connector", "Tomcat Coyote connector", "Medium"),
    ("glassfish server", "GlassFish default error page", "Medium"),
    ("django debug", "Django debug page", "High"),
    ("you're seeing this error because you have <code>debug = true", "Django DEBUG=True", "High"),
    ("whitelabel error page", "Spring Boot Whitelabel error", "Medium"),
    ("powered by express", "Express default error page", "Medium"),
    ("cannot get /", "Express/Node.js default 404", "Low"),
    ("cannot post /", "Express/Node.js default 405", "Low"),
    ("sinatra doesn't know this ditty", "Sinatra default 404", "Medium"),
    ("routing error", "Rails routing error", "High"),
    ("actioncontroller::routingerror", "Rails ActionController error", "High"),
    ("web application could not be started", "Phusion Passenger error", "High"),
    ("502 bad gateway", "Proxy/LB error page", "Low"),
    ("cloudflare", "Cloudflare error page", "Low"),
]

# Headers that indicate information disclosure in error responses
_SENSITIVE_ERROR_HEADERS = [
    ("x-powered-by", "Sensitive header", "Medium", "X-Powered-By header reveals technology stack"),
    ("x-aspnet-version", "Sensitive header", "Medium", "X-AspNet-Version reveals .NET framework version"),
    ("x-aspnetmvc-version", "Sensitive header", "Medium", "X-AspNetMvc-Version reveals MVC framework version"),
    ("x-debug", "Sensitive header", "High", "X-Debug header indicates debug mode is active"),
    ("x-debug-token", "Sensitive header", "High", "X-Debug-Token exposes Symfony debug profiler"),
    ("x-debug-token-link", "Sensitive header", "High", "X-Debug-Token-Link exposes Symfony profiler URL"),
    ("x-runtime", "Sensitive header", "Low", "X-Runtime reveals server processing time"),
    ("x-request-id", "Sensitive header", "Low", "X-Request-Id exposes internal tracking identifier"),
    ("x-correlation-id", "Sensitive header", "Low", "X-Correlation-Id exposes internal tracking identifier"),
    ("x-amzn-requestid", "Sensitive header", "Medium", "X-Amzn-RequestId reveals AWS infrastructure"),
    ("x-amzn-trace-id", "Sensitive header", "Medium", "X-Amzn-Trace-Id reveals AWS X-Ray tracing"),
    ("x-cloud-trace-context", "Sensitive header", "Medium", "X-Cloud-Trace-Context reveals Google Cloud infrastructure"),
    ("x-envoy-upstream-service-time", "Sensitive header", "Medium", "Envoy proxy header reveals service mesh details"),
    ("x-backend-server", "Sensitive header", "High", "X-Backend-Server reveals internal server hostname"),
    ("x-served-by", "Sensitive header", "Medium", "X-Served-By reveals internal server identity"),
    ("x-cache", "Sensitive header", "Low", "X-Cache reveals caching infrastructure"),
    ("via", "Sensitive header", "Low", "Via header reveals proxy/CDN chain"),
]


def _scan_body_for_indicators(body: str) -> list:
    """Return list of {indicator, category, severity} found via substrings and regex."""
    if not body:
        return []
    body_lower = body.lower()
    found = []
    seen = set()

    for phrase, category, sev in _ERROR_INDICATORS:
        if phrase in body_lower and phrase not in seen:
            seen.add(phrase)
            found.append({"indicator": phrase, "category": category, "severity": sev})

    for pattern, category, sev, desc in _ERROR_REGEX_PATTERNS:
        match = pattern.search(body)
        if match:
            matched = match.group(0)
            key = f"regex:{category}:{matched[:60]}"
            if key not in seen:
                seen.add(key)
                found.append({"indicator": f"{desc}: {matched[:80]}", "category": category, "severity": sev})

    for fp_phrase, identity, sev in _ERROR_PAGE_FINGERPRINTS:
        if fp_phrase in body_lower and identity not in seen:
            seen.add(identity)
            found.append({"indicator": identity, "category": "Error page fingerprint", "severity": sev})

    return found


def _scan_headers_for_disclosure(headers: dict) -> list:
    """Check response headers for information disclosure indicators."""
    found = []
    if not headers:
        return found
    for hdr_name, category, sev, desc in _SENSITIVE_ERROR_HEADERS:
        val = headers.get(hdr_name)
        if val:
            found.append({"indicator": f"{hdr_name}: {val[:100]}", "category": category, "severity": sev, "description": desc})
    server_val = headers.get("server", "")
    if server_val and re.search(r'[\d.]+', server_val):
        found.append({"indicator": f"Server: {server_val}", "category": "Version disclosure", "severity": "High",
                       "description": "Server header reveals software version number"})
    return found


def run_error_handling_check(url: str, extra_headers=None, method="GET", body=None) -> dict:
    target_domain = get_domain(url)
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    path = (parsed.path or "").rstrip("/")

    probe_specs = [
        # (path_suffix, label, method_override)
        ("/__nonexistent_probe_12345", "Non-existent path (root)", None),
        ("/api/__nonexistent_probe_12345", "Non-existent path (API)", None),
        ((path + "/__nonexistent_probe_12345") if path else "/__nonexistent_probe_12345", "Non-existent path (app context)", None),
        # Special characters to trigger parser/WAF errors
        ("/" + urllib.parse.quote("test'\"<>{}|\\"), "Special characters in path", None),
        # SQL-like input in query string
        ((path or "/") + "?id=1'%20OR%201=1--", "SQL injection trigger in query", None),
        # Percent-encoded traversal attempt
        ("/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "Path traversal (encoded)", None),
        # Null byte injection
        ("/" + urllib.parse.quote("test\x00.php"), "Null byte in path", None),
        # Very long path to trigger buffer/length errors
        ("/" + "A" * 2000, "Oversized path segment", None),
        # Format-string-like input
        ("/%s%s%s%s%s%s%s%s%s%s", "Format string probe", None),
        # Common debug/admin endpoints
        ("/actuator/env", "Spring Actuator probe", None),
        ("/debug", "Debug endpoint probe", None),
        ("/.env", "Environment file probe", None),
        ("/server-status", "Apache status probe", None),
        ("/elmah.axd", "ASP.NET ELMAH probe", None),
        ("/trace", "Spring trace endpoint", None),
        # Method-based probes
        ("/" + (path.lstrip("/") or ""), "TRACE method probe", "TRACE"),
        ("/" + (path.lstrip("/") or ""), "DELETE method probe", "DELETE"),
        ("/" + (path.lstrip("/") or ""), "PUT method (no body)", "PUT"),
    ]
    seen_paths = set()
    probes = []
    for p_path, label, meth_override in probe_specs:
        key = (p_path, meth_override or method)
        if key not in seen_paths:
            seen_paths.add(key)
            probes.append((p_path, label, meth_override))

    base_result = {
        "targetDomain": target_domain,
        "originalUrl": url,
        "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
    }
    references = [
        "CWE-209: Information Exposure Through an Error Message",
        "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        "CWE-756: Missing Custom Error Page",
        "OWASP Testing Guide: OTG-ERR-001 to OTG-ERR-004",
        "OWASP Top 10: A05:2021 – Security Misconfiguration",
    ]

    all_found = []
    probes_result = []
    worst_status = None
    response_snippet = None

    for probe_path, probe_label, meth_override in probes:
        probe_url = base.rstrip("/") + ("/" + probe_path.lstrip("/")) if not probe_path.startswith("?") else base.rstrip("/") + (path or "/") + probe_path
        actual_method = meth_override or method
        try:
            resp_headers, resp_body, status = fetch_url(
                probe_url, extra_headers=extra_headers,
                method=actual_method, body=body if actual_method in ("POST", "PUT", "PATCH") else None,
            )
            if worst_status is None or (status >= 500 and (worst_status or 0) < 500) or status > (worst_status or 0):
                worst_status = status

            found_here = _scan_body_for_indicators(resp_body)
            hdr_findings = _scan_headers_for_disclosure(resp_headers)
            found_here.extend(hdr_findings)

            if status == 405:
                allow = resp_headers.get("allow", "")
                if allow:
                    found_here.append({"indicator": f"Allow: {allow}", "category": "Method disclosure", "severity": "Low",
                                       "description": "405 response reveals accepted HTTP methods"})

            for item in found_here:
                dup_key = item["indicator"][:80]
                if not any(f["indicator"][:80] == dup_key for f in all_found):
                    all_found.append({**item, "probeUrl": probe_url, "probeLabel": probe_label, "probeMethod": actual_method})

            if found_here and response_snippet is None and resp_body:
                snippet = (resp_body[:600] + "…") if len(resp_body) > 600 else resp_body
                response_snippet = snippet.replace("\r", " ").replace("\n", " ").strip()[:500]

            probes_result.append({
                "probeUrl": probe_url, "probeLabel": probe_label,
                "method": actual_method, "statusCode": status,
                "indicatorsCount": len(found_here),
            })
        except Exception as e:
            probes_result.append({
                "probeUrl": probe_url, "probeLabel": probe_label,
                "method": actual_method, "error": str(e),
                "statusCode": None, "indicatorsCount": 0,
            })

    if all(p.get("error") for p in probes_result):
        err_msg = "; ".join(p.get("error", "") for p in probes_result[:1])
        return {
            **base_result, "probeUrl": probes_result[0]["probeUrl"] if probes_result else url,
            "probeStatus": None, "probes": probes_result, "error": err_msg,
            "riskLevel": "Unknown", "findings": [], "sensitiveLeaked": [],
            "executiveSummary": f"All probes failed: {err_msg}. Manual check of error handling is recommended.",
            "simpleTerms": "The scanner could not complete the error-handling check. Try again or inspect the site manually.",
            "recommendation": "Probes failed; manual check recommended.",
            "references": references,
        }

    by_category = {}
    for item in all_found:
        cat = item["category"]
        if cat not in by_category:
            guid = _ERROR_CATEGORY_GUIDANCE.get(cat, {})
            by_category[cat] = {
                "category": cat, "severity": item["severity"],
                "evidence": [], "probes": [],
                "impact": guid.get("impact", ""), "remediation": guid.get("remediation", ""),
            }
        sev_rank = {"High": 3, "Medium": 2, "Low": 1}
        if sev_rank.get(item["severity"], 0) > sev_rank.get(by_category[cat]["severity"], 0):
            by_category[cat]["severity"] = item["severity"]
        if item["indicator"] not in by_category[cat]["evidence"]:
            by_category[cat]["evidence"].append(item["indicator"])
        probe_ref = f"{item.get('probeMethod', 'GET')} {item.get('probeLabel', '')}"
        if probe_ref not in by_category[cat]["probes"]:
            by_category[cat]["probes"].append(probe_ref)

    findings = sorted(by_category.values(), key=lambda f: -{"High": 3, "Medium": 2, "Low": 1}.get(f["severity"], 0))
    severities = [f["severity"] for f in findings]
    risk = "High" if "High" in severities else "Medium" if "Medium" in severities else "Low" if findings else "Low"

    probe_url_primary = probes_result[0]["probeUrl"] if probes_result else url
    status_primary = probes_result[0].get("statusCode") if probes_result else worst_status

    successful_probes = [p for p in probes_result if not p.get("error")]
    probes_with_findings = [p for p in probes_result if p.get("indicatorsCount", 0) > 0]

    if all_found:
        high_cats = [f["category"] for f in findings if f["severity"] == "High"]
        cat_summary = ", ".join(high_cats[:4]) if high_cats else ", ".join(f["category"] for f in findings[:4])
        executive_summary = (
            f"Error handling analysis of {target_domain} detected {len(all_found)} information disclosure indicator(s) "
            f"across {len(findings)} category/categories: {cat_summary}. "
            f"{len(probes_with_findings)} of {len(successful_probes)} probes triggered disclosures. "
            f"Risk level: {risk}. These disclosures aid attacker reconnaissance and should be remediated."
        )
        simple_terms = (
            f"When the scanner sent unusual requests to {target_domain}, the server responded with error pages "
            "that reveal internal technical details. This information helps attackers understand the technology stack "
            "and find known vulnerabilities to exploit."
        )
        rec_parts = ["Replace all default error pages with custom, generic responses that do not reveal technical details."]
        if any(f["category"] in ("Stack trace", "Debug exposure") for f in findings):
            rec_parts.append("Disable debug mode and stack trace output in production immediately.")
        if any(f["category"] == "Database" for f in findings):
            rec_parts.append("Suppress database error details in client responses; use parameterized queries.")
        if any("Framework" in f["category"] for f in findings):
            rec_parts.append("Configure the application framework to use generic error handlers in production.")
        if any(f["category"] == "Credential leak" for f in findings):
            rec_parts.append("URGENT: Rotate any exposed credentials immediately and audit error handlers for sensitive data.")
        if any(f["category"] in ("Sensitive header", "Version disclosure") for f in findings):
            rec_parts.append("Remove or suppress technology-revealing response headers (Server, X-Powered-By, X-Debug-*).")
        if any(f["category"] == "Error page fingerprint" for f in findings):
            rec_parts.append("Replace default server error pages (404, 500) with custom pages that do not identify the stack.")
        if any(f["category"] == "Path disclosure" for f in findings):
            rec_parts.append("Ensure file system paths are never included in client-facing error responses.")
        if any(f["category"] == "Internal IP" for f in findings):
            rec_parts.append("Strip internal/private IP addresses from all response headers and bodies.")
        recommendation = " ".join(rec_parts)
    else:
        executive_summary = (
            f"Error handling analysis of {target_domain} sent {len(successful_probes)} probes designed to trigger "
            f"error responses. No information disclosure indicators were detected in response bodies or headers. "
            f"The server appears to handle errors securely with generic responses."
        )
        simple_terms = (
            f"The scanner tested {target_domain} with various unusual requests and the server did not leak "
            "any internal technical details in its error responses. This is the correct and secure behaviour."
        )
        recommendation = (
            "No information disclosure detected. Continue to use custom error pages and avoid "
            "exposing stack traces, file paths, or technology details in production error responses."
        )

    return {
        **base_result,
        "probeUrl": probe_url_primary,
        "probeStatus": status_primary,
        "probes": probes_result,
        "sensitiveLeaked": list(dict.fromkeys(f["indicator"] for f in all_found)),
        "riskLevel": risk,
        "findings": findings,
        "executiveSummary": executive_summary,
        "simpleTerms": simple_terms,
        "recommendation": recommendation,
        "responseSnippet": response_snippet,
        "references": references,
    }


# --- URL tampering (simple: tampered path/query, check for info leak) ---
def run_url_tampering_check(url: str, extra_headers=None, method="GET", body=None) -> dict:
    target_domain = get_domain(url)
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    tests = [
        ("Path traversal", base + "/..%2f..%2fetc%2fpasswd", "Path traversal probe"),
        ("Invalid query", url + ("&" if "?" in url else "?") + "id=1' OR '1'='1", "SQL-like query"),
    ]
    results = []
    for name, tampered_url, desc in tests:
        try:
            _, resp_body, status = fetch_url(tampered_url, extra_headers=extra_headers, method=method, body=body)
            # Heuristic: different status or long body might indicate different handling
            results.append({
                "test": name,
                "description": desc,
                "tamperedUrl": tampered_url,
                "statusCode": status,
                "bodyLength": len(resp_body or ""),
                "note": "Check manually for sensitive data in response.",
            })
        except Exception as e:
            results.append({
                "test": name,
                "description": desc,
                "tamperedUrl": tampered_url,
                "error": str(e),
            })
    return {
        "targetDomain": target_domain,
        "originalUrl": url,
        "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "tests": results,
        "recommendation": "Validate and sanitize all URL inputs; avoid reflecting user input in responses.",
    }


# --- Sensitive Data Exposure / PII Clear Text ---

_PII_PATTERNS = [
    {
        "id": "pan", "category": "Indian PAN Number", "severity": "High",
        "regex": re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),
        "impact": "PAN numbers are permanent government-issued identifiers. Exposure enables identity theft, fraudulent tax filings, and financial fraud.",
        "remediation": "Mask PAN numbers in API responses (e.g., ABCDE****F). Only return masked values; never transmit full PAN outside secure internal services.",
    },
    {
        "id": "aadhaar", "category": "Aadhaar Number", "severity": "High",
        "regex": re.compile(r'\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b'),
        "impact": "Aadhaar is a unique biometric-linked identity number. Leakage enables impersonation, SIM swap fraud, and unauthorized identity verification.",
        "remediation": "Mask Aadhaar in responses (e.g., XXXX XXXX 1234). Store securely with encryption at rest. Never expose in API responses.",
    },
    {
        "id": "card", "category": "Credit/Debit Card Number", "severity": "High",
        "regex": re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2})|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,4}\b'),
        "impact": "Card numbers enable unauthorized purchases and financial fraud. PCI-DSS mandates that full card numbers must never appear in API responses.",
        "remediation": "Display only last 4 digits (e.g., **** **** **** 1234). Ensure PCI-DSS compliance for all payment data handling.",
        "luhn": True,
    },
    {
        "id": "phone", "category": "Phone Number", "severity": "Medium",
        "regex": re.compile(r'\b(?:\+91[\s-]?)?[6-9]\d{9}\b'),
        "impact": "Phone numbers enable phishing via SMS/calls, SIM swap attacks, and correlation of user identity across services.",
        "remediation": "Mask phone numbers (e.g., +91 ******* 890). Return full numbers only when functionally required and behind strong authorization.",
    },
    {
        "id": "email", "category": "Email Address", "severity": "Medium",
        "regex": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "impact": "Exposed emails enable targeted phishing, credential stuffing, and spam campaigns. Combined with other PII, they amplify identity theft risk.",
        "remediation": "Mask email addresses (e.g., s****@example.com). Only return full emails to the authenticated owner of that email.",
    },
    {
        "id": "ifsc", "category": "IFSC Code", "severity": "Low",
        "regex": re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b'),
        "impact": "IFSC codes identify bank branches. Alone they are low risk, but combined with account numbers they enable unauthorized transactions.",
        "remediation": "IFSC codes are semi-public, but avoid exposing them alongside account numbers or other financial identifiers.",
    },
    {
        "id": "jwt", "category": "JWT Token in Response", "severity": "High",
        "regex": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
        "impact": "JWT tokens are authentication credentials. If exposed in the response body, attackers can hijack user sessions or impersonate users.",
        "remediation": "Never return JWT tokens in response bodies. Use HttpOnly Secure cookies or Authorization headers exclusively.",
    },
]

_SENSITIVE_FIELD_NAMES = {
    "pan": "Indian PAN Number", "pannumber": "Indian PAN Number", "pancard": "Indian PAN Number",
    "pan_number": "Indian PAN Number", "pan_card": "Indian PAN Number",
    "aadhaar": "Aadhaar Number", "aadhar": "Aadhaar Number", "aadhaarnumber": "Aadhaar Number",
    "aadhaar_number": "Aadhaar Number", "aadhar_number": "Aadhaar Number", "uid_number": "Aadhaar Number",
    "password": "Password / Secret", "passwd": "Password / Secret", "secret": "Password / Secret",
    "apikey": "Password / Secret", "api_key": "Password / Secret",
    "privatekey": "Password / Secret", "private_key": "Password / Secret",
    "secretkey": "Password / Secret", "secret_key": "Password / Secret",
    "accesstoken": "Password / Secret", "access_token": "Password / Secret",
    "refreshtoken": "Password / Secret", "refresh_token": "Password / Secret",
    "ssn": "Social Security Number", "socialsecurity": "Social Security Number",
    "cardnumber": "Credit/Debit Card Number", "card_number": "Credit/Debit Card Number",
    "cvv": "CVV / Card Security Code", "cvc": "CVV / Card Security Code",
    "cvv2": "CVV / Card Security Code", "card_cvv": "CVV / Card Security Code",
    "phonenumber": "Phone Number", "phone_number": "Phone Number",
    "mobile": "Phone Number", "mobilenumber": "Phone Number", "mobile_number": "Phone Number",
    "contactnumber": "Phone Number", "contact_number": "Phone Number",
    "emailid": "Email Address", "email_id": "Email Address",
    "emailaddress": "Email Address", "email_address": "Email Address",
    "dob": "Date of Birth", "dateofbirth": "Date of Birth", "date_of_birth": "Date of Birth",
    "birthdate": "Date of Birth", "birth_date": "Date of Birth",
    "accountnumber": "Bank Account Number", "account_number": "Bank Account Number",
    "bankaccount": "Bank Account Number", "bank_account": "Bank Account Number",
    "accountno": "Bank Account Number", "account_no": "Bank Account Number",
    "permanentaddress": "Residential Address", "permanent_address": "Residential Address",
    "correspondenceaddress": "Residential Address", "correspondence_address": "Residential Address",
    "fathername": "Family Member Name", "father_name": "Family Member Name",
    "mothername": "Family Member Name", "mother_name": "Family Member Name",
    "nomineename": "Nominee Name", "nominee_name": "Nominee Name",
    "ifsc": "IFSC Code", "ifsccode": "IFSC Code", "ifsc_code": "IFSC Code",
    "bankifsc": "IFSC Code", "bank_ifsc": "IFSC Code",
    "beneficiaryifsc": "IFSC Code", "beneficiary_ifsc": "IFSC Code",
}

_MASK_PATTERNS = [
    re.compile(r'^[Xx*]{3,}'),           # starts with XXX or ***
    re.compile(r'[Xx*]{4,}'),            # contains XXXX or ****
    re.compile(r'\*{2,}@\*{2,}'),        # masked email **@**
    re.compile(r'^\*+\d{1,4}$'),         # *****1234
    re.compile(r'^\d{0,2}[Xx*]+\d{0,4}$'),  # 12XXXX3456
]


def _is_masked(val: str) -> bool:
    """Return True if the value appears to be masked/redacted."""
    s = str(val).strip()
    if not s or s.lower() in ("null", "none", "", "n/a", "na"):
        return True
    for p in _MASK_PATTERNS:
        if p.search(s):
            return True
    return False


def _luhn_check(num_str: str) -> bool:
    """Validate a number string with the Luhn algorithm."""
    digits = [int(d) for d in re.sub(r'[\s-]', '', num_str) if d.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _redact_value(val: str, pii_id: str) -> str:
    """Return a partially redacted version of the value for evidence display."""
    s = str(val).strip()
    if len(s) <= 4:
        return "***"
    if pii_id in ("email",):
        at = s.find("@")
        if at > 1:
            return s[0] + "*" * (at - 1) + s[at:]
        return "***@" + s.split("@")[-1] if "@" in s else s[:2] + "***"
    if pii_id in ("pan",):
        return s[:2] + "***" + s[-1:] if len(s) >= 5 else "***"
    if pii_id in ("aadhaar",):
        clean = re.sub(r'[\s-]', '', s)
        return "XXXX XXXX " + clean[-4:] if len(clean) >= 4 else "***"
    if pii_id in ("card",):
        clean = re.sub(r'[\s-]', '', s)
        return "**** **** **** " + clean[-4:] if len(clean) >= 4 else "***"
    if pii_id in ("phone",):
        clean = re.sub(r'[\s-]', '', s)
        return clean[:3] + "****" + clean[-3:] if len(clean) >= 7 else "***"
    if pii_id in ("jwt",):
        return s[:20] + "..." if len(s) > 20 else s[:6] + "..."
    if len(s) > 6:
        return s[:2] + "*" * (len(s) - 4) + s[-2:]
    return s[:1] + "***" + s[-1:]


_SF_NORM = {k.replace("_", ""): v for k, v in _SENSITIVE_FIELD_NAMES.items()}


def _walk_json(obj, path="$", results=None):
    """Walk a JSON object and flag sensitive field names with cleartext values."""
    if results is None:
        results = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            current_path = f"{path}.{key}"
            key_lower = key.lower().replace("-", "").replace("_", "")
            key_normalized = key.lower()
            field_cat = None
            if key_normalized in _SENSITIVE_FIELD_NAMES or key_lower in _SF_NORM:
                field_cat = _SENSITIVE_FIELD_NAMES.get(key_normalized) or _SF_NORM.get(key_lower, "Sensitive Field")
                if isinstance(val, str) and val.strip() and not _is_masked(val):
                    also_regex = any(
                        p["category"] == field_cat and p["regex"].search(val)
                        for p in _PII_PATTERNS
                    )
                    results.append({
                        "source": "json_field+regex" if also_regex else "json_field",
                        "field": key,
                        "path": current_path,
                        "category": field_cat,
                        "value": val,
                    })
            if isinstance(val, (dict, list)):
                _walk_json(val, current_path, results)
            elif isinstance(val, str) and len(val) >= 6:
                for p in _PII_PATTERNS:
                    if field_cat and p["category"] == field_cat:
                        continue
                    m = p["regex"].search(val)
                    if m:
                        matched = m.group(0)
                        if p.get("luhn") and not _luhn_check(matched):
                            continue
                        if not _is_masked(matched):
                            results.append({
                                "source": "regex",
                                "field": key,
                                "path": current_path,
                                "category": p["category"],
                                "pii_id": p["id"],
                                "value": matched,
                            })
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _walk_json(item, f"{path}[{i}]", results)
    return results


def _scan_response_text(text: str):
    """Scan raw response text for PII patterns (fallback when body is not JSON)."""
    results = []
    for p in _PII_PATTERNS:
        for m in p["regex"].finditer(text[:50000]):
            matched = m.group(0)
            if p.get("luhn") and not _luhn_check(matched):
                continue
            if not _is_masked(matched):
                start = max(0, m.start() - 30)
                end = min(len(text), m.end() + 30)
                context = text[start:end].replace("\n", " ").strip()
                results.append({
                    "source": "body_text",
                    "field": None,
                    "path": f"response_body[{m.start()}:{m.end()}]",
                    "category": p["category"],
                    "pii_id": p["id"],
                    "value": matched,
                    "context": context,
                })
    return results


def _check_response_headers(resp_headers: dict) -> list:
    """Check response headers for sensitive data exposure issues."""
    issues = []
    cc = resp_headers.get("Cache-Control", "")
    pragma = resp_headers.get("Pragma", "")
    if not cc:
        issues.append({
            "header": "Cache-Control",
            "severity": "Medium",
            "issue": "Cache-Control header is missing",
            "detail": "Without Cache-Control, proxies and browsers may cache API responses containing sensitive data. Cached PII can be retrieved by other users on shared devices or through proxy logs.",
            "fix": "Add 'Cache-Control: no-store, no-cache, must-revalidate, private' to all responses containing sensitive data.",
        })
    elif "public" in cc.lower() or ("no-store" not in cc.lower() and "private" not in cc.lower()):
        issues.append({
            "header": "Cache-Control",
            "severity": "Medium",
            "issue": f"Cache-Control allows caching: {cc}",
            "detail": "The current Cache-Control value permits caching of API responses. If the response contains PII, it may be stored in browser caches, CDN caches, or proxy servers.",
            "fix": "Set 'Cache-Control: no-store, no-cache, must-revalidate, private' for endpoints that return sensitive data.",
        })
    cookies = resp_headers.get("Set-Cookie", "")
    if cookies:
        cookie_parts = cookies.lower()
        if "secure" not in cookie_parts:
            issues.append({
                "header": "Set-Cookie",
                "severity": "High",
                "issue": "Cookie set without Secure flag",
                "detail": "Cookies without the Secure flag can be transmitted over unencrypted HTTP connections, allowing network attackers to intercept session tokens or sensitive cookie values.",
                "fix": "Add the 'Secure' flag to all Set-Cookie headers.",
            })
        if "httponly" not in cookie_parts:
            issues.append({
                "header": "Set-Cookie",
                "severity": "Medium",
                "issue": "Cookie set without HttpOnly flag",
                "detail": "Cookies without HttpOnly can be accessed by client-side JavaScript. If an XSS vulnerability exists, attackers can steal session tokens.",
                "fix": "Add the 'HttpOnly' flag to cookies that don't need JavaScript access.",
            })
    return issues


def run_sensitive_data_check(url: str, extra_headers=None, method="GET", body=None) -> dict:
    """Scan an API response for exposed PII and sensitive data in cleartext."""
    target_domain = get_domain(url)
    base_result = {
        "targetDomain": target_domain,
        "originalUrl": url,
        "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
    }

    headers = {"User-Agent": "Mozilla/5.0 (SecurityScanner)", "Accept": "application/json, text/html, */*"}
    if extra_headers:
        headers.update(extra_headers)

    try:
        resp = requests.request(
            method or "GET", url, headers=headers,
            json=body if body and isinstance(body, dict) else None,
            data=body if body and not isinstance(body, dict) else None,
            timeout=SCANNER_TIMEOUT, verify=True, allow_redirects=True,
        )
    except Exception as e:
        return {
            **base_result, "error": str(e), "riskLevel": "Unknown",
            "findings": [], "headerIssues": [], "piiStats": {},
            "executiveSummary": f"Could not reach {target_domain}: {e}. Manual inspection recommended.",
            "simpleTerms": "The scanner could not connect to the server to check for sensitive data.",
            "recommendation": "Ensure the URL is reachable and try again.",
        }

    status_code = resp.status_code
    resp_headers = dict(resp.headers)
    body_text = resp.text or ""

    # Scan for PII
    pii_hits = []
    is_json = False
    try:
        json_body = resp.json()
        is_json = True
        pii_hits = _walk_json(json_body)
    except Exception:
        if body_text.strip():
            pii_hits = _scan_response_text(body_text)

    # Deduplicate hits by (category, value)
    seen = set()
    unique_hits = []
    for h in pii_hits:
        key = (h["category"], h.get("value", ""))
        if key not in seen:
            seen.add(key)
            unique_hits.append(h)

    # Check headers
    header_issues = _check_response_headers(resp_headers)

    # Build findings grouped by category
    cat_map = {}
    for h in unique_hits:
        cat = h["category"]
        if cat not in cat_map:
            pii_def = next((p for p in _PII_PATTERNS if p["category"] == cat), None)
            cat_map[cat] = {
                "category": cat,
                "severity": pii_def["severity"] if pii_def else "Medium",
                "impact": pii_def["impact"] if pii_def else "Sensitive data exposed in API response may be used for identity theft or fraud.",
                "remediation": pii_def["remediation"] if pii_def else "Mask or remove sensitive data from API responses.",
                "evidence": [],
            }
        pii_id = h.get("pii_id") or h["category"].lower().split()[0]
        cat_map[cat]["evidence"].append({
            "field": h.get("field"),
            "path": h.get("path"),
            "value": h.get("value", ""),
            "source": h.get("source", "unknown"),
            "context": h.get("context"),
            "detectionMethod": {
                "json_field": "Sensitive field name detected in JSON response",
                "json_field+regex": "Sensitive field name detected + value confirmed by regex pattern",
                "regex": "PII pattern matched via regex in JSON value",
                "body_text": "PII pattern matched in response body text",
            }.get(h.get("source", ""), "Pattern match"),
        })
        if h.get("source") == "json_field" and cat_map[cat]["severity"] == "Medium":
            if cat in ("Password / Secret", "CVV / Card Security Code"):
                cat_map[cat]["severity"] = "High"

    findings = sorted(cat_map.values(), key=lambda f: {"High": 0, "Medium": 1, "Low": 2}.get(f["severity"], 3))

    # PII stats
    pii_stats = {}
    for h in unique_hits:
        pii_stats[h["category"]] = pii_stats.get(h["category"], 0) + 1

    # Risk level
    high_count = sum(1 for f in findings if f["severity"] == "High")
    med_count = sum(1 for f in findings if f["severity"] == "Medium")
    has_header_high = any(i["severity"] == "High" for i in header_issues)
    if high_count > 0 or has_header_high:
        risk = "High"
    elif med_count > 0 or header_issues:
        risk = "Medium"
    elif len(unique_hits) > 0:
        risk = "Low"
    else:
        risk = "None"

    # Executive summary
    total_pii = len(unique_hits)
    total_types = len(pii_stats)
    if total_pii == 0 and not header_issues:
        exec_summary = (
            f"The API response from {target_domain} (HTTP {status_code}) was scanned for sensitive data exposure. "
            f"No PII or sensitive data in cleartext was detected in the {'JSON' if is_json else 'response'} body or headers. "
            f"The endpoint appears to handle sensitive data appropriately."
        )
        simple = "No sensitive data like PAN numbers, Aadhaar, card numbers, emails, or phone numbers was found exposed in the API response."
    else:
        parts = []
        if total_pii > 0:
            type_names = ", ".join(pii_stats.keys())
            parts.append(
                f"{total_pii} instance{'s' if total_pii != 1 else ''} of sensitive data across "
                f"{total_types} categor{'ies' if total_types != 1 else 'y'} ({type_names}) "
                f"{'were' if total_pii != 1 else 'was'} found in cleartext"
            )
        if header_issues:
            parts.append(f"{len(header_issues)} response header issue{'s' if len(header_issues) != 1 else ''}")
        exec_summary = (
            f"The API response from {target_domain} (HTTP {status_code}) was scanned for sensitive data exposure. "
            f"The scan identified {' and '.join(parts)}. "
        )
        if high_count > 0:
            exec_summary += (
                "This represents a significant data exposure risk. Cleartext PII in API responses can be intercepted, "
                "logged by proxies, cached by browsers, or harvested by malicious scripts. Immediate remediation is required."
            )
        else:
            exec_summary += (
                "While no critical PII was found, the identified issues should be addressed to strengthen the security posture "
                "and comply with data protection regulations."
            )
        simple_parts = []
        for cat_name, cnt in pii_stats.items():
            simple_parts.append(f"{cnt} {cat_name}{'s' if cnt > 1 else ''}")
        simple = f"The API response exposes: {', '.join(simple_parts)}. This data is visible in cleartext and should be masked or removed."

    # Recommendation
    rec_parts = []
    if high_count > 0:
        high_cats = [f["category"] for f in findings if f["severity"] == "High"]
        rec_parts.append(f"Immediately mask or remove {', '.join(high_cats)} from API responses.")
    if med_count > 0:
        med_cats = [f["category"] for f in findings if f["severity"] == "Medium"]
        rec_parts.append(f"Mask {', '.join(med_cats)} or restrict to authorized consumers only.")
    low_count = sum(1 for f in findings if f["severity"] == "Low")
    if low_count > 0:
        low_cats = [f["category"] for f in findings if f["severity"] == "Low"]
        rec_parts.append(f"Review exposure of {', '.join(low_cats)} — while individually low risk, ensure they are not returned alongside higher-sensitivity identifiers (e.g., account numbers, PAN) that could increase combined risk.")
    if header_issues:
        rec_parts.append("Fix response header issues: " + "; ".join(i["fix"] for i in header_issues))
    if not rec_parts:
        rec_parts.append("No sensitive data or header issues detected. Continue monitoring API responses for sensitive data exposure.")
    recommendation = " ".join(rec_parts)

    # Compliance references
    compliance = []
    if any(f["category"] in ("Indian PAN Number", "Aadhaar Number") for f in findings):
        compliance.append({"standard": "IT Act 2000 / DPDP Act 2023 (India)", "detail": "Section 43A mandates reasonable security for sensitive personal data. PAN and Aadhaar are classified as sensitive personal data under Indian law."})
    if any(f["category"] == "Credit/Debit Card Number" for f in findings):
        compliance.append({"standard": "PCI-DSS v4.0", "detail": "Requirement 3.4 — Render PAN unreadable anywhere it is stored or transmitted. Full card numbers must never appear in API responses."})
    if any(f["category"] in ("Email Address", "Phone Number", "Date of Birth", "Residential Address") for f in findings):
        compliance.append({"standard": "GDPR Article 5(1)(f) / DPDP Act 2023", "detail": "Personal data must be processed with appropriate security. Transmitting PII in cleartext violates the integrity and confidentiality principle."})
    if any(f["category"] in ("Password / Secret", "CVV / Card Security Code") for f in findings):
        compliance.append({"standard": "OWASP API Security Top 10 — API3:2023", "detail": "Broken Object Property Level Authorization — API endpoints must not expose sensitive properties like passwords, secrets, or security codes in responses."})

    # Scan metadata
    content_type = resp_headers.get("Content-Type", "unknown")
    resp_size = len(body_text)

    return {
        **base_result,
        "httpStatus": status_code,
        "isJson": is_json,
        "contentType": content_type,
        "responseSize": resp_size,
        "riskLevel": risk,
        "findings": findings,
        "headerIssues": header_issues,
        "piiStats": pii_stats,
        "totalPiiInstances": total_pii,
        "totalCategories": total_types,
        "fieldsScanned": "JSON tree" if is_json else "response body text",
        "executiveSummary": exec_summary,
        "simpleTerms": simple,
        "recommendation": recommendation,
        "compliance": compliance,
    }


# --- SSL/TLS: SSL Labs API with local TLS fallback ---
LOCAL_SSL_TIMEOUT = 4

def _protocol_to_local_grade(protocol: str) -> tuple:
    """Map negotiated protocol to a local grade and status. Returns (grade, status)."""
    if not protocol:
        return ("F", "Failed")
    p = (protocol or "").upper()
    if "TLSV1.3" in p or "TLS 1.3" in p:
        return ("A", "Strong — TLS 1.3")
    if "TLSV1.2" in p or "TLS 1.2" in p:
        return ("B", "Good — TLS 1.2")
    if "TLSV1.1" in p or "TLS 1.1" in p:
        return ("C", "Weak — TLS 1.1")
    if "TLSV1" in p or "TLS 1.0" in p:
        return ("D", "Weak — TLS 1.0")
    if "SSL" in p:
        return ("F", "Insecure — SSLv3 or older")
    return ("?", "Unknown")


def _parse_cipher_details(cipher_name: str, bits=None) -> dict:
    """Parse an OpenSSL cipher suite name into its components and security properties."""
    name = (cipher_name or "").upper().replace("-", "_")
    kx = auth = enc = mode = mac = "Unknown"
    fs = aead = False
    strength = "unknown"

    if "ECDHE" in name:
        kx, fs = "ECDHE", True
    elif "DHE" in name or "EDH" in name:
        kx, fs = "DHE", True
    elif "ECDH" in name:
        kx = "ECDH"
    else:
        kx = "RSA (static)"

    if "ECDSA" in name:
        auth = "ECDSA"
    elif "RSA" in name:
        auth = "RSA"

    if "CHACHA20" in name:
        enc, mode, aead = "ChaCha20-Poly1305", "AEAD", True
    elif "AES" in name:
        enc = "AES-256" if ("AES_256" in name or "AES256" in name) else ("AES-128" if ("AES_128" in name or "AES128" in name) else "AES")
        if "GCM" in name:
            mode, aead = "GCM (AEAD)", True
        elif "CCM" in name:
            mode, aead = "CCM (AEAD)", True
        else:
            mode = "CBC"
    elif "3DES" in name or "DES_CBC3" in name:
        enc, mode = "3DES", "CBC"
    elif "RC4" in name:
        enc, mode = "RC4", "Stream"

    if aead:
        mac = "AEAD (integrated)"
    elif "SHA384" in name:
        mac = "SHA-384"
    elif "SHA256" in name:
        mac = "SHA-256"
    elif "SHA" in name:
        mac = "SHA-1"
    elif "MD5" in name:
        mac = "MD5"

    b = int(bits) if bits else 0
    if enc in ("RC4", "3DES") or mac in ("MD5", "SHA-1") and not aead:
        strength = "weak"
    elif b >= 256 or (b >= 128 and aead and fs):
        strength = "strong"
    elif b >= 128:
        strength = "acceptable"
    elif b > 0:
        strength = "weak"

    return {
        "name": cipher_name, "bits": bits,
        "keyExchange": kx, "authentication": auth,
        "encryption": enc, "mode": mode, "mac": mac,
        "forwardSecrecy": fs, "aead": aead, "strength": strength,
    }


def _parse_cert_dict(cert: dict) -> dict:
    """Extract useful certificate fields from Python ssl getpeercert() dict."""
    if not cert:
        return None
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    sans = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
    return {
        "commonName": subject.get("commonName"),
        "organization": subject.get("organizationName"),
        "issuerCN": issuer.get("commonName"),
        "issuerOrg": issuer.get("organizationName"),
        "validFrom": cert.get("notBefore"),
        "validUntil": cert.get("notAfter"),
        "altNames": sans,
        "serialNumber": cert.get("serialNumber"),
        "version": cert.get("version"),
        "ocsp": list(cert.get("OCSP", ())),
        "caIssuers": list(cert.get("caIssuers", ())),
    }


def _local_ssl_check(host: str, port: int = 443) -> dict:
    """Local TLS check: protocol, cipher, certificate basics, and a protocol-based grade."""
    out = {"protocol": None, "cipher": None, "localGrade": None, "localStatus": None,
           "cipherDetails": None, "certInfo": None, "certTrusted": None}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=LOCAL_SSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                out["protocol"] = ssock.version()
                try:
                    cipher = ssock.cipher()
                    if cipher:
                        out["cipher"] = f"{cipher[0]} ({cipher[2]} bits)" if len(cipher) >= 3 else str(cipher[0])
                        out["cipherDetails"] = _parse_cipher_details(cipher[0], cipher[2] if len(cipher) >= 3 else None)
                except Exception:
                    pass
                grade, status = _protocol_to_local_grade(out["protocol"])
                out["localGrade"] = f"{grade} (local)"
                out["localStatus"] = status
    except ssl.SSLError as e:
        out["error"] = str(e)
        out["protocol"] = "connection failed"
        out["localGrade"] = "F (local)"
        out["localStatus"] = "Connection failed"
    except Exception as e:
        out["error"] = str(e)
        out["localGrade"] = "F (local)"
        out["localStatus"] = "Connection failed"

    try:
        ctx2 = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=LOCAL_SSL_TIMEOUT) as sock2:
            with ctx2.wrap_socket(sock2, server_hostname=host) as ssock2:
                cert = ssock2.getpeercert()
                if cert:
                    out["certInfo"] = _parse_cert_dict(cert)
                    out["certTrusted"] = True
    except ssl.SSLCertVerificationError:
        out["certTrusted"] = False
    except Exception:
        pass

    return out


def _enumerate_local_protocols(host: str, port: int = 443) -> list:
    """Probe which TLS/SSL protocol versions the server supports."""
    PROTO_MAP = []
    if hasattr(ssl, "TLSVersion"):
        PROTO_MAP.append(("TLS 1.3", ssl.TLSVersion.TLSv1_3))
        PROTO_MAP.append(("TLS 1.2", ssl.TLSVersion.TLSv1_2))
        PROTO_MAP.append(("TLS 1.1", ssl.TLSVersion.TLSv1_1))
        PROTO_MAP.append(("TLS 1.0", ssl.TLSVersion.TLSv1))

    results = []
    for name, ver in PROTO_MAP:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            with socket.create_connection((host, port), timeout=LOCAL_SSL_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    results.append({"name": name, "enabled": True, "insecure": name in ("TLS 1.0", "TLS 1.1")})
        except Exception:
            results.append({"name": name, "enabled": False, "insecure": False})
    return results


def _enumerate_local_ciphers(host: str, port: int = 443) -> dict:
    """Enumerate supported cipher suites by iteratively removing the server's preferred cipher.

    Returns {protocol_version: [list of cipher names in server-preference order]}.
    """
    TLS_VERSIONS = []
    if hasattr(ssl, "TLSVersion"):
        TLS_VERSIONS.append(("TLS 1.3", ssl.TLSVersion.TLSv1_3))
        TLS_VERSIONS.append(("TLS 1.2", ssl.TLSVersion.TLSv1_2))

    result = {}
    for proto_name, ver in TLS_VERSIONS:
        ciphers_found = []
        excluded = set()
        for _ in range(50):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ver
                ctx.maximum_version = ver

                if proto_name == "TLS 1.3":
                    pass  # TLS 1.3 ciphers can't be excluded via set_ciphers
                else:
                    avail = [c["name"] for c in ctx.get_ciphers() if c["name"] not in excluded]
                    if not avail:
                        break
                    ctx.set_ciphers(":".join(avail))

                with socket.create_connection((host, port), timeout=LOCAL_SSL_TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cipher = ssock.cipher()
                        if not cipher or cipher[0] in excluded:
                            break
                        name = cipher[0]
                        bits = cipher[2] if len(cipher) >= 3 else None
                        ciphers_found.append({"name": name, "bits": bits})
                        excluded.add(name)
                        if proto_name == "TLS 1.3":
                            break  # can't exclude TLS 1.3 ciphers individually
            except Exception:
                break
        if ciphers_found:
            result[proto_name] = ciphers_found

    # For TLS 1.3, try known cipher names individually
    if "TLS 1.3" in result and len(result["TLS 1.3"]) == 1 and hasattr(ssl, "TLSVersion"):
        tls13_known = [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ]
        found_13 = []
        for cipher_name in tls13_known:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                with socket.create_connection((host, port), timeout=LOCAL_SSL_TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        c = ssock.cipher()
                        if c and c[0] == cipher_name:
                            found_13.append({"name": c[0], "bits": c[2] if len(c) >= 3 else None})
            except Exception:
                pass
        if found_13:
            result["TLS 1.3"] = found_13

    return result


def _ts_to_iso(ts):
    """Convert Unix timestamp to ISO date string. API may use seconds or milliseconds."""
    if ts is None:
        return None
    try:
        sec = ts / 1000.0 if ts > 1e12 else ts
        return datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%a, %d %b %Y %H:%M:%S UTC")
    except Exception:
        return str(ts)


def _parse_ssl_labs_full_report(data: dict, host: str, ssl_labs_url: str) -> dict:
    """Build a rich SSL report from SSL Labs API response when status is READY and full data is present."""
    endpoints = data.get("endpoints") or []
    certs_raw = data.get("certs") or []
    certs_by_id = {c.get("id"): c for c in certs_raw if c.get("id") is not None}
    grade = data.get("grade") or "N/A"
    ip_address = None
    details = None
    for ep in endpoints:
        if ep.get("ipAddress"):
            ip_address = ip_address or ep.get("ipAddress")
        if grade in (None, "N/A") and ep.get("grade"):
            grade = ep["grade"]
        if ep.get("details") and details is None:
            details = ep.get("details")
            if not ip_address and ep.get("ipAddress"):
                ip_address = ep.get("ipAddress")
    if not details:
        return {
            "host": host,
            "error": False,
            "grade": grade,
            "endpointGrade": grade,
            "ipAddress": ip_address,
            "sslLabsUrl": ssl_labs_url,
            "reportTitle": f"SSL Report: {host}" + (f" ({ip_address})" if ip_address else ""),
            "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "summary": f"Grade: {grade}. For full certificate and cipher details see the Qualys SSL Labs report linked below.",
            "recommendation": "Ensure TLS 1.2+ only and strong ciphers; fix any certificate issues.",
        }
    # Certificates from first chain
    certificates = []
    cert_chains = details.get("certChains") or []
    if cert_chains:
        for cert_id in cert_chains[0].get("certIds") or []:
            c = certs_by_id.get(cert_id)
            if not c:
                continue
            rev_status = c.get("revocationStatus")
            rev_text = {0: "Not checked", 1: "Revoked", 2: "Good (not revoked)", 3: "Error", 4: "No revocation info", 5: "Internal error"}.get(rev_status, "Unknown")
            cert_entry = {
                "subject": c.get("subject"),
                "serialNumber": c.get("serialNumber"),
                "commonNames": c.get("commonNames") or [],
                "altNames": c.get("altNames") or [],
                "validFrom": _ts_to_iso(c.get("notBefore")),
                "validUntil": _ts_to_iso(c.get("notAfter")),
                "issuer": c.get("issuerSubject"),
                "signatureAlgorithm": c.get("sigAlg"),
                "keyAlg": c.get("keyAlg"),
                "keySize": c.get("keySize"),
                "sha256Fingerprint": c.get("sha256Hash"),
                "pinSha256": c.get("pinSha256"),
                "revocationStatus": rev_text,
                "revocationInfo": c.get("revocationInfo"),
                "crlUris": c.get("crlURIs") or [],
                "ocspUris": c.get("ocspURIs") or [],
                "extendedValidation": c.get("validationType") == "E",
                "dnsCaa": c.get("dnsCaa"),
                "sct": c.get("sct"),
                "weakKeyDebian": c.get("keyKnownDebianInsecure"),
            }
            certificates.append(cert_entry)
    chain_issues = cert_chains[0].get("issues", 0) if cert_chains else 0
    chain_issues_text = "None" if chain_issues == 0 else str(chain_issues)
    certificates_provided = len(cert_chains[0].get("certIds") or []) if cert_chains else 0
    # Protocols (Configuration)
    protocols = []
    for p in details.get("protocols") or []:
        ver = p.get("version") or p.get("id")
        name = (p.get("name") or "TLS") + " " + str(ver) if ver else (p.get("name") or "Unknown")
        q = p.get("q")
        enabled = q != 0 if q is not None else True
        protocols.append({"name": name, "version": ver, "enabled": enabled, "insecure": q == 0})
    # Cipher suites by protocol
    cipher_suites = []
    for ps in details.get("suites") or []:
        proto_name = "TLS " + str(ps.get("protocol", ""))
        list_suites = ps.get("list") or []
        suites = [{"name": s.get("name"), "weak": s.get("q") in (0, 1), "cipherStrength": s.get("cipherStrength"), "kxType": s.get("kxType"), "kxStrength": s.get("kxStrength")} for s in list_suites]
        cipher_suites.append({"protocol": proto_name, "preference": ps.get("preference"), "suites": suites})
    # Protocol details (vulnerabilities and features)
    reneg = details.get("renegSupport")
    reneg_secure = (reneg is not None and (reneg & 2) != 0) if reneg is not None else None
    reneg_insecure = (reneg is not None and (reneg & 1) != 0) if reneg is not None else None
    session_tickets = details.get("sessionTickets")
    session_ticket_ok = (session_tickets is not None and (session_tickets & 1) != 0) if session_tickets is not None else None
    heartbleed = details.get("heartbleed")
    poodle_tls = details.get("poodleTls")
    poodle_tls_vuln = poodle_tls == 2 if poodle_tls is not None else None
    robot = details.get("bleichenbacher")
    robot_vuln = robot in (2, 3) if robot is not None else None
    freak = details.get("freak")
    logjam = details.get("logjam")
    drown = details.get("drownVulnerable")
    zombie_poodle = details.get("zombiePoodle")
    zombie_vuln = zombie_poodle in (2, 3) if zombie_poodle is not None else None
    golden_doodle = details.get("goldenDoodle")
    golden_vuln = golden_doodle in (4, 5) if golden_doodle is not None else None
    ticketbleed = details.get("ticketbleed")
    ticketbleed_vuln = ticketbleed == 2 if ticketbleed is not None else None
    zero_rtt = details.get("zeroRTTEnabled")
    protocol_details = [
        {"name": "Secure Renegotiation", "value": "Supported" if reneg_secure else "No", "ok": reneg_secure},
        {"name": "Insecure Client-Initiated Renegotiation", "value": "No" if not reneg_insecure else "Yes", "ok": not reneg_insecure},
        {"name": "BEAST (server-side)", "value": "Not mitigated" if details.get("vulnBeast") else "No", "ok": not details.get("vulnBeast")},
        {"name": "POODLE (SSLv3)", "value": "No" if not details.get("poodle") else "Yes", "ok": not details.get("poodle")},
        {"name": "POODLE (TLS)", "value": "Vulnerable" if poodle_tls_vuln else ("No" if poodle_tls_vuln is not None else "N/A"), "ok": not poodle_tls_vuln if poodle_tls_vuln is not None else None},
        {"name": "Downgrade prevention (TLS_FALLBACK_SCSV)", "value": "Yes" if details.get("fallbackScsv") else "No", "ok": details.get("fallbackScsv")},
        {"name": "SSL/TLS compression", "value": "No" if not details.get("compressionMethods") else "Yes", "ok": not details.get("compressionMethods")},
        {"name": "RC4", "value": "No" if not details.get("supportsRc4") else "Yes", "ok": not details.get("supportsRc4")},
        {"name": "Heartbleed (CVE-2014-0160)", "value": "Vulnerable" if heartbleed else ("No" if heartbleed is not None else "N/A"), "ok": not heartbleed if heartbleed is not None else None},
        {"name": "ROBOT (Bleichenbacher)", "value": "Vulnerable" if robot_vuln else ("No" if robot_vuln is not None else "N/A"), "ok": not robot_vuln if robot_vuln is not None else None},
        {"name": "FREAK", "value": "Vulnerable" if freak else ("No" if freak is not None else "N/A"), "ok": not freak if freak is not None else None},
        {"name": "Logjam", "value": "Vulnerable" if logjam else ("No" if logjam is not None else "N/A"), "ok": not logjam if logjam is not None else None},
        {"name": "DROWN", "value": "Vulnerable" if drown else ("No" if drown is not None else "N/A"), "ok": not drown if drown is not None else None},
        {"name": "Zombie POODLE", "value": "Vulnerable" if zombie_vuln else ("No" if zombie_vuln is not None else "N/A"), "ok": not zombie_vuln if zombie_vuln is not None else None},
        {"name": "GOLDENDOODLE", "value": "Vulnerable" if golden_vuln else ("No" if golden_vuln is not None else "N/A"), "ok": not golden_vuln if golden_vuln is not None else None},
        {"name": "Ticketbleed (CVE-2016-9244)", "value": "Vulnerable" if ticketbleed_vuln else ("No" if ticketbleed_vuln is not None else "N/A"), "ok": not ticketbleed_vuln if ticketbleed_vuln is not None else None},
        {"name": "Forward Secrecy", "value": "Yes" if (details.get("forwardSecrecy") or 0) > 0 else "No", "ok": (details.get("forwardSecrecy") or 0) > 0},
        {"name": "ALPN", "value": (details.get("alpnProtocols") or "No").replace(" ", ", ") if details.get("alpnProtocols") else "No", "ok": bool(details.get("alpnProtocols"))},
        {"name": "NPN", "value": (details.get("npnProtocols") or "No").replace(" ", ", ") if details.get("npnProtocols") else "No", "ok": bool(details.get("npnProtocols"))},
        {"name": "Session resumption (tickets)", "value": "Yes" if session_ticket_ok else "No", "ok": session_ticket_ok},
        {"name": "0-RTT (TLS 1.3)", "value": "Enabled" if zero_rtt == 1 else ("Disabled" if zero_rtt == 0 else "N/A"), "ok": zero_rtt != 1 if zero_rtt is not None else None},
    ]
    # Remove rows where value is "N/A" (test not applicable/not run)
    protocol_details = [d for d in protocol_details if d["value"] != "N/A"]
    # Handshake simulation
    sims = details.get("sims") or {}
    sim_results = sims.get("results") or []
    handshake_simulation = []
    for sim in sim_results:
        client = sim.get("client") or {}
        client_name = client.get("name") or "Unknown"
        platform = client.get("platform") or ""
        ver = client.get("version") or ""
        client_label = f"{client_name} {ver}/{platform}".strip(" /")
        err = sim.get("errorCode")
        err_msg = sim.get("errorMessage") or ""
        if err and err != 0:
            handshake_simulation.append({"client": client_label, "protocol": None, "suite": None, "error": err_msg})
        else:
            handshake_simulation.append({
                "client": client_label,
                "protocol": "TLS " + str(sim.get("protocolId", "")),
                "suite": sim.get("suiteName"),
                "error": None,
            })
    # HSTS and HTTP
    hsts = details.get("hstsPolicy") or {}
    hsts_status = hsts.get("status") or "unknown"
    http_status = details.get("httpStatusCode")
    server_sig = details.get("serverSignature") or "-"
    test_time = data.get("testTime")
    start_time = data.get("startTime")
    duration_sec = (test_time - start_time) / 1000.0 if (test_time and start_time) else None
    report = {
        "host": host,
        "error": False,
        "grade": grade,
        "endpointGrade": grade,
        "ipAddress": ip_address,
        "sslLabsUrl": ssl_labs_url,
        "reportTitle": f"SSL Report: {host}" + (f" ({ip_address})" if ip_address else ""),
        "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "certificates": certificates,
        "chainIssues": chain_issues_text,
        "certificatesProvided": certificates_provided,
        "protocols": protocols,
        "cipherSuites": cipher_suites,
        "protocolDetails": protocol_details,
        "handshakeSimulation": handshake_simulation,
        "hstsStatus": hsts_status,
        "httpStatusCode": http_status,
        "serverSignature": server_sig,
        "testDurationSeconds": round(duration_sec, 2) if duration_sec is not None else None,
    }
    obs = _generate_ssl_observation(report)
    report["observation"] = obs["observation"]
    report["observationFindings"] = obs["observationFindings"]
    report["summary"] = obs.get("summary", f"Grade: {grade}.")
    report["recommendation"] = obs.get("recommendation", "Ensure TLS 1.2+ only and strong ciphers.")
    return report


def _generate_ssl_observation(report: dict) -> dict:
    """Generate a professional, human-readable security observation from the SSL report data.

    Returns a dict with 'observation', 'observationFindings', 'summary', 'recommendation'.
    Every statement must be factually verifiable from the scan data.
    """
    host = report.get("host", "the target server")
    grade = (report.get("grade") or report.get("localGrade") or "N/A").replace(" (local)", "")
    findings = []
    issues = []
    positives = []

    # ── Protocol analysis ──
    protocols_list = report.get("protocols") or []
    local_proto = report.get("localProtocol") or ""
    deprecated_protos = []
    supported_protos = []
    if protocols_list:
        for p in protocols_list:
            name = p.get("name", "")
            if p.get("enabled"):
                supported_protos.append(name)
                if "1.0" in name or "1.1" in name or "SSL" in name.upper():
                    deprecated_protos.append(name)
    elif local_proto:
        supported_protos.append(local_proto)
        if "1.0" in local_proto or "1.1" in local_proto or "SSL" in local_proto.upper():
            deprecated_protos.append(local_proto)

    if deprecated_protos:
        names = ", ".join(deprecated_protos)
        issues.append(f"deprecated protocol versions still enabled ({names})")
        findings.append({
            "type": "issue", "severity": "High",
            "title": "Deprecated TLS/SSL Protocols Enabled",
            "detail": f"The server supports {names}, which are known to be insecure and susceptible to attacks such as POODLE and BEAST. These should be disabled immediately, leaving only TLS 1.2 and TLS 1.3 enabled.",
        })

    has_tls13 = any("1.3" in p for p in supported_protos)
    has_tls12 = any("1.2" in p for p in supported_protos)
    if has_tls13:
        positives.append("TLS 1.3 support")
    if has_tls12 and not has_tls13:
        findings.append({
            "type": "note", "severity": "Low",
            "title": "TLS 1.3 Not Supported",
            "detail": "The server supports TLS 1.2 which is currently secure, but TLS 1.3 offers improved performance (fewer round trips) and stronger security (removes legacy cipher suites). Enabling TLS 1.3 is recommended.",
        })

    # ── Cipher suite analysis ──
    cipher_suites = report.get("cipherSuites") or []
    cd = report.get("cipherDetails") or {}
    weak_ciphers = []
    total_ciphers = 0
    cbc_ciphers = []
    cbc_with_fs = []
    cbc_without_fs = []
    non_fs_ciphers = []

    def _is_cbc_cipher(cname: str) -> bool:
        upper = cname.upper().replace("-", "_")
        if "_CBC_" in upper:
            return True
        if "AES" in upper and "GCM" not in upper and "CCM" not in upper and "CHACHA" not in upper:
            if not (upper.startswith("TLS_") and "_WITH_" not in upper):
                return True
        return False

    if cipher_suites:
        for group in cipher_suites:
            for s in group.get("suites") or []:
                total_ciphers += 1
                name = s.get("name", "")
                is_tls13 = "_WITH_" not in name and name.startswith("TLS_")
                has_fs = is_tls13 or any(kx in name for kx in ("ECDHE", "DHE"))
                if s.get("weak"):
                    weak_ciphers.append(name)
                if _is_cbc_cipher(name):
                    cbc_ciphers.append(name)
                    if has_fs:
                        cbc_with_fs.append(name)
                    else:
                        cbc_without_fs.append(name)
                if not has_fs:
                    non_fs_ciphers.append(name)
    elif cd:
        total_ciphers = 1
        cipher_name = cd.get("name", "")
        has_fs = cd.get("forwardSecrecy", False)
        if cd.get("strength") == "weak":
            weak_ciphers.append(cipher_name)
        if cd.get("mode", "").upper() == "CBC" or (not cd.get("aead")):
            cbc_ciphers.append(cipher_name)
            if has_fs:
                cbc_with_fs.append(cipher_name)
            else:
                cbc_without_fs.append(cipher_name)
        if not has_fs:
            non_fs_ciphers.append(cipher_name)

    if weak_ciphers:
        examples = weak_ciphers[:3]
        example_str = ", ".join(examples) + (" and others" if len(weak_ciphers) > 3 else "")
        issues.append(f"{len(weak_ciphers)} weak cipher suite{'s' if len(weak_ciphers) != 1 else ''}")

        reason_parts = []
        if cbc_ciphers:
            reason_parts.append(f"{len(cbc_ciphers)} use AES in CBC mode, which is susceptible to padding oracle attacks (Lucky Thirteen, POODLE on TLS) and lacks authenticated encryption (AEAD)")
        if non_fs_ciphers:
            reason_parts.append(f"{len(non_fs_ciphers)} use static RSA key exchange, which does not provide forward secrecy — meaning if the server's private key is ever compromised, all past encrypted communications can be retroactively decrypted")
        reason_text = "; ".join(reason_parts) + "." if reason_parts else "These ciphers use outdated cryptographic constructions."

        findings.append({
            "type": "issue", "severity": "High",
            "title": "Weak Cipher Suites Detected",
            "detail": f"During the assessment, it was observed that {len(weak_ciphers)} out of {total_ciphers} supported cipher suites are considered weak — specifically {example_str}. Breakdown: {reason_text} Modern attackers can exploit these weaknesses to decrypt intercepted traffic, tamper with data in transit, or perform man-in-the-middle attacks.",
        })

    if cbc_ciphers and not weak_ciphers:
        examples = cbc_ciphers[:2]
        example_str = ", ".join(examples)
        issues.append(f"cipher suites using CBC mode ({len(cbc_ciphers)})")
        findings.append({
            "type": "issue", "severity": "Medium",
            "title": "CBC Mode Cipher Suites in Use",
            "detail": f"The server negotiates {len(cbc_ciphers)} cipher suite{'s' if len(cbc_ciphers) != 1 else ''} that use AES in CBC (Cipher Block Chaining) mode, such as {example_str}. CBC mode ciphers are susceptible to padding oracle attacks (e.g., Lucky Thirteen, POODLE on TLS) and do not provide authenticated encryption. Prefer AEAD ciphers such as AES-GCM or ChaCha20-Poly1305.",
        })

    if non_fs_ciphers:
        nfs_examples = non_fs_ciphers[:2]
        issues.append(f"{len(non_fs_ciphers)} cipher suite{'s' if len(non_fs_ciphers) != 1 else ''} without forward secrecy")
        findings.append({
            "type": "issue", "severity": "Medium",
            "title": "Cipher Suites Without Forward Secrecy",
            "detail": f"{len(non_fs_ciphers)} cipher suite{'s' if len(non_fs_ciphers) != 1 else ''} use static RSA key exchange (e.g., {', '.join(nfs_examples)}), which does not provide forward secrecy. Without forward secrecy, if the server's private key is compromised at any point in the future, all previously recorded encrypted traffic can be decrypted retroactively. Only cipher suites using ephemeral key exchange (ECDHE/DHE) provide this protection.",
        })
    elif (cd.get("forwardSecrecy") is True) or any("Forward Secrecy" in (d.get("name", "") or "") and d.get("ok") for d in report.get("protocolDetails") or []):
        positives.append("forward secrecy")

    # ── Vulnerability checks (full report) ──
    _VULN_NAMES = {
        "BEAST", "BEAST (server-side)", "POODLE (SSLv3)", "POODLE (TLS)",
        "Heartbleed (CVE-2014-0160)", "ROBOT (Bleichenbacher)", "FREAK",
        "Logjam", "DROWN", "Zombie POODLE", "GOLDENDOODLE",
        "Ticketbleed (CVE-2016-9244)",
        "Insecure Client-Initiated Renegotiation", "RC4", "SSL/TLS compression",
    }
    vuln_details = report.get("protocolDetails") or []
    vuln_found = []
    for v in vuln_details:
        name = v.get("name", "")
        val = v.get("value", "")
        ok = v.get("ok")
        if name not in _VULN_NAMES:
            continue
        is_vuln = False
        if name in ("Insecure Client-Initiated Renegotiation", "RC4", "SSL/TLS compression"):
            is_vuln = val.lower() == "yes"
        elif name in ("BEAST", "BEAST (server-side)"):
            is_vuln = "not mitigated" in val.lower() or val.lower() == "yes"
        else:
            is_vuln = ok is False and val.lower() not in ("no", "n/a", "")
        if is_vuln:
            vuln_found.append(name)

    if vuln_found:
        names = ", ".join(vuln_found)
        issues.append(f"known vulnerabilities ({names})")
        findings.append({
            "type": "issue", "severity": "Critical",
            "title": "Known TLS Vulnerabilities Detected",
            "detail": f"The server is vulnerable to: {names}. These are well-documented attack vectors with publicly available exploit code. They can allow attackers to decrypt traffic, steal session cookies, or perform man-in-the-middle attacks. Immediate patching and configuration hardening is required.",
        })

    no_vulns = bool(vuln_details) and not vuln_found

    # ── Certificate trust ──
    cert_trusted = report.get("certTrusted")
    ci = report.get("certInfo")
    certs = report.get("certificates") or []
    if cert_trusted is None and certs:
        cert_trusted = True
    if cert_trusted is False:
        issues.append("certificate validation failure")
        findings.append({
            "type": "issue", "severity": "High",
            "title": "Certificate Not Trusted",
            "detail": "The server's TLS certificate failed validation. This could mean it is self-signed, expired, issued for a different hostname, or signed by an untrusted Certificate Authority. Browsers will show security warnings, and API clients may reject the connection.",
        })
    elif cert_trusted is True:
        issuer = ""
        if ci and ci.get("issuerOrg"):
            issuer = f" issued by {ci['issuerOrg']}"
        elif certs and certs[0].get("issuer"):
            raw_issuer = certs[0]["issuer"]
            cn_match = re.search(r"CN=([^,]+)", raw_issuer) if raw_issuer else None
            issuer = f" issued by {cn_match.group(1)}" if cn_match else f" issued by {raw_issuer}"
        positives.append(f"valid trusted certificate{issuer}")

    # ── Build the observation paragraph ──
    obs = [f"During the SSL/TLS security assessment of {host}, the server received an overall grade of {grade}."]

    if positives and not issues:
        obs.append(f"The configuration demonstrates strong security practices including {', '.join(positives)}. No significant weaknesses were identified.")
    elif positives and issues:
        obs.append(f"While the server has positive attributes ({', '.join(positives)}), the assessment identified the following concerns: {'; '.join(issues)}.")
    elif issues:
        obs.append(f"The assessment identified the following concerns: {'; '.join(issues)}.")
    else:
        obs.append("The assessment completed with limited data available for detailed analysis.")

    if weak_ciphers:
        examples = weak_ciphers[:3]
        obs.append(
            f"Specifically, {len(weak_ciphers)} out of {total_ciphers} cipher suites "
            f"are considered weak (e.g., {', '.join(examples)})."
        )
        if cbc_ciphers and non_fs_ciphers:
            obs.append(
                f"Of these, {len(cbc_ciphers)} use AES in CBC mode (susceptible to padding oracle attacks) "
                f"and {len(non_fs_ciphers)} use static RSA key exchange (no forward secrecy). "
                f"Modern attackers can exploit these weaknesses to decrypt intercepted data or perform man-in-the-middle attacks."
            )
        elif cbc_ciphers:
            obs.append(
                f"These {len(cbc_ciphers)} cipher{'s' if len(cbc_ciphers) != 1 else ''} use AES in CBC mode, "
                f"which is susceptible to padding oracle attacks and lacks authenticated encryption (AEAD)."
            )
        elif non_fs_ciphers:
            obs.append(
                f"These {len(non_fs_ciphers)} cipher{'s' if len(non_fs_ciphers) != 1 else ''} use static RSA key exchange "
                f"and do not provide forward secrecy."
            )

    if deprecated_protos:
        obs.append(
            f"Additionally, deprecated protocol version{'s' if len(deprecated_protos) != 1 else ''} "
            f"({', '.join(deprecated_protos)}) {'are' if len(deprecated_protos) != 1 else 'is'} still enabled, "
            f"exposing the server to protocol downgrade attacks."
        )

    if vuln_found:
        obs.append(
            f"The server was also found to be vulnerable to {', '.join(vuln_found)}, "
            f"which are well-known attacks with publicly available exploit tools."
        )

    if grade in ("A+", "A"):
        if issues:
            obs.append(
                f"Despite the {grade} grade (which reflects server cipher preference and HSTS configuration), "
                f"the identified weak cipher suites should be removed to eliminate residual risk."
            )
        else:
            obs.append("The current configuration meets industry best practices. Continue monitoring for newly discovered vulnerabilities.")
    elif grade == "B":
        if issues:
            obs.append("The configuration is generally good but has room for improvement. Addressing the identified issues would elevate the grade to A.")
        else:
            obs.append("The configuration is generally good but has room for improvement. Enabling TLS 1.3 support would elevate the grade to A.")
    elif grade in ("C", "D"):
        obs.append("The server has notable security weaknesses that should be addressed promptly to meet industry standards.")
    elif grade == "F":
        obs.append("The server has critical security deficiencies requiring immediate attention. The configuration is significantly below acceptable standards.")

    # ── Dynamic summary ──
    summary_parts = [f"Overall grade: {grade}."]
    if supported_protos:
        summary_parts.append(f"Protocols: {', '.join(supported_protos)}.")
    if total_ciphers > 0:
        summary_parts.append(f"{total_ciphers} cipher suites supported" + (f" ({len(weak_ciphers)} weak)" if weak_ciphers else " (all strong)") + ".")
    if vuln_found:
        summary_parts.append(f"Vulnerabilities detected: {', '.join(vuln_found)}.")
    elif no_vulns:
        summary_parts.append("No known vulnerabilities detected.")
    if cert_trusted is True:
        summary_parts.append("Certificate is valid and trusted.")
    elif cert_trusted is False:
        summary_parts.append("Certificate validation FAILED.")

    # ── Dynamic recommendation ──
    rec_parts = []
    if weak_ciphers:
        cbc_count = len(cbc_ciphers)
        nfs_count = len(non_fs_ciphers)
        parts = []
        if cbc_count:
            parts.append(f"remove {cbc_count} CBC-mode cipher{'s' if cbc_count != 1 else ''}")
        if nfs_count:
            parts.append(f"remove {nfs_count} static-RSA cipher{'s' if nfs_count != 1 else ''} that lack forward secrecy")
        rec_parts.append(f"Disable {len(weak_ciphers)} weak cipher suites: {'; '.join(parts)}. Retain only AEAD ciphers (AES-GCM, ChaCha20-Poly1305) with ephemeral key exchange (ECDHE).")
    if deprecated_protos:
        rec_parts.append(f"Disable deprecated protocols: {', '.join(deprecated_protos)}. Only TLS 1.2 and TLS 1.3 should remain enabled.")
    if vuln_found:
        rec_parts.append(f"Patch server to address: {', '.join(vuln_found)}.")
    if cert_trusted is False:
        rec_parts.append("Fix certificate — ensure it is valid, not expired, matches the hostname, and is signed by a trusted CA.")
    if not has_tls13 and has_tls12:
        rec_parts.append("Enable TLS 1.3 for improved security and performance.")
    if not rec_parts:
        rec_parts.append("Configuration is strong. Continue monitoring for newly discovered vulnerabilities and cipher deprecations.")

    return {
        "observation": " ".join(obs),
        "observationFindings": findings,
        "summary": " ".join(summary_parts),
        "recommendation": " ".join(rec_parts),
    }


def _build_local_fallback(host: str, ssl_labs_url: str, context: str = "") -> dict:
    """Run a local TLS check and build a report dict from its results."""
    local = _local_ssl_check(host)
    grade = local.get("localGrade") or "N/A (local)"
    status = local.get("localStatus") or ""
    protocol = local.get("protocol") or local.get("error") or "unknown"

    # ── Enumerate protocols & cipher suites ──
    protocols = _enumerate_local_protocols(host)
    cipher_map = _enumerate_local_ciphers(host)

    # Build cipher suites in the same format as SSL Labs full reports
    cipher_suites = []
    all_parsed_ciphers = []
    total_ciphers = 0
    for proto_name in ("TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"):
        ciphers = cipher_map.get(proto_name)
        if not ciphers:
            continue
        suites = []
        for c in ciphers:
            parsed = _parse_cipher_details(c["name"], c.get("bits"))
            all_parsed_ciphers.append(parsed)
            is_weak = parsed["strength"] == "weak" or (not parsed["aead"] and parsed["mode"] == "CBC") or (not parsed["forwardSecrecy"] and proto_name != "TLS 1.3")
            suites.append({
                "name": c["name"],
                "kxType": parsed["keyExchange"] if parsed["forwardSecrecy"] else None,
                "cipherStrength": c.get("bits"),
                "weak": is_weak,
            })
            total_ciphers += 1
        cipher_suites.append({
            "protocol": proto_name,
            "preference": True,
            "suites": suites,
        })

    # Determine supported protocol names
    supported_protos = [p["name"] for p in protocols if p["enabled"]]
    has_tls13 = any("1.3" in p for p in supported_protos)
    has_deprecated = any(p["enabled"] and p["insecure"] for p in protocols)

    # Re-grade based on full protocol enumeration
    if supported_protos:
        if has_deprecated:
            grade = "C (local)"
            status = "Deprecated protocols enabled"
        elif has_tls13 and "TLS 1.2" in supported_protos:
            grade = "A (local)"
            status = "Excellent — TLS 1.2 + 1.3"
        elif has_tls13:
            grade = "A (local)"
            status = "Excellent — TLS 1.3"
        # else keep the grade from _local_ssl_check

    summary_parts = [f"{context + ' ' if context else ''}Local check: {status}."]
    summary_parts.append(f"Protocols: {', '.join(supported_protos) if supported_protos else protocol}.")
    if local.get("cipher"):
        summary_parts.append(f"Preferred cipher: {local['cipher']}.")
    if total_ciphers > 0:
        weak_count = sum(1 for s in cipher_suites for c in s.get("suites", []) if c.get("weak"))
        summary_parts.append(f"{total_ciphers} cipher suites supported{f' ({weak_count} weak)' if weak_count else ''}.")
    summary = " ".join(summary_parts)

    cd = local.get("cipherDetails") or {}
    assessment = []
    proto_upper = (protocol or "").upper()

    # Protocol assessment
    if supported_protos:
        proto_val = ", ".join(supported_protos)
        if has_deprecated:
            assessment.append({"name": "Protocol version", "value": proto_val, "status": "bad", "detail": "Deprecated protocols (TLS 1.0/1.1) must be disabled"})
        elif has_tls13:
            assessment.append({"name": "Protocol version", "value": proto_val, "status": "good", "detail": "Latest TLS 1.3 supported with TLS 1.2 fallback" if "TLS 1.2" in supported_protos else "Latest and most secure TLS version"})
        else:
            assessment.append({"name": "Protocol version", "value": proto_val, "status": "good", "detail": "Secure and widely supported"})
    elif "1.3" in proto_upper:
        assessment.append({"name": "Protocol version", "value": "TLS 1.3", "status": "good", "detail": "Latest and most secure TLS version"})
    elif "1.2" in proto_upper:
        assessment.append({"name": "Protocol version", "value": "TLS 1.2", "status": "good", "detail": "Secure and widely supported"})
    elif "1.1" in proto_upper:
        assessment.append({"name": "Protocol version", "value": "TLS 1.1", "status": "bad", "detail": "Deprecated — upgrade to TLS 1.2 or 1.3"})
    elif "1.0" in proto_upper or "SSL" in proto_upper:
        assessment.append({"name": "Protocol version", "value": protocol, "status": "bad", "detail": "Insecure — must upgrade immediately"})

    if cd.get("forwardSecrecy") is not None:
        assessment.append({
            "name": "Forward secrecy",
            "value": f"{cd['keyExchange']}" if cd["forwardSecrecy"] else "Not supported",
            "status": "good" if cd["forwardSecrecy"] else "bad",
            "detail": "Compromised server key cannot decrypt past sessions" if cd["forwardSecrecy"] else "Past sessions vulnerable if server key is compromised",
        })
    if cd.get("aead") is not None:
        assessment.append({
            "name": "Authenticated encryption",
            "value": cd.get("mode", "Unknown"),
            "status": "good" if cd["aead"] else "warn",
            "detail": "AEAD cipher provides both confidentiality and integrity" if cd["aead"] else "CBC mode is susceptible to padding oracle attacks",
        })
    if cd.get("bits"):
        b = int(cd["bits"])
        assessment.append({
            "name": "Cipher strength",
            "value": f"{cd.get('encryption', 'Unknown')} ({b} bits)",
            "status": "good" if b >= 128 else "bad",
            "detail": "Strong symmetric encryption" if b >= 256 else ("Strong symmetric encryption (AEAD)" if b >= 128 and cd.get("aead") else ("Adequate symmetric encryption" if b >= 128 else "Weak — upgrade cipher suite")),
        })
    ct = local.get("certTrusted")
    ci = local.get("certInfo")
    if ct is True:
        assessment.append({"name": "Certificate trusted", "value": "Yes", "status": "good", "detail": f"Issued by {ci.get('issuerOrg') or ci.get('issuerCN') or 'trusted CA'}" if ci else "Valid and trusted by OS certificate store"})
    elif ct is False:
        assessment.append({"name": "Certificate trusted", "value": "No", "status": "bad", "detail": "Certificate failed validation — may be self-signed, expired, or hostname mismatch"})

    # Cipher suite stats
    if total_ciphers > 0:
        weak_count = sum(1 for s in cipher_suites for c in s.get("suites", []) if c.get("weak"))
        assessment.append({"name": "Cipher suites", "value": f"{total_ciphers} supported", "status": "good" if weak_count == 0 else "warn", "detail": f"All ciphers are strong" if weak_count == 0 else f"{weak_count} weak cipher(s) should be disabled"})

    assessment.append({"name": "Vulnerability checks", "value": "—", "status": "na", "detail": "BEAST, POODLE, Heartbleed, ROBOT checks require SSL Labs"})

    rec_parts = []
    if not has_tls13 and ("1.2" in proto_upper or "1.1" in proto_upper or "1.0" in proto_upper):
        rec_parts.append("Enable TLS 1.3 for best security and performance.")
    if has_deprecated:
        dep_names = [p["name"] for p in protocols if p["enabled"] and p["insecure"]]
        rec_parts.append(f"Disable {', '.join(dep_names)} immediately — deprecated and insecure.")
    if cd.get("forwardSecrecy") is False:
        rec_parts.append("Configure cipher suites to prefer ECDHE key exchange for forward secrecy.")
    if cd.get("aead") is False:
        rec_parts.append("Prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305) over CBC mode.")
    if total_ciphers > 0:
        weak_count = sum(1 for s in cipher_suites for c in s.get("suites", []) if c.get("weak"))
        if weak_count:
            rec_parts.append(f"Disable {weak_count} weak cipher suite(s) — remove CBC-mode and non-ECDHE ciphers.")
    if ct is False:
        rec_parts.append("Fix certificate issues — ensure it is issued by a trusted CA and matches the hostname.")
    rec_parts.append("Run a full Qualys SSL Labs scan for comprehensive vulnerability assessment when the server is publicly accessible.")
    recommendation = " ".join(rec_parts)

    report = {
        "host": host,
        "error": False,
        "grade": grade,
        "endpointGrade": grade,
        "sslLabsUrl": ssl_labs_url,
        "reportTitle": f"SSL Report: {host}",
        "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "summary": summary,
        "recommendation": recommendation,
        "localProtocol": local.get("protocol"),
        "localCipher": local.get("cipher"),
        "localGrade": grade,
        "localStatus": status,
        "localError": local.get("error"),
        "cipherDetails": cd if cd else None,
        "certInfo": ci,
        "certTrusted": ct,
        "assessment": assessment,
        "protocols": protocols if protocols else None,
        "cipherSuites": cipher_suites if cipher_suites else None,
        "localEnumeration": True,
    }
    obs = _generate_ssl_observation(report)
    report["observation"] = obs["observation"]
    report["observationFindings"] = obs["observationFindings"]
    return report


def _ssl_labs_endpoints_usable(data: dict) -> bool:
    """Return True if at least one SSL Labs endpoint has a real grade or populated protocols."""
    for ep in data.get("endpoints") or []:
        if ep.get("grade"):
            return True
        det = ep.get("details") or {}
        if det.get("protocols") and len(det["protocols"]) > 0:
            return True
    return False


def _enrich_with_local_tls(report: dict, host: str) -> dict:
    """When SSL Labs returns minimal data, supplement with local TLS handshake info."""
    if report.get("localProtocol") or report.get("certificates"):
        return report
    try:
        local = _local_ssl_check(host)
        if local.get("protocol") and local["protocol"] != "connection failed":
            report["localProtocol"] = local.get("protocol")
            report["localCipher"] = local.get("cipher")
            report["localGrade"] = local.get("localGrade")
            report["localStatus"] = local.get("localStatus")
            if report.get("grade") in (None, "N/A"):
                report["grade"] = local.get("localGrade") or report.get("grade")
                report["endpointGrade"] = report["grade"]
            ctx = f"Local TLS handshake: {local.get('localStatus', '')}. Protocol: {local.get('protocol', '?')}."
            if local.get("cipher"):
                ctx += f" Cipher: {local['cipher']}."
            report["summary"] = ctx + " " + (report.get("summary") or "")
    except Exception:
        pass
    return report


def _poll_ssl_labs(api_base: str, host: str, req_kw: dict) -> dict:
    """Poll SSL Labs /analyze until READY or ERROR, then return the response data."""
    data = None
    for attempt in range(20):
        params = {"host": host, "fromCache": "on", "all": "done", "maxAge": 24}
        r = requests.get(f"{api_base}/analyze", params=params, **req_kw)
        if r.status_code == 441:
            raise ValueError("SSL_LABS_NOT_REGISTERED")
        if r.status_code == 429:
            time.sleep(15)
            continue
        if r.status_code in (503, 529):
            time.sleep(20)
            continue
        r.raise_for_status()
        data = r.json()
        status = data.get("status")
        if status in ("READY", "ERROR"):
            break
        # DNS / IN_PROGRESS — wait before next poll (variable backoff)
        time.sleep(5 if attempt < 3 else 10)
    return data or {"status": "ERROR", "statusMessage": "No response from SSL Labs"}


def _process_ssl_labs_response(data: dict, host: str, ssl_labs_url: str, api_version: str) -> dict:
    """Turn a READY SSL Labs response into a report dict."""
    status = data.get("status")

    if status == "ERROR":
        raise RuntimeError(data.get("statusMessage") or "SSL Labs returned an error")

    if status != "READY":
        raise RuntimeError(f"SSL Labs not ready (status={status})")

    if _ssl_labs_endpoints_usable(data):
        report = _parse_ssl_labs_full_report(data, host, ssl_labs_url)
        # Enrich grade from endpoint level (v3/v4 store grade per endpoint, not at top level)
        if report.get("grade") in (None, "N/A"):
            for ep in data.get("endpoints") or []:
                if ep.get("grade"):
                    report["grade"] = ep["grade"]
                    report["endpointGrade"] = ep["grade"]
                    break
        # Supplement with local TLS if Labs returned READY but no cert/protocol data
        if not report.get("certificates") and not report.get("protocols"):
            report = _enrich_with_local_tls(report, host)
        report["_apiVersion"] = api_version
        return report

    # READY but no usable endpoint data — collect endpoint messages
    ep_messages = []
    for ep in data.get("endpoints") or []:
        msg = ep.get("statusMessage", "")
        ip = ep.get("ipAddress", "")
        if msg:
            ep_messages.append(f"{ip}: {msg}" if ip else msg)
    ep_note = "; ".join(ep_messages) if ep_messages else "SSL Labs could not reach the server"
    raise RuntimeError(f"SSL Labs endpoints not usable: {ep_note}")


def run_ssl_analysis(url_or_host: str) -> dict:
    host = get_domain(url_or_host).split(":")[0]
    if not host or host == "Unknown":
        return {"error": True, "message": "Invalid host", "host": url_or_host}

    ssl_labs_url = f"https://www.ssllabs.com/ssltest/analyze.html?d={host}"
    req_kw_base = {"timeout": 15, "verify": False}

    # ---- Attempt SSL Labs v4 (requires registered email) ----
    if SSL_LABS_EMAIL:
        try:
            req_kw_v4 = {**req_kw_base, "headers": {"email": SSL_LABS_EMAIL}}
            data = _poll_ssl_labs("https://api.ssllabs.com/api/v4", host, req_kw_v4)
            return _process_ssl_labs_response(data, host, ssl_labs_url, "v4")
        except ValueError as e:
            if "SSL_LABS_NOT_REGISTERED" in str(e):
                pass  # email not registered yet — fall through to v3
        except RuntimeError as e:
            ep_note = str(e)
            try:
                report = _build_local_fallback(host, ssl_labs_url, f"SSL Labs v4: {ep_note}.")
                # Collect endpoint messages if any
                return report
            except Exception:
                pass
        except requests.RequestException:
            pass  # Network error — try v3
        except Exception:
            pass

    # ---- Attempt SSL Labs v3 (legacy, deprecated Jan 2024, still partially functional) ----
    try:
        data = _poll_ssl_labs("https://api.ssllabs.com/api/v3", host, req_kw_base)
        return _process_ssl_labs_response(data, host, ssl_labs_url, "v3")
    except RuntimeError as e:
        ep_note = str(e)
        ep_messages = []
        try:
            report = _build_local_fallback(host, ssl_labs_url, f"SSL Labs: {ep_note}.")
            report["endpointMessages"] = ep_messages
            if not SSL_LABS_EMAIL:
                report["_needsV4Email"] = True
            return report
        except Exception:
            return {
                "host": host, "error": False,
                "grade": "N/A",
                "sslLabsUrl": ssl_labs_url,
                "reportTitle": f"SSL Report: {host}",
                "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "summary": f"SSL Labs: {ep_note}. Local TLS check also failed.",
                "recommendation": "Ensure the server accepts HTTPS connections on port 443.",
                "_needsV4Email": not bool(SSL_LABS_EMAIL),
            }
    except requests.RequestException as e:
        try:
            report = _build_local_fallback(host, ssl_labs_url, f"SSL Labs API unavailable ({type(e).__name__}).")
            if not SSL_LABS_EMAIL:
                report["_needsV4Email"] = True
            return report
        except Exception:
            return {
                "host": host, "error": True,
                "message": str(e) or "SSL Labs request failed",
                "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            }
    except Exception as e:
        return {
            "host": host, "error": True,
            "message": str(e) or "SSL analysis failed",
            "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        }
