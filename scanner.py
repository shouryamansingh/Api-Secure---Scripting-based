"""
Security scanner: headers, CORS, SSL/TLS, server disclosure, error handling, URL tampering.
Uses config for timeouts when available.
"""
import re
import ssl
import socket
import time
import urllib.parse
from datetime import datetime

import requests

try:
    from config import SCANNER_TIMEOUT
except ImportError:
    SCANNER_TIMEOUT = 15

try:
    from urllib3.exceptions import InsecureRequestWarning
    import urllib3
    urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "X-Permitted-Cross-Domain-Policies",
]


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


def fetch_url(url: str, origin=None, follow_redirects=True):
    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if origin and str(origin).strip():
        req_headers["Origin"] = str(origin).strip()
    resp = requests.get(
        url,
        allow_redirects=follow_redirects,
        headers=req_headers,
        timeout=SCANNER_TIMEOUT,
        verify=False,
    )
    # Use plain dict so header iteration is reliable on all platforms
    out_headers = _normalize_headers(dict(resp.headers))
    return out_headers, resp.text, resp.status_code


def fetch_options(url: str, origin: str):
    """Send OPTIONS preflight request with Origin. Returns normalized headers or None on failure."""
    if not origin or not str(origin).strip():
        return None
    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Origin": str(origin).strip(),
        "Access-Control-Request-Method": "GET",
        "Accept": "*/*",
    }
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


def build_evaluated_headers(original_headers: dict) -> dict:
    evaluated = {}
    for name in REQUIRED_HEADERS:
        value = get_header(original_headers, name)
        present = bool(value)
        severity = "ok" if present else "critical"
        if present and name == "Strict-Transport-Security":
            if "max-age=" not in str(value).lower():
                severity = "warning"
        if present and name == "Content-Security-Policy":
            if not str(value).strip():
                severity = "warning"
        evaluated[name] = {
            "present": present,
            "value": value if value else None,
            "severity": severity,
            "description": f"Security header: {name}",
            "issue": (
                "Weak configuration" if severity == "warning" else "Configured"
                if value
                else f"Missing {name} header"
            ),
            "impact": "Low risk" if value else "High security risk",
            "recommendation": "Review configuration" if value else f"Add {name} header",
        }
    return evaluated


def _headers_from_response(resp) -> dict:
    """Build normalized headers dict from a requests Response. Use plain dict for reliable iteration."""
    raw = dict(resp.headers)
    return _normalize_headers(raw)


def run_headers_analysis(url: str) -> dict:
    target_domain = get_domain(url)
    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    best_headers = {}
    for follow_redirects in (True, False):
        try:
            resp = requests.get(
                url,
                allow_redirects=follow_redirects,
                headers=req_headers,
                timeout=SCANNER_TIMEOUT,
                verify=False,
            )
            # dict(resp.headers) then normalize so we reliably read all headers
            h = _normalize_headers(dict(resp.headers))
            if _count_security_headers_present(h) > _count_security_headers_present(best_headers):
                best_headers = h
            if best_headers and _count_security_headers_present(best_headers) == len(REQUIRED_HEADERS):
                break
        except Exception:
            continue
    evaluated_headers = build_evaluated_headers(best_headers)

    header_list = [{"name": n, **info} for n, info in evaluated_headers.items()]
    critical_count = sum(1 for h in header_list if h["severity"] == "critical")
    warning_count = sum(1 for h in header_list if h["severity"] == "warning")
    ok_count = sum(1 for h in header_list if h["severity"] == "ok")
    total_headers = len(REQUIRED_HEADERS)
    score = max(0, round(((ok_count + warning_count * 0.5) / total_headers) * 100))
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
        "scannedAt": datetime.utcnow().isoformat() + "Z",
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
    }


def _normalize_headers(headers: dict) -> dict:
    if not headers or not isinstance(headers, dict):
        return {}
    out = {}
    for k, v in headers.items():
        key = k.lower()
        out[key] = v[0] if isinstance(v, (list, tuple)) else v
    return out


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
        "timestamp": datetime.utcnow().isoformat() + "Z",
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


def run_cors_analysis(url: str, origin_sent=None) -> dict:
    # Passive: no origin sent. Active: user-provided origin.
    sent_origin = (origin_sent or "").strip() or None
    headers, _, _ = fetch_url(url, origin=sent_origin)
    options_headers = None
    cors_from_preflight = False

    # When testing with an origin, also send OPTIONS preflight; merge CORS headers if GET had none
    if sent_origin:
        options_headers = fetch_options(url, sent_origin)
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
    """Classify severity of a single disclosure (Critical/High/Medium/Low/Informational)."""
    v = (value or "").strip().lower()
    has_version = bool(VERSION_PATTERN.search(v))
    name_lower = header_name.lower()
    if "x-powered-by" in name_lower and has_version:
        return "Critical"  # Exact runtime version (PHP, etc.) is high value for attackers
    if "server" in name_lower or "x-aspnet-version" in name_lower or "x-aspnetmvc-version" in name_lower:
        if has_version:
            return "High"
        if any(x in v for x in ["apache", "nginx", "iis", "jetty", "tomcat"]):
            return "Medium"
        return "Low"
    if "via" in name_lower:
        return "Low" if "cloudflare" in v or "akamai" in v else "Medium"
    if "link" in name_lower and ("wp-json" in v or "wordpress" in v):
        return "High"
    if "x-runtime" in name_lower or "x-version" in name_lower or "x-generator" in name_lower:
        return "High" if has_version else "Medium"
    if "x-drupal-cache" in name_lower:
        return "Medium"
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
    """Rule-based risk (Low/Medium/High), justification, and detailed recommendations."""
    if not found:
        return "Informational", "No technology or version headers detected.", [], 5.0
    disclosure_indicators = list(found.keys())
    version_pattern = re.compile(r"\d+\.\d+(\.\d+)?")
    has_version = any(version_pattern.search(str(v)) for v in found.values())
    count = len(found)
    # Confidence 0-10: more headers + versions = higher confidence in risk
    confidence = min(10.0, 4.0 + count * 1.2 + (2.0 if has_version else 0) + (1.5 if "X-Powered-By" in disclosure_indicators else 0))
    if count >= 3 or (has_version and count >= 2):
        risk = "High"
        justification = "Multiple headers expose technology and/or version numbers; attackers can target known CVEs."
    elif has_version or count >= 2:
        risk = "Medium"
        justification = "Version or stack details are exposed; consider masking to reduce reconnaissance value."
    else:
        risk = "Low"
        justification = "Limited disclosure; framework or server type may be visible without exact versions."

    recs = [
        "Disable the 'X-Powered-By' header in the PHP configuration to prevent language version disclosure.",
        "Configure the web server (Nginx/Apache) to suppress version strings in the 'Server' response header.",
        "Remove WordPress 'Link' headers pointing to the REST API and the 'generator' meta tag from the HTML source.",
        "Use Cloudflare Transform Rules to strip sensitive headers (Server, X-Powered-By) before they reach the client.",
        "Restrict access to the WordPress XML-RPC and REST API endpoints to authorized IP addresses or authenticated users only.",
        "Implement a strict Content Security Policy (CSP) and other security headers (HSTS, X-Frame-Options, X-Content-Type-Options) to mitigate exploit attempts.",
    ]
    if possible_versions.get("Runtime Environment") or "X-Powered-By" in disclosure_indicators:
        recs.insert(0, "In PHP: set expose_php = Off in php.ini. In ASP.NET: remove X-Powered-By / X-AspNet-Version.")
    return risk, justification, recs, round(confidence, 1)


def _build_executive_summary(domain: str, found: dict, stack: str, risk_level: str, possible_versions: dict) -> str:
    """Build a detailed executive summary paragraph."""
    if not found:
        return f"The domain {domain} was analyzed. No technology or version headers were detected; the server does not explicitly disclose stack or version information in response headers."
    disclosure_list = ", ".join(found.keys())
    runtime = possible_versions.get("Runtime Environment") or ""
    server_cdn = possible_versions.get("Web Server/CDN") or ""
    parts = [
        f"The infrastructure is identified as {stack}.",
        f"This level of information disclosure is a security concern as it allows attackers to research and deploy exploits specifically tailored to the identified versions and software stack.",
    ]
    if runtime or server_cdn:
        parts.insert(1, f"The server explicitly discloses {runtime or server_cdn} via headers such as {disclosure_list}.")
    parts.append(
        f"The domain {domain} was analyzed. Exposing server and technology versions publicly via headers like server, x-powered-by, link can allow attackers to identify known vulnerabilities. "
        "Attackers may leverage this information for targeted attacks such as Remote Code Execution, Privilege Escalation, or Denial-of-Service."
    )
    return " ".join(parts)


def run_server_disclosure_analysis(url: str) -> dict:
    headers, body, status = fetch_url(url)
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

    # Attack scenario, impact, likelihood
    has_version = any(VERSION_PATTERN.search(str(v)) for v in found.values())
    attack_scenario = (
        "An attacker can use the disclosed stack and version information to search for known CVEs and vendor advisories, then attempt targeted exploits (e.g. Remote Code Execution, Privilege Escalation, or Denial-of-Service) against the identified software versions."
        if found else "No stack or version disclosure detected; reconnaissance value is limited."
    )
    business_impact = "Reconnaissance facilitation; targeted exploitation; potential compliance finding." if found else "Minimal."
    likelihood = "High" if (has_version and len(found) >= 2) else ("Medium" if found else "Low")

    # Remediation priority from risk
    priority_map = {"High": "P1", "Medium": "P2", "Low": "P3", "Informational": "P3"}
    remediation_priority = priority_map.get(risk_level, "P2")
    verification_step = "After changing server or application configuration, re-run this scan and confirm that the listed headers are removed or show generic values only."
    expected_state = "Server: generic value or absent; X-Powered-By: absent; Link: no version or API disclosure; other version headers removed or generic."

    # HTML disclosure checks
    html_disclosures = _html_disclosure_checks(body or "")

    # Summary metrics: disclosure score 0-100, counts
    critical_high = sum(1 for d in disclosures if d.get("severity") in ("Critical", "High"))
    with_version = sum(1 for d in disclosures if VERSION_PATTERN.search(str(d.get("value") or "")))
    product_only = len(disclosures) - with_version
    # Score: higher = worse (more exposure). Base 0, +15 per Critical, +10 per High, +5 per Medium, +2 per Low/Info. Cap 100.
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
        "scannedAt": datetime.utcnow().isoformat() + "Z",
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
        "configurationExamples": CONFIG_EXAMPLES,
        "references": [
            "OWASP A06:2021 - Security Misconfiguration",
            "NIST SP 800-53 Rev.5 - CM-6 / SI-2",
            "CIS Benchmark - Web Server / Application Hardening",
        ],
        "affectedComponents": affected_components,
        "cveNote": "Disclosed versions should be checked against CVE databases and vendor security advisories. Consider: https://cve.mitre.org/ or https://nvd.nist.gov/",
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
    ("stack trace", "Stack / trace", "High"),
    ("stacktrace", "Stack / trace", "High"),
    ("traceback", "Stack / trace", "High"),
    ("exception", "Exception / runtime", "High"),
    ("at line", "Stack / trace", "High"),
    ("file ", "Path / file", "High"),
    (" in /", "Path / file", "High"),
    (".py\",", "Framework (Python)", "High"),
    (".py'", "Framework (Python)", "High"),
    (".php", "Framework (PHP)", "High"),
    (".java", "Framework (Java)", "High"),
    (".rb", "Framework (Ruby)", "High"),
    ("django", "Framework (Python)", "High"),
    ("flask", "Framework (Python)", "High"),
    ("spring", "Framework (Java)", "High"),
    ("fatal error", "Runtime error", "Medium"),
    ("warning:", "Runtime error", "Medium"),
    ("notice:", "Runtime error", "Low"),
    ("undefined index", "Runtime error", "Medium"),
    ("undefined variable", "Runtime error", "Medium"),
    ("sqlstate", "Database", "High"),
    ("odbc ", "Database", "High"),
    ("postgresql", "Database", "High"),
    ("mysql_", "Database", "High"),
    ("sqlite", "Database", "High"),
    ("oracle ", "Database", "High"),
    ("internal server error", "Generic error", "Medium"),
    ("connection refused", "Infrastructure", "Medium"),
    ("permission denied", "Infrastructure", "Medium"),
]

# Per-category impact and remediation for findings
_ERROR_CATEGORY_GUIDANCE = {
    "Stack / trace": {
        "impact": "Attackers can see code paths, line numbers, and file names, making it easier to find bugs and craft exploits.",
        "remediation": "Disable stack traces and debug mode in production. Log full details server-side only; return a generic message to the client.",
    },
    "Path / file": {
        "impact": "File or directory paths may reveal application structure, OS, or sensitive locations.",
        "remediation": "Never expose real paths in error responses. Use generic messages and log paths internally.",
    },
    "Framework (Python)": {
        "impact": "Framework name and version help attackers target known CVEs and framework-specific vulnerabilities.",
        "remediation": "Turn off debug/development mode in production. Remove or genericize framework error pages.",
    },
    "Framework (PHP)": {
        "impact": "PHP version and paths help attackers target known PHP vulnerabilities and paths.",
        "remediation": "Set display_errors=Off and log_errors=On. Use custom error pages that do not leak stack or paths.",
    },
    "Framework (Java)": {
        "impact": "Java/runtime stack traces reveal application structure and library versions.",
        "remediation": "Configure the app server to show generic error pages and log full stack traces only on the server.",
    },
    "Framework (Ruby)": {
        "impact": "Ruby/Rails stack traces can expose routes, gems, and file paths.",
        "remediation": "Set consider_all_requests_local = false and use custom error pages in production.",
    },
    "Exception / runtime": {
        "impact": "Exception messages often contain internal state, variable names, or logic details.",
        "remediation": "Catch exceptions and return generic user messages; log the real exception server-side only.",
    },
    "Runtime error": {
        "impact": "Warnings and notices can reveal configuration, deprecated usage, or environment details.",
        "remediation": "Disable display of warnings/notices to users in production; log them instead.",
    },
    "Database": {
        "impact": "Database type, version, or SQL state can aid SQL injection and version-specific attacks.",
        "remediation": "Never expose raw DB errors or SQL state to clients. Map errors to generic messages and log details.",
    },
    "Generic error": {
        "impact": "Generic error text may still leak that the server is in an error state or reveal branding.",
        "remediation": "Use consistent, minimal error pages that do not reveal server or technology details.",
    },
    "Infrastructure": {
        "impact": "Connection or permission messages can reveal backend topology or OS.",
        "remediation": "Handle upstream/connection errors and return generic messages; avoid forwarding infrastructure errors.",
    },
}


def _scan_body_for_indicators(body: str) -> list:
    """Return list of {indicator, category, severity} found in body (lowercased)."""
    body_lower = (body or "").lower()
    found = []
    for phrase, category, sev in _ERROR_INDICATORS:
        if phrase in body_lower:
            found.append({"indicator": phrase, "category": category, "severity": sev})
    return found


def run_error_handling_check(url: str) -> dict:
    target_domain = get_domain(url)
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    path = (parsed.path or "").rstrip("/")
    # Multiple probes to trigger different error handlers (path, alt path, query)
    probe_paths = [
        "/__nonexistent_probe_12345",
        "/api/__nonexistent_probe_12345",
        (path + "/__nonexistent_probe_12345") if path else "/__nonexistent_probe_12345",
    ]
    probe_paths = list(dict.fromkeys(probe_paths))  # dedupe
    base_result = {
        "targetDomain": target_domain,
        "originalUrl": url,
        "scannedAt": datetime.utcnow().isoformat() + "Z",
    }
    references = [
        "CWE-209: Information Exposure Through an Error Message",
        "OWASP: Improper Error Handling (A04:2021 – Insecure Design / A05:2021 – Security Misconfiguration)",
    ]
    all_found = []
    probes_result = []
    worst_status = None
    response_snippet = None

    for probe_path in probe_paths:
        probe_url = base.rstrip("/") + ("/" + probe_path.lstrip("/"))
        try:
            _, body, status = fetch_url(probe_url)
            if worst_status is None or (status >= 500 and worst_status < 500) or status > (worst_status or 0):
                worst_status = status
            found_here = _scan_body_for_indicators(body)
            for item in found_here:
                if not any(f["indicator"] == item["indicator"] and f.get("probeUrl") == probe_url for f in all_found):
                    all_found.append({**item, "probeUrl": probe_url})
            # Keep first probe's body for snippet if we have findings and no snippet yet
            if found_here and response_snippet is None and body:
                snippet = (body[:500] + "…") if len(body) > 500 else body
                # Sanitize: remove newlines for single-line preview, escape for safety
                response_snippet = snippet.replace("\r", " ").replace("\n", " ").strip()[:400]
            probes_result.append({
                "probeUrl": probe_url,
                "statusCode": status,
                "indicatorsCount": len(found_here),
            })
        except Exception as e:
            probes_result.append({"probeUrl": probe_url, "error": str(e), "statusCode": None, "indicatorsCount": 0})

    # If all probes failed, return error
    if all(p.get("error") for p in probes_result):
        err_msg = "; ".join(p.get("error", "") for p in probes_result[:1])
        return {
            **base_result,
            "probeUrl": base.rstrip("/") + probe_paths[0],
            "probeStatus": None,
            "probes": probes_result,
            "error": err_msg,
            "riskLevel": "Unknown",
            "findings": [],
            "sensitiveLeaked": [],
            "executiveSummary": f"The probe(s) failed: {err_msg}. Manual check of error handling is recommended.",
            "simpleTerms": "The scanner could not complete the error-handling check. Try again or inspect the site manually.",
            "recommendation": "Probe failed; manual check recommended.",
            "references": references,
        }

    # Merge by category and add impact/remediation
    by_category = {}
    for item in all_found:
        cat = item["category"]
        if cat not in by_category:
            guid = _ERROR_CATEGORY_GUIDANCE.get(cat, {})
            by_category[cat] = {
                "category": cat,
                "severity": item["severity"],
                "evidence": [],
                "impact": guid.get("impact", ""),
                "remediation": guid.get("remediation", ""),
            }
        if item["indicator"] not in by_category[cat]["evidence"]:
            by_category[cat]["evidence"].append(item["indicator"])
    findings = list(by_category.values())
    severities = [f["severity"] for f in findings]
    risk = "High" if "High" in severities else "Medium" if "Medium" in severities else "Low"
    probe_url_primary = base.rstrip("/") + ("/" + probe_paths[0].lstrip("/"))
    status_primary = next((p["statusCode"] for p in probes_result if p.get("probeUrl") == probe_url_primary), worst_status)

    if all_found:
        executive_summary = (
            f"The server returned error response(s) (HTTP {status_primary} or similar) that contain sensitive technical details. "
            f"{len(all_found)} indicator(s) across {len(findings)} category/categories were detected (stack traces, database or framework leakage). "
            "This can help attackers understand the application stack and exploit known vulnerabilities."
        )
        simple_terms = (
            "The site showed detailed error page(s) that reveal internal information (e.g. stack traces or database names). "
            "Such pages should be replaced with generic messages in production."
        )
        recommendation = (
            "Ensure error pages do not expose stack traces, file paths, or framework/database details. "
            "Use generic user-facing messages and log details server-side only."
        )
    else:
        executive_summary = (
            f"The server responded to non-existent path(s) with HTTP {status_primary or '—'}. "
            "No obvious stack trace or sensitive technical leakage was detected in the response body."
        )
        simple_terms = (
            "The site did not expose obvious error details in the probe response(s). "
            "Continue to use secure development practices and avoid exposing stack traces or DB errors to users."
        )
        recommendation = "No obvious error leakage detected. Keep error handling locked down in production."

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
def run_url_tampering_check(url: str) -> dict:
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
            _, body, status = fetch_url(tampered_url)
            # Heuristic: different status or long body might indicate different handling
            results.append({
                "test": name,
                "description": desc,
                "tamperedUrl": tampered_url,
                "statusCode": status,
                "bodyLength": len(body or ""),
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
        "scannedAt": datetime.utcnow().isoformat() + "Z",
        "tests": results,
        "recommendation": "Validate and sanitize all URL inputs; avoid reflecting user input in responses.",
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


def _local_ssl_check(host: str, port: int = 443) -> dict:
    """Local TLS check: protocol, cipher (if available), and a protocol-based grade."""
    out = {"protocol": None, "cipher": None, "localGrade": None, "localStatus": None}
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
    return out


def _ts_to_iso(ts):
    """Convert Unix timestamp to ISO date string. API may use seconds or milliseconds."""
    if ts is None:
        return None
    try:
        sec = ts / 1000.0 if ts > 1e12 else ts
        return datetime.utcfromtimestamp(sec).strftime("%a, %d %b %Y %H:%M:%S UTC")
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
            "scannedAt": datetime.utcnow().isoformat() + "Z",
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
    session_resumption = details.get("sessionResumption")
    session_tickets = details.get("sessionTickets")
    session_ticket_ok = (session_tickets is not None and (session_tickets & 1) != 0) if session_tickets is not None else None
    protocol_details = [
        {"name": "Secure Renegotiation", "value": "Supported" if reneg_secure else "No", "ok": reneg_secure},
        {"name": "Insecure Client-Initiated Renegotiation", "value": "No" if not reneg_insecure else "Yes", "ok": not reneg_insecure},
        {"name": "BEAST (server-side)", "value": "Not mitigated" if details.get("vulnBeast") else "No", "ok": not details.get("vulnBeast")},
        {"name": "POODLE (SSLv3)", "value": "No" if not details.get("poodle") else "Yes", "ok": not details.get("poodle")},
        {"name": "Downgrade prevention (TLS_FALLBACK_SCSV)", "value": "Yes" if details.get("fallbackScsv") else "No", "ok": details.get("fallbackScsv")},
        {"name": "SSL/TLS compression", "value": "No" if not details.get("compressionMethods") else "Yes", "ok": not details.get("compressionMethods")},
        {"name": "RC4", "value": "No" if not details.get("supportsRc4") else "Yes", "ok": not details.get("supportsRc4")},
        {"name": "Forward Secrecy", "value": "Yes" if (details.get("forwardSecrecy") or 0) > 0 else "No", "ok": (details.get("forwardSecrecy") or 0) > 0},
        {"name": "ALPN", "value": (details.get("alpnProtocols") or "No").replace(" ", ", ") if details.get("alpnProtocols") else "No", "ok": bool(details.get("alpnProtocols"))},
        {"name": "NPN", "value": (details.get("npnProtocols") or "No").replace(" ", ", ") if details.get("npnProtocols") else "No", "ok": bool(details.get("npnProtocols"))},
        {"name": "Session resumption (tickets)", "value": "Yes" if session_ticket_ok else "No", "ok": session_ticket_ok},
    ]
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
    return {
        "host": host,
        "error": False,
        "grade": grade,
        "endpointGrade": grade,
        "ipAddress": ip_address,
        "sslLabsUrl": ssl_labs_url,
        "reportTitle": f"SSL Report: {host}" + (f" ({ip_address})" if ip_address else ""),
        "scannedAt": datetime.utcnow().isoformat() + "Z",
        "summary": f"Grade: {grade}. For full certificate, cipher suite, and chain details see the Qualys SSL Labs report linked below.",
        "recommendation": "Ensure TLS 1.2+ only and strong ciphers; fix any certificate issues.",
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


def run_ssl_analysis(url_or_host: str) -> dict:
    host = get_domain(url_or_host).split(":")[0]
    if not host or host == "Unknown":
        return {"error": True, "message": "Invalid host", "host": url_or_host}
    api_base = "https://api.ssllabs.com/api/v3"
    req_kw = {"timeout": 10, "verify": False}
    try:
        r = requests.get(f"{api_base}/analyze", params={"host": host, "fromCache": "on", "all": "done", "maxAge": 48}, **req_kw)
        r.raise_for_status()
        data = r.json()
        if data.get("status") == "ERROR":
            return {
                "host": host,
                "error": True,
                "message": data.get("statusMessage") or "SSL Labs returned an error",
                "scannedAt": datetime.utcnow().isoformat() + "Z",
            }
        if data.get("status") in ("ERROR", "DNS"):
            return {
                "host": host,
                "error": True,
                "message": data.get("statusMessage") or data.get("status") or "Analysis failed",
                "scannedAt": datetime.utcnow().isoformat() + "Z",
            }
        if data.get("status") != "READY":
            try:
                local = _local_ssl_check(host)
                grade = local.get("localGrade") or "N/A (local)"
                status = local.get("localStatus") or ""
                protocol = local.get("protocol") or local.get("error") or "unknown"
                summary = f"Local check: {status}. Negotiated protocol: {protocol}."
                if local.get("cipher"):
                    summary += f" Cipher: {local['cipher']}."
                summary += " For full certificate and cipher details, see the Qualys SSL Labs report linked below."
                return {
                    "host": host,
                    "error": False,
                    "grade": grade,
                    "endpointGrade": grade,
                    "sslLabsUrl": f"https://www.ssllabs.com/ssltest/analyze.html?d={host}",
                    "reportTitle": f"SSL Report: {host}",
                    "scannedAt": datetime.utcnow().isoformat() + "Z",
                    "summary": summary,
                    "recommendation": "Prefer TLS 1.2 or 1.3 only; disable TLS 1.0/1.1. Use SSL Labs when available for certificate and cipher details.",
                    "localProtocol": local.get("protocol"),
                    "localCipher": local.get("cipher"),
                    "localGrade": grade,
                    "localStatus": status,
                    "localError": local.get("error"),
                }
            except Exception:
                return {
                    "host": host,
                    "error": True,
                    "message": "SSL Labs not ready and local check failed",
                    "scannedAt": datetime.utcnow().isoformat() + "Z",
                }
        ssl_labs_url = f"https://www.ssllabs.com/ssltest/analyze.html?d={host}"
        return _parse_ssl_labs_full_report(data, host, ssl_labs_url)
    except requests.RequestException as e:
        try:
            local = _local_ssl_check(host)
            grade = local.get("localGrade") or "N/A (local)"
            status = local.get("localStatus") or ""
            protocol = local.get("protocol") or local.get("error") or "unknown"
            summary = f"SSL Labs API was unavailable. Local check: {status}. Protocol: {protocol}."
            if local.get("cipher"):
                summary += f" Cipher: {local['cipher']}."
            summary += " Use the link below for a full SSL Labs report when their API is available."
            return {
                "host": host,
                "error": False,
                "grade": grade,
                "endpointGrade": grade,
                "sslLabsUrl": f"https://www.ssllabs.com/ssltest/analyze.html?d={host}",
                "reportTitle": f"SSL Report: {host}",
                "scannedAt": datetime.utcnow().isoformat() + "Z",
                "summary": summary,
                "recommendation": "Prefer TLS 1.2 or 1.3 only; disable older protocols. For certificate and full cipher analysis, run the SSL Labs test via the link below when their API is up.",
                "localProtocol": local.get("protocol"),
                "localCipher": local.get("cipher"),
                "localGrade": grade,
                "localStatus": status,
                "localError": local.get("error"),
            }
        except Exception:
            return {
                "host": host,
                "error": True,
                "message": str(e) or "SSL Labs request failed",
                "scannedAt": datetime.utcnow().isoformat() + "Z",
            }
    except Exception as e:
        # Ensure we always return a dict so the backend never gets a missing sslReport
        return {
            "host": host,
            "error": True,
            "message": str(e) or "SSL analysis failed",
            "scannedAt": datetime.utcnow().isoformat() + "Z",
        }
