"""
Email service: build HTML security report and send via SMTP or Gmail API (OAuth).
Used when Report Recipients are set and email is configured in .env.
"""
import base64
import html
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

from config import (
    EMAIL_ENABLED,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASSWORD,
    SMTP_FROM,
    SMTP_USE_TLS,
    SMTP_ENABLED,
    GMAIL_OAUTH_ENABLED,
    GOOGLE_SENDER_EMAIL,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REFRESH_TOKEN,
)


def _escape(s):
    if s is None:
        return ""
    return html.escape(str(s).strip())


# ── n8n "Working API Secure" combined report theme ──────────────────────────
_COMBINED_STYLES = """
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;background:#f5f5f5;line-height:1.6;color:#333;}
.combined-report-container{max-width:1000px;margin:0 auto;padding:30px 20px;}
.main-header{text-align:center;padding:50px 30px;background:linear-gradient(135deg,#1e3c72 0%,#2a5298 100%);color:white;border-radius:12px;margin-bottom:40px;box-shadow:0 4px 15px rgba(0,0,0,0.15);}
.main-header h1{margin:0 0 15px 0;font-size:2.2rem;font-weight:700;}
.main-header .domain{margin:0 0 8px 0;font-size:1.2rem;opacity:.95;}
.main-header .meta{margin:0;font-size:.95rem;opacity:.85;}
.individual-report{background:white;margin-bottom:40px;border-radius:12px;overflow:visible;box-shadow:0 4px 15px rgba(0,0,0,0.1);isolation:isolate;}
.report-section-header{background:linear-gradient(135deg,#2a5298,#1e3c72);color:white;padding:20px 30px;margin:0;border-radius:12px 12px 0 0;}
.report-section-header h2{margin:0;font-size:1.4rem;font-weight:600;color:white!important;}
.report-content{background:white;padding:25px 30px;border-radius:0 0 12px 12px;}
.site-info{background:#f8f9fa;border-radius:10px;padding:14px 18px;margin-bottom:20px;border-left:4px solid #2a5298;}
.site-url{font-size:1.1rem;font-weight:600;color:#2a5298;margin-bottom:4px;}
.scan-time{color:#6c757d;font-size:.9rem;}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:20px;}
.summary-card{background:white;border-radius:10px;padding:14px;box-shadow:0 2px 10px rgba(0,0,0,0.08);border-left:4px solid #ddd;display:flex;align-items:center;gap:12px;}
.card-icon{font-size:1.4rem;flex-shrink:0;}
.card-value{font-size:1.3rem;font-weight:700;}
.card-title{font-size:.75rem;color:#6c757d;text-transform:uppercase;letter-spacing:.5px;}
.progress-wrap{background:white;border-radius:10px;padding:16px;margin-bottom:20px;box-shadow:0 2px 10px rgba(0,0,0,0.08);}
.progress-label{font-size:.95rem;font-weight:600;margin-bottom:10px;color:#2a5298;}
.progress-bar{background:#e9ecef;border-radius:50px;height:14px;overflow:hidden;margin-bottom:8px;}
.progress-fill{height:100%;border-radius:50px;}
.progress-text{text-align:center;font-size:1rem;font-weight:600;}
.section{background:white;border-radius:10px;margin-bottom:20px;box-shadow:0 2px 10px rgba(0,0,0,0.08);overflow:hidden;}
.section-header{background:linear-gradient(135deg,#2a5298,#1e3c72);color:white;padding:12px 18px;font-size:1rem;font-weight:600;}
.section-content{padding:16px 18px;}
.headers-table{width:100%;border-collapse:collapse;font-size:.88rem;}
.headers-table th{background:#f8f9fa;padding:10px 12px;text-align:left;font-weight:600;border-bottom:2px solid #dee2e6;color:#495057;}
.headers-table td{padding:10px 12px;border-bottom:1px solid #dee2e6;vertical-align:middle;}
.header-name{font-weight:600;color:#2a5298;}
.status-icon{display:inline-block;width:18px;height:18px;border-radius:50%;text-align:center;line-height:18px;color:white;font-weight:bold;margin-right:5px;font-size:.72rem;}
.status-icon.success{background:#28a745;}
.status-icon.danger{background:#dc3545;}
.severity-badge{padding:3px 8px;border-radius:14px;font-size:.68rem;font-weight:600;text-transform:uppercase;}
.severity-critical{background:#dc3545;color:white;}
.severity-warning{background:#ffc107;color:#212529;}
.severity-ok{background:#28a745;color:white;}
.no-value{color:#6c757d;font-style:italic;}
.list-item{padding:7px 0;border-bottom:1px solid #f1f3f4;}
.list-item:last-child{border-bottom:none;}
.no-items{text-align:center;padding:12px;color:#28a745;font-weight:600;background:#f8fff9;border-radius:8px;list-style:none;}
.ai-findings{background:linear-gradient(135deg,#f8f9ff,#fff8f8);border-left:4px solid #6f42c1;border-radius:8px;padding:14px;white-space:pre-wrap;font-size:.9rem;line-height:1.5;}
.kv-table{width:100%;border-collapse:collapse;font-size:.88rem;}
.kv-table td{padding:8px 12px;border-bottom:1px solid #dee2e6;vertical-align:top;}
.kv-table td:first-child{font-weight:600;color:#495057;width:35%;white-space:nowrap;}
.main-footer{text-align:center;padding:40px 30px;background:linear-gradient(135deg,#1e3c72 0%,#2a5298 100%);color:white;border-radius:12px;margin-top:40px;box-shadow:0 4px 15px rgba(0,0,0,0.15);}
.main-footer h3{margin:0 0 12px 0;font-size:1.4rem;font-weight:700;}
.main-footer p{margin:0 0 6px 0;font-size:.95rem;opacity:.9;}
"""


def _section_card(icon, title, content_html):
    return f'<div class="individual-report"><div class="report-section-header"><h2>{icon} {_escape(title)}</h2></div><div class="report-content">{content_html}</div></div>'


def _headers_section(r):
    hr = r.get("headersReport") or {}
    if hr.get("error"):
        return _section_card("&#128737;", "HTTP Security Headers", f'<p style="color:#dc3545;">{_escape(hr.get("message","Error running headers analysis."))}</p>')
    score = hr.get("score", 0)
    grade = hr.get("grade", "F")
    critical = hr.get("criticalCount", 0)
    warnings_count = hr.get("warningCount", 0)
    evaluated = hr.get("evaluatedHeaders") or {}
    vulnerabilities = hr.get("vulnerabilities") or []
    warnings = hr.get("warnings") or []
    recommendations = hr.get("recommendations") or []
    ai_notes = hr.get("aiHeaderNotes") or ""
    pc = "#28a745" if score >= 80 else "#ffc107" if score >= 60 else "#dc3545"
    gc = {"A": "#28a745", "B": "#17a2b8", "C": "#ffc107", "D": "#fd7e14", "F": "#dc3545"}.get(grade, "#dc3545")
    cards = [
        ("Security Score", f"{score}%", "&#128202;", pc),
        ("Grade", grade, "&#127775;", gc),
        ("Critical Issues", str(critical), "&#128680;", "#dc3545"),
        ("Warnings", str(warnings_count), "&#9888;", "#ffc107"),
    ]
    cards_html = "".join(
        f'<div class="summary-card" style="border-left-color:{c[3]}"><div class="card-icon">{c[2]}</div><div><div class="card-value" style="color:{c[3]}">{_escape(c[1])}</div><div class="card-title">{_escape(c[0])}</div></div></div>'
        for c in cards
    )
    rows = []
    for name, info in (evaluated if isinstance(evaluated, dict) else {}).items():
        present = info.get("present") if isinstance(info, dict) else False
        val = info.get("value") if isinstance(info, dict) else None
        sev = (info.get("severity") or "critical").lower() if isinstance(info, dict) else "critical"
        dv = (str(val)[:60] + "…") if val and len(str(val)) > 60 else (val or "")
        dv_html = _escape(dv) if dv else '<span class="no-value">Not set</span>'
        icon_html = '<span class="status-icon success">&#10003;</span>' if present else '<span class="status-icon danger">&#10007;</span>'
        sev_cls = "severity-critical" if sev == "critical" else "severity-warning" if sev == "warning" else "severity-ok"
        rows.append(f'<tr><td class="header-name">{_escape(name)}</td><td>{icon_html} {"Present" if present else "Missing"}</td><td>{dv_html}</td><td><span class="severity-badge {sev_cls}">{sev.upper()}</span></td></tr>')
    tbl = ('<table class="headers-table"><thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Severity</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table>") if rows else "<p>No header data.</p>"
    def uli(items, em="&#128161;"):
        if not items:
            return '<li class="no-items">None &#10003;</li>'
        return "".join(f'<li class="list-item">{em} {_escape(str(i))}</li>' for i in items)
    body = (
        f'<div class="summary-grid">{cards_html}</div>'
        f'<div class="progress-wrap"><div class="progress-label">Security Score</div><div class="progress-bar"><div class="progress-fill" style="width:{max(5,score)}%;background:{pc};"></div></div><div class="progress-text" style="color:{pc};">{score}% &mdash; Grade {grade}</div></div>'
        f'<div class="section"><div class="section-header">Header Analysis</div><div class="section-content">{tbl}</div></div>'
        f'<div class="section"><div class="section-header">&#128680; Critical Vulnerabilities</div><div class="section-content"><ul style="list-style:none;padding:0;">{uli(vulnerabilities,"&#128680;")}</ul></div></div>'
        f'<div class="section"><div class="section-header">&#9888; Warnings</div><div class="section-content"><ul style="list-style:none;padding:0;">{uli(warnings,"&#9888;")}</ul></div></div>'
        f'<div class="section"><div class="section-header">&#128161; Recommendations</div><div class="section-content"><ul style="list-style:none;padding:0;">{uli(recommendations,"&#128161;")}</ul></div></div>'
        + (f'<div class="section"><div class="section-header">&#128203; Professional Summary</div><div class="section-content"><div class="ai-findings">{_escape(ai_notes)}</div></div></div>' if ai_notes else "")
    )
    return _section_card("&#128737;", "HTTP Security Headers", body)


def _cors_section(r):
    cr = r.get("corsReport") or {}
    if cr.get("error"):
        return _section_card("&#127760;", "CORS Validation", f'<p style="color:#dc3545;">{_escape(cr.get("message","Error running CORS analysis."))}</p>')
    risk = cr.get("riskLevel") or cr.get("configuration", {}).get("riskLevel") or "Unknown"
    findings = cr.get("findings") or []
    config = cr.get("configuration") or {}
    rc = "#dc3545" if "high" in risk.lower() or "critical" in risk.lower() else "#ffc107" if "medium" in risk.lower() or "moderate" in risk.lower() else "#28a745"
    rows = "".join(f'<tr><td>{_escape(k)}</td><td><code>{_escape(str(v))}</code></td></tr>' for k, v in config.items() if v not in (None, "", []))
    kv_tbl = f'<table class="kv-table">{rows}</table>' if rows else "<p>No CORS configuration data.</p>"
    findings_html = "".join(f'<li class="list-item">&#9888; {_escape(str(f))}</li>' for f in findings) if findings else '<li class="no-items">No issues found &#10003;</li>'
    body = (
        f'<div class="section"><div class="section-header">Risk Level</div><div class="section-content"><span style="font-size:1.1rem;font-weight:700;color:{rc};">{_escape(risk)}</span></div></div>'
        f'<div class="section"><div class="section-header">CORS Configuration</div><div class="section-content">{kv_tbl}</div></div>'
        f'<div class="section"><div class="section-header">Findings</div><div class="section-content"><ul style="list-style:none;padding:0;">{findings_html}</ul></div></div>'
    )
    return _section_card("&#127760;", "CORS Validation", body)


def _ssl_section(r):
    sr = r.get("sslReport") or {}
    if sr.get("error"):
        return _section_card("&#128274;", "SSL / TLS Security", f'<p style="color:#dc3545;">{_escape(sr.get("message","Error running SSL analysis."))}</p>')
    grade = sr.get("grade") or "—"
    gc = {"A": "#28a745", "A+": "#28a745", "B": "#17a2b8", "C": "#ffc107", "D": "#fd7e14", "F": "#dc3545"}.get(grade, "#6c757d")
    checks = sr.get("checks") or []
    issues = sr.get("issues") or []
    rows = "".join(f'<tr><td>{_escape(str(c.get("name","—")))}</td><td><code>{_escape(str(c.get("value","—")))}</code></td><td>{"&#10003;" if c.get("ok") else "&#10007;"}</td></tr>' for c in checks) if checks else ""
    chk_tbl = f'<table class="kv-table"><thead><tr><th>Check</th><th>Value</th><th>OK</th></tr></thead><tbody>{rows}</tbody></table>' if rows else "<p>No SSL check data.</p>"
    issues_html = "".join(f'<li class="list-item">&#9888; {_escape(str(i))}</li>' for i in issues) if issues else '<li class="no-items">No issues &#10003;</li>'
    body = (
        f'<div class="section"><div class="section-header">SSL Grade</div><div class="section-content"><span style="font-size:1.5rem;font-weight:800;color:{gc};">{_escape(grade)}</span></div></div>'
        f'<div class="section"><div class="section-header">Checks</div><div class="section-content">{chk_tbl}</div></div>'
        f'<div class="section"><div class="section-header">Issues</div><div class="section-content"><ul style="list-style:none;padding:0;">{issues_html}</ul></div></div>'
    )
    return _section_card("&#128274;", "SSL / TLS Security", body)


def _server_section(r):
    srv = r.get("serverReport") or {}
    if srv.get("error"):
        return _section_card("&#9881;", "Server Version Disclosure", f'<p style="color:#dc3545;">{_escape(srv.get("message","Error."))}</p>')
    risk = srv.get("riskLevel") or "Unknown"
    disclosures = srv.get("disclosures") or []
    rc = "#dc3545" if "high" in risk.lower() or "critical" in risk.lower() else "#ffc107" if "medium" in risk.lower() else "#28a745"
    rows = "".join(f'<tr><td>{_escape(str(d.get("name","—")))}</td><td><code>{_escape(str(d.get("value","—")))}</code></td><td>{_escape(str(d.get("severity","—")))}</td></tr>' for d in disclosures) if disclosures else ""
    tbl = f'<table class="kv-table"><thead><tr><th>Header/Field</th><th>Value</th><th>Severity</th></tr></thead><tbody>{rows}</tbody></table>' if rows else "<p>No disclosures detected.</p>"
    body = (
        f'<div class="section"><div class="section-header">Risk Level</div><div class="section-content"><span style="font-size:1.1rem;font-weight:700;color:{rc};">{_escape(risk)}</span></div></div>'
        f'<div class="section"><div class="section-header">Disclosures</div><div class="section-content">{tbl}</div></div>'
    )
    return _section_card("&#9881;", "Server Version Disclosure", body)


def _error_section(r):
    eh = r.get("errorHandlingReport") or {}
    if eh.get("error"):
        return _section_card("&#9888;", "Improper Error Handling", f'<p style="color:#dc3545;">{_escape(eh.get("message","Error."))}</p>')
    risk = eh.get("riskLevel") or "Unknown"
    findings = eh.get("findings") or []
    rc = "#dc3545" if "high" in risk.lower() else "#ffc107" if "medium" in risk.lower() else "#28a745"
    findings_html = "".join(f'<li class="list-item">&#9888; {_escape(str(f))}</li>' for f in findings) if findings else '<li class="no-items">No issues found &#10003;</li>'
    body = (
        f'<div class="section"><div class="section-header">Risk Level</div><div class="section-content"><span style="font-size:1.1rem;font-weight:700;color:{rc};">{_escape(risk)}</span></div></div>'
        f'<div class="section"><div class="section-header">Findings</div><div class="section-content"><ul style="list-style:none;padding:0;">{findings_html}</ul></div></div>'
    )
    return _section_card("&#9888;", "Improper Error Handling", body)


def _tamper_section(r):
    ut = r.get("urlTamperingReport") or {}
    if ut.get("error"):
        return _section_card("&#128279;", "URL Tampering", f'<p style="color:#dc3545;">{_escape(ut.get("message","Error."))}</p>')
    tests = ut.get("tests") or []
    rows = "".join(
        f'<tr><td style="word-break:break-all;max-width:260px;">{_escape(str(t.get("url","—")))}</td><td>{_escape(str(t.get("statusCode","—")))}</td><td>{_escape(str(t.get("bodyLength","—")))}</td><td>{_escape(str(t.get("riskLevel","—")))}</td></tr>'
        for t in tests
    ) if tests else ""
    tbl = (f'<table class="kv-table"><thead><tr><th>URL</th><th>Status</th><th>Body Length</th><th>Risk</th></tr></thead><tbody>{rows}</tbody></table>') if rows else "<p>No tampering tests run.</p>"
    body = f'<div class="section"><div class="section-header">Test Results ({len(tests)} probes)</div><div class="section-content">{tbl}</div></div>'
    return _section_card("&#128279;", "URL Tampering Analysis", body)


def _build_single_result_sections(r):
    """Return list of (present, html) tuples for each check in a single scan result."""
    sections = []
    if r.get("headersReport") is not None:
        sections.append(_headers_section(r))
    if r.get("corsReport") is not None:
        sections.append(_cors_section(r))
    if r.get("sslReport") is not None:
        sections.append(_ssl_section(r))
    if r.get("serverReport") is not None:
        sections.append(_server_section(r))
    if r.get("errorHandlingReport") is not None:
        sections.append(_error_section(r))
    if r.get("urlTamperingReport") is not None:
        sections.append(_tamper_section(r))
    return sections


def build_html_report(scan_result):
    """Build combined HTML report matching the Working API Secure n8n theme."""
    if scan_result.get("batch") and scan_result.get("results"):
        results = scan_result["results"]
    else:
        results = [scan_result] if scan_result else []

    first = results[0] if results else {}
    domain = first.get("targetDomain") or first.get("url") or "Unknown"
    try:
        scanned = datetime.fromisoformat((first.get("scannedAt") or "").replace("Z", "+00:00")).strftime("%d %b %Y, %H:%M UTC")
    except Exception:
        scanned = first.get("scannedAt") or ""
    test_count = sum(
        1 for k in ("headersReport", "corsReport", "sslReport", "serverReport", "errorHandlingReport", "urlTamperingReport")
        if first.get(k) is not None
    ) if first else 0

    all_sections = []
    for idx, r in enumerate(results):
        if len(results) > 1:
            url_label = r.get("url") or r.get("targetDomain") or f"URL {idx + 1}"
            all_sections.append(f'<div style="margin:30px 0 10px;padding:14px 20px;background:linear-gradient(135deg,#1e3c72,#2a5298);color:white;border-radius:10px;font-size:1.05rem;font-weight:600;">&#127760; {_escape(url_label)}</div>')
        all_sections.extend(_build_single_result_sections(r))

    sections_html = "\n".join(all_sections) if all_sections else "<p>No scan data available.</p>"

    year = datetime.utcnow().year
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Security Report &mdash; {_escape(domain)}</title>
<style>{_COMBINED_STYLES}</style>
</head>
<body>
<div class="combined-report-container">
  <div class="main-header">
    <h1>&#128737; Comprehensive Security Report</h1>
    <p class="domain">&#127760; {_escape(domain)}</p>
    <p class="meta">&#128197; {_escape(scanned)} &nbsp;|&nbsp; &#128269; {test_count} security test{"s" if test_count != 1 else ""} completed</p>
  </div>
  {sections_html}
  <div class="main-footer">
    <h3>&#128274; API Secure Scanner</h3>
    <p>Scan &middot; Analyze &middot; Report</p>
    <p>&copy; {year} API Secure &mdash; Keep your APIs secure with regular audits</p>
  </div>
</div>
</body>
</html>"""


def _parse_emails(recipient_emails_str):
    """Parse comma/semicolon separated emails; return list of valid-looking addresses."""
    if not recipient_emails_str or not isinstance(recipient_emails_str, str):
        return []
    # Simple valid email pattern
    pattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    seen = set()
    out = []
    for part in re.split(r"[,;\s]+", recipient_emails_str):
        part = part.strip()
        if not part:
            continue
        match = pattern.search(part)
        if match and match.group(0) not in seen:
            seen.add(match.group(0))
            out.append(match.group(0))
    return out


def _send_via_gmail_api(emails, msg):
    """Send MIMEMultipart message via Gmail API using OAuth2 refresh token. Returns (True, None) or (False, error_str)."""
    try:
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request
        from googleapiclient.discovery import build
    except ImportError:
        return False, "Install: pip install google-auth google-auth-oauthlib google-api-python-client"
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode().rstrip("=").replace("+", "-").replace("/", "_")
    credentials = Credentials(
        token=None,
        refresh_token=GOOGLE_REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=["https://www.googleapis.com/auth/gmail.send"],
    )
    credentials.refresh(Request())
    service = build("gmail", "v1", credentials=credentials)
    body = {"raw": raw}
    service.users().messages().send(userId="me", body=body).execute()
    return True, None


def send_report(recipient_emails_str, scan_result):
    """
    Send the security report to the given recipients.
    recipient_emails_str: comma- or semicolon-separated email addresses.
    scan_result: the scan API response (single result or batch).
    Returns (success: bool, message: str).
    """
    if not EMAIL_ENABLED:
        return False, "Email is not configured. Set SMTP settings or Gmail OAuth (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN, GOOGLE_SENDER_EMAIL) in .env."
    emails = _parse_emails(recipient_emails_str)
    if not emails:
        return False, "No valid recipient email addresses."
    subject = "API Secure – Security report"
    if scan_result.get("batch") and scan_result.get("results"):
        urls = scan_result.get("results", [])
        if urls:
            first = urls[0].get("url") or urls[0].get("targetDomain") or "API"
            subject = f"API Secure – Security report ({len(urls)} URLs)"
        else:
            subject = "API Secure – Security report"
    else:
        url = (scan_result or {}).get("url") or (scan_result or {}).get("targetDomain") or "API"
        subject = f"API Secure – Security report for {str(url)[:50]}"
    html_body = build_html_report(scan_result)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject[:998]
    msg["To"] = ", ".join(emails)
    msg.attach(MIMEText(f"Security report for {subject}", "plain"))
    msg.attach(MIMEText(html_body, "html"))
    if GMAIL_OAUTH_ENABLED:
        msg["From"] = GOOGLE_SENDER_EMAIL
        try:
            ok, err = _send_via_gmail_api(emails, msg)
            if ok:
                return True, f"Report sent to {len(emails)} recipient(s)."
            return False, err or "Gmail API send failed."
        except Exception as e:
            return False, str(e)
    msg["From"] = SMTP_FROM or SMTP_USER
    try:
        if SMTP_USE_TLS:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
                server.starttls()
                if SMTP_USER and SMTP_PASSWORD:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_FROM or SMTP_USER, emails, msg.as_string())
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
                if SMTP_USER and SMTP_PASSWORD:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_FROM or SMTP_USER, emails, msg.as_string())
        return True, f"Report sent to {len(emails)} recipient(s)."
    except smtplib.SMTPAuthenticationError as e:
        return False, f"SMTP authentication failed: {e}"
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {e}"
    except Exception as e:
        return False, str(e)
