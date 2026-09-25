"""
Instant template-based HTTP security header analysis.
Produces the same data shape as ai_service.analyze_headers() but with zero
external API calls, zero latency, and zero quota consumption.

Used as the immediate (synchronous) result while the LLM runs in the background.
"""

# ── Header knowledge base ──────────────────────────────────────────────────────
# Each entry: whatItDoes, risk (if missing/weak), fix (recommended value)
_HEADER_KB = {
    "Content-Security-Policy": {
        "whatItDoes": (
            "Controls which sources of scripts, images, and other content the browser is "
            "allowed to load. It acts as a whitelist that stops attackers from injecting "
            "malicious scripts into your pages."
        ),
        "missingRisk": (
            "Without this protection, attackers who find a way to inject code into your page "
            "(cross-site scripting) can steal user login cookies, redirect users to fake sites, "
            "or silently perform actions on a user's behalf."
        ),
        "weakRisk": (
            "The policy is present but allows unsafe directives such as 'unsafe-inline' or "
            "'unsafe-eval', which significantly weakens protection against script injection attacks."
        ),
        "fix": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';",
        "priority": 2,
    },
    "Strict-Transport-Security": {
        "whatItDoes": (
            "Instructs browsers to only ever connect to your site over an encrypted (HTTPS) "
            "connection. Once seen, browsers will refuse to load your site over plain HTTP, "
            "even if a user types 'http://' manually."
        ),
        "missingRisk": (
            "Without this, users on public Wi-Fi can have their connection intercepted. An attacker "
            "on the same network could silently downgrade the connection to plain HTTP and read or "
            "modify everything the user sends — including passwords and session tokens."
        ),
        "weakRisk": (
            "The header is present but the max-age is too short, or includeSubDomains is missing, "
            "leaving subdomains and short-lived sessions unprotected."
        ),
        "fix": "max-age=31536000; includeSubDomains; preload",
        "priority": 1,
    },
    "X-Content-Type-Options": {
        "whatItDoes": (
            "Prevents the browser from guessing (or 'sniffing') what type of file a response is. "
            "Without it, browsers might execute a text file as JavaScript if it looks like code."
        ),
        "missingRisk": (
            "Attackers could upload a file disguised as something harmless (e.g., an image) that "
            "the browser executes as a script, enabling them to run malicious code on your site."
        ),
        "weakRisk": (
            "The header is set to a non-standard value and may not provide full protection "
            "in all browsers."
        ),
        "fix": "nosniff",
        "priority": 3,
    },
    "X-Frame-Options": {
        "whatItDoes": (
            "Prevents your website from being embedded inside another website's page using frames. "
            "This stops a technique called 'clickjacking', where an invisible version of your site "
            "is overlaid on a fake page to steal clicks."
        ),
        "missingRisk": (
            "Attackers can embed your site invisibly on their own page and trick users into clicking "
            "buttons or links without knowing it — for example, transferring money or changing "
            "account settings without consent."
        ),
        "weakRisk": (
            "The header is set but uses ALLOW-FROM which is not supported by modern browsers. "
            "Use Content-Security-Policy frame-ancestors instead."
        ),
        "fix": "DENY",
        "priority": 4,
    },
    "Referrer-Policy": {
        "whatItDoes": (
            "Controls how much information about the current page URL is shared when a user clicks "
            "a link to another site. This protects sensitive information that might be in your URLs "
            "(such as user IDs or session tokens) from leaking to third parties."
        ),
        "missingRisk": (
            "When users navigate away from your site, the full URL — which may contain session tokens "
            "or personal data — gets sent to the destination website in the Referer header, "
            "potentially exposing private user information."
        ),
        "weakRisk": (
            "The referrer policy is set but allows more URL information to leak than necessary. "
            "Tighten it to 'strict-origin-when-cross-origin' or 'no-referrer'."
        ),
        "fix": "strict-origin-when-cross-origin",
        "priority": 5,
    },
    "Permissions-Policy": {
        "whatItDoes": (
            "Restricts which browser features and device capabilities (like camera, microphone, "
            "location) your website and any embedded third-party code are allowed to access. "
            "It's a permission whitelist for powerful browser APIs."
        ),
        "missingRisk": (
            "Without this, any third-party scripts or ads on your page could silently access "
            "the user's microphone, camera, or location. Malicious embedded content could "
            "spy on users without them knowing."
        ),
        "weakRisk": (
            "The policy is present but may allow more browser features than your application needs, "
            "unnecessarily expanding the attack surface."
        ),
        "fix": "camera=(), microphone=(), geolocation=(), payment=()",
        "priority": 6,
    },
    "X-XSS-Protection": {
        "whatItDoes": (
            "Enables the built-in XSS (cross-site scripting) filter in older browsers. Modern "
            "browsers have largely deprecated it in favour of Content-Security-Policy, but it "
            "still provides a safety net for older browser users."
        ),
        "missingRisk": (
            "Older browsers that support this filter won't have it active, slightly increasing "
            "the risk of reflected script injection attacks for users on legacy browsers."
        ),
        "weakRisk": (
            "The header is set to '0', which actually disables the XSS filter entirely. "
            "This is the opposite of what is needed and removes a layer of defence."
        ),
        "fix": "1; mode=block",
        "priority": 7,
    },
    "Cross-Origin-Embedder-Policy": {
        "whatItDoes": (
            "Controls whether your page can load resources (images, scripts) from other websites. "
            "When set to 'require-corp', it prevents your page from loading cross-origin content "
            "that hasn't explicitly allowed it, protecting against data leakage attacks."
        ),
        "missingRisk": (
            "Sophisticated attackers can exploit browser vulnerabilities (like Spectre) to read "
            "memory from cross-origin resources loaded by your page, potentially stealing "
            "sensitive data from other sites a user is logged into."
        ),
        "weakRisk": (
            "The policy is set but to a permissive value that doesn't provide meaningful "
            "isolation against cross-origin data leakage."
        ),
        "fix": "require-corp",
        "priority": 8,
    },
    "Cross-Origin-Opener-Policy": {
        "whatItDoes": (
            "Controls whether your page shares a browser session with pages it opens (or pages "
            "that open it). Setting this to 'same-origin' prevents other websites from accessing "
            "your page's window object, stopping window hijacking attacks."
        ),
        "missingRisk": (
            "A page opened by your site (or that opens your site) could access your window "
            "object, read its content, or redirect users to a malicious URL. This is particularly "
            "risky for login flows and OAuth redirects."
        ),
        "weakRisk": (
            "The policy is set but to 'same-origin-allow-popups', which still allows some "
            "cross-origin window access via popups."
        ),
        "fix": "same-origin",
        "priority": 9,
    },
    "X-Permitted-Cross-Domain-Policies": {
        "whatItDoes": (
            "Tells Adobe Flash and PDF readers whether they are allowed to make cross-domain "
            "requests from your site. Setting this to 'none' prevents legacy plugins from "
            "establishing unauthorised connections."
        ),
        "missingRisk": (
            "Legacy browser plugins like Flash could make unauthorised requests to other domains "
            "on behalf of your site, potentially leaking data or being exploited for "
            "cross-site request forgery via old plugin vulnerabilities."
        ),
        "weakRisk": (
            "The policy allows some cross-domain access by plugins. Set to 'none' unless "
            "you specifically need legacy plugin support."
        ),
        "fix": "none",
        "priority": 10,
    },
}

_RISK_LEVELS = {0: "Good", 1: "Low", 2: "Medium", 3: "Medium", 4: "High", 5: "High"}

_EXEC_SUMMARY_TEMPLATES = {
    "Good": (
        "{domain} has a strong security posture. All critical HTTP security headers are properly "
        "configured, providing solid baseline protection against common web attacks. The site enforces "
        "encrypted connections, prevents script injection, and guards against clickjacking. "
        "Continue monitoring for any configuration drift and review the Content-Security-Policy "
        "periodically to ensure it stays current with your application's needs."
    ),
    "Low": (
        "{domain} has a mostly solid security configuration with {critical} minor gap(s) to address. "
        "The majority of critical protections are in place. The missing headers pose a low but real "
        "risk — addressing them will complete your baseline security hardening and is recommended "
        "as part of routine maintenance. Review the recommendations below and implement them in your "
        "next deployment cycle."
    ),
    "Medium": (
        "{domain} has a moderate security posture with {critical} critical protection(s) missing. "
        "While some security headers are correctly configured, the gaps present real attack opportunities. "
        "An attacker could potentially exploit these missing protections to inject malicious scripts, "
        "intercept connections, or trick users into unintended actions. These issues should be prioritised "
        "and remediated in the near term to avoid potential data breaches or user harm."
    ),
    "High": (
        "{domain} has significant security gaps with {critical} critical protection(s) missing. "
        "Several important security headers are absent, leaving users and data exposed to well-known "
        "attack techniques including script injection, connection interception, and clickjacking. "
        "These missing protections are straightforward to add and should be treated as high-priority "
        "fixes. Delaying remediation increases the risk of a security incident that could damage "
        "user trust and result in regulatory consequences."
    ),
    "Critical": (
        "{domain} is critically exposed — {critical} out of 10 security headers are missing or "
        "misconfigured. This API/site has almost no browser-level security protections in place. "
        "Attackers could intercept connections, inject malicious code, steal user sessions, and "
        "perform clickjacking attacks with little resistance. This represents a serious security "
        "risk and should be treated as an urgent remediation item. Adding these headers typically "
        "requires a single deployment change to your web server or application configuration."
    ),
}


def _evaluate_header_severity(name: str, info: dict) -> tuple:
    """
    Returns (severity, whatItDoes, status, risk, fix, finding_details) for a single header.
    Consumes the deep-analysis `findings` list from the scanner when available.
    """
    kb = _HEADER_KB.get(name, {})
    present = info.get("present", False)
    value = (info.get("value") or "").strip()
    raw_severity = (info.get("severity") or "").lower()
    findings = info.get("findings") or []

    what_it_does = kb.get("whatItDoes", f"A security header that controls {name} browser behaviour.")
    fix = kb.get("fix", "Consult the OWASP Secure Headers Project for the recommended value.")

    if not present:
        severity = "critical"
        status = "Not configured — this protection is completely missing from your site."
        risk = kb.get("missingRisk", "This missing header leaves your site exposed to common browser-level attacks.")
        fix_out = f"Add this header to your server response. Recommended value: {fix}"
        return severity, what_it_does, status, risk, fix_out, []

    high_findings = [f for f in findings if f.get("severity") in ("high", "critical")]
    med_findings = [f for f in findings if f.get("severity") == "medium"]
    low_findings = [f for f in findings if f.get("severity") in ("low", "info")]

    if high_findings or med_findings:
        severity = "warning"
        issue_titles = [f["title"] for f in high_findings + med_findings]
        status = (
            f"Present but has configuration weaknesses: {'; '.join(issue_titles[:3])}."
            + (f" Current value: {value[:60]}..." if len(value) > 60 else f" Current value: {value}." if value else "")
        )
        risk_parts = [f["detail"] for f in high_findings[:2]] or [f["detail"] for f in med_findings[:2]]
        risk = " ".join(risk_parts)
        fix_parts = []
        for f in high_findings + med_findings:
            fid = f.get("id", "")
            if "csp-unsafe-inline" == fid:
                fix_parts.append("Remove 'unsafe-inline' from script-src; use nonce-based or hash-based CSP instead.")
            elif "csp-unsafe-eval" == fid:
                fix_parts.append("Remove 'unsafe-eval' from script-src; refactor code to avoid eval().")
            elif "csp-unsafe-hashes" == fid:
                fix_parts.append("Review use of 'unsafe-hashes'; prefer nonce-based CSP for event handlers.")
            elif "data-script" in fid:
                fix_parts.append("Remove 'data:' from script-src — it allows full script injection via data URIs.")
            elif "data-connect" in fid:
                fix_parts.append("Remove 'data:' from connect-src to prevent data exfiltration bypasses.")
            elif "blob-script" in fid:
                fix_parts.append("Remove 'blob:' from script-src if not required by your application.")
            elif "csp-wildcard" in fid:
                fix_parts.append("Replace wildcard '*' with specific, trusted origins in all CSP directives.")
            elif "csp-http-" in fid:
                fix_parts.append("Replace http:// sources with https:// to prevent mixed content and MITM attacks.")
            elif "base-uri" in fid:
                fix_parts.append("Add base-uri 'self' to your CSP to prevent base tag injection.")
            elif "object-src" in fid:
                fix_parts.append("Add object-src 'none' to block legacy plugin embeds.")
            elif "form-action" in fid:
                fix_parts.append("Add form-action 'self' to prevent form submission to attacker-controlled origins.")
            elif "no-default-src" in fid:
                fix_parts.append("Add a default-src directive as the fallback for all unlisted resource types.")
            elif "unsafe-inline-style" in fid:
                fix_parts.append("Remove 'unsafe-inline' from style-src where possible; use nonces for inline styles.")
            elif "max-age" in fid:
                fix_parts.append("Increase max-age to at least 31536000 (1 year) for HSTS preload eligibility.")
            elif "hsts-no-subdomains" in fid:
                fix_parts.append("Add includeSubDomains to cover all subdomains with HSTS.")
            elif "allow-from" in fid:
                fix_parts.append("Replace ALLOW-FROM with CSP frame-ancestors directive (modern browser support).")
            elif "xxss-disabled" in fid or ("disabled" in fid and "xxss" in fid):
                fix_parts.append("Set X-XSS-Protection to '1; mode=block' or rely on a strong CSP.")
            elif "rp-invalid" in fid:
                fix_parts.append(f"Use a valid Referrer-Policy value. Recommended: {fix}")
            elif "permissive" in fid or "pp-" in fid:
                fix_parts.append(f"Tighten the policy: {f.get('detail', '')[:80]}")
            elif "invalid" in fid:
                fix_parts.append(f"Set the correct value. Recommended: {fix}")
            else:
                fix_parts.append(f"{f.get('detail', '')[:100]}")
        fix_out = " ".join(fix_parts[:4]) if fix_parts else f"Review and tighten the configuration. Recommended value: {fix}"
    elif low_findings:
        severity = "ok"
        status = f"Configured with minor notes: {'; '.join(f['title'] for f in low_findings[:2])}."
        risk = "No significant risk — minor improvements possible."
        notes = [f["detail"] for f in low_findings[:2]]
        fix_out = " ".join(notes)
    else:
        severity = "ok"
        status = "Properly configured and protecting your site."
        risk = "No immediate risk — this protection is active."
        fix_out = "No action needed."

    return severity, what_it_does, status, risk, fix_out, findings


def analyze_headers_template(evaluated_headers: dict, target_domain: str,
                              extra_findings: list | None = None) -> dict:
    """
    Instant template-based analysis. Returns the same shape as ai_service.analyze_headers().
    Always succeeds — no network calls, no API keys, no latency.
    Consumes deep-analysis findings from the scanner for richer reports.
    """
    headers_out = []
    critical_count = 0
    warning_count = 0
    ok_count = 0

    header_order = list(_HEADER_KB.keys())
    for name in (evaluated_headers or {}):
        if name not in header_order:
            header_order.append(name)

    for name in header_order:
        info = (evaluated_headers or {}).get(name)
        if info is None:
            info = {"present": False, "severity": "critical", "value": None}

        result = _evaluate_header_severity(name, info)
        sev, what_it_does, status, risk, fix_out = result[0], result[1], result[2], result[3], result[4]
        header_findings = result[5] if len(result) > 5 else []
        value = info.get("value") or None

        if sev == "critical":
            critical_count += 1
        elif sev == "warning":
            warning_count += 1
        else:
            ok_count += 1

        headers_out.append({
            "name": name,
            "present": info.get("present", False),
            "value": value,
            "severity": sev,
            "whatItDoes": what_it_does,
            "status": status,
            "risk": risk,
            "fix": fix_out,
            "findings": header_findings,
            "description": what_it_does,
            "issue": status,
            "impact": risk,
            "recommendation": fix_out,
        })

    # Overall risk — factor in warnings (misconfigured headers) as well
    if critical_count >= 6:
        overall_risk = "Critical"
    elif critical_count >= 4:
        overall_risk = "High"
    elif critical_count >= 2:
        overall_risk = "Medium"
    elif critical_count >= 1:
        overall_risk = "Low"
    elif warning_count >= 2:
        overall_risk = "Low"
    else:
        overall_risk = "Good"

    risk_explanations = {
        "Critical": (
            f"Your site is critically exposed — {critical_count} of 10 security headers are missing. "
            "Attackers could intercept connections, inject malicious code, steal sessions, and perform "
            "clickjacking with minimal effort. Immediate remediation is required."
        ),
        "High": (
            f"Your site has {critical_count} critical security headers missing, leaving it vulnerable "
            "to script injection, connection interception, and clickjacking. These are high-priority fixes."
        ),
        "Medium": (
            f"Your site is missing {critical_count} important security header(s). While some protections "
            "are in place, the gaps create real attack opportunities that should be addressed soon."
        ),
        "Low": (
            f"Your site has a mostly solid configuration with {critical_count} missing header(s)"
            + (f" and {warning_count} header(s) with configuration weaknesses" if warning_count else "")
            + ". Addressing these will complete your baseline security hardening."
        ),
        "Good": (
            "All critical security headers are properly configured."
            + (f" {warning_count} header(s) have minor configuration notes — see details below." if warning_count else "")
            + " Your site has strong baseline protection."
        ),
    }

    exec_summary = _EXEC_SUMMARY_TEMPLATES.get(overall_risk, "").format(
        domain=target_domain, critical=critical_count
    )

    # Append a findings-aware paragraph to the executive summary
    warn_headers = [h for h in headers_out if h["severity"] == "warning"]
    if warn_headers:
        weak_names = [h["name"] for h in warn_headers]
        exec_summary += (
            f"\n\nAdditionally, {len(warn_headers)} header(s) are present but have configuration weaknesses "
            f"that reduce their effectiveness: {', '.join(weak_names)}. "
            "See the detailed findings below for specific issues and remediation steps."
        )

    # Top recommendations — critical first, then warnings, sorted by KB priority
    issue_headers = [h for h in headers_out if h["severity"] in ("critical", "warning")]
    issue_headers.sort(key=lambda h: (0 if h["severity"] == "critical" else 1,
                                       _HEADER_KB.get(h["name"], {}).get("priority", 99)))
    top_recs = []
    for i, h in enumerate(issue_headers[:5], start=1):
        kb = _HEADER_KB.get(h["name"], {})
        if h["severity"] == "critical":
            action = f"Add the {h['name']} header to your server configuration."
            why = kb.get("missingRisk", "")[:150]
        else:
            action = f"Fix configuration weaknesses in {h['name']}."
            why = h.get("risk", kb.get("weakRisk", ""))[:150]
        top_recs.append({
            "priority": i,
            "header": h["name"],
            "action": action,
            "why": why,
            "exampleValue": kb.get("fix", ""),
        })

    crit_names = [h["name"] for h in headers_out if h["severity"] == "critical"]
    warn_names = [h["name"] for h in headers_out if h["severity"] == "warning"]
    ok_names = [h["name"] for h in headers_out if h["severity"] == "ok"]
    notes_lines = [f"Security Analysis — {target_domain}", "", exec_summary, ""]
    if crit_names:
        notes_lines.append(f"CRITICAL ({len(crit_names)}): " + ", ".join(crit_names))
    if warn_names:
        notes_lines.append(f"WARNINGS ({len(warn_names)}): " + ", ".join(warn_names))
    if ok_names:
        notes_lines.append(f"PASSED ({len(ok_names)}): " + ", ".join(ok_names))

    return {
        "aiHeaders": headers_out,
        "aiSummary": {
            "criticalCount": critical_count,
            "warningCount": warning_count,
            "okCount": ok_count,
            "totalHeaders": len(headers_out),
        },
        "aiExecutiveSummary": exec_summary,
        "aiOverallRisk": overall_risk,
        "aiRiskExplanation": risk_explanations.get(overall_risk, ""),
        "aiTopRecs": top_recs,
        "aiHeaderNotes": "\n".join(notes_lines),
        "aiSource": "template",
        "extraFindings": extra_findings or [],
    }
