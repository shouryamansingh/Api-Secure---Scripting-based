"""
AI-powered security analysis via OpenRouter.
Supports multiple API keys with automatic rotation when one key is rate-limited.
Set OPENROUTER_API_KEYS (comma-separated) in .env to enable.

Cache: LLM results are cached per domain for 24 hours so repeated scans of the
same domain don't burn quota.
"""
import json
import logging
import time
import urllib3
import requests
import threading
from datetime import datetime as _dt, timezone as _tz

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from config import AI_ENABLED, OPENROUTER_API_KEYS, OPENROUTER_BASE_URL, OPENROUTER_MODEL

logger = logging.getLogger(__name__)

_TIMEOUT = 90
_FALLBACK_MODEL = None  # openrouter/free auto-routes; retries go to different models
_MAX_TOKENS = 4096

# Seconds to back off when a key gets a temporary upstream 429
_TEMP_BACKOFF = 5

# ── Per-key rate tracking + global stats ──────────────────────────────────────

_lock = threading.Lock()
_active_key_idx = 0  # index into OPENROUTER_API_KEYS

# Per-key state: tracks which keys are exhausted
_key_states = {}
for _i, _k in enumerate(OPENROUTER_API_KEYS):
    _label = _k[-4:] if len(_k) > 4 else _k
    _key_states[_i] = {
        "label": f"...{_label}",
        "exhausted": False,
        "limited_at": None,
        "resets_at": None,
        "calls": 0,
        "successes": 0,
    }

_global_stats = {
    "calls_total": 0,
    "calls_success": 0,
    "calls_failed": 0,
    "calls_rate_limited": 0,
    "last_error": None,
}

# ── LLM result cache (domain → result, keyed by domain, TTL 24h) ──────────────
_CACHE_TTL_SECONDS = 86400  # 24 hours
_cache: dict = {}          # domain -> {"result": dict, "cached_at": float}
_cache_lock = threading.Lock()


def _cache_get(domain: str) -> dict | None:
    """Return cached LLM result for domain if still fresh, else None."""
    with _cache_lock:
        entry = _cache.get(domain)
        if not entry:
            return None
        age = time.time() - entry["cached_at"]
        if age > _CACHE_TTL_SECONDS:
            del _cache[domain]
            return None
        logger.info("Cache HIT for domain=%s (age=%.0fs)", domain, age)
        return entry["result"]


def _cache_set(domain: str, result: dict) -> None:
    """Store LLM result in cache for domain."""
    with _cache_lock:
        _cache[domain] = {"result": result, "cached_at": time.time()}
        logger.info("Cache SET for domain=%s", domain)


def cache_invalidate(domain: str) -> None:
    """Manually invalidate cache for a domain (e.g. on forced retry)."""
    with _cache_lock:
        _cache.pop(domain, None)


def get_cache_info() -> dict:
    """Return cache stats for debugging."""
    with _cache_lock:
        now = time.time()
        entries = [
            {"domain": d, "age_seconds": int(now - v["cached_at"])}
            for d, v in _cache.items()
        ]
        return {"cached_domains": len(entries), "entries": entries, "ttl_seconds": _CACHE_TTL_SECONDS}


def get_rate_state() -> dict:
    """Return combined state for the frontend quota bar."""
    with _lock:
        total_keys = len(OPENROUTER_API_KEYS)
        exhausted_count = sum(1 for s in _key_states.values() if s["exhausted"])
        all_exhausted = exhausted_count == total_keys and total_keys > 0
        active_label = _key_states.get(_active_key_idx, {}).get("label", "none")
        resets_at = None
        for s in _key_states.values():
            if s["resets_at"]:
                if resets_at is None or s["resets_at"] < resets_at:
                    resets_at = s["resets_at"]
        return {
            "is_limited": all_exhausted,
            "calls_total": _global_stats["calls_total"],
            "calls_success": _global_stats["calls_success"],
            "calls_failed": _global_stats["calls_failed"],
            "calls_rate_limited": _global_stats["calls_rate_limited"],
            "last_error": _global_stats["last_error"],
            "limit_resets_at": resets_at,
            "daily_limit": 200 * total_keys,
            "total_keys": total_keys,
            "exhausted_keys": exhausted_count,
            "active_key": active_label,
            "keys": [
                {"label": s["label"], "exhausted": s["exhausted"], "calls": s["calls"], "successes": s["successes"]}
                for s in _key_states.values()
            ],
        }


def _get_active_key():
    """Return (api_key, key_index) tuple, or (None, -1) if all exhausted."""
    global _active_key_idx
    with _lock:
        if not OPENROUTER_API_KEYS:
            return None, -1
        n = len(OPENROUTER_API_KEYS)
        for _ in range(n):
            state = _key_states.get(_active_key_idx)
            if state and not state["exhausted"]:
                return OPENROUTER_API_KEYS[_active_key_idx], _active_key_idx
            _active_key_idx = (_active_key_idx + 1) % n
        return None, -1


def _rotate_key(exhausted_idx: int, resets_at: str = None):
    """Mark key as exhausted and rotate to the next available key."""
    with _lock:
        global _active_key_idx
        state = _key_states.get(exhausted_idx)
        if state:
            state["exhausted"] = True
            state["limited_at"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if resets_at:
                state["resets_at"] = resets_at
        n = len(OPENROUTER_API_KEYS)
        for _ in range(n):
            _active_key_idx = (_active_key_idx + 1) % n
            next_state = _key_states.get(_active_key_idx)
            if next_state and not next_state["exhausted"]:
                logger.info("Rotated to key %s (index %d)", next_state["label"], _active_key_idx)
                return
        logger.warning("All %d API keys exhausted", n)


def _record_call(key_idx: int, success: bool, rate_limited: bool = False, error: str = None):
    with _lock:
        _global_stats["calls_total"] += 1
        ks = _key_states.get(key_idx)
        if ks:
            ks["calls"] += 1
            if success:
                ks["successes"] += 1
        if success:
            _global_stats["calls_success"] += 1
            _global_stats["last_error"] = None
        else:
            _global_stats["calls_failed"] += 1
            if error:
                _global_stats["last_error"] = error
            if rate_limited:
                _global_stats["calls_rate_limited"] += 1


def _extract_json(text: str) -> dict | None:
    """
    Robustly extract the first complete JSON object from text.
    Handles plain JSON, markdown fences, conversational wrapping,
    and truncated JSON (attempts to close unclosed brackets/braces).
    """
    if not text:
        return None
    stripped = text.strip()
    if stripped.startswith("```"):
        parts = stripped.split("```", 2)
        inner = parts[1] if len(parts) > 1 else ""
        if inner.startswith("json"):
            inner = inner[4:]
        stripped = inner.rsplit("```", 1)[0].strip()

    # Try direct parse
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # Find first { and last } to extract embedded JSON object
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(stripped[start:end + 1])
        except json.JSONDecodeError:
            pass

    # Truncated JSON recovery: response was cut off by max_tokens.
    # Progressively trim from the end until we find parseable JSON.
    if start != -1:
        fragment = stripped[start:]
        for cut in range(len(fragment) - 1, max(len(fragment) // 3, 20), -1):
            ch = fragment[cut]
            if ch not in (',', ':', '"', ' ', '\n', '\r', '\t'):
                continue
            candidate = fragment[:cut].rstrip(', \t\n\r:')
            open_b = candidate.count("[") - candidate.count("]")
            open_c = candidate.count("{") - candidate.count("}")
            if open_c <= 0:
                continue
            patched = candidate + "]" * max(open_b, 0) + "}" * max(open_c, 0)
            try:
                result = json.loads(patched)
                logger.info("Recovered truncated JSON (trimmed %d chars)", len(fragment) - cut)
                return result
            except json.JSONDecodeError:
                continue

    return None


class _RateLimited(Exception):
    """Raised when a key hits its daily quota — triggers rotation to next key."""
    pass


class _UpstreamBusy(Exception):
    """Raised when the upstream model provider is temporarily overloaded (not a key issue)."""
    pass


def _parse_429(resp, key_label) -> tuple:
    """Parse a 429 response and determine if it's a daily quota issue or temporary upstream."""
    resets_at = None
    err_msg = f"Rate limit (429) key={key_label}"
    is_daily_quota = False

    try:
        err_body = resp.json()
        raw_err = err_body.get("error", {})
        err_msg = raw_err.get("message", err_msg)
        metadata = raw_err.get("metadata", {})

        meta_hdrs = metadata.get("headers", {})
        remaining = meta_hdrs.get("X-RateLimit-Remaining")
        reset_ms = int(meta_hdrs.get("X-RateLimit-Reset", 0))
        if reset_ms > 0:
            resets_at = _dt.fromtimestamp(reset_ms / 1000, tz=_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if remaining is not None and int(remaining) <= 0 and reset_ms > 0:
            is_daily_quota = True

        raw_msg = metadata.get("raw", "")
        if "temporarily rate-limited upstream" in raw_msg or "temporarily rate-limited upstream" in err_msg:
            is_daily_quota = False
        elif "daily" in err_msg.lower() or "quota" in err_msg.lower():
            is_daily_quota = True
    except Exception:
        pass

    return err_msg, resets_at, is_daily_quota


def _call_one_model(api_key: str, key_idx: int, model: str,
                     system_prompt: str, user_content: str) -> dict | None:
    """
    Single OpenRouter call with a specific key + model.
    Raises _RateLimited on daily quota 429 (key should be rotated).
    Raises _UpstreamBusy on temporary upstream 429 (model provider overloaded, same key is fine).
    """
    req_headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://api-secure.app",
        "X-Title": "API Secure Scanner",
    }
    combined_user = f"{system_prompt}\n\n---\n\n{user_content}"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": combined_user}],
        "temperature": 0.1,
        "max_tokens": _MAX_TOKENS,
    }
    key_label = f"...{api_key[-4:]}" if len(api_key) > 4 else api_key
    try:
        logger.info("OpenRouter call → key=%s model=%s", key_label, model)
        resp = requests.post(OPENROUTER_BASE_URL, json=payload, headers=req_headers,
                             timeout=_TIMEOUT, verify=False)

        if resp.status_code == 429:
            err_msg, resets_at, is_daily_quota = _parse_429(resp, key_label)
            _record_call(key_idx, False, rate_limited=True, error=err_msg)

            if is_daily_quota:
                _rotate_key(key_idx, resets_at)
                logger.warning("Key %s daily quota exhausted, rotating", key_label)
                raise _RateLimited(key_label)
            else:
                logger.warning("Upstream temp 429 on model=%s key=%s: %s", model, key_label, err_msg)
                raise _UpstreamBusy(err_msg)

        if resp.status_code in (400, 404, 422, 500, 503):
            logger.warning("OpenRouter HTTP %s key=%s model=%s: %.200s",
                           resp.status_code, key_label, model, resp.text)
            _record_call(key_idx, False, error=f"HTTP {resp.status_code}")
            return None

        resp.raise_for_status()
        data = resp.json()

        if "error" in data:
            err_msg = str(data["error"])
            is_rl = "rate" in err_msg.lower() or "429" in err_msg
            _record_call(key_idx, False, rate_limited=is_rl, error=err_msg)
            if is_rl:
                _rotate_key(key_idx)
                raise _RateLimited(key_label)
            return None

        raw_content = data.get("choices", [{}])[0].get("message", {}).get("content", "") or ""
        content = raw_content.strip()
        if not content:
            _record_call(key_idx, False, error="Empty content")
            return None

        result = _extract_json(content)
        if not result:
            logger.warning("Non-JSON from model %s: %.200s", model, content)
            _record_call(key_idx, False, error="Non-JSON response")
            return None

        _record_call(key_idx, True)
        logger.info("OpenRouter SUCCESS key=%s model=%s", key_label, model)
        return result

    except (_RateLimited, _UpstreamBusy):
        raise
    except requests.exceptions.Timeout:
        _record_call(key_idx, False, error=f"Timeout ({_TIMEOUT}s)")
        logger.warning("Timeout key=%s model=%s", key_label, model)
        return None
    except requests.RequestException as e:
        _record_call(key_idx, False, error=str(e))
        return None
    except Exception as e:
        _record_call(key_idx, False, error=str(e))
        return None


def _call_openrouter(system_prompt: str, user_content: str) -> dict | None:
    """
    Try the configured model (typically openrouter/free which auto-routes).
    On daily-quota 429, rotate keys. On upstream-busy 429 or timeout, wait
    briefly and retry (openrouter/free routes to a different model each time).
    Up to _MAX_ATTEMPTS total tries before giving up.
    """
    if not AI_ENABLED:
        return None

    model = OPENROUTER_MODEL
    max_key_rotations = len(OPENROUTER_API_KEYS)
    max_attempts = 3  # total attempts (timeout/upstream retries)
    attempt = 0

    while attempt < max_attempts:
        key_rotations = 0
        while key_rotations < max_key_rotations:
            api_key, key_idx = _get_active_key()
            if api_key is None:
                logger.warning("All API keys exhausted — no AI result")
                return None
            try:
                result = _call_one_model(api_key, key_idx, model, system_prompt, user_content)
                if result:
                    return result
                # Non-429 failure (timeout, bad response, etc) — retry with backoff
                attempt += 1
                if attempt < max_attempts:
                    wait = _TEMP_BACKOFF * attempt
                    logger.info("Attempt %d/%d failed, retrying in %ds", attempt, max_attempts, wait)
                    time.sleep(wait)
                break  # break inner loop to retry outer

            except _RateLimited:
                key_rotations += 1
                logger.info("Key rotated (%d/%d), retrying model %s",
                            key_rotations, max_key_rotations, model)

            except _UpstreamBusy:
                attempt += 1
                if attempt < max_attempts:
                    logger.info("Upstream busy (attempt %d/%d), waiting %ds before retry",
                                attempt, max_attempts, _TEMP_BACKOFF)
                    time.sleep(_TEMP_BACKOFF)
                break  # break inner key loop to retry
        else:
            break  # all keys exhausted in inner loop

    logger.warning("All attempts exhausted — no AI result")
    return None


# ── Prompt 1: HTTP Header Security Analysis ──────────────────────────────────

_HEADERS_SYSTEM = """You are a senior cybersecurity consultant writing a professional security audit report for a CLIENT who may NOT be technical. You MUST respond with ONLY a raw JSON object — no prose, no markdown fences, nothing else. Start with { and end with }.

Use this EXACT JSON structure:

{
  "executiveSummary": "A 4-6 sentence professional paragraph written for a non-technical executive. Explain in plain English: (1) how well-protected this website/API currently is, (2) what the main security gaps are and what real-world attacks they enable (use everyday language like 'hackers could trick users' not 'XSS vector'), (3) the business risk (data theft, reputation damage, regulatory fines), and (4) the top 2-3 actions to take first. Be specific to this domain — never generic.",
  "overallRisk": "Critical|High|Medium|Low|Good",
  "riskExplanation": "One sentence explaining the risk level in plain English, e.g. 'wYour API has several important security protections missing, leaving it vulnerable to common attacks.'",
  "headers": [
    {
      "name": "Header-Name",
      "present": true,
      "value": "actual-value-or-null",
      "severity": "critical|warning|ok",
      "whatItDoes": "One sentence in simple English explaining what this security setting protects against. Write for someone who is not a developer. Example: 'This setting tells browsers to only connect to your site over secure (encrypted) connections, preventing eavesdropping.'",
      "status": "Plain English status. If ok: 'Properly configured and protecting your site.' If warning: explain the weakness simply. If critical/missing: 'Not configured — your site is missing this protection.'",
      "risk": "If not ok: explain in plain English what could go wrong. Use concrete scenarios like 'An attacker could embed your website inside a fake page to steal user clicks and passwords.' If ok: 'No immediate risk — this protection is active.'",
      "fix": "If not ok: one clear actionable sentence for a developer, with the exact header value to add. If ok: 'No action needed.'"
    }
  ],
  "topRecommendations": [
    {
      "priority": 1,
      "header": "Header-Name",
      "action": "Clear one-sentence instruction a developer can act on immediately",
      "why": "One sentence explaining the business benefit of this fix in plain English",
      "exampleValue": "exact-header-value-to-copy"
    }
  ],
  "summary": {
    "criticalCount": 0,
    "warningCount": 0,
    "okCount": 0,
    "totalHeaders": 10
  }
}

RULES:
- Analyze exactly these 10 headers: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection, Cross-Origin-Embedder-Policy, Cross-Origin-Opener-Policy, X-Permitted-Cross-Domain-Policies.
- Missing header → severity "critical". Weak/partial config → severity "warning". Correct → severity "ok".
- ALL descriptions must be understandable by a non-technical person. Never use jargon like "XSS", "MIME sniffing", "CORS" without explaining what it means in the same sentence.
- topRecommendations: only critical/warning items, sorted by priority (most dangerous first), max 5.
- Return ONLY valid JSON. No text outside the JSON object."""


def analyze_headers(evaluated_headers: dict, target_domain: str,
                    force_refresh: bool = False) -> dict | None:
    """
    Call OpenRouter to get AI-enriched header analysis.
    Checks the domain cache first — returns cached result if available and fresh.
    Returns dict with keys: aiHeaders, aiSummary, aiExecutiveSummary, aiOverallRisk,
                            aiTopRecs, aiHeaderNotes, aiRiskExplanation, aiSource.
    Returns None if AI is disabled or call fails.
    """
    if not AI_ENABLED:
        return None

    # Check cache first (skip if force_refresh)
    if not force_refresh:
        cached = _cache_get(target_domain)
        if cached:
            return {**cached, "aiSource": "cache"}

    # Format headers for the prompt
    lines = [f"Target domain: {target_domain}", ""]
    for name, info in (evaluated_headers or {}).items():
        present = info.get("present", False)
        value = info.get("value") or "Not Set"
        lines.append(f"{name}: {'Present' if present else 'Missing'} | Value: {value}")
    formatted = "\n".join(lines)

    result = _call_openrouter(_HEADERS_SYSTEM, formatted)
    if not result:
        logger.warning("analyze_headers: OpenRouter returned no result for domain=%s", target_domain)
        return None

    summary = result.get("summary") or {}
    ai_headers = result.get("headers") or []
    executive_summary = result.get("executiveSummary") or ""
    overall_risk = result.get("overallRisk") or ""
    risk_explanation = result.get("riskExplanation") or ""
    top_recs = result.get("topRecommendations") or []

    critical_items = [h for h in ai_headers if h.get("severity") == "critical"]
    warning_items = [h for h in ai_headers if h.get("severity") == "warning"]
    ok_items = [h for h in ai_headers if h.get("severity") == "ok"]
    notes_lines = [f"AI Security Analysis — {target_domain}", ""]
    if executive_summary:
        notes_lines.append(executive_summary)
        notes_lines.append("")
    if critical_items:
        notes_lines.append(f"CRITICAL ({len(critical_items)} headers): " + ", ".join(h.get("name","") for h in critical_items))
    if warning_items:
        notes_lines.append(f"WARNINGS ({len(warning_items)} headers): " + ", ".join(h.get("name","") for h in warning_items))
    if ok_items:
        notes_lines.append(f"PASSED ({len(ok_items)} headers): " + ", ".join(h.get("name","") for h in ok_items))

    output = {
        "aiHeaders": ai_headers,
        "aiSummary": summary,
        "aiExecutiveSummary": executive_summary,
        "aiOverallRisk": overall_risk,
        "aiRiskExplanation": risk_explanation,
        "aiTopRecs": top_recs,
        "aiHeaderNotes": "\n".join(notes_lines),
        "aiSource": "llm",
    }
    # Store in cache for next 24h
    _cache_set(target_domain, output)
    return output


# ── Prompt 2: HTML Content Security Analysis ─────────────────────────────────

_CONTENT_SYSTEM = """You are a cybersecurity expert. You MUST respond with ONLY a raw JSON object — no prose, no markdown, no explanation, nothing else. Start your response with { and end with }. Analyze the HTML content for vulnerabilities using this JSON structure:

{
  "contentAnalysis": {
    "criticalVulnerabilities": [
      {
        "title": "Issue name",
        "description": "What the issue is",
        "impact": "Potential damage",
        "recommendation": "How to fix"
      }
    ],
    "informationLeakage": [],
    "clientSideWeaknesses": []
  },
  "summary": "Brief 2-3 sentence summary of main security concerns found in the content."
}

Look for:
- Inline scripts without CSP
- Exposed sensitive data
- Unsafe JavaScript practices
- Missing security attributes

Return ONLY the JSON, no explanations."""


def analyze_content(html_content: str) -> dict | None:
    """
    Call OpenRouter with Prompt 2 to analyse HTML content for vulnerabilities.
    Returns dict with keys: contentAnalysis (dict), summary (str), aiContentNotes (str).
    Returns None if AI is disabled or call fails.
    """
    if not AI_ENABLED:
        return None

    # Truncate very long HTML — model context limit
    truncated = html_content[:8000] if html_content and len(html_content) > 8000 else (html_content or "")
    if not truncated.strip():
        return None

    result = _call_openrouter(_CONTENT_SYSTEM, truncated)
    if not result:
        return None

    content_analysis = result.get("contentAnalysis") or {}
    summary = result.get("summary") or ""

    # Build plain-text notes
    critical = content_analysis.get("criticalVulnerabilities") or []
    leakage = content_analysis.get("informationLeakage") or []
    weaknesses = content_analysis.get("clientSideWeaknesses") or []
    notes_lines = ["AI Content Security Analysis:", ""]
    if critical:
        notes_lines.append(f"Critical Vulnerabilities ({len(critical)}):")
        for v in critical:
            notes_lines.append(f"  • {v.get('title','')}: {v.get('description','')}")
        notes_lines.append("")
    if leakage:
        notes_lines.append(f"Information Leakage ({len(leakage)}):")
        for v in leakage:
            notes_lines.append(f"  • {v.get('title', str(v))}")
        notes_lines.append("")
    if weaknesses:
        notes_lines.append(f"Client-Side Weaknesses ({len(weaknesses)}):")
        for v in weaknesses:
            notes_lines.append(f"  • {v.get('title', str(v))}")
        notes_lines.append("")
    if summary:
        notes_lines.append("Summary:")
        notes_lines.append(summary)

    return {
        "contentAnalysis": content_analysis,
        "aiSummary": summary,
        "aiContentNotes": "\n".join(notes_lines),
    }
