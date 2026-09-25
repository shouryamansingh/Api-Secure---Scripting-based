"""
Loader for the YAML-defined HTTP header analysis rules.

Loads files from security-controls/http-header-analysis/ once at import time
and exposes:

  REQUIRED_HEADERS:        list[str]
  DEPRECATED_HEADERS:      dict[header_name, {severity, title, detail}]
  INFO_LEAK_HEADERS:       dict[header_name, {severity, title, detail}]
  PP_SENSITIVE_FEATURES:   dict[feature, description]
  FINDINGS:                dict[finding_id, template]
  make_finding(id, **ctx): build a finding dict from a template, formatting
                           any {placeholder}s in title/detail using ctx and
                           respecting ctx['id_override'] when supplied.
  LOADED:                  True if YAML files were loaded successfully, False
                           if PyYAML or the files were missing (in which case
                           the constants above are empty dicts/lists).

The module never raises on import: if anything goes wrong (PyYAML missing,
files missing, parse error) the constants stay empty and LOADED is False.
scanner.py is expected to check LOADED and fall back to inline defaults.
"""
from __future__ import annotations

import os
from typing import Any

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_RULES_DIR = os.path.join(_THIS_DIR, "security-controls", "http-header-analysis")

REQUIRED_HEADERS: list[str] = []
DEPRECATED_HEADERS: dict[str, dict[str, Any]] = {}
INFO_LEAK_HEADERS: dict[str, dict[str, Any]] = {}
PP_SENSITIVE_FEATURES: dict[str, str] = {}
FINDINGS: dict[str, dict[str, Any]] = {}
LOADED: bool = False
LOAD_ERROR: str | None = None


def _load_yaml(path: str):
    import yaml  # type: ignore[import-not-found]
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


try:
    headers_doc = _load_yaml(os.path.join(_RULES_DIR, "headers.yaml")) or {}
    findings_doc = _load_yaml(os.path.join(_RULES_DIR, "findings.yaml")) or {}
    deprecated_doc = _load_yaml(os.path.join(_RULES_DIR, "deprecated-headers.yaml")) or {}
    info_leak_doc = _load_yaml(os.path.join(_RULES_DIR, "info-leak-headers.yaml")) or {}
    pp_doc = _load_yaml(os.path.join(_RULES_DIR, "permissions-policy-features.yaml")) or {}

    REQUIRED_HEADERS = list(headers_doc.get("required_headers") or [])
    DEPRECATED_HEADERS = dict(deprecated_doc)
    INFO_LEAK_HEADERS = dict(info_leak_doc)
    PP_SENSITIVE_FEATURES = dict(pp_doc)
    FINDINGS = dict(findings_doc)

    if REQUIRED_HEADERS and FINDINGS:
        LOADED = True
    else:
        LOAD_ERROR = "YAML files loaded but required content missing"
except ModuleNotFoundError as e:
    LOAD_ERROR = f"PyYAML not installed: {e}"
except FileNotFoundError as e:
    LOAD_ERROR = f"rule file missing: {e}"
except Exception as e:  # noqa: BLE001 — defensive at import time
    LOAD_ERROR = f"failed to load YAML rules: {e}"


def make_finding(finding_id: str, **ctx: Any) -> dict[str, Any]:
    """Build a finding dict from a YAML template.

    The template is looked up by ``finding_id``. The returned dict has the
    same keys as the template (with id added/overridden). String values are
    formatted with ``ctx`` (using ``str.format``); other values pass through.

    ctx may include ``id_override`` to set a dynamic id (e.g.
    ``"csp-http-script-src"``); the id key in the template (if any) is
    ignored.

    If the template is missing, returns a defensive placeholder rather than
    raising — this should not happen in production but keeps the scanner
    alive if the YAML is mistakenly truncated.
    """
    template = FINDINGS.get(finding_id)
    if template is None:
        return {
            "id": ctx.get("id_override", finding_id),
            "severity": "info",
            "title": f"(missing finding template: {finding_id})",
            "detail": "",
        }

    out: dict[str, Any] = {"id": ctx.get("id_override", finding_id)}
    for key, value in template.items():
        if key == "id":
            continue
        if isinstance(value, str) and ctx:
            try:
                out[key] = value.format(**ctx)
            except (KeyError, IndexError):
                out[key] = value
        else:
            out[key] = value
    return out
