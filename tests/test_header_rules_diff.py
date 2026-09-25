"""
Behavioral-equivalence test for the YAML-driven HTTP header rules refactor.

For every finding the scanner can emit, this test hand-crafts a header value
that triggers it and asserts that the resulting finding dict matches a
literal snapshot taken from the original (pre-refactor) scanner.py.

If anyone edits a YAML rule and accidentally changes its behavior, this test
fails immediately and points at the rule that drifted.

Run from the Main Project dir:
    python3 -m pytest tests/test_header_rules_diff.py -v
or just:
    python3 tests/test_header_rules_diff.py
"""
from __future__ import annotations

import os
import sys
import unittest

# Make scanner.py importable when running directly
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

import scanner  # noqa: E402


def _find(findings: list, finding_id: str) -> dict:
    """Locate a finding by id; fail clearly if missing."""
    for f in findings:
        if f.get("id") == finding_id:
            return f
    raise AssertionError(
        f"Expected finding id {finding_id!r} not in findings: "
        f"{[x.get('id') for x in findings]}"
    )


class CSPRules(unittest.TestCase):
    def test_csp_empty_returns_single_critical(self):
        out = scanner._deep_analyze_csp("")
        self.assertEqual(out, [{
            "id": "csp-empty",
            "severity": "critical",
            "title": "Empty CSP",
            "detail": "The Content-Security-Policy header is present but empty, providing no protection.",
            "deduction": 10,
        }])

    def test_csp_no_default_src(self):
        f = _find(scanner._deep_analyze_csp("script-src 'self'"), "csp-no-default-src")
        self.assertEqual(f, {
            "id": "csp-no-default-src",
            "severity": "medium",
            "title": "Missing default-src directive",
            "detail": (
                "Without default-src, any directive you haven't explicitly set has no "
                "fallback restriction — the browser allows loading from anywhere for those "
                "resource types."
            ),
            "deduction": 3,
        })

    def test_csp_unsafe_inline(self):
        f = _find(scanner._deep_analyze_csp("default-src 'self'; script-src 'unsafe-inline'"), "csp-unsafe-inline")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["title"], "'unsafe-inline' in script-src")
        self.assertEqual(f["deduction"], 5)
        self.assertIn("Allows inline <script> tags to execute", f["detail"])

    def test_csp_unsafe_eval(self):
        f = _find(scanner._deep_analyze_csp("default-src 'self'; script-src 'unsafe-eval'"), "csp-unsafe-eval")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["deduction"], 5)

    def test_csp_unsafe_hashes(self):
        f = _find(scanner._deep_analyze_csp("default-src 'self'; script-src 'unsafe-hashes'"), "csp-unsafe-hashes")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["deduction"], 2)

    def test_csp_blob_script(self):
        f = _find(scanner._deep_analyze_csp("default-src 'self'; script-src blob:"), "csp-blob-script")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["deduction"], 2)

    def test_csp_data_script(self):
        f = _find(scanner._deep_analyze_csp("default-src 'self'; script-src data:"), "csp-data-script")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["deduction"], 4)

    def test_csp_http_dynamic_id(self):
        # Original code emits id "csp-http-{directive_name}" with the http source truncated to 50 chars
        f = _find(
            scanner._deep_analyze_csp("default-src 'self'; connect-src http://evil.example.com"),
            "csp-http-connect-src",
        )
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["deduction"], 2)
        self.assertEqual(f["title"], "http: source in connect-src")
        self.assertIn("http://evil.example.com", f["detail"])
        self.assertIn("man-in-the-middle", f["detail"])

    def test_csp_http_breaks_after_first(self):
        # Original loops and breaks on first directive with http: source
        out = scanner._deep_analyze_csp(
            "default-src 'self'; connect-src http://a.example; img-src http://b.example"
        )
        http_findings = [f for f in out if f["id"].startswith("csp-http-")]
        self.assertEqual(len(http_findings), 1, "expected exactly one csp-http-* finding")

    def test_csp_wildcard_aggregates(self):
        # Three wildcards → directives_display has all three; no "(+N more)" suffix
        f = _find(
            scanner._deep_analyze_csp("default-src *; script-src *; img-src *"),
            "csp-wildcard",
        )
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["deduction"], 4)
        self.assertEqual(f["title"], "Wildcard '*' in default-src, script-src, img-src")

    def test_csp_wildcard_more_than_three(self):
        # Five wildcard directives → title shows first three + "(+2 more)"
        val = "default-src *; script-src *; img-src *; style-src *; font-src *"
        f = _find(scanner._deep_analyze_csp(val), "csp-wildcard")
        self.assertEqual(f["title"], "Wildcard '*' in default-src, script-src, img-src (+2 more)")
        # detail lists all five
        self.assertIn("default-src, script-src, img-src, style-src, font-src", f["detail"])

    def test_csp_data_img(self):
        f = _find(scanner._deep_analyze_csp("default-src 'self'; img-src data:"), "csp-data-img")
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["deduction"], 0)

    def test_csp_data_font(self):
        f = _find(scanner._deep_analyze_csp("default-src 'self'; font-src data:"), "csp-data-font")
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["deduction"], 0)

    def test_csp_data_connect(self):
        f = _find(scanner._deep_analyze_csp("default-src 'self'; connect-src data:"), "csp-data-connect")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["deduction"], 2)

    def test_csp_missing_directives(self):
        # default-src 'self' fires several "missing X" findings
        out = scanner._deep_analyze_csp("default-src 'self'")
        ids = {f["id"] for f in out}
        for expected in (
            "csp-no-base-uri",
            "csp-no-object-src",
            "csp-no-form-action",
            "csp-no-frame-ancestors",
            "csp-no-upgrade-insecure",
        ):
            self.assertIn(expected, ids)

    def test_csp_object_src_suppressed_by_default_src_none(self):
        # If default-src includes 'none', csp-no-object-src should NOT fire
        out = scanner._deep_analyze_csp("default-src 'none'")
        ids = {f["id"] for f in out}
        self.assertNotIn("csp-no-object-src", ids)

    def test_csp_unsafe_inline_style(self):
        f = _find(
            scanner._deep_analyze_csp("default-src 'self'; style-src 'unsafe-inline'"),
            "csp-unsafe-inline-style",
        )
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["deduction"], 1)

    def test_csp_deprecated_report_uri(self):
        out = scanner._deep_analyze_csp("default-src 'self'; report-uri /csp-report")
        f = _find(out, "csp-deprecated-report-uri")
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["deduction"], 0)

    def test_csp_report_uri_not_deprecated_when_report_to_also_set(self):
        out = scanner._deep_analyze_csp(
            "default-src 'self'; report-uri /csp-report; report-to default"
        )
        ids = {f["id"] for f in out}
        self.assertNotIn("csp-deprecated-report-uri", ids)


class HSTSRules(unittest.TestCase):
    def test_hsts_empty(self):
        self.assertEqual(scanner._deep_analyze_hsts(""), [{
            "id": "hsts-empty",
            "severity": "critical",
            "title": "Empty HSTS",
            "detail": "The HSTS header is present but empty.",
            "deduction": 10,
        }])

    def test_hsts_no_max_age_returns_early(self):
        out = scanner._deep_analyze_hsts("includeSubDomains; preload")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "hsts-no-max-age")
        self.assertEqual(out[0]["severity"], "high")
        self.assertEqual(out[0]["deduction"], 8)

    def test_hsts_max_age_zero(self):
        f = _find(scanner._deep_analyze_hsts("max-age=0"), "hsts-max-age-zero")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["deduction"], 8)

    def test_hsts_max_age_short(self):
        # 1 day = 86400
        f = _find(scanner._deep_analyze_hsts("max-age=86400"), "hsts-max-age-short")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["deduction"], 3)
        self.assertEqual(f["title"], "max-age too short (86400s = 1d)")
        self.assertIn("Current max-age is 86400 seconds (1 days)", f["detail"])

    def test_hsts_max_age_moderate(self):
        # Between 30 days (2592000) and 365 days (31536000)
        f = _find(scanner._deep_analyze_hsts("max-age=5000000"), "hsts-max-age-moderate")
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["deduction"], 1)
        # 5000000 // 86400 = 57 days
        self.assertEqual(f["title"], "max-age below best practice (5000000s = 57d)")

    def test_hsts_no_subdomains(self):
        f = _find(scanner._deep_analyze_hsts("max-age=31536000"), "hsts-no-subdomains")
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["deduction"], 1)

    def test_hsts_no_preload(self):
        f = _find(scanner._deep_analyze_hsts("max-age=31536000"), "hsts-no-preload")
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["deduction"], 0)


class XFrameOptionsRules(unittest.TestCase):
    def test_empty_returns_empty(self):
        self.assertEqual(scanner._deep_analyze_x_frame_options(""), [])

    def test_allow_from(self):
        f = _find(
            scanner._deep_analyze_x_frame_options("ALLOW-FROM https://example.com"),
            "xfo-allow-from",
        )
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["deduction"], 3)

    def test_sameorigin(self):
        f = _find(scanner._deep_analyze_x_frame_options("SAMEORIGIN"), "xfo-sameorigin")
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["deduction"], 0)

    def test_invalid(self):
        f = _find(scanner._deep_analyze_x_frame_options("GARBAGE"), "xfo-invalid")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["deduction"], 3)
        self.assertEqual(f["title"], "Non-standard value: GARBAGE")

    def test_deny_is_clean(self):
        self.assertEqual(scanner._deep_analyze_x_frame_options("DENY"), [])


class ReferrerPolicyRules(unittest.TestCase):
    def test_duplicate(self):
        f = _find(scanner._deep_analyze_referrer_policy("no-referrer, no-referrer"), "rp-duplicate")
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["deduction"], 1)
        self.assertIn("no-referrer, no-referrer", f["detail"])

    def test_invalid(self):
        f = _find(scanner._deep_analyze_referrer_policy("banana"), "rp-invalid")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["deduction"], 2)
        self.assertEqual(f["title"], "Invalid Referrer-Policy value: banana")

    def test_unsafe_url(self):
        f = _find(scanner._deep_analyze_referrer_policy("unsafe-url"), "rp-unsafe-url")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["deduction"], 5)

    def test_downgrade(self):
        f = _find(scanner._deep_analyze_referrer_policy("no-referrer-when-downgrade"), "rp-downgrade")
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["deduction"], 1)

    def test_origin_only(self):
        f = _find(scanner._deep_analyze_referrer_policy("origin"), "rp-origin-only")
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["deduction"], 0)
        self.assertEqual(f["title"], "Referrer-Policy: origin")


class XXSSProtectionRules(unittest.TestCase):
    def test_disabled(self):
        f = _find(scanner._deep_analyze_x_xss_protection("0"), "xxss-disabled")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["deduction"], 2)

    def test_no_block(self):
        f = _find(scanner._deep_analyze_x_xss_protection("1"), "xxss-no-block")
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["deduction"], 1)

    def test_proper_value_is_clean(self):
        self.assertEqual(scanner._deep_analyze_x_xss_protection("1; mode=block"), [])


class PermissionsPolicyRules(unittest.TestCase):
    def test_permissive_camera(self):
        out = scanner._deep_analyze_permissions_policy("camera=*")
        f = _find(out, "pp-permissive-camera")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["deduction"], 2)
        self.assertEqual(f["title"], "camera allowed for all origins")
        self.assertIn("camera access", f["detail"])

    def test_self_camera(self):
        out = scanner._deep_analyze_permissions_policy("camera=(self)")
        f = _find(out, "pp-self-camera")
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["deduction"], 0)

    def test_floc_block_missing(self):
        f = _find(scanner._deep_analyze_permissions_policy("camera=(self)"), "pp-no-floc-block")
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["deduction"], 0)

    def test_floc_block_suppressed_when_interest_cohort_blocked(self):
        out = scanner._deep_analyze_permissions_policy("interest-cohort=()")
        ids = {f["id"] for f in out}
        self.assertNotIn("pp-no-floc-block", ids)


class COEPCOOPRules(unittest.TestCase):
    def test_coep_unsafe_none(self):
        f = _find(scanner._deep_analyze_coep("unsafe-none"), "coep-unsafe-none")
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["deduction"], 1)

    def test_coop_unsafe_none(self):
        f = _find(scanner._deep_analyze_coop("unsafe-none"), "coop-unsafe-none")
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["deduction"], 1)

    def test_coop_allow_popups(self):
        f = _find(scanner._deep_analyze_coop("same-origin-allow-popups"), "coop-allow-popups")
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["deduction"], 0)


class XContentTypeOptionsRules(unittest.TestCase):
    def test_invalid(self):
        f = _find(scanner._deep_analyze_x_content_type_options("sniff"), "xcto-invalid")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["deduction"], 3)
        self.assertEqual(f["title"], "Non-standard value: sniff")

    def test_nosniff_is_clean(self):
        self.assertEqual(scanner._deep_analyze_x_content_type_options("nosniff"), [])


class XPermittedCrossDomainRules(unittest.TestCase):
    def test_permissive_all(self):
        f = _find(scanner._deep_analyze_x_permitted_cross_domain("all"), "xpcd-permissive")
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["deduction"], 1)
        self.assertEqual(f["title"], "Permissive value: all")

    def test_none_is_clean(self):
        self.assertEqual(scanner._deep_analyze_x_permitted_cross_domain("none"), [])


class ServerDisclosure(unittest.TestCase):
    def _headers(self, **kw):
        # _detect_server_disclosure expects normalized (lowercased) keys
        return {k.lower(): v for k, v in kw.items()}

    def test_server_with_version(self):
        f = _find(
            scanner._detect_server_disclosure(self._headers(Server="nginx/1.18.0")),
            "server-version-disclosure",
        )
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["title"], "Server header discloses version: nginx/1.18.0")
        self.assertNotIn("deduction", f)  # server disclosure findings have no deduction

    def test_server_without_version(self):
        f = _find(
            scanner._detect_server_disclosure(self._headers(Server="nginx")),
            "server-name-disclosure",
        )
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["title"], "Server header: nginx")

    def test_deprecated_expect_ct(self):
        out = scanner._detect_server_disclosure(self._headers(**{"Expect-CT": "max-age=86400"}))
        f = _find(out, "deprecated-expect-ct")
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["title"], "Deprecated Expect-CT header present")

    def test_deprecated_x_powered_by_includes_value_prefix(self):
        out = scanner._detect_server_disclosure(self._headers(**{"X-Powered-By": "Express"}))
        f = _find(out, "deprecated-x-powered-by")
        self.assertEqual(f["severity"], "medium")
        self.assertTrue(f["detail"].startswith("Value: Express. "))

    def test_info_leak_via_header_appends_value(self):
        out = scanner._detect_server_disclosure(self._headers(Via="1.1 proxy.internal"))
        f = _find(out, "info-leak-via")
        self.assertIn("(1.1 proxy.internal)", f["title"])

    def test_internal_ip_in_header(self):
        out = scanner._detect_server_disclosure(self._headers(**{"X-Server-IP": "10.0.0.5"}))
        f = _find(out, "internal-ip-x-server-ip")
        self.assertEqual(f["severity"], "medium")
        self.assertIn("10.0.0.5", f["title"])

    def test_version_in_non_standard_header(self):
        out = scanner._detect_server_disclosure(self._headers(**{"X-Custom-Stack": "myapp/2.3.4"}))
        f = _find(out, "version-x-custom-stack")
        self.assertEqual(f["severity"], "low")
        self.assertIn("2.3.4", f["title"])

    def test_missing_corp(self):
        f = _find(scanner._detect_server_disclosure({}), "missing-corp")
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["title"], "Missing Cross-Origin-Resource-Policy (CORP)")

    def test_cache_api_no_store_with_cache_header(self):
        out = scanner._detect_server_disclosure(self._headers(**{
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=60",
        }))
        f = _find(out, "cache-api-no-store")
        self.assertIn("'public, max-age=60'", f["detail"])

    def test_cache_api_no_store_without_cache_header(self):
        out = scanner._detect_server_disclosure(self._headers(**{"Content-Type": "application/json"}))
        f = _find(out, "cache-api-no-store")
        self.assertIn("no Cache-Control header set", f["detail"])


class FullPipelineSmoke(unittest.TestCase):
    """End-to-end: build_evaluated_headers + scoring math still produce expected shape."""

    def test_evaluated_headers_shape(self):
        headers = {
            "content-security-policy": "default-src 'none'; base-uri 'none'; "
                                       "object-src 'none'; form-action 'none'; "
                                       "frame-ancestors 'none'; upgrade-insecure-requests",
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "interest-cohort=()",
            "x-xss-protection": "1; mode=block",
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-opener-policy": "same-origin",
            "x-permitted-cross-domain-policies": "none",
        }
        out = scanner.build_evaluated_headers(headers)
        self.assertEqual(set(out.keys()), set(scanner.REQUIRED_HEADERS))
        for name, info in out.items():
            self.assertTrue(info["present"], f"{name} should be present")
            self.assertEqual(info["severity"], "ok", f"{name} should be ok, got {info}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
