"""
tests/test_web_hardening.py
Checks de durcissement web passifs (services/web_hardening.py) — `_check_headers`/
`_check_cookies` sont des fonctions pures sur un `httpx.Headers` déjà construit, aucune
requête réseau réelle nécessaire pour les tester (contrairement à `_check_tls`/`check_website`,
volontairement hors périmètre ici — vrai socket TCP/TLS, cf. STATUS.md pour la vérification en
conditions réelles déjà faite contre example.com/github.com).
"""

import httpx

from services.web_hardening import _check_cookies, _check_headers


class TestCheckHeaders:
    def test_all_headers_missing(self):
        checks = _check_headers(httpx.Headers({}))
        assert len(checks) == 5
        assert all(c["status"] == "warn" for c in checks)

    def test_all_headers_present(self):
        headers = httpx.Headers({
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        })
        checks = _check_headers(headers)
        assert all(c["status"] == "ok" for c in checks)

    def test_frame_ancestors_in_csp_covers_missing_x_frame_options(self):
        # X-Frame-Options absent mais la CSP porte frame-ancestors — même rôle
        # (anti-clickjacking), ne doit pas doublement avertir.
        headers = httpx.Headers({"Content-Security-Policy": "frame-ancestors 'self'"})
        checks = _check_headers(headers)
        xfo = next(c for c in checks if c["id"] == "x_frame_options")
        assert xfo["status"] == "ok"
        assert "frame-ancestors" in xfo["detail"]

    def test_csp_without_frame_ancestors_still_warns_on_missing_x_frame_options(self):
        headers = httpx.Headers({"Content-Security-Policy": "default-src 'self'"})
        checks = _check_headers(headers)
        xfo = next(c for c in checks if c["id"] == "x_frame_options")
        assert xfo["status"] == "warn"

    def test_header_value_truncated_in_detail(self):
        long_csp = "default-src " + "'self' " * 50
        headers = httpx.Headers({"Content-Security-Policy": long_csp})
        checks = _check_headers(headers)
        csp = next(c for c in checks if c["id"] == "csp")
        assert len(csp["detail"]) <= len("Présent : ") + 120


class TestCheckCookies:
    def test_no_set_cookie_header_returns_none(self):
        assert _check_cookies(httpx.Headers({})) is None

    def test_cookie_missing_both_flags_warns(self):
        headers = httpx.Headers([("set-cookie", "session=abc123; Path=/")])
        result = _check_cookies(headers)
        assert result["status"] == "warn"
        assert "session" in result["detail"]
        assert "secure" in result["detail"]
        assert "httponly" in result["detail"]

    def test_cookie_with_both_flags_ok(self):
        headers = httpx.Headers([("set-cookie", "session=abc123; Secure; HttpOnly; SameSite=Strict")])
        result = _check_cookies(headers)
        assert result["status"] == "ok"

    def test_cookie_missing_only_httponly_reported(self):
        # Cas réel rencontré en conditions réelles contre github.com (cf. STATUS.md 17/08/2026) —
        # cookie _octo Secure mais sans HttpOnly, correctement détecté.
        headers = httpx.Headers([("set-cookie", "_octo=xyz; Secure; Path=/")])
        result = _check_cookies(headers)
        assert result["status"] == "warn"
        assert "httponly" in result["detail"]
        assert "secure" not in result["detail"].split("manque")[1]

    def test_multiple_cookies_mixed_compliance(self):
        headers = httpx.Headers([
            ("set-cookie", "good=1; Secure; HttpOnly"),
            ("set-cookie", "bad=2; Path=/"),
        ])
        result = _check_cookies(headers)
        assert result["status"] == "warn"
        assert "bad" in result["detail"]
        assert "good" not in result["detail"]
