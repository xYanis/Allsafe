"""
tests/test_net_guard_fuzz.py
Fuzzing par propriétés (hypothesis) de services/net_guard.py — garde-fou SSRF des
sources de veille (cf. audit/AUDIT_SECURITE.md #1). Deux propriétés distinctes :
  1. Aucune entrée arbitraire ne doit faire planter la fonction autrement qu'avec
     ValueError — DNS mocké pour ne jamais toucher le réseau pendant le fuzzing (un
     texte qui ressemble à un hostname valide déclencherait sinon une vraie
     résolution DNS, lente et non déterministe, à chaque exemple généré).
  2. Classification correcte pour N'IMPORTE QUELLE adresse IP (v4 et v6, y compris
     les formes IPv4-mappées type ::ffff:127.0.0.1 — contournement SSRF classique) :
     le verdict accepté/rejeté doit toujours correspondre à ipaddress.*.is_private/
     is_loopback/etc, quelle que soit la décoration de l'URL autour (port, chemin).
"""
import ipaddress
import socket
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from services.net_guard import validate_public_url


def _is_unroutable(ip) -> bool:
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


@given(url=st.text(max_size=200))
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_never_crashes_on_arbitrary_text(url):
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("mocked: no DNS during fuzzing")):
        try:
            validate_public_url(url)
        except ValueError:
            pass


@given(ip=st.ip_addresses(), port=st.integers(min_value=1, max_value=65535) | st.none())
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_classification_matches_ipaddress_module(ip, port):
    host = f"[{ip}]" if ip.version == 6 else str(ip)
    port_part = f":{port}" if port else ""
    url = f"http://{host}{port_part}/some/path?x=1"

    fake_sockaddr = (str(ip), port or 0) if ip.version == 4 else (str(ip), port or 0, 0, 0)
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    with patch("socket.getaddrinfo", return_value=[(family, None, None, "", fake_sockaddr)]):
        if _is_unroutable(ip):
            with pytest.raises(ValueError):
                validate_public_url(url)
        else:
            assert validate_public_url(url) == url


@pytest.mark.parametrize("url", [
    "http://2130706433/",               # 127.0.0.1 en décimal
    "http://0x7f000001/",               # 127.0.0.1 en hexadécimal
    "http://0177.0.0.1/",               # 127.0.0.1 en octal partiel
    "http://127.1/",                    # forme courte
    "http://[::ffff:127.0.0.1]/",       # IPv4-mappée en IPv6
    "http://[::ffff:169.254.169.254]/", # métadonnées cloud, IPv4-mappée
    "http://0/",                        # 0.0.0.0
    "http://localhost/",
    "http://LOCALHOST/",
])
def test_known_ssrf_bypass_attempts_rejected(url):
    """Contournements SSRF documentés — contre le vrai `socket.getaddrinfo` (pas
    mocké : ce sont des IP littérales/localhost, résolues localement sans trafic
    réseau réel)."""
    with pytest.raises(ValueError):
        validate_public_url(url)


def test_genuine_public_ip_accepted():
    assert validate_public_url("http://8.8.8.8/") == "http://8.8.8.8/"
