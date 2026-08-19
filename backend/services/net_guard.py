"""
services/net_guard.py
Garde-fou SSRF — partagé par les sources de veille (WatchSource) et tout futur
appel HTTP sortant piloté par une URL saisie par l'utilisateur.

cf. audit/AUDIT_SECURITE.md #1 : sans auth sur l'API, un `url` non validé pointant
vers 127.0.0.1, le VLAN interne ou les métadonnées cloud est un SSRF exploitable
par quiconque a accès au réseau.
"""

import ipaddress
import socket
from urllib.parse import urlparse


def validate_public_url(url: str) -> str:
    """Rejette tout ce qui n'est pas http(s) vers un hôte public routable.
    Lève ValueError sinon. À rappeler après chaque redirection (DNS rebinding)."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise ValueError("Schéma non autorisé (http/https uniquement)")
    if not p.hostname:
        raise ValueError("Hôte manquant")
    try:
        addrs = socket.getaddrinfo(p.hostname, None)
    except socket.gaierror:
        raise ValueError(f"Résolution DNS impossible : {p.hostname}")
    for family, _, _, _, sockaddr in addrs:
        ip = ipaddress.ip_address(sockaddr[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ValueError(f"Adresse non routable interdite : {ip}")
    return url
