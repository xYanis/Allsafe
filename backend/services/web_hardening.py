"""
services/web_hardening.py
Checks de durcissement web passifs (17/08/2026, asset_type="website") — équivalent gratuit des
défauts web de Cyberwatch (référence utilisateur), limité au sous-ensemble qui reste dans le
principe de non-intervention d'Allsafe (CLAUDE.md §1) : une requête HTTP GET normale (celle que
n'importe quel navigateur ferait) et l'observation de la négociation TLS. **Aucun payload
d'exploitation, aucune tentative d'injection** — la détection réelle de SQLi/XSS nécessiterait
d'envoyer des charges de test pour observer si elles s'exécutent, un test actif hors du périmètre
de CyberVuln (cf. docs/AUDITS.md, qui exclut explicitement sqlmap pour la même raison).

Même principe que services/network_protocol_check.py pour les actifs réseau : ces actifs n'ont
ni OS ni scan SSH/WinRM, checks stockés dans leur propre colonne (`Asset.web_compliance`), pas
dans `last_scan_result` (concept sans objet ici).
"""

import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import SessionLocal
from models import Asset

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 8.0
MAX_CONCURRENT_ASSETS = 20

# Protocoles TLS dépréciés — même esprit que ssh_weak_algos (services/asset_scanner.py),
# côté négociation TLS plutôt que SSH.
_WEAK_TLS_VERSIONS = {"SSLv3", "TLSv1", "TLSv1.1"}

# En-têtes de sécurité HTTP recherchés — id du check, nom de l'en-tête, libellé.
_SECURITY_HEADERS = [
    ("hsts", "Strict-Transport-Security", "HSTS (Strict-Transport-Security)"),
    ("csp", "Content-Security-Policy", "Content-Security-Policy"),
    ("x_content_type_options", "X-Content-Type-Options", "X-Content-Type-Options"),
    ("x_frame_options", "X-Frame-Options", "X-Frame-Options (clickjacking)"),
    ("referrer_policy", "Referrer-Policy", "Referrer-Policy"),
]


def _check_tls(hostname: str, port: int) -> dict:
    """Négociation TLS standard (ce qu'importe quel client TLS fait pour se connecter) —
    lit juste le protocole retenu par le serveur, n'envoie aucune donnée applicative."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                version = tls_sock.version()
        if version in _WEAK_TLS_VERSIONS:
            return {"id": "tls_protocol", "label": "Protocole TLS", "status": "warn",
                    "detail": f"Protocole déprécié négocié : {version}"}
        return {"id": "tls_protocol", "label": "Protocole TLS", "status": "ok",
                "detail": f"Protocole négocié : {version}"}
    except Exception as exc:
        return {"id": "tls_protocol", "label": "Protocole TLS", "status": "unknown",
                "detail": f"Négociation TLS impossible : {exc}"}


def _check_headers(headers: httpx.Headers) -> list[dict]:
    checks = []
    for check_id, header_name, label in _SECURITY_HEADERS:
        value = headers.get(header_name)
        # X-Frame-Options : une CSP avec frame-ancestors couvre le même rôle (clickjacking),
        # ne pas doublement avertir si l'un des deux est présent.
        if check_id == "x_frame_options" and not value and "frame-ancestors" in (headers.get("Content-Security-Policy") or ""):
            checks.append({"id": check_id, "label": label, "status": "ok",
                            "detail": "Couvert par frame-ancestors dans la CSP"})
            continue
        if value:
            checks.append({"id": check_id, "label": label, "status": "ok", "detail": f"Présent : {value[:120]}"})
        else:
            checks.append({"id": check_id, "label": label, "status": "warn", "detail": "En-tête absent"})
    return checks


def _check_cookies(headers: httpx.Headers) -> Optional[dict]:
    cookies = headers.get_list("set-cookie")
    if not cookies:
        return None
    issues = []
    for raw in cookies:
        lower = raw.lower()
        name = raw.split("=", 1)[0].strip()
        missing = [f for f in ("secure", "httponly") if f not in lower]
        if missing:
            issues.append(f"{name} (manque {', '.join(missing)})")
    if issues:
        return {"id": "cookie_flags", "label": "Cookies Secure/HttpOnly", "status": "warn",
                "detail": "; ".join(issues)}
    return {"id": "cookie_flags", "label": "Cookies Secure/HttpOnly", "status": "ok",
            "detail": f"{len(cookies)} cookie(s), tous marqués Secure+HttpOnly"}


async def check_website(url: str) -> dict:
    """{"checks": [...], "checked_at": iso} pour une URL — un GET HTTP normal + une
    négociation TLS standard, rien de plus."""
    now = datetime.now(timezone.utc).isoformat()
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"checks": [{"id": "web_reachable", "label": "URL", "status": "unknown",
                             "detail": "URL invalide (http:// ou https:// attendu)"}], "checked_at": now}

    checks: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            response = await client.get(url if "://" in url else f"https://{url}")
    except httpx.HTTPError as exc:
        return {"checks": [{"id": "web_reachable", "label": "Accessibilité", "status": "unknown",
                             "detail": f"Site injoignable : {exc}"}], "checked_at": now}

    if parsed.scheme == "https" or response.url.scheme == "https":
        port = parsed.port or 443
        checks.append(_check_tls(response.url.host or parsed.hostname, port))
    else:
        checks.append({"id": "tls_protocol", "label": "Protocole TLS", "status": "warn",
                        "detail": "Site servi en HTTP simple, sans TLS"})

    checks.extend(_check_headers(response.headers))
    cookie_check = _check_cookies(response.headers)
    if cookie_check:
        checks.append(cookie_check)

    return {"checks": checks, "checked_at": now}


async def run_all_website_checks(db: Optional[AsyncSession] = None, asset_ids: Optional[list[str]] = None) -> dict:
    """Point d'entrée principal : tous les actifs `asset_type="website"` actifs (ou seulement
    `asset_ids` si fourni — 17/08/2026, cf. services/scan_policy.py, un groupe de criticité ne
    doit tester que ses propres sites web), testés en parallèle (borné par
    MAX_CONCURRENT_ASSETS), un seul commit à la fin — même patron que
    services/network_protocol_check.py::check_all_network_assets. Le bouton manuel existant
    (`POST /assets/web-hardening/run`) n'appelle jamais avec `asset_ids` : comportement
    inchangé (tous les sites web)."""
    own_session = db is None
    if own_session:
        db = SessionLocal()

    stats = {"checked": 0, "warnings": 0, "skipped_no_url": 0}
    try:
        query = select(Asset).where(Asset.asset_type == "website", Asset.status == "active")
        if asset_ids is not None:
            query = query.where(Asset.id.in_(asset_ids))
        assets = (await db.execute(query)).scalars().all()

        semaphore = asyncio.Semaphore(MAX_CONCURRENT_ASSETS)

        async def _check_bounded(asset: Asset) -> Optional[dict]:
            if not asset.url:
                return None
            async with semaphore:
                return await check_website(asset.url)

        results = await asyncio.gather(*(_check_bounded(a) for a in assets))

        for asset, result in zip(assets, results):
            if result is None:
                stats["skipped_no_url"] += 1
                continue
            asset.web_compliance = result
            stats["checked"] += 1
            if any(c["status"] == "warn" for c in result["checks"]):
                stats["warnings"] += 1

        await db.commit()
        logger.info(
            "Checks web : %d actifs vérifiés, %d avertissements, %d sans URL",
            stats["checked"], stats["warnings"], stats["skipped_no_url"],
        )
    except Exception:
        await db.rollback()
        raise
    finally:
        if own_session:
            await db.close()

    return stats
