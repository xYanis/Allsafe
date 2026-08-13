"""
services/withsecure_client.py
Client de lecture seule pour l'API WithSecure Elements (EDR/EPP déjà déployé sur
le parc — 60 serveurs, 1100 postes, cf. mémoire session 28/07/2026).

Complète CBR sans le remplacer :
- get_missing_updates() : correctifs manquants avec CVE/CVSS réels par machine —
  confirmé Windows uniquement (testé en direct sur un appareil Debian : 0 résultat).
  Les VM Linux restent entièrement dépendantes de debian_tracker.py + SSH.
- get_security_events() / get_incidents() / get_detections() : détections EDR/EPP,
  destinées à alimenter SecurityEvent (rien d'écrit ici, ingestion à part).

Le module Vulnerability Management (ex-Radar) n'est PAS souscrit (vérifié dans
Security Center : "Paramètres des vulnérabilités" y est verrouillé) — uniquement
l'API Elements standard est utilisée ici, jamais l'API VM dépréciée.

Lecture seule stricte : le client OAuth2 côté WithSecure Security Center doit être
créé avec la case "Read-only" cochée. Aucun appel de ce module n'écrit ni n'agit sur
une machine, cohérent avec la règle de non-intervention (CLAUDE.md § Règles absolues).
"""

import base64
import logging
import time
from typing import Optional

import httpx

from config import settings

logger = logging.getLogger(__name__)

API_BASE = "https://api.connect.withsecure.com"
USER_AGENT = "Allsafe-CyberVuln/1.0"

# Le token expire au bout de ~30 min (1799s observé en pratique). Marge de
# sécurité pour ne jamais envoyer une requête avec un token expiré pile au
# moment de l'appel (latence réseau, horloge légèrement désynchronisée).
TOKEN_EXPIRY_MARGIN_SECONDS = 60

# Rate limit documenté : 300 req/min sur les endpoints EDR (devices, incidents,
# security-events, audit-log, response-actions). Non enforced côté client ici —
# le volume d'un cycle de polling périodique sur ~1160 appareils reste très en
# dessous, mais à garder en tête si la fréquence de polling augmente un jour.

_token_cache: dict = {"access_token": None, "expires_at": 0.0}


class WithSecureConfigError(RuntimeError):
    """Levée si WITHSECURE_API_CLIENT_ID/SECRET ne sont pas configurés."""


def is_configured() -> bool:
    return bool(settings.WITHSECURE_API_CLIENT_ID and settings.WITHSECURE_API_CLIENT_SECRET)


async def _get_token(client: httpx.AsyncClient, force: bool = False) -> str:
    """Authentification OAuth2 client_credentials. Réutilise le token en cache
    process tant qu'il n'est pas proche de l'expiration — évite de ré-authentifier
    à chaque appel (cf. patch_checker.py / ip_watch.py, même logique de cache)."""
    if not is_configured():
        raise WithSecureConfigError(
            "WITHSECURE_API_CLIENT_ID / WITHSECURE_API_CLIENT_SECRET non configurés dans .env"
        )

    now = time.time()
    if not force and _token_cache["access_token"] and now < _token_cache["expires_at"]:
        return _token_cache["access_token"]

    basic = base64.b64encode(
        f"{settings.WITHSECURE_API_CLIENT_ID}:{settings.WITHSECURE_API_CLIENT_SECRET}".encode()
    ).decode()
    response = await client.post(
        "/as/token.oauth2",
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": USER_AGENT,
        },
        data={"grant_type": "client_credentials", "scope": "connect.api.read"},
    )
    response.raise_for_status()
    data = response.json()

    _token_cache["access_token"] = data["access_token"]
    _token_cache["expires_at"] = now + data.get("expires_in", 1800) - TOKEN_EXPIRY_MARGIN_SECONDS
    return _token_cache["access_token"]


async def _request(client: httpx.AsyncClient, method: str, path: str, **kwargs) -> dict:
    token = await _get_token(client)
    headers = kwargs.pop("headers", {})
    headers.setdefault("Authorization", f"Bearer {token}")
    headers.setdefault("User-Agent", USER_AGENT)
    headers.setdefault("Accept", "application/json")

    response = await client.request(method, path, headers=headers, **kwargs)
    if response.status_code == 401:
        # Token invalidé côté serveur avant l'échéance calculée localement (ex:
        # révocation manuelle) — un seul retry après ré-authentification forcée,
        # pas de boucle.
        token = await _get_token(client, force=True)
        headers["Authorization"] = f"Bearer {token}"
        response = await client.request(method, path, headers=headers, **kwargs)
    response.raise_for_status()
    return response.json()


async def _paginate(client: httpx.AsyncClient, method: str, path: str, params: dict) -> list[dict]:
    items: list[dict] = []
    anchor: Optional[str] = None
    while True:
        page_params = dict(params)
        if anchor:
            page_params["anchor"] = anchor
        data = await _request(client, method, path, params=page_params)
        items.extend(data.get("items", []))
        anchor = data.get("nextAnchor")
        if not anchor:
            break
    return items


# ─── Appareils ────────────────────────────────────────────────────────────────

async def get_devices(*, device_type: Optional[str] = None) -> list[dict]:
    """Liste complète des appareils de l'organisation (pagination automatique).
    Ne distingue PAS poste/serveur via le paramètre `type` (seuls
    computer/connector/mobile existent côté API) — utiliser
    `subscription.productVariant` (ex: "serverprotection_premium_rdr" vs
    "computerprotection_premium_edr") pour filtrer côté appelant."""
    params = {"limit": 200}
    if device_type:
        params["type"] = device_type
    async with httpx.AsyncClient(base_url=API_BASE, timeout=20) as client:
        return await _paginate(client, "GET", "/devices/v1/devices", params)


# ─── Correctifs manquants (CVE/CVSS) — confirmé Windows uniquement ────────────

async def get_missing_updates(device_id: str, *, severity: Optional[str] = None) -> list[dict]:
    """Correctifs manquants pour un appareil, avec CVE ID + CVSS v3 quand
    disponibles (feature "Software Updater", incluse dans la licence EPP
    Premium — pas besoin du module Vulnerability Management non souscrit).
    Retourne une liste vide sur un appareil Linux (testé en direct sur Debian,
    28/07/2026) : ne pas s'appuyer dessus hors du périmètre Windows."""
    async with httpx.AsyncClient(base_url=API_BASE, timeout=20) as client:
        data: dict = {"deviceId": device_id}
        if severity:
            data["severity"] = severity
        token = await _get_token(client)
        response = await client.post(
            "/software-updates/v1/missing-updates",
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=data,
        )
        response.raise_for_status()
        return response.json().get("items", [])


# ─── Événements de sécurité / incidents EDR (Broad Context Detections) ────────

async def get_security_events(
    *,
    persistence_timestamp_start: str,
    persistence_timestamp_end: Optional[str] = None,
    engine_group: Optional[list[str]] = None,
    severity: Optional[list[str]] = None,
) -> list[dict]:
    """Événements EPP/EDR sur une fenêtre de 30 jours maximum. Destiné à
    alimenter SecurityEvent (mapping/ingestion fait par l'appelant, pas ici)."""
    params: dict = {"persistenceTimestampStart": persistence_timestamp_start}
    if persistence_timestamp_end:
        params["persistenceTimestampEnd"] = persistence_timestamp_end
    if engine_group:
        params["engineGroup"] = engine_group
    if severity:
        params["severity"] = severity

    async with httpx.AsyncClient(base_url=API_BASE, timeout=20) as client:
        return await _paginate(client, "POST", "/security-events/v1/security-events", params)


async def get_incidents(*, archived: bool = False) -> list[dict]:
    """Broad Context Detections (incidents EDR corrélés). `resolution` (une fois
    `status=closed`) reflète une décision prise côté WithSecure — à lire pour
    informer le statut local CBR, jamais à modifier depuis ici (PATCH non utilisé,
    cf. non-intervention)."""
    async with httpx.AsyncClient(base_url=API_BASE, timeout=20) as client:
        return await _paginate(client, "GET", "/incidents/v1/incidents", {"archived": str(archived).lower()})


async def get_detections(incident_id: str) -> list[dict]:
    """Timeline détaillée d'un incident (BCD)."""
    async with httpx.AsyncClient(base_url=API_BASE, timeout=20) as client:
        return await _paginate(
            client, "GET", "/incidents/v1/detections", {"incidentId": incident_id, "limit": 100}
        )
