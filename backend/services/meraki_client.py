"""
services/meraki_client.py
Client de lecture seule pour l'API Cisco Meraki Dashboard (04/08/2026, supervision réseau).

Comble le vide identifié lors de la discussion PRTG du 31/07/2026 (jamais codée) : remonter
l'état en ligne/hors ligne des actifs réseau. Aucun appel de ce module n'écrit ni n'agit sur
un équipement Meraki (seuls des GET sont utilisés), cohérent avec la règle de
non-intervention (CLAUDE.md § Règles absolues) — CBR héberge et affiche l'état constaté,
il ne configure jamais rien côté Meraki.

Auth : clé API personnelle envoyée dans l'en-tête `X-Cisco-Meraki-API-Key` (pas d'OAuth2,
contrairement à WithSecure — la clé elle-même fait foi, cf. services/withsecure_client.py
pour le pattern équivalent avec token).
"""

import logging
from typing import Optional

import httpx

from config import settings

logger = logging.getLogger(__name__)

API_BASE = "https://api.meraki.com/api/v1"
USER_AGENT = "Allsafe-CyberVuln/1.0"

# Rate limit documenté : 10 req/s par clé API (pic), avec retry-after sur 429 —
# non enforced côté client ici, le volume d'un cycle de polling périodique sur un
# parc de cette taille (72 actifs, largement moins d'équipements réseau purs)
# reste très en dessous. À revoir si la fréquence de polling augmente un jour.


class MerakiConfigError(RuntimeError):
    """Levée si MERAKI_API_KEY n'est pas configurée."""


def is_configured() -> bool:
    return bool(settings.MERAKI_API_KEY)


def _headers() -> dict:
    return {
        "X-Cisco-Meraki-API-Key": settings.MERAKI_API_KEY,
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }


async def _request(client: httpx.AsyncClient, method: str, path: str, **kwargs) -> httpx.Response:
    if not is_configured():
        raise MerakiConfigError("MERAKI_API_KEY non configurée dans .env")
    response = await client.request(method, path, headers=_headers(), **kwargs)
    response.raise_for_status()
    return response


async def get_organizations() -> list[dict]:
    """Organisations visibles par cette clé API — sert à résoudre l'organisation
    par défaut quand MERAKI_ORGANIZATION_ID n'est pas renseigné."""
    async with httpx.AsyncClient(base_url=API_BASE, timeout=20) as client:
        response = await _request(client, "GET", "/organizations")
        return response.json()


async def _get_device_statuses_for_org(client: httpx.AsyncClient, org_id: str) -> list[dict]:
    items: list[dict] = []
    path = f"/organizations/{org_id}/devices/statuses"
    params = {"perPage": 1000}
    while path:
        response = await _request(client, "GET", path, params=params)
        items.extend(response.json())
        path = None
        params = {}
        link = response.headers.get("Link", "")
        for part in link.split(","):
            if 'rel="next"' in part:
                next_url = part[part.find("<") + 1: part.find(">")]
                # L'URL "next" est absolue (host compris) — httpx.AsyncClient a un
                # base_url fixe, on ne garde donc que le chemin + la query.
                path = next_url.replace(API_BASE, "")
    return items


async def get_device_statuses(organization_id: Optional[str] = None) -> list[dict]:
    """État de tous les équipements réseau (pagination automatique par
    `perPage`/`startingAfter`, cf. en-tête `Link` renvoyé par l'API Meraki).

    Chaque entrée contient notamment : name, serial, mac, networkId, status
    ("online"/"offline"/"alerting"/"dormant"), lastReportedAt, productType, model,
    publicIp, tags. Lecture seule — ne modifie rien côté Meraki.

    Sans `organization_id` ni `MERAKI_ORGANIZATION_ID` configuré, agrège **toutes**
    les organisations visibles par la clé — constaté en conditions réelles (04/08/2026) :
    une même clé peut voir plusieurs organisations bien réelles et distinctes (ex. deux
    entités du même groupe, l'une avec les bornes Wi-Fi, l'autre avec les pare-feux),
    se limiter à la première aurait silencieusement ignoré la seconde."""
    async with httpx.AsyncClient(base_url=API_BASE, timeout=20) as client:
        if organization_id:
            return await _get_device_statuses_for_org(client, organization_id)
        if settings.MERAKI_ORGANIZATION_ID:
            return await _get_device_statuses_for_org(client, settings.MERAKI_ORGANIZATION_ID)

        orgs = (await _request(client, "GET", "/organizations")).json()
        if not orgs:
            raise MerakiConfigError("Aucune organisation visible par cette clé API Meraki")
        if len(orgs) > 1:
            logger.info(
                "%d organisations Meraki visibles — agrégation de toutes (%s). "
                "Renseigner MERAKI_ORGANIZATION_ID pour n'en cibler qu'une seule.",
                len(orgs), ", ".join(o.get("name", "?") for o in orgs),
            )
        items: list[dict] = []
        for org in orgs:
            items.extend(await _get_device_statuses_for_org(client, org["id"]))
        return items
