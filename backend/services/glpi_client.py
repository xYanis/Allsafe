"""
services/glpi_client.py
Client de lecture seule pour l'API REST GLPI (11/08/2026, CMDB patrimoine) — troisième
sonde externe après Meraki/PRTG (cf. services/meraki_client.py / prtg_client.py), mais
rôle différent : GLPI n'alimente jamais `network_status` (ce n'est pas un outil de
supervision réseau), il enrichit le patrimoine (`Asset.hardware`) des actifs déjà connus,
cf. services/glpi_matcher.py. Aucun appel de ce module n'écrit côté GLPI (uniquement
initSession/killSession et des GET) — cohérent avec la règle de non-intervention
(CLAUDE.md § Règles absolues).

Auth : deux jetons statiques (App-Token du client API + User-Token du compte de service
dédié, lecture seule côté GLPI) envoyés à `initSession`, qui renvoie un Session-Token de
courte durée à utiliser pour les appels suivants — contrairement à Meraki (clé API seule
en en-tête) et PRTG (apitoken en query param), GLPI a une notion de session explicite à
fermer (`killSession`) plutôt qu'une auth stateless par requête.
"""

import logging
from contextlib import asynccontextmanager
from typing import Optional

import httpx

from config import settings

logger = logging.getLogger(__name__)

USER_AGENT = "Allsafe-CyberVuln/1.0"

# expand_dropdowns=true résout les colonnes *_id (locations_id, computermodels_id,
# manufacturers_id...) directement en libellé texte dans la réponse — évite une série
# d'appels séparés pour retrouver le nom d'un site/modèle/fabricant à partir de son id.
COMPUTER_PARAMS = {"expand_dropdowns": "true"}

# Taille de page côté pagination `range` (GLPI n'a pas d'équivalent au count=50000 de
# PRTG en une seule requête) — 500 reste large marge sous la limite serveur par défaut
# de GLPI (souvent 1000+), tout en gardant chaque appel raisonnable.
PAGE_SIZE = 500


class GlpiConfigError(RuntimeError):
    """Levée si GLPI_URL / GLPI_APP_TOKEN / GLPI_USER_TOKEN ne sont pas configurés."""


def is_configured() -> bool:
    return bool(settings.GLPI_URL and settings.GLPI_APP_TOKEN and settings.GLPI_USER_TOKEN)


def _base_url() -> str:
    return (settings.GLPI_URL or "").rstrip("/")


@asynccontextmanager
async def _session():
    """Ouvre une session GLPI (initSession) et la ferme systématiquement (killSession),
    y compris en cas d'exception pendant les appels — jamais de session orpheline côté
    GLPI. Fournit (client httpx, headers déjà porteurs de App-Token + Session-Token)."""
    if not is_configured():
        raise GlpiConfigError("GLPI_URL / GLPI_APP_TOKEN / GLPI_USER_TOKEN non configurés dans .env")

    async with httpx.AsyncClient(timeout=30, headers={"User-Agent": USER_AGENT}) as client:
        init = await client.get(
            f"{_base_url()}/initSession",
            headers={
                "App-Token": settings.GLPI_APP_TOKEN,
                "Authorization": f"user_token {settings.GLPI_USER_TOKEN}",
            },
        )
        init.raise_for_status()
        session_token = init.json()["session_token"]
        headers = {"App-Token": settings.GLPI_APP_TOKEN, "Session-Token": session_token}
        try:
            yield client, headers
        finally:
            try:
                await client.get(f"{_base_url()}/killSession", headers=headers)
            except httpx.HTTPError:
                # Jamais bloquant : une session GLPI expire de toute façon d'elle-même
                # après un délai d'inactivité côté serveur.
                logger.warning("GLPI : échec de killSession (non bloquant)", exc_info=True)


def _total_from_content_range(header: Optional[str]) -> Optional[int]:
    # Format GLPI : "0-499/1234" (position de début-fin / total). Absent si la liste
    # tient en une seule page ou si le serveur ne le renvoie pas.
    if not header or "/" not in header:
        return None
    try:
        return int(header.rsplit("/", 1)[-1])
    except ValueError:
        return None


async def get_computers() -> list[dict]:
    """Tous les Computer GLPI (serveurs/postes), paginés par `range` — lecture seule,
    ne modifie rien côté GLPI. Chaque entrée porte notamment : id, name (utilisé pour
    le rapprochement, cf. glpi_matcher.py), serial, otherserial (n° d'inventaire),
    computermodels_id/manufacturers_id/locations_id (résolus en texte par
    expand_dropdowns, cf. COMPUTER_PARAMS)."""
    computers: list[dict] = []
    async with _session() as (client, headers):
        start = 0
        while True:
            params = {**COMPUTER_PARAMS, "range": f"{start}-{start + PAGE_SIZE - 1}"}
            response = await client.get(f"{_base_url()}/Computer", headers=headers, params=params)
            response.raise_for_status()
            batch = response.json()
            if not isinstance(batch, list) or not batch:
                break
            computers.extend(batch)

            total = _total_from_content_range(response.headers.get("Content-Range"))
            if (total is not None and start + PAGE_SIZE >= total) or len(batch) < PAGE_SIZE:
                break
            start += PAGE_SIZE

    return computers
