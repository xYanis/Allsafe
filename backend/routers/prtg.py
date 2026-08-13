"""
routers/prtg.py
Déclenchement manuel + statut de la synchronisation PRTG (état réseau en ligne/hors
ligne des actifs, cf. services/prtg_matcher.py). Même schéma que routers/meraki.py,
`import_new_assets` inclus (04/08/2026, décision revue en cours de session).
"""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from models import Asset, NetworkStatus, SyncState
from services.prtg_matcher import sync_network_status, SOURCE

router = APIRouter()


@router.post("/run")
async def trigger_prtg_sync(import_new_assets: bool = False):
    """
    Devices PRTG → actifs CBR → NetworkStatus, à partir de l'état en ligne/hors ligne
    remonté par l'API cœur PRTG. N'écrit jamais côté PRTG (lecture seule). Retourne
    "prtg_not_configured" si PRTG_URL / PRTG_API_TOKEN sont absents de .env.

    `import_new_assets` (04/08/2026, demande explicite) : crée un Asset
    (`asset_type="network"`, `source="prtg"`) pour chaque device sans correspondance
    déjà dans CBR (hors objets internes PRTG — sonde, serveur central), au lieu de le
    laisser invisible. Défaut `False` — un cycle planifié ne doit jamais créer des
    actifs silencieusement sans qu'on le demande explicitement à chaque appel
    (cf. services/prtg_matcher.py).
    """
    stats = await sync_network_status(import_new_assets=import_new_assets)
    return stats


@router.get("/status")
async def prtg_sync_status(session: AsyncSession = Depends(get_session)):
    """Date de la dernière synchronisation PRTG — lu au chargement de page, même
    mécanisme que GET /api/meraki/status."""
    state = await session.get(SyncState, "prtg_network_status")
    return {"last_synced_at": state.last_synced_at.isoformat() if state and state.last_synced_at else None}


@router.get("/ssl-certificates")
async def list_ssl_certificates(session: AsyncSession = Depends(get_session)):
    """
    Certificats SSL surveillés par PRTG, aplatis un par ligne (un actif peut en
    porter plusieurs — ex. plusieurs sites hébergés sur un même VPS), triés par
    `days_remaining` croissant (celui qui expire le plus tôt en premier).

    Lit `NetworkStatus.metrics.ssl_certificates` (écrit par
    services/prtg_matcher.py à chaque sync) plutôt que d'interroger PRTG en
    direct à chaque chargement de page — cohérent avec le reste du module
    (instantané en base, pas de round-trip PRTG synchrone côté requête HTTP).
    """
    rows = (await session.execute(
        select(NetworkStatus, Asset.name)
        .join(Asset, Asset.id == NetworkStatus.asset_id)
        .where(NetworkStatus.source == SOURCE)
    )).all()

    certificates = []
    for network_status, asset_name in rows:
        for cert in (network_status.metrics or {}).get("ssl_certificates") or []:
            certificates.append({
                "asset_id": str(network_status.asset_id),
                "asset_name": asset_name,
                "sensor": cert.get("sensor"),
                "days_remaining": cert.get("days_remaining"),
            })

    certificates.sort(key=lambda c: c["days_remaining"] if c["days_remaining"] is not None else float("inf"))
    return certificates
