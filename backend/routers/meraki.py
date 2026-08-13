"""
routers/meraki.py
Déclenchement manuel + statut de la synchronisation Meraki (état réseau en ligne/hors
ligne des actifs, cf. services/meraki_matcher.py). Même schéma que routers/withsecure.py.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from models import SyncState
from services.meraki_matcher import sync_network_status

router = APIRouter()


@router.post("/run")
async def trigger_meraki_sync(import_new_assets: bool = False):
    """
    Équipements Meraki → actifs CBR → NetworkStatus, à partir de l'état en ligne/hors
    ligne remonté par l'API Dashboard Meraki. N'écrit jamais côté Meraki (lecture seule).
    Retourne "meraki_not_configured" si MERAKI_API_KEY est absente de .env.

    `import_new_assets` (04/08/2026, demande explicite) : crée un Asset
    (`asset_type="network"`, `source="meraki"`) pour chaque équipement sans
    correspondance déjà dans CBR, au lieu de le laisser invisible. Défaut `False` —
    un cycle planifié ne doit jamais créer des actifs silencieusement sans qu'on le
    demande explicitement à chaque appel (cf. services/meraki_matcher.py).
    """
    stats = await sync_network_status(import_new_assets=import_new_assets)
    return stats


@router.get("/status")
async def meraki_sync_status(session: AsyncSession = Depends(get_session)):
    """Date de la dernière synchronisation Meraki — lu au chargement de page, même
    mécanisme que GET /api/withsecure/status."""
    state = await session.get(SyncState, "meraki_network_status")
    return {"last_synced_at": state.last_synced_at.isoformat() if state and state.last_synced_at else None}
