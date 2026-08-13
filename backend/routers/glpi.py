"""
routers/glpi.py
Déclenchement manuel + statut de la synchronisation GLPI (enrichissement patrimoine des
actifs déjà connus, cf. services/glpi_matcher.py). Contrairement à routers/meraki.py /
routers/prtg.py : pas de paramètre `import_new_assets`, GLPI ne crée jamais d'actif.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from models import SyncState
from services.glpi_matcher import sync_inventory, SYNC_STATE_KEY

router = APIRouter()


@router.post("/run")
async def trigger_glpi_sync():
    """
    Computer GLPI → actifs Allsafe déjà connus (patrimoine : modèle, n° de série, n°
    d'inventaire, fabricant, localisation). N'écrit jamais côté GLPI (lecture seule) et
    ne crée jamais d'actif — GLPI enrichit ce qu'Allsafe connaît déjà, il n'est pas une
    source de découverte (contrairement à Meraki/PRTG et leur `import_new_assets`).
    Retourne "glpi_not_configured" si GLPI_URL / GLPI_APP_TOKEN / GLPI_USER_TOKEN sont
    absents de .env.
    """
    return await sync_inventory()


@router.get("/status")
async def glpi_sync_status(session: AsyncSession = Depends(get_session)):
    """Date de la dernière synchronisation GLPI — même mécanisme que GET /api/prtg/status."""
    state = await session.get(SyncState, SYNC_STATE_KEY)
    return {"last_synced_at": state.last_synced_at.isoformat() if state and state.last_synced_at else None}
