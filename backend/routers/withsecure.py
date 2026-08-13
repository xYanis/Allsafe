"""
routers/withsecure.py
Déclenchement manuel + statut de la synchronisation WithSecure Elements
(correctifs manquants CVE/CVSS, serveurs Windows uniquement — cf.
services/withsecure_matcher.py).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from models import SyncState
from services.withsecure_matcher import sync_windows_vulnerabilities

router = APIRouter()


@router.post("/run")
async def trigger_withsecure_sync():
    """
    Appareils serveurs Windows WithSecure → actifs CBR → Vulnerability, à
    partir des correctifs manquants (CVE/CVSS) remontés par l'agent EDR/EPP
    déjà déployé. Ne crée jamais d'actif, n'écrit jamais côté WithSecure
    (lecture seule, scope connect.api.read). Retourne "withsecure_not_configured"
    si WITHSECURE_API_CLIENT_ID/SECRET sont absents de .env.
    """
    stats = await sync_windows_vulnerabilities()
    return stats


@router.get("/status")
async def withsecure_sync_status(session: AsyncSession = Depends(get_session)):
    """Date de la dernière synchronisation WithSecure — lu au chargement de
    page, même mécanisme que GET /api/sync/match-status."""
    state = await session.get(SyncState, "withsecure_missing_updates")
    return {"last_synced_at": state.last_synced_at.isoformat() if state and state.last_synced_at else None}
