from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_session
from services.stats import compute_stats

router = APIRouter()


@router.get("")
async def get_stats(asset_id: str | None = None, session: AsyncSession = Depends(get_session)):
    """
    `asset_id` (optionnel) : un ou plusieurs UUID d'actifs séparés par virgule — restreint
    tous les compteurs à ce sous-ensemble du parc (filtre "Actifs" du dashboard, un/plusieurs/
    tous). Sans ce paramètre, périmètre par défaut = actifs "entièrement configurés"
    uniquement (07/08/2026, `default_configured_only`, cf. services/stats.py) — pas le parc
    entier. Comportement spécifique à cet endpoint (dashboard) : `routers/reports.py` appelle
    `compute_stats` directement sans ce paramètre, toujours sur le parc entier.
    """
    asset_ids = [v.strip() for v in asset_id.split(",") if v.strip()] if asset_id else None
    return await compute_stats(session, asset_ids=asset_ids, default_configured_only=True)
