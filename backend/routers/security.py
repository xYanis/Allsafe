"""
routers/security.py
Événements de déception (honeypots DB) — couche D (canal d'alerte in-app).

Expose le journal `security_events` alimenté par les objets leurres
(backend/db/deception_setup.sql). Consommé par la bannière rouge du Dashboard.
Aucune écriture d'événement ici : les événements naissent en SQL, au moment où
un attaquant touche une vue/rôle leurre — l'API ne fait que lire et acquitter.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_admin
from database import get_session
from models import SecurityEvent

router = APIRouter()


def _event_dict(e: SecurityEvent) -> dict:
    return {
        "id": e.id,
        "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
        "source": e.source,                 # honey_read | honey_write | decoy_role
        "object_name": e.object_name,
        "operation": e.operation,
        "db_user": e.db_user,
        "client_addr": str(e.client_addr) if e.client_addr is not None else None,
        "detail": e.detail,
        "acknowledged": e.acknowledged,
        "ack_by": e.ack_by,
        "ack_at": e.ack_at.isoformat() if e.ack_at else None,
    }


@router.get("/events")
async def list_events(
    unack_only: bool = Query(False, description="Ne renvoyer que les événements non acquittés"),
    limit: int = Query(100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    _admin=Depends(require_admin),
):
    """Journal des accès aux objets leurres, le plus récent d'abord. Réservé admin — le
    compteur ci-dessous reste accessible à tout utilisateur connecté (badge sidebar)."""
    q = select(SecurityEvent).order_by(SecurityEvent.occurred_at.desc()).limit(limit)
    if unack_only:
        q = q.where(SecurityEvent.acknowledged.is_(False))
    rows = (await session.execute(q)).scalars().all()
    return {"events": [_event_dict(e) for e in rows]}


@router.get("/events/count")
async def events_count(session: AsyncSession = Depends(get_session)):
    """Compteur léger pour la bannière du Dashboard (poll régulier) : nombre
    d'événements non acquittés + horodatage du plus récent."""
    unack = await session.scalar(
        select(func.count()).select_from(SecurityEvent).where(SecurityEvent.acknowledged.is_(False))
    )
    latest = await session.scalar(
        select(func.max(SecurityEvent.occurred_at)).where(SecurityEvent.acknowledged.is_(False))
    )
    return {"unacknowledged": unack or 0, "latest": latest.isoformat() if latest else None}


class AckPayload(BaseModel):
    ack_by: Optional[str] = None


@router.post("/events/{event_id}/ack")
async def ack_event(event_id: int, data: AckPayload, session: AsyncSession = Depends(get_session),
                     _admin=Depends(require_admin)):
    """Acquitter un événement (l'analyste a vu/traité l'alerte) — le retire de la
    bannière. N'efface jamais la ligne : la trace reste pour l'audit."""
    e = await session.get(SecurityEvent, event_id)
    if not e:
        raise HTTPException(404, "Événement introuvable")
    e.acknowledged = True
    e.ack_by = data.ack_by or None
    e.ack_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(e)
    return _event_dict(e)


@router.post("/events/ack-all")
async def ack_all(data: AckPayload, session: AsyncSession = Depends(get_session),
                   _admin=Depends(require_admin)):
    """Acquitter tous les événements non acquittés d'un coup."""
    now = datetime.now(timezone.utc)
    res = await session.execute(
        update(SecurityEvent).where(SecurityEvent.acknowledged.is_(False))
        .values(acknowledged=True, ack_by=data.ack_by or None, ack_at=now)
    )
    await session.commit()
    return {"acknowledged": res.rowcount or 0}
