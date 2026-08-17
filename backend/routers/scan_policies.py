"""
routers/scan_policies.py
Politiques de scan planifié par criticité (cf. models.py::ScanPolicy) — 4 lignes fixes (une par
valeur de `asset.tags.criticite`), éditables depuis Paramètres > Intégrations. Contrairement à
`analysts.py`, pas de POST/DELETE : le jeu de lignes est fixe (seedé une fois pour toutes dans
`db/schema_patches.sql`), seul PATCH a un sens ici.

`run-now` utilise `require_admin_or_internal` plutôt que `require_admin` : c'est le même
endpoint que le poller horaire `tasks/scheduled_tasks.py::check_scan_policies` appelle en
interne (X-Internal-Token), pour ne jamais dupliquer la logique de déclenchement entre le
bouton manuel et le planning automatique (cf. services/scan_policy.py pour l'explication de
pourquoi ce déclenchement doit toujours passer par le process backend).

Router monté SANS dependency de niveau router dans main.py (contrairement à la plupart des
autres routers, `dependencies=_authed`) — un jeton interne n'a pas de session/cookie, une
dependency posée au niveau du router s'exécuterait avant la dependency `require_admin_or_internal`
de la route et rejetterait l'appel avant même qu'elle ne s'exécute. Protection posée route par
route à la place, même précédent que `routers/patch_check.py`.
"""

from typing import Optional

import asyncio

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_auth, require_admin, require_admin_or_internal
from database import get_session
from models import ScanPolicy, SyncState
from services.scan_policy import is_policy_running, run_scan_for_criticite

router = APIRouter()

VALID_CRITICITES = ("critique", "haute", "moyenne", "faible")


class ScanPolicyUpdate(BaseModel):
    enabled: Optional[bool] = None
    frequency: Optional[str] = None
    hour: Optional[int] = None
    weekday: Optional[int] = None


async def _dict(p: ScanPolicy, session: AsyncSession) -> dict:
    state = await session.get(SyncState, f"scan_policy_{p.criticite}")
    return {
        "criticite": p.criticite,
        "enabled": p.enabled,
        "frequency": p.frequency,
        "hour": p.hour,
        "weekday": p.weekday,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
        "running": is_policy_running(p.criticite),
        "last_run_at": state.last_synced_at.isoformat() if state and state.last_synced_at else None,
        "last_run_status": state.status if state else None,
    }


@router.get("")
async def list_scan_policies(session: AsyncSession = Depends(get_session), _user=Depends(require_auth)):
    rows = (await session.execute(select(ScanPolicy).order_by(ScanPolicy.criticite))).scalars().all()
    return {"items": [await _dict(p, session) for p in rows]}


@router.patch("/{criticite}")
async def update_scan_policy(
    criticite: str,
    data: ScanPolicyUpdate,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(require_admin),
):
    policy = (await session.execute(select(ScanPolicy).where(ScanPolicy.criticite == criticite))).scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Politique introuvable.")
    if data.frequency is not None and data.frequency not in ("daily", "weekly"):
        raise HTTPException(400, "frequency doit être 'daily' ou 'weekly'.")
    if data.hour is not None and not (0 <= data.hour <= 23):
        raise HTTPException(400, "hour doit être compris entre 0 et 23.")
    if data.weekday is not None and not (0 <= data.weekday <= 6):
        raise HTTPException(400, "weekday doit être compris entre 0 (lundi) et 6 (dimanche).")
    for field in ("enabled", "frequency", "hour", "weekday"):
        value = getattr(data, field)
        if value is not None:
            setattr(policy, field, value)
    await session.commit()
    await session.refresh(policy)
    return await _dict(policy, session)


@router.post("/{criticite}/run-now")
async def run_scan_policy_now(criticite: str, _admin=Depends(require_admin_or_internal)):
    if criticite not in VALID_CRITICITES:
        raise HTTPException(404, "Criticité inconnue.")
    if is_policy_running(criticite):
        return {"status": "already_running"}
    asyncio.create_task(run_scan_for_criticite(criticite))
    return {"status": "started"}
