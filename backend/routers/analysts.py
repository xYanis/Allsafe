"""
routers/analysts.py
Registre des analystes (cf. models.py::Analyst) — CRUD simple, remplace la liste `ANALYSTS`
codée en dur côté frontend, alimente les menus déroulants d'attribution (validé par,
déclaré par...) partout dans l'app. La lecture (GET) reste ouverte à tout utilisateur
connecté (`require_auth`, posé au niveau du router dans main.py) — ces dropdowns en ont
besoin partout. L'écriture (POST/PATCH/DELETE) est réservée admin (30/07/2026, gérée
depuis Paramètres > Administration > onglet Analystes, `AdministrationSecurity.jsx`).
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_admin
from database import get_session
from models import Analyst

router = APIRouter()


class AnalystCreate(BaseModel):
    name: str


class AnalystUpdate(BaseModel):
    name: Optional[str] = None


def _dict(a: Analyst) -> dict:
    return {
        "id": str(a.id),
        "name": a.name,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


@router.get("")
async def list_analysts(session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(select(Analyst).order_by(Analyst.name))).scalars().all()
    return {"items": [_dict(a) for a in rows]}


@router.post("", status_code=201)
async def create_analyst(data: AnalystCreate, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    name = data.name.strip()
    if not name:
        raise HTTPException(400, "Le nom est obligatoire.")
    existing = (await session.execute(select(Analyst).where(Analyst.name == name))).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Un analyste porte déjà ce nom.")
    analyst = Analyst(name=name)
    session.add(analyst)
    await session.commit()
    await session.refresh(analyst)
    return _dict(analyst)


@router.patch("/{analyst_id}")
async def update_analyst(analyst_id: str, data: AnalystUpdate, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    analyst = await session.get(Analyst, analyst_id)
    if not analyst:
        raise HTTPException(404, "Analyste introuvable.")
    if data.name is not None:
        name = data.name.strip()
        if not name:
            raise HTTPException(400, "Le nom est obligatoire.")
        existing = (await session.execute(select(Analyst).where(Analyst.name == name, Analyst.id != analyst_id))).scalar_one_or_none()
        if existing:
            raise HTTPException(409, "Un analyste porte déjà ce nom.")
        analyst.name = name
    await session.commit()
    await session.refresh(analyst)
    return _dict(analyst)


@router.delete("/{analyst_id}", status_code=204)
async def delete_analyst(analyst_id: str, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    analyst = await session.get(Analyst, analyst_id)
    if not analyst:
        raise HTTPException(404, "Analyste introuvable.")
    await session.delete(analyst)
    await session.commit()
