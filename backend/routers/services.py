"""
routers/services.py
Services/départements (cf. models.py::Service) — RH, DSI, Juridique, Direction... regroupent les
postes du registre Rôles (OrganizationRole.service_id), avec un code couleur pour la grille de
cartes d'Administration > Rôles. Même convention que routers/analysts.py : lecture ouverte à tout
connecté, écriture réservée admin.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_admin
from database import get_session
from models import Service

router = APIRouter()


class ServiceCreate(BaseModel):
    name: str
    color: str
    icon: Optional[str] = None


class ServiceUpdate(BaseModel):
    name: Optional[str] = None
    color: Optional[str] = None
    icon: Optional[str] = None


def _dict(s: Service) -> dict:
    return {
        "id": str(s.id),
        "name": s.name,
        "color": s.color,
        "icon": s.icon,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


@router.get("")
async def list_services(session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(select(Service).order_by(Service.name))).scalars().all()
    return {"items": [_dict(s) for s in rows]}


@router.post("", status_code=201)
async def create_service(data: ServiceCreate, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    name = data.name.strip()
    color = data.color.strip()
    if not name:
        raise HTTPException(400, "Le nom est obligatoire.")
    if not color:
        raise HTTPException(400, "La couleur est obligatoire.")
    existing = (await session.execute(select(Service).where(Service.name == name))).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Un service porte déjà ce nom.")
    service = Service(name=name, color=color, icon=(data.icon or None))
    session.add(service)
    await session.commit()
    await session.refresh(service)
    return _dict(service)


@router.patch("/{service_id}")
async def update_service(service_id: str, data: ServiceUpdate, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    service = await session.get(Service, service_id)
    if not service:
        raise HTTPException(404, "Service introuvable.")
    if data.name is not None:
        name = data.name.strip()
        if not name:
            raise HTTPException(400, "Le nom est obligatoire.")
        existing = (await session.execute(
            select(Service).where(Service.name == name, Service.id != service_id)
        )).scalar_one_or_none()
        if existing:
            raise HTTPException(409, "Un service porte déjà ce nom.")
        service.name = name
    if data.color is not None:
        color = data.color.strip()
        if not color:
            raise HTTPException(400, "La couleur est obligatoire.")
        service.color = color
    if data.icon is not None:
        service.icon = data.icon or None
    await session.commit()
    await session.refresh(service)
    return _dict(service)


@router.delete("/{service_id}", status_code=204)
async def delete_service(service_id: str, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    service = await session.get(Service, service_id)
    if not service:
        raise HTTPException(404, "Service introuvable.")
    await session.delete(service)
    await session.commit()
