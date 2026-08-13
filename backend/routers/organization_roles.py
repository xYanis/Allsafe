"""
routers/organization_roles.py
Registre « Rôles » (cf. models.py::OrganizationRole) — organigramme simple (poste -> personne ->
email), utilisé par la Gestion de crise et les Incidents pour savoir à qui se référer selon le
poste. Même convention que routers/analysts.py : lecture (GET) ouverte à tout utilisateur
connecté (`require_auth`, posé au niveau du router dans main.py), écriture (POST/PATCH/DELETE)
réservée admin (Administration > onglet Rôles).

`service_id` (optionnel) rattache un poste à un Service (cf. routers/services.py) — résolu en
`service_name`/`service_color` à la lecture (jointure légère, même pattern que
`_crisis_titles` dans routers/incidents.py) pour que le frontend n'ait pas de requête séparée.

`reports_to_id` (31/07/2026, optionnel) : auto-référence vers un autre OrganizationRole, alimente
le mini organigramme par service (Administration > Services > "Voir l'organigramme"). Résolu en
`reports_to_name`/`reports_to_position` à la lecture, même principe que service_name/service_color.
Écriture protégée contre les cycles (`_would_create_cycle`) — sans ça, A rapporte à B et B rapporte
à A boucle indéfiniment au premier rendu de l'organigramme côté frontend.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_admin
from database import get_session
from models import OrganizationRole, Service

router = APIRouter()


class OrganizationRoleCreate(BaseModel):
    position: str
    name: str
    email: Optional[str] = None
    service_id: Optional[str] = None
    reports_to_id: Optional[str] = None


class OrganizationRoleUpdate(BaseModel):
    position: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None
    service_id: Optional[str] = None
    clear_service: bool = False  # distingue "champ absent du payload" de "détacher le service"
    reports_to_id: Optional[str] = None
    clear_reports_to: bool = False  # idem, pour détacher le supérieur


async def _services_by_id(session: AsyncSession) -> dict[str, Service]:
    rows = (await session.execute(select(Service))).scalars().all()
    return {str(s.id): s for s in rows}


async def _roles_by_id(session: AsyncSession) -> dict[str, OrganizationRole]:
    rows = (await session.execute(select(OrganizationRole))).scalars().all()
    return {str(r.id): r for r in rows}


def _dict(r: OrganizationRole, services: dict[str, Service] | None = None, roles: dict[str, OrganizationRole] | None = None) -> dict:
    services = services or {}
    roles = roles or {}
    service = services.get(str(r.service_id)) if r.service_id else None
    manager = roles.get(str(r.reports_to_id)) if r.reports_to_id else None
    return {
        "id": str(r.id),
        "position": r.position,
        "name": r.name,
        "email": r.email,
        "service_id": str(r.service_id) if r.service_id else None,
        "service_name": service.name if service else None,
        "service_color": service.color if service else None,
        "service_icon": service.icon if service else None,
        "reports_to_id": str(r.reports_to_id) if r.reports_to_id else None,
        "reports_to_name": manager.name if manager else None,
        "reports_to_position": manager.position if manager else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


async def _validate_service_id(session: AsyncSession, service_id: Optional[str]) -> None:
    if service_id is None:
        return
    service = await session.get(Service, service_id)
    if not service:
        raise HTTPException(400, "Service introuvable.")


async def _validate_reports_to(session: AsyncSession, role_id: Optional[str], reports_to_id: Optional[str]) -> None:
    if reports_to_id is None:
        return
    if reports_to_id == role_id:
        raise HTTPException(400, "Un poste ne peut pas rapporter à lui-même.")
    manager = await session.get(OrganizationRole, reports_to_id)
    if not manager:
        raise HTTPException(400, "Supérieur introuvable.")
    if role_id is None:
        return  # création : aucun poste existant ne peut encore pointer vers ce rôle, pas de cycle possible
    # Remonte la chaîne des supérieurs depuis le supérieur proposé : si on retombe sur role_id,
    # l'affectation créerait un cycle (A -> B -> A). Profondeur bornée par sécurité, même si les
    # créations/mises à jour ci-dessous ne devraient jamais laisser de cycle se former.
    pointer = manager
    for _ in range(200):
        if pointer.reports_to_id is None:
            return
        if str(pointer.reports_to_id) == role_id:
            raise HTTPException(400, "Cette affectation créerait une boucle hiérarchique.")
        pointer = await session.get(OrganizationRole, pointer.reports_to_id)
        if pointer is None:
            return
    raise HTTPException(400, "Chaîne hiérarchique trop profonde ou corrompue.")


@router.get("")
async def list_roles(session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(select(OrganizationRole).order_by(OrganizationRole.position))).scalars().all()
    services = await _services_by_id(session)
    roles = {str(r.id): r for r in rows}
    return {"items": [_dict(r, services, roles) for r in rows]}


@router.post("", status_code=201)
async def create_role(data: OrganizationRoleCreate, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    position = data.position.strip()
    name = data.name.strip()
    if not position:
        raise HTTPException(400, "Le poste est obligatoire.")
    if not name:
        raise HTTPException(400, "Le nom est obligatoire.")
    await _validate_service_id(session, data.service_id)
    await _validate_reports_to(session, None, data.reports_to_id)
    role = OrganizationRole(
        position=position, name=name, email=(data.email or "").strip() or None,
        service_id=data.service_id, reports_to_id=data.reports_to_id,
    )
    session.add(role)
    await session.commit()
    await session.refresh(role)
    return _dict(role, await _services_by_id(session), await _roles_by_id(session))


@router.patch("/{role_id}")
async def update_role(role_id: str, data: OrganizationRoleUpdate, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    role = await session.get(OrganizationRole, role_id)
    if not role:
        raise HTTPException(404, "Rôle introuvable.")
    if data.position is not None:
        position = data.position.strip()
        if not position:
            raise HTTPException(400, "Le poste est obligatoire.")
        role.position = position
    if data.name is not None:
        name = data.name.strip()
        if not name:
            raise HTTPException(400, "Le nom est obligatoire.")
        role.name = name
    if data.email is not None:
        role.email = data.email.strip() or None
    if data.clear_service:
        role.service_id = None
    elif data.service_id is not None:
        await _validate_service_id(session, data.service_id)
        role.service_id = data.service_id
    if data.clear_reports_to:
        role.reports_to_id = None
    elif data.reports_to_id is not None:
        await _validate_reports_to(session, role_id, data.reports_to_id)
        role.reports_to_id = data.reports_to_id
    await session.commit()
    await session.refresh(role)
    return _dict(role, await _services_by_id(session), await _roles_by_id(session))


@router.delete("/{role_id}", status_code=204)
async def delete_role(role_id: str, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    role = await session.get(OrganizationRole, role_id)
    if not role:
        raise HTTPException(404, "Rôle introuvable.")
    await session.delete(role)
    await session.commit()
