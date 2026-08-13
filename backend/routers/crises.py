"""
routers/crises.py
Gestion de crise (31/07/2026, module Incidents) — escalade d'un ou plusieurs incidents
en crise : cellule de crise (rôles nommés), journal de décisions et de communications
internes/externes. Comble le vide identifié par ROADMAP_RNCP42335.md (Bloc 1.5).

Endpoints minces : la logique de mutation vit dans services/crisis.py (même convention
que routers/incidents.py + services/nis2_deadlines.py) ; la création (qui EST déjà une
activation, cf. Crisis.activated_at obligatoire) est traitée directement ici, comme
Incident.create_incident.

Aucune notification/envoi réel depuis l'app : les communications de crise sont
**tracées**, jamais envoyées — même garde-fou que le reste du module Incidents
(cf. docs/INCIDENTS.md § 2).
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_admin
from database import get_session
from models import Crisis, CrisisTimelineEntry, CrisisContact, Incident
from services import crisis as crisis_service
from services.crisis_timeline import record as record_timeline

router = APIRouter()


# ─── Schémas ──────────────────────────────────────────────────────────────────

class CrisisCreate(BaseModel):
    title: str
    description: Optional[str] = None
    activated_by: str


class CrisisStepCompletion(BaseModel):
    """Une étape cochée du Plan d'action (CRISIS_STEPS, frontend/src/constants/
    crisisPlaybook.js) — même forme qu'incidents.py::ResponseStepCompletion, dupliquée
    localement plutôt qu'importée d'un autre router pour un schéma aussi petit."""
    index: int
    by: str
    at: Optional[datetime] = None


class CrisisUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    completed_crisis_steps: Optional[list[CrisisStepCompletion]] = None


class ContactCreate(BaseModel):
    name: str
    role: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    website_url: Optional[str] = None
    notes: Optional[str] = None


class ContactUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    website_url: Optional[str] = None
    notes: Optional[str] = None


class StandDownPayload(BaseModel):
    analyst: str
    justification: str


class RoleAssignPayload(BaseModel):
    role: str
    analyst_name: str
    by: str


class LinkIncidentPayload(BaseModel):
    incident_id: str
    by: str


class DecisionPayload(BaseModel):
    author: str
    content: str


class CommunicationPayload(BaseModel):
    author: str
    content: str
    audience: str  # interne | externe


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _guard(fn):
    """Traduit un ValueError de services/crisis.py en HTTP — même convention que
    routers/incidents.py::_guard."""
    try:
        fn()
    except ValueError as e:
        msg = str(e)
        code = 409 if ("déjà" in msg or "n'est pas rattaché" in msg) else 400
        raise HTTPException(code, msg)


async def _get_or_404(session: AsyncSession, crisis_id: str) -> Crisis:
    c = await session.get(Crisis, crisis_id)
    if not c:
        raise HTTPException(404, "Crise introuvable")
    return c


async def _linked_incidents(session: AsyncSession, crisis_id: str) -> list[dict]:
    rows = (await session.execute(
        select(Incident.id, Incident.title, Incident.status).where(Incident.crisis_id == crisis_id)
    )).all()
    return [{"id": str(r[0]), "title": r[1], "status": r[2]} for r in rows]


async def _linked_incidents_by_crisis(session: AsyncSession, crisis_ids: list[str]) -> dict[str, list[dict]]:
    """Même contenu que `_linked_incidents`, mais une requête groupée pour toute une
    liste de crises (03/08/2026, revue de code) — `list_crises` en faisait une par
    ligne, même classe de bug que l'incident des ~265k vulns."""
    if not crisis_ids:
        return {}
    rows = (await session.execute(
        select(Incident.crisis_id, Incident.id, Incident.title, Incident.status)
        .where(Incident.crisis_id.in_(crisis_ids))
    )).all()
    by_crisis: dict[str, list[dict]] = {cid: [] for cid in crisis_ids}
    for crisis_id, inc_id, title, status in rows:
        by_crisis[str(crisis_id)].append({"id": str(inc_id), "title": title, "status": status})
    return by_crisis


def _crisis_dict(c: Crisis, linked_incidents: list[dict] | None = None) -> dict:
    return {
        "id": str(c.id),
        "title": c.title,
        "description": c.description,
        "status": c.status,
        "activated_at": c.activated_at.isoformat() if c.activated_at else None,
        "activated_by": c.activated_by,
        "stood_down_at": c.stood_down_at.isoformat() if c.stood_down_at else None,
        "stood_down_by": c.stood_down_by,
        "stand_down_justification": c.stand_down_justification,
        "crisis_roles": c.crisis_roles or [],
        "completed_crisis_steps": c.completed_crisis_steps or [],
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "linked_incidents": linked_incidents if linked_incidents is not None else [],
    }


def _contact_dict(c: CrisisContact) -> dict:
    return {
        "id": str(c.id),
        "name": c.name,
        "role": c.role,
        "email": c.email,
        "phone": c.phone,
        "website_url": c.website_url,
        "notes": c.notes,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


def _timeline_dict(e: CrisisTimelineEntry) -> dict:
    return {
        "id": str(e.id),
        "event_type": e.event_type,
        "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
        "author": e.author,
        "old_value": e.old_value,
        "new_value": e.new_value,
        "notes": e.notes,
        "meta": e.meta,
    }


# ─── Intervenants à prévenir ──────────────────────────────────────────────────
# ⚠️ Déclarées AVANT les routes /{crisis_id} ci-dessous (même ordre qu'incidents.py pour
# /notification-contacts avant /{incident_id}) : sinon FastAPI matcherait "contacts" comme
# un crisis_id sur GET/POST /crises/contacts.

@router.get("/contacts")
async def list_contacts(session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(select(CrisisContact).order_by(CrisisContact.name))).scalars().all()
    return {"items": [_contact_dict(c) for c in rows]}


@router.post("/contacts", status_code=201)
async def create_contact(data: ContactCreate, session: AsyncSession = Depends(get_session)):
    if not data.name.strip():
        raise HTTPException(400, "Le nom est obligatoire.")
    c = CrisisContact(
        name=data.name.strip(), role=data.role, email=data.email,
        phone=data.phone, website_url=data.website_url, notes=data.notes,
    )
    session.add(c)
    await session.commit()
    await session.refresh(c)
    return _contact_dict(c)


@router.patch("/contacts/{contact_id}")
async def update_contact(contact_id: str, data: ContactUpdate, session: AsyncSession = Depends(get_session)):
    c = await session.get(CrisisContact, contact_id)
    if not c:
        raise HTTPException(404, "Contact introuvable.")
    if data.name is not None:
        if not data.name.strip():
            raise HTTPException(400, "Le nom est obligatoire.")
        c.name = data.name.strip()
    if data.role is not None: c.role = data.role
    if data.email is not None: c.email = data.email
    if data.phone is not None: c.phone = data.phone
    if data.website_url is not None: c.website_url = data.website_url
    if data.notes is not None: c.notes = data.notes
    await session.commit()
    await session.refresh(c)
    return _contact_dict(c)


@router.delete("/contacts/{contact_id}", status_code=204)
async def delete_contact(contact_id: str, session: AsyncSession = Depends(get_session)):
    c = await session.get(CrisisContact, contact_id)
    if not c:
        raise HTTPException(404, "Contact introuvable.")
    await session.delete(c)
    await session.commit()


# ─── Liste / détail / création / édition ─────────────────────────────────────

@router.get("")
async def list_crises(
    status: Optional[str] = None,
    q: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
):
    query = select(Crisis).order_by(Crisis.activated_at.desc())
    if status:
        query = query.where(Crisis.status == status)
    rows = (await session.execute(query)).scalars().all()
    if q:
        needle = q.lower()
        rows = [c for c in rows if needle in (c.title or "").lower() or needle in (c.description or "").lower()]

    linked_by_crisis = await _linked_incidents_by_crisis(session, [str(c.id) for c in rows])
    items = [_crisis_dict(c, linked_by_crisis.get(str(c.id), [])) for c in rows]
    return {"total": len(items), "items": items}


@router.get("/{crisis_id}")
async def get_crisis(crisis_id: str, session: AsyncSession = Depends(get_session)):
    c = await _get_or_404(session, crisis_id)
    return _crisis_dict(c, await _linked_incidents(session, c.id))


@router.post("", status_code=201)
async def create_crisis(data: CrisisCreate, session: AsyncSession = Depends(get_session)):
    if not data.title.strip():
        raise HTTPException(400, "Titre obligatoire pour activer une crise.")
    if not data.activated_by.strip():
        raise HTTPException(400, "Analyste obligatoire pour activer une crise.")

    now = datetime.now(timezone.utc)
    c = Crisis(
        title=data.title.strip(),
        description=data.description,
        status="active",
        activated_at=now,
        activated_by=data.activated_by.strip(),
    )
    session.add(c)
    await session.flush()  # crisis.id posé avant l'entrée de timeline (FK)
    record_timeline(session, c.id, "activated", data.activated_by.strip(), new_value="active", notes=data.description)
    await session.commit()
    await session.refresh(c)
    return _crisis_dict(c, [])


@router.patch("/{crisis_id}")
async def update_crisis(crisis_id: str, data: CrisisUpdate, session: AsyncSession = Depends(get_session)):
    c = await _get_or_404(session, crisis_id)
    if data.title is not None:
        if not data.title.strip():
            raise HTTPException(400, "Titre obligatoire.")
        c.title = data.title.strip()
    if data.description is not None:
        c.description = data.description
    if data.completed_crisis_steps is not None:
        c.completed_crisis_steps = [
            {"index": s.index, "by": s.by, "at": (s.at or datetime.now(timezone.utc)).isoformat()}
            for s in data.completed_crisis_steps
        ]
    await session.commit()
    await session.refresh(c)
    return _crisis_dict(c, await _linked_incidents(session, c.id))


@router.delete("/{crisis_id}", status_code=204)
async def delete_crisis(crisis_id: str, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    """Suppression possible (crise déclarée par erreur/doublon) — même principe que
    DELETE /api/incidents/{id}. `crisis_id` sur les incidents liés repasse à NULL
    automatiquement (ON DELETE SET NULL), ils ne sont pas supprimés.
    Réservé admin (03/08/2026, audit sécurité) — même raison que delete_incident."""
    c = await _get_or_404(session, crisis_id)
    await session.delete(c)
    await session.commit()


@router.get("/{crisis_id}/timeline")
async def get_crisis_timeline(crisis_id: str, session: AsyncSession = Depends(get_session)):
    await _get_or_404(session, crisis_id)
    rows = (await session.execute(
        select(CrisisTimelineEntry).where(CrisisTimelineEntry.crisis_id == crisis_id)
        .order_by(CrisisTimelineEntry.occurred_at.asc())
    )).scalars().all()
    return {"entries": [_timeline_dict(e) for e in rows]}


# ─── Désactivation ────────────────────────────────────────────────────────────

@router.post("/{crisis_id}/stand-down")
async def stand_down(crisis_id: str, data: StandDownPayload, session: AsyncSession = Depends(get_session)):
    c = await _get_or_404(session, crisis_id)
    _guard(lambda: crisis_service.stand_down_crisis(session, c, data.analyst, data.justification))
    await session.commit()
    await session.refresh(c)
    return _crisis_dict(c, await _linked_incidents(session, c.id))


# ─── Cellule de crise ─────────────────────────────────────────────────────────

@router.post("/{crisis_id}/roles")
async def assign_role(crisis_id: str, data: RoleAssignPayload, session: AsyncSession = Depends(get_session)):
    c = await _get_or_404(session, crisis_id)
    _guard(lambda: crisis_service.assign_role(session, c, data.role, data.analyst_name, data.by))
    await session.commit()
    await session.refresh(c)
    return _crisis_dict(c, await _linked_incidents(session, c.id))


@router.delete("/{crisis_id}/roles/{role}")
async def remove_role(crisis_id: str, role: str, by: str = Query(...), session: AsyncSession = Depends(get_session)):
    c = await _get_or_404(session, crisis_id)
    _guard(lambda: crisis_service.remove_role(session, c, role, by))
    await session.commit()
    await session.refresh(c)
    return _crisis_dict(c, await _linked_incidents(session, c.id))


# ─── Incidents liés ───────────────────────────────────────────────────────────

@router.post("/{crisis_id}/incidents")
async def link_incident(crisis_id: str, data: LinkIncidentPayload, session: AsyncSession = Depends(get_session)):
    c = await _get_or_404(session, crisis_id)
    inc = await session.get(Incident, data.incident_id)
    if not inc:
        raise HTTPException(404, "Incident introuvable")
    _guard(lambda: crisis_service.link_incident(session, c, inc, data.by))
    await session.commit()
    return _crisis_dict(c, await _linked_incidents(session, c.id))


@router.delete("/{crisis_id}/incidents/{incident_id}")
async def unlink_incident(
    crisis_id: str, incident_id: str, by: str = Query(...), session: AsyncSession = Depends(get_session),
):
    c = await _get_or_404(session, crisis_id)
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "Incident introuvable")
    _guard(lambda: crisis_service.unlink_incident(session, c, inc, by))
    await session.commit()
    return _crisis_dict(c, await _linked_incidents(session, c.id))


# ─── Journal : décisions / communications ────────────────────────────────────

@router.post("/{crisis_id}/decisions")
async def add_decision(crisis_id: str, data: DecisionPayload, session: AsyncSession = Depends(get_session)):
    c = await _get_or_404(session, crisis_id)
    _guard(lambda: crisis_service.record_decision(session, c, data.author, data.content))
    await session.commit()
    rows = (await session.execute(
        select(CrisisTimelineEntry).where(CrisisTimelineEntry.crisis_id == crisis_id)
        .order_by(CrisisTimelineEntry.occurred_at.asc())
    )).scalars().all()
    return {"entries": [_timeline_dict(e) for e in rows]}


@router.post("/{crisis_id}/communications")
async def add_communication(crisis_id: str, data: CommunicationPayload, session: AsyncSession = Depends(get_session)):
    c = await _get_or_404(session, crisis_id)
    _guard(lambda: crisis_service.record_communication(session, c, data.author, data.content, data.audience))
    await session.commit()
    rows = (await session.execute(
        select(CrisisTimelineEntry).where(CrisisTimelineEntry.crisis_id == crisis_id)
        .order_by(CrisisTimelineEntry.occurred_at.asc())
    )).scalars().all()
    return {"entries": [_timeline_dict(e) for e in rows]}
