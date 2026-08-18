"""
routers/release_notes.py
Notes de version (18/08/2026, demande explicite, cf. models.py::ReleaseNote) — deux portées
(`scope`) dans la même table : `allsafe` (page Paramètres) et `agent` (page dédiée, Sécurité >
Agents). Même convention que routers/services.py : lecture ouverte à tout connecté, écriture
réservée admin.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_admin
from database import get_session
from models import ReleaseNote

router = APIRouter()

VALID_SCOPES = {"allsafe", "agent"}
VALID_CATEGORIES = {"feature", "fix"}


class ReleaseNoteCreate(BaseModel):
    scope: str
    version: Optional[str] = None
    category: str = "feature"
    title: str
    description: Optional[str] = None
    created_by: Optional[str] = None


class ReleaseNoteUpdate(BaseModel):
    version: Optional[str] = None
    category: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None


def _dict(n: ReleaseNote) -> dict:
    return {
        "id": str(n.id),
        "scope": n.scope,
        "version": n.version,
        "category": n.category,
        "title": n.title,
        "description": n.description,
        "created_by": n.created_by,
        "created_at": n.created_at.isoformat() if n.created_at else None,
    }


@router.get("")
async def list_release_notes(
    scope: str = Query(..., description="'allsafe' ou 'agent'"),
    session: AsyncSession = Depends(get_session),
):
    if scope not in VALID_SCOPES:
        raise HTTPException(400, "scope invalide (attendu : allsafe ou agent).")
    rows = (await session.execute(
        select(ReleaseNote).where(ReleaseNote.scope == scope).order_by(ReleaseNote.created_at.desc())
    )).scalars().all()
    return {"items": [_dict(n) for n in rows]}


@router.post("", status_code=201)
async def create_release_note(data: ReleaseNoteCreate, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    if data.scope not in VALID_SCOPES:
        raise HTTPException(400, "scope invalide (attendu : allsafe ou agent).")
    if data.category not in VALID_CATEGORIES:
        raise HTTPException(400, "category invalide (attendu : feature ou fix).")
    title = data.title.strip()
    if not title:
        raise HTTPException(400, "Le titre est obligatoire.")
    note = ReleaseNote(
        scope=data.scope, version=(data.version or None), category=data.category,
        title=title, description=(data.description or None), created_by=(data.created_by or None),
    )
    session.add(note)
    await session.commit()
    await session.refresh(note)
    return _dict(note)


@router.patch("/{note_id}")
async def update_release_note(note_id: str, data: ReleaseNoteUpdate, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    note = await session.get(ReleaseNote, note_id)
    if not note:
        raise HTTPException(404, "Note introuvable.")
    if data.category is not None and data.category not in VALID_CATEGORIES:
        raise HTTPException(400, "category invalide (attendu : feature ou fix).")
    if data.title is not None:
        title = data.title.strip()
        if not title:
            raise HTTPException(400, "Le titre est obligatoire.")
        note.title = title
    if data.version is not None:
        note.version = data.version or None
    if data.category is not None:
        note.category = data.category
    if data.description is not None:
        note.description = data.description or None
    await session.commit()
    await session.refresh(note)
    return _dict(note)


@router.delete("/{note_id}", status_code=204)
async def delete_release_note(note_id: str, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    note = await session.get(ReleaseNote, note_id)
    if not note:
        raise HTTPException(404, "Note introuvable.")
    await session.delete(note)
    await session.commit()
