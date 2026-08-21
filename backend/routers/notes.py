"""
routers/notes.py
Module Documentation > Notes (12/08/2026) — prise de notes personnelle structurée
(Thème > Sujet en Markdown, cf. docs/Notes.md), qui remplace le glossaire plat
initial (terme/définition) le même jour. Trois ressources :
- `themes` : registre ouvert (CRUD calqué sur routers/document_types.py).
- `subjects` : fiches de cours en Markdown, rattachées à un thème.
- `images` : images insérées inline dans un sujet (glisser-déposer/upload), fichier
  sur disque + URL servie pour insertion `![alt](url)` côté frontend.

Accès protégé au niveau du router par require_page("/notes") (main.py), pas de
restriction admin en plus : notes personnelles, pas un registre d'organisation.
Propriété par utilisateur (21/08/2026, audit #39) : chaque compte ne voit et ne
modifie que ses propres thèmes/sujets/images — 404 en cas d'accès cross-user pour
ne pas révéler l'existence des objets d'autrui.
Phase 1 seulement (Thèmes/Sujets/Markdown/images) — pas de génération de QCM par IA
ici, reporté à plus tard (demande explicite de l'utilisateur).
"""

import os
import uuid as uuidlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_auth
from database import get_session
from models import NoteImage, NoteSubject, NoteTheme, User
from services.note_images import CONTENT_TYPES, NOTE_IMAGES_ROOT, ensure_note_images_dir, validate_note_image

router = APIRouter()


# ─── Schémas ──────────────────────────────────────────────────────────────────

class ThemeCreate(BaseModel):
    name: str
    icon: str = '📁'
    color: str = '#8b949e'


class ThemeUpdate(BaseModel):
    name: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = None


class SubjectCreate(BaseModel):
    theme_id: str
    title: str
    content_markdown: str = ''


class SubjectUpdate(BaseModel):
    theme_id: Optional[str] = None
    title: Optional[str] = None
    content_markdown: Optional[str] = None


def _theme_dict(t: NoteTheme, subject_count: int = None) -> dict:
    d = {
        "id": str(t.id), "name": t.name, "icon": t.icon, "color": t.color,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }
    if subject_count is not None:
        d["subject_count"] = subject_count
    return d


def _subject_dict(s: NoteSubject) -> dict:
    return {
        "id": str(s.id), "theme_id": str(s.theme_id), "title": s.title,
        "content_markdown": s.content_markdown,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
    }


# ─── Thèmes ───────────────────────────────────────────────────────────────────

@router.get("/themes")
async def list_themes(user: User = Depends(require_auth), session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(NoteTheme).where(NoteTheme.user_id == user.id).order_by(NoteTheme.name)
    )).scalars().all()
    theme_ids = [t.id for t in rows]
    counts: dict = {}
    if theme_ids:
        counts = dict((await session.execute(
            select(NoteSubject.theme_id, func.count())
            .where(NoteSubject.theme_id.in_(theme_ids))
            .group_by(NoteSubject.theme_id)
        )).all())
    return {"items": [_theme_dict(t, counts.get(t.id, 0)) for t in rows]}


@router.post("/themes", status_code=201)
async def create_theme(data: ThemeCreate, user: User = Depends(require_auth), session: AsyncSession = Depends(get_session)):
    name = data.name.strip()
    if not name:
        raise HTTPException(400, "Le nom est obligatoire.")
    existing = (await session.execute(
        select(NoteTheme).where(NoteTheme.name == name, NoteTheme.user_id == user.id)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Un thème porte déjà ce nom.")
    theme = NoteTheme(user_id=user.id, name=name, icon=data.icon.strip() or '📁', color=data.color.strip() or '#8b949e')
    session.add(theme)
    await session.commit()
    await session.refresh(theme)
    return _theme_dict(theme, 0)


@router.patch("/themes/{theme_id}")
async def update_theme(theme_id: str, data: ThemeUpdate, user: User = Depends(require_auth), session: AsyncSession = Depends(get_session)):
    theme = await session.get(NoteTheme, theme_id)
    if not theme or theme.user_id != user.id:
        raise HTTPException(404, "Thème introuvable.")
    if data.name is not None:
        name = data.name.strip()
        if not name:
            raise HTTPException(400, "Le nom est obligatoire.")
        existing = (await session.execute(
            select(NoteTheme).where(NoteTheme.name == name, NoteTheme.user_id == user.id, NoteTheme.id != theme_id)
        )).scalar_one_or_none()
        if existing:
            raise HTTPException(409, "Un thème porte déjà ce nom.")
        theme.name = name
    if data.icon is not None:
        theme.icon = data.icon.strip() or theme.icon
    if data.color is not None:
        theme.color = data.color.strip() or theme.color
    await session.commit()
    await session.refresh(theme)
    return _theme_dict(theme)


@router.delete("/themes/{theme_id}", status_code=204)
async def delete_theme(theme_id: str, user: User = Depends(require_auth), session: AsyncSession = Depends(get_session)):
    theme = await session.get(NoteTheme, theme_id)
    if not theme or theme.user_id != user.id:
        raise HTTPException(404, "Thème introuvable.")
    existing_subject = (await session.execute(
        select(NoteSubject.id).where(NoteSubject.theme_id == theme_id).limit(1)
    )).scalar_one_or_none()
    if existing_subject:
        raise HTTPException(409, "Ce thème contient encore des sujets — supprimez-les d'abord.")
    await session.delete(theme)
    await session.commit()


# ─── Sujets ───────────────────────────────────────────────────────────────────

@router.get("/subjects")
async def list_subjects(theme_id: Optional[str] = None, user: User = Depends(require_auth), session: AsyncSession = Depends(get_session)):
    # content_markdown inclus (pour l'aperçu texte de la carte côté frontend) : usage
    # personnel, quelques dizaines de sujets attendus, pas le volume qui justifierait de
    # l'exclure comme raw_data sur les CVE (cf. cpe_matcher.py::run_cpe_matching).
    query = select(NoteSubject).where(NoteSubject.user_id == user.id).order_by(NoteSubject.updated_at.desc())
    if theme_id:
        query = query.where(NoteSubject.theme_id == theme_id)
    rows = (await session.execute(query)).scalars().all()
    return {"items": [_subject_dict(s) for s in rows]}


@router.get("/subjects/{subject_id}")
async def get_subject(subject_id: str, user: User = Depends(require_auth), session: AsyncSession = Depends(get_session)):
    subject = await session.get(NoteSubject, subject_id)
    if not subject or subject.user_id != user.id:
        raise HTTPException(404, "Sujet introuvable.")
    return _subject_dict(subject)


@router.post("/subjects", status_code=201)
async def create_subject(data: SubjectCreate, user: User = Depends(require_auth), session: AsyncSession = Depends(get_session)):
    title = data.title.strip()
    if not title:
        raise HTTPException(400, "Le titre est obligatoire.")
    theme = await session.get(NoteTheme, data.theme_id)
    if not theme or theme.user_id != user.id:
        raise HTTPException(404, "Thème introuvable.")
    subject = NoteSubject(user_id=user.id, theme_id=data.theme_id, title=title, content_markdown=data.content_markdown or '')
    session.add(subject)
    await session.commit()
    await session.refresh(subject)
    return _subject_dict(subject)


@router.patch("/subjects/{subject_id}")
async def update_subject(subject_id: str, data: SubjectUpdate, user: User = Depends(require_auth), session: AsyncSession = Depends(get_session)):
    subject = await session.get(NoteSubject, subject_id)
    if not subject or subject.user_id != user.id:
        raise HTTPException(404, "Sujet introuvable.")
    if data.theme_id is not None:
        theme = await session.get(NoteTheme, data.theme_id)
        if not theme or theme.user_id != user.id:
            raise HTTPException(404, "Thème introuvable.")
        subject.theme_id = data.theme_id
    if data.title is not None:
        title = data.title.strip()
        if not title:
            raise HTTPException(400, "Le titre est obligatoire.")
        subject.title = title
    if data.content_markdown is not None:
        subject.content_markdown = data.content_markdown
    subject.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(subject)
    return _subject_dict(subject)


@router.delete("/subjects/{subject_id}", status_code=204)
async def delete_subject(subject_id: str, user: User = Depends(require_auth), session: AsyncSession = Depends(get_session)):
    subject = await session.get(NoteSubject, subject_id)
    if not subject or subject.user_id != user.id:
        raise HTTPException(404, "Sujet introuvable.")
    # Nettoyage disque (18/08/2026, cf. audit/AUDIT_SECURITE.md #36) — `NoteImage.
    # subject_id` a `ondelete="CASCADE"` : supprimer un sujet efface les lignes en base,
    # mais jamais les fichiers sur disque (le cascade DB ne touche pas au volume Docker
    # `note_images`). Fait ici AVANT `session.delete(subject)`, pas après : une fois le
    # cascade DB exécuté, les lignes NoteImage de ce sujet n'existent plus pour lister
    # quels fichiers effacer.
    images = (await session.execute(
        select(NoteImage).where(NoteImage.subject_id == subject_id)
    )).scalars().all()
    for image in images:
        path = os.path.join(NOTE_IMAGES_ROOT, image.stored_filename)
        if os.path.isfile(path):
            os.remove(path)
    await session.delete(subject)
    await session.commit()


# ─── Images ───────────────────────────────────────────────────────────────────

@router.post("/images", status_code=201)
async def upload_image(
    file: UploadFile = File(...),
    subject_id: Optional[str] = Form(None),
    user: User = Depends(require_auth),
    session: AsyncSession = Depends(get_session),
):
    if subject_id:
        subject = await session.get(NoteSubject, subject_id)
        if not subject or subject.user_id != user.id:
            raise HTTPException(404, "Sujet introuvable.")

    content = await file.read()
    try:
        ext = validate_note_image(content, file.filename or "")
    except ValueError as e:
        raise HTTPException(400, str(e))

    stored_filename = f"{uuidlib.uuid4()}{ext}"
    dir_path = ensure_note_images_dir()
    with open(os.path.join(dir_path, stored_filename), "wb") as f:
        f.write(content)

    image = NoteImage(
        user_id=user.id, subject_id=subject_id or None,
        filename=file.filename, stored_filename=stored_filename,
        size_bytes=len(content), uploaded_at=datetime.now(timezone.utc),
    )
    session.add(image)
    await session.commit()
    await session.refresh(image)
    return {"id": str(image.id), "url": f"/api/notes/images/{image.id}/file"}


@router.get("/images/{image_id}/file")
async def get_image_file(image_id: str, user: User = Depends(require_auth), session: AsyncSession = Depends(get_session)):
    image = await session.get(NoteImage, image_id)
    if not image or image.user_id != user.id:
        raise HTTPException(404, "Image introuvable")
    path = os.path.join(NOTE_IMAGES_ROOT, image.stored_filename)
    if not os.path.isfile(path):
        raise HTTPException(404, "Fichier introuvable sur le disque")
    ext = os.path.splitext(image.stored_filename)[1]
    return FileResponse(path, media_type=CONTENT_TYPES.get(ext, "application/octet-stream"), content_disposition_type="inline")


@router.delete("/images/{image_id}", status_code=204)
async def delete_note_image(image_id: str, user: User = Depends(require_auth), session: AsyncSession = Depends(get_session)):
    """18/08/2026, cf. audit/AUDIT_SECURITE.md #36 — n'existait pas jusqu'ici, contrairement
    aux trois modules frères (documents.py, incidents.py, audits.py, qui font tous ce même
    os.remove + session.delete) : tout compte avec accès /notes pouvait uploader des images
    (5 Mo chacune, sans limite de nombre) sans jamais pouvoir en récupérer une seule —
    accumulation illimitée dans le volume note_images, sans mécanisme de purge."""
    image = await session.get(NoteImage, image_id)
    if not image or image.user_id != user.id:
        raise HTTPException(404, "Image introuvable.")
    path = os.path.join(NOTE_IMAGES_ROOT, image.stored_filename)
    if os.path.isfile(path):
        os.remove(path)
    await session.delete(image)
    await session.commit()
