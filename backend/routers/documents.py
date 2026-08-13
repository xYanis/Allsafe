"""
routers/documents.py
Module Documentation (31/07/2026, conformité NIS 2) — documents de gouvernance (PSSI, chartes,
organigramme...). Deux ressources :
- `document-types` : registre ouvert des types de documents (CRUD calqué sur routers/analysts.py
  — lecture ouverte, écriture admin).
- `documents` : fichiers uploadés, groupés par type. Pas de table de versions séparée : chaque
  upload crée une nouvelle ligne, triée par `uploaded_at desc` — la plus récente est la version
  courante, les autres forment l'historique (cf. models.py::Document).

Aucun endpoint de suppression de type n'efface les documents existants : la FK
`Document.document_type_id` n'a pas de `ondelete`, Postgres refuse la suppression tant que des
documents y sont rattachés — interceptée ici en 409 plutôt que de laisser remonter une erreur SQL.
"""

import os
import uuid as uuidlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_admin
from database import get_session
from models import Document, DocumentType
from services.document_storage import (
    ensure_document_type_dir, document_type_dir, validate_document, CONTENT_TYPES, PREVIEWABLE,
)

router = APIRouter()


# ─── Schémas ──────────────────────────────────────────────────────────────────

class DocumentTypeCreate(BaseModel):
    name: str


class DocumentTypeUpdate(BaseModel):
    name: Optional[str] = None


def _type_dict(t: DocumentType) -> dict:
    return {
        "id": str(t.id),
        "name": t.name,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


def _document_dict(d: Document) -> dict:
    return {
        "id": str(d.id),
        "document_type_id": str(d.document_type_id),
        "filename": d.filename,
        "size_bytes": d.size_bytes,
        "uploaded_by": d.uploaded_by,
        "notes": d.notes,
        "uploaded_at": d.uploaded_at.isoformat() if d.uploaded_at else None,
    }


# ─── Types de documents ───────────────────────────────────────────────────────

@router.get("/document-types")
async def list_document_types(session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(select(DocumentType).order_by(DocumentType.name))).scalars().all()
    return {"items": [_type_dict(t) for t in rows]}


@router.post("/document-types", status_code=201)
async def create_document_type(data: DocumentTypeCreate, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    name = data.name.strip()
    if not name:
        raise HTTPException(400, "Le nom est obligatoire.")
    existing = (await session.execute(select(DocumentType).where(DocumentType.name == name))).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Un type de document porte déjà ce nom.")
    doc_type = DocumentType(name=name)
    session.add(doc_type)
    await session.commit()
    await session.refresh(doc_type)
    return _type_dict(doc_type)


@router.patch("/document-types/{type_id}")
async def update_document_type(type_id: str, data: DocumentTypeUpdate, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    doc_type = await session.get(DocumentType, type_id)
    if not doc_type:
        raise HTTPException(404, "Type de document introuvable.")
    if data.name is not None:
        name = data.name.strip()
        if not name:
            raise HTTPException(400, "Le nom est obligatoire.")
        existing = (await session.execute(
            select(DocumentType).where(DocumentType.name == name, DocumentType.id != type_id)
        )).scalar_one_or_none()
        if existing:
            raise HTTPException(409, "Un type de document porte déjà ce nom.")
        doc_type.name = name
    await session.commit()
    await session.refresh(doc_type)
    return _type_dict(doc_type)


@router.delete("/document-types/{type_id}", status_code=204)
async def delete_document_type(type_id: str, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    doc_type = await session.get(DocumentType, type_id)
    if not doc_type:
        raise HTTPException(404, "Type de document introuvable.")
    existing_doc = (await session.execute(
        select(Document.id).where(Document.document_type_id == type_id).limit(1)
    )).scalar_one_or_none()
    if existing_doc:
        raise HTTPException(409, "Ce type contient encore des documents — supprimez-les d'abord.")
    try:
        await session.delete(doc_type)
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(409, "Ce type contient encore des documents — supprimez-les d'abord.")


# ─── Documents ────────────────────────────────────────────────────────────────

@router.get("/documents")
async def list_documents(document_type_id: Optional[str] = None, session: AsyncSession = Depends(get_session)):
    query = select(Document).order_by(Document.uploaded_at.desc())
    if document_type_id:
        query = query.where(Document.document_type_id == document_type_id)
    rows = (await session.execute(query)).scalars().all()
    return {"items": [_document_dict(d) for d in rows]}


@router.post("/documents", status_code=201)
async def upload_document(
    file: UploadFile = File(...),
    document_type_id: str = Form(...),
    uploaded_by: str = Form(...),
    notes: Optional[str] = Form(None),
    session: AsyncSession = Depends(get_session),
    _admin=Depends(require_admin),
):
    doc_type = await session.get(DocumentType, document_type_id)
    if not doc_type:
        raise HTTPException(404, "Type de document introuvable.")

    content = await file.read()
    try:
        ext = validate_document(content, file.filename or "")
    except ValueError as e:
        raise HTTPException(400, str(e))

    stored_filename = f"{uuidlib.uuid4()}{ext}"
    dir_path = ensure_document_type_dir(document_type_id)
    with open(os.path.join(dir_path, stored_filename), "wb") as f:
        f.write(content)

    document = Document(
        document_type_id=document_type_id, filename=file.filename, stored_filename=stored_filename,
        size_bytes=len(content), uploaded_by=uploaded_by, notes=(notes or "").strip() or None,
        uploaded_at=datetime.now(timezone.utc),
    )
    session.add(document)
    await session.commit()
    await session.refresh(document)
    return _document_dict(document)


@router.get("/documents/{document_id}/download")
async def download_document(document_id: str, session: AsyncSession = Depends(get_session)):
    document = await session.get(Document, document_id)
    if not document:
        raise HTTPException(404, "Document introuvable")
    path = os.path.join(document_type_dir(str(document.document_type_id)), document.stored_filename)
    if not os.path.isfile(path):
        raise HTTPException(404, "Fichier introuvable sur le disque")
    ext = os.path.splitext(document.stored_filename)[1]
    return FileResponse(
        path, filename=document.filename,
        media_type=CONTENT_TYPES.get(ext, "application/octet-stream"),
        # inline : le navigateur affiche PDF/images directement (prévisualisation) ; attachment
        # pour Word/Excel — aucune API web ne peut ouvrir l'appli native depuis une page, le
        # téléchargement + double-clic côté OS reste le seul chemin pour ces formats.
        content_disposition_type="inline" if ext in PREVIEWABLE else "attachment",
    )


@router.delete("/documents/{document_id}", status_code=204)
async def delete_document(document_id: str, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    document = await session.get(Document, document_id)
    if not document:
        raise HTTPException(404, "Document introuvable")
    path = os.path.join(document_type_dir(str(document.document_type_id)), document.stored_filename)
    await session.delete(document)
    await session.commit()
    if os.path.isfile(path):
        os.remove(path)
