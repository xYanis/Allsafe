"""
routers/windows_app_mappings.py
Correspondance nom d'application Windows -> produit CPE (cf. models.py::WindowsAppMapping).
CRUD simple, même pattern que routers/analysts.py : lecture ouverte à tout utilisateur
connecté (`require_auth`, posé au niveau du router dans main.py) — le matching CPE
(`services/cpe_matcher.py`) en a besoin en lecture pour toutes les vulns, pas seulement
côté admin. L'écriture (POST/PATCH/DELETE) est réservée admin, gérée depuis
Administration > onglet Correspondances Windows.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_admin
from database import get_session
from models import WindowsAppMapping

router = APIRouter()


class WindowsAppMappingCreate(BaseModel):
    pattern: str
    cpe_product: str
    cpe_vendor: Optional[str] = None


class WindowsAppMappingUpdate(BaseModel):
    pattern: Optional[str] = None
    cpe_product: Optional[str] = None
    cpe_vendor: Optional[str] = None


def _dict(m: WindowsAppMapping) -> dict:
    return {
        "id": str(m.id),
        "pattern": m.pattern,
        "cpe_product": m.cpe_product,
        "cpe_vendor": m.cpe_vendor,
        "created_at": m.created_at.isoformat() if m.created_at else None,
    }


@router.get("")
async def list_mappings(session: AsyncSession = Depends(get_session)):
    rows = (
        await session.execute(select(WindowsAppMapping).order_by(WindowsAppMapping.pattern))
    ).scalars().all()
    return {"items": [_dict(m) for m in rows]}


@router.post("", status_code=201)
async def create_mapping(
    data: WindowsAppMappingCreate,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(require_admin),
):
    pattern = data.pattern.strip().lower()
    product = data.cpe_product.strip().lower()
    if not pattern:
        raise HTTPException(400, "Le motif est obligatoire.")
    if not product:
        raise HTTPException(400, "Le produit CPE est obligatoire.")
    existing = (
        await session.execute(select(WindowsAppMapping).where(WindowsAppMapping.pattern == pattern))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Ce motif est déjà mappé.")
    mapping = WindowsAppMapping(
        pattern=pattern,
        cpe_product=product,
        cpe_vendor=(data.cpe_vendor or "").strip() or None,
    )
    session.add(mapping)
    await session.commit()
    await session.refresh(mapping)
    return _dict(mapping)


@router.patch("/{mapping_id}")
async def update_mapping(
    mapping_id: str,
    data: WindowsAppMappingUpdate,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(require_admin),
):
    mapping = await session.get(WindowsAppMapping, mapping_id)
    if not mapping:
        raise HTTPException(404, "Correspondance introuvable.")
    if data.pattern is not None:
        pattern = data.pattern.strip().lower()
        if not pattern:
            raise HTTPException(400, "Le motif est obligatoire.")
        existing = (
            await session.execute(
                select(WindowsAppMapping).where(
                    WindowsAppMapping.pattern == pattern, WindowsAppMapping.id != mapping_id
                )
            )
        ).scalar_one_or_none()
        if existing:
            raise HTTPException(409, "Ce motif est déjà mappé.")
        mapping.pattern = pattern
    if data.cpe_product is not None:
        product = data.cpe_product.strip().lower()
        if not product:
            raise HTTPException(400, "Le produit CPE est obligatoire.")
        mapping.cpe_product = product
    if data.cpe_vendor is not None:
        mapping.cpe_vendor = data.cpe_vendor.strip() or None
    await session.commit()
    await session.refresh(mapping)
    return _dict(mapping)


@router.delete("/{mapping_id}", status_code=204)
async def delete_mapping(
    mapping_id: str,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(require_admin),
):
    mapping = await session.get(WindowsAppMapping, mapping_id)
    if not mapping:
        raise HTTPException(404, "Correspondance introuvable.")
    await session.delete(mapping)
    await session.commit()
