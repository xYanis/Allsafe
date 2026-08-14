"""
routers/users.py
CRUD des comptes utilisateurs — réservé au rôle admin (`dependencies=[Depends(require_admin)]`
posé au niveau du router dans main.py, pas besoin de le redéclarer sur chaque route ici).
Pas de reset de mot de passe par email (aucune infra SMTP dans ce projet on-prem) : un admin
force `must_change_password=true`, l'utilisateur choisit son nouveau mot de passe à la
prochaine connexion (cf. routers/auth.py::change_password).
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from models import Analyst, User, UserSession
from services.access_control import PAGE_KEYS
from services.auth import hash_password, validate_password_strength

router = APIRouter()

# Plafond de comptes créables (12/08/2026, demande utilisateur) — compte tous les
# comptes existants, actifs ou désactivés (un compte désactivé occupe toujours une
# place ; le supprimer en libère une). Purement un plafond de création, ne bloque ni
# la connexion ni la modification d'un compte déjà existant.
MAX_USERS = 5


class UserCreate(BaseModel):
    email: str
    full_name: str
    password: str
    role: str = "analyst"
    allowed_pages: Optional[list[str]] = None  # None = accès total (défaut)


class UserUpdate(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    force_password_reset: Optional[bool] = None
    allowed_pages: Optional[list[str]] = None
    grant_full_access: bool = False  # distingue "champ absent" de "retour à l'accès total"


def _dict(u: User) -> dict:
    return {
        "id": str(u.id),
        "email": u.email,
        "full_name": u.full_name,
        "role": u.role,
        "is_active": u.is_active,
        "must_change_password": u.must_change_password,
        "allowed_pages": u.allowed_pages,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


def _validate_allowed_pages(pages: Optional[list[str]]) -> None:
    if pages is None:
        return
    unknown = set(pages) - PAGE_KEYS
    if unknown:
        raise HTTPException(400, f"Page(s) inconnue(s) : {', '.join(sorted(unknown))}")


async def _ensure_analyst(session: AsyncSession, full_name: str) -> None:
    """Auto-intègre un compte créé au registre Analystes (31/07/2026, demande utilisateur) —
    best-effort, ne fusionne pas les deux tables (cf. models.py::User docstring) : juste un
    raccourci pour ne pas avoir à l'ajouter deux fois. Silencieux si un analyste porte déjà
    ce nom exact (pas de doublon, pas d'écrasement)."""
    name = full_name.strip()
    existing = (await session.execute(select(Analyst).where(Analyst.name == name))).scalar_one_or_none()
    if not existing:
        session.add(Analyst(name=name))


@router.get("")
async def list_users(session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(select(User).order_by(User.full_name))).scalars().all()
    return {"items": [_dict(u) for u in rows]}


@router.post("", status_code=201)
async def create_user(data: UserCreate, session: AsyncSession = Depends(get_session)):
    email = data.email.strip().lower()
    if not email or not data.full_name.strip():
        raise HTTPException(400, "Email et nom sont obligatoires.")
    if data.role not in ("admin", "analyst"):
        raise HTTPException(400, "Rôle invalide.")
    validate_password_strength(data.password)
    _validate_allowed_pages(data.allowed_pages)
    existing = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Un compte existe déjà avec cet email.")
    user_count = (await session.execute(select(func.count()).select_from(User))).scalar_one()
    if user_count >= MAX_USERS:
        raise HTTPException(403, f"Nombre maximum de comptes atteint ({MAX_USERS}).")
    user = User(
        email=email, full_name=data.full_name.strip(), role=data.role,
        password_hash=hash_password(data.password), must_change_password=True,
        allowed_pages=data.allowed_pages,
    )
    session.add(user)
    await _ensure_analyst(session, data.full_name)
    await session.commit()
    await session.refresh(user)
    return _dict(user)


@router.patch("/{user_id}")
async def update_user(user_id: str, data: UserUpdate, session: AsyncSession = Depends(get_session)):
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(404, "Compte introuvable.")
    if data.email is not None:
        email = data.email.strip().lower()
        if not email:
            raise HTTPException(400, "L'email est obligatoire.")
        existing = (await session.execute(
            select(User).where(User.email == email, User.id != user_id)
        )).scalar_one_or_none()
        if existing:
            raise HTTPException(409, "Un compte existe déjà avec cet email.")
        user.email = email
    if data.full_name is not None:
        if not data.full_name.strip():
            raise HTTPException(400, "Le nom est obligatoire.")
        user.full_name = data.full_name.strip()
    if data.role is not None:
        if data.role not in ("admin", "analyst"):
            raise HTTPException(400, "Rôle invalide.")
        user.role = data.role
    if data.is_active is not None:
        user.is_active = data.is_active
    if data.force_password_reset:
        user.must_change_password = True
    if data.grant_full_access:
        user.allowed_pages = None
    elif data.allowed_pages is not None:
        _validate_allowed_pages(data.allowed_pages)
        user.allowed_pages = data.allowed_pages
    user.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(user)
    return _dict(user)


@router.delete("/{user_id}", status_code=204)
async def delete_user(user_id: str, session: AsyncSession = Depends(get_session)):
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(404, "Compte introuvable.")
    await session.delete(user)
    await session.commit()


@router.post("/{user_id}/revoke-sessions")
async def revoke_sessions(user_id: str, session: AsyncSession = Depends(get_session)):
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(404, "Compte introuvable.")
    await session.execute(delete(UserSession).where(UserSession.user_id == user_id))
    await session.commit()
    return {"revoked": True}
