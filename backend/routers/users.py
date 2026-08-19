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

from auth_deps import require_admin
from database import get_session
from models import Analyst, PasswordResetRequest, User, UserSession
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


class ResolvePasswordReset(BaseModel):
    new_password: str


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


# ─── « Mot de passe oublié » (18/08/2026) ────────────────────────────────────────────
# Demandes créées publiquement depuis Login.jsx (cf. routers/auth.py::forgot_password) —
# visibles ici, traitées manuellement par un admin (pas d'infra SMTP, cf. docstring
# de ce module). Router déjà admin-only au niveau de main.py, rien à ajouter ici.

def _reset_request_dict(r: PasswordResetRequest, u: Optional[User]) -> dict:
    return {
        "id": str(r.id),
        "user_id": str(r.user_id),
        "email": u.email if u else None,
        "full_name": u.full_name if u else None,
        "message": r.message,
        "status": r.status,
        "requested_at": r.requested_at.isoformat() if r.requested_at else None,
    }


@router.get("/password-reset-requests")
async def list_password_reset_requests(session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(PasswordResetRequest, User)
        .join(User, PasswordResetRequest.user_id == User.id)
        .where(PasswordResetRequest.status == "pending")
        .order_by(PasswordResetRequest.requested_at.desc())
    )).all()
    return {"items": [_reset_request_dict(r, u) for r, u in rows]}


# Compteur léger pour le badge de l'onglet Utilisateurs (Administration) — même mécanique
# que securityEventsCount()/nis2_pending_count ailleurs dans l'app.
@router.get("/password-reset-requests/count")
async def password_reset_requests_count(session: AsyncSession = Depends(get_session)):
    total = (await session.execute(
        select(func.count()).select_from(PasswordResetRequest).where(PasswordResetRequest.status == "pending")
    )).scalar_one()
    return {"pending": total}


@router.post("/password-reset-requests/{request_id}/resolve")
async def resolve_password_reset_request(
    request_id: str, data: ResolvePasswordReset,
    admin: User = Depends(require_admin), session: AsyncSession = Depends(get_session),
):
    """L'admin fixe lui-même le mot de passe provisoire (comme il le fait déjà à la
    création d'un compte, cf. UserFormModal.jsx) — communiqué à l'utilisateur hors
    application (oral, chat interne...). `must_change_password` forcé dans la foulée :
    l'utilisateur choisit son propre mot de passe définitif à sa prochaine connexion,
    via l'écran de changement forcé déjà existant (ProtectedRoute.jsx).

    `with_for_update()` (18/08/2026, cf. audit/AUDIT_SECURITE.md #23) : sans verrou de
    ligne, deux admins traitant la même demande à la même seconde passent tous deux le
    contrôle `status != "pending"` avant que l'un des deux ne commite — le second mot de
    passe écrase le premier sans erreur pour aucun des deux (impact faible, 5 comptes max,
    mais réel). Le verrou sérialise : le second admin voit `status="resolved"` à jour une
    fois son tour venu, et reçoit le 404 attendu au lieu d'écraser silencieusement.

    Sessions révoquées après remise à zéro (#21) : sans ça, un cookie de session volé pour
    ce compte restait valide après la remise à zéro (juste restreint aux 3 routes autorisées
    tant que `must_change_password` est vrai) et redevenait pleinement valide dès que
    l'utilisateur légitime changeait son mot de passe — exactement le scénario que ce flow
    est censé couvrir (perte d'appareil, session compromise). `revoke_sessions` ci-dessus
    fait déjà ce même DELETE pour l'action admin équivalente."""
    req = (await session.execute(
        select(PasswordResetRequest).where(PasswordResetRequest.id == request_id).with_for_update()
    )).scalar_one_or_none()
    if not req or req.status != "pending":
        raise HTTPException(404, "Demande introuvable ou déjà traitée.")
    user = await session.get(User, req.user_id)
    if not user:
        raise HTTPException(404, "Compte introuvable.")
    validate_password_strength(data.new_password)
    user.password_hash = hash_password(data.new_password)
    user.must_change_password = True
    user.updated_at = datetime.now(timezone.utc)
    await session.execute(delete(UserSession).where(UserSession.user_id == user.id))
    req.status = "resolved"
    req.resolved_at = datetime.now(timezone.utc)
    req.resolved_by = admin.full_name
    await session.commit()
    return {"resolved": True}


@router.post("/password-reset-requests/{request_id}/dismiss")
async def dismiss_password_reset_request(
    request_id: str, admin: User = Depends(require_admin), session: AsyncSession = Depends(get_session),
):
    """Rejette une demande sans toucher au mot de passe (doublon, erreur, demande non
    fondée...) — reste consultable en base (status=dismissed) plutôt que supprimée.
    `with_for_update()` : même garde-fou de course que `resolve_password_reset_request`
    ci-dessus (#23), moins critique ici (aucune donnée écrasée) mais même cohérence."""
    req = (await session.execute(
        select(PasswordResetRequest).where(PasswordResetRequest.id == request_id).with_for_update()
    )).scalar_one_or_none()
    if not req or req.status != "pending":
        raise HTTPException(404, "Demande introuvable ou déjà traitée.")
    req.status = "dismissed"
    req.resolved_at = datetime.now(timezone.utc)
    req.resolved_by = admin.full_name
    await session.commit()
    return {"dismissed": True}
