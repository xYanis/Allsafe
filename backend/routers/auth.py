"""
routers/auth.py
Login/logout/session courante — seul router de `/api/*` sans dependency d'auth globale
(le login doit rester public). `/logout`, `/me`, `/change-password` se protègent
individuellement via `Depends(require_auth)` sur la route, cf. main.py.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import SESSION_COOKIE_NAME, require_auth
from config import settings
from database import get_session
from models import PasswordResetRequest, User, UserSession
from services.auth import (
    MAX_CONCURRENT_SESSIONS,
    _hash_token,
    count_active_sessions,
    count_recent_failures,
    create_session,
    delete_session,
    hash_password,
    is_locked_out,
    record_audit,
    validate_password_strength,
    verify_password,
)

router = APIRouter()

# Alignés sur services/auth.py::SESSION_TTL (8h) — cohérent entre la durée de vie
# serveur de la session et celle du cookie qui la porte.
COOKIE_MAX_AGE = 8 * 3600


def _client_ip(request: Request) -> str:
    return (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.headers.get("X-Real-IP", "")
        or (request.client.host if request.client else "unknown")
    )


class LoginPayload(BaseModel):
    email: str
    password: str


class ForgotPasswordPayload(BaseModel):
    email: str
    message: str | None = None


class ChangePasswordPayload(BaseModel):
    current_password: str
    new_password: str


class ChangeEmailPayload(BaseModel):
    current_password: str
    new_email: str


@router.post("/login")
async def login(payload: LoginPayload, request: Request, response: Response,
                 session: AsyncSession = Depends(get_session)):
    email = payload.email.strip().lower()
    ip = _client_ip(request)
    user_agent = request.headers.get("User-Agent", "")[:512]

    if await is_locked_out(session, email, ip):
        await record_audit(session, "LOGIN_FAILED", email_attempt=email, ip_address=ip,
                            user_agent=user_agent, details={"reason": "lockout"})
        await session.commit()
        raise HTTPException(429, "Trop de tentatives — réessayez dans quelques minutes.")

    user = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()

    # Message générique identique dans tous les cas (mauvais mot de passe, compte
    # inexistant ou désactivé) — pas d'énumération de comptes par le contenu de la réponse.
    generic_error = HTTPException(401, "Email ou mot de passe incorrect.")

    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        await record_audit(session, "LOGIN_FAILED", user_id=user.id if user else None,
                            email_attempt=email, ip_address=ip, user_agent=user_agent)
        await session.commit()
        raise generic_error

    if await count_active_sessions(session) >= MAX_CONCURRENT_SESSIONS:
        await record_audit(session, "LOGIN_FAILED", user_id=user.id, email_attempt=email,
                            ip_address=ip, user_agent=user_agent, details={"reason": "session_limit"})
        await session.commit()
        # 503, pas 429 : le frontend réserve déjà 429 au verrou anti-bruteforce avec son
        # propre message fixe (cf. Login.jsx) — un statut différent évite qu'il écrase le
        # message ci-dessous par celui du verrou.
        raise HTTPException(503, "Nombre maximum de connexions simultanées atteint — réessayez plus tard.")

    raw_token = await create_session(session, user, ip, user_agent)
    await record_audit(session, "LOGIN_SUCCESS", user_id=user.id, email_attempt=email,
                        ip_address=ip, user_agent=user_agent)
    await session.commit()

    response.set_cookie(
        SESSION_COOKIE_NAME, raw_token,
        max_age=COOKIE_MAX_AGE, httponly=True, samesite="lax", secure=settings.COOKIE_SECURE,
        path="/",
    )
    return {
        "id": str(user.id), "email": user.email, "full_name": user.full_name,
        "role": user.role, "must_change_password": user.must_change_password,
        "allowed_pages": user.allowed_pages,
    }


# « Mot de passe oublié » (18/08/2026, demande explicite) — public comme /login (utilisateur
# pas encore authentifié). Pas d'infra SMTP dans ce projet (cf. routers/users.py) : aucun lien
# de réinitialisation envoyé, la demande reste visible par un admin (Administration >
# Utilisateurs) jusqu'à ce qu'il fixe lui-même un mot de passe provisoire (cf.
# routers/users.py::resolve_password_reset_request), communiqué à l'utilisateur hors appli.
#
# Message générique renvoyé quel que soit le cas (email inconnu, compte désactivé, ou
# demande bien créée) — même principe anti-énumération que /login ci-dessus : le contenu de
# la réponse ne doit jamais confirmer qu'une adresse existe dans la base.
@router.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordPayload, session: AsyncSession = Depends(get_session)):
    generic = {"sent": True, "message": "Si un compte existe avec cet email, une demande a été transmise à un administrateur."}
    email = payload.email.strip().lower()
    if not email:
        return generic
    user = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if not user or not user.is_active:
        return generic

    # Une seule demande en attente par compte — un utilisateur qui reclique ne doit pas
    # empiler des doublons dans la liste de l'admin, juste rafraîchir la plus récente.
    existing = (await session.execute(
        select(PasswordResetRequest).where(
            PasswordResetRequest.user_id == user.id, PasswordResetRequest.status == "pending",
        )
    )).scalar_one_or_none()
    message = (payload.message or "").strip()[:2000] or None
    if existing:
        existing.message = message
        existing.requested_at = datetime.now(timezone.utc)
    else:
        session.add(PasswordResetRequest(user_id=user.id, message=message))
    await session.commit()
    return generic


@router.post("/logout")
async def logout(request: Request, response: Response,
                  user: User = Depends(require_auth), session: AsyncSession = Depends(get_session)):
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if raw_token:
        await delete_session(session, raw_token)
    await record_audit(session, "LOGOUT", user_id=user.id, email_attempt=user.email)
    await session.commit()
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"logged_out": True}


@router.get("/me")
async def me(user: User = Depends(require_auth)):
    return {
        "id": str(user.id), "email": user.email, "full_name": user.full_name,
        "role": user.role, "must_change_password": user.must_change_password,
        "allowed_pages": user.allowed_pages,
    }


@router.post("/change-password")
async def change_password(payload: ChangePasswordPayload, user: User = Depends(require_auth),
                           session: AsyncSession = Depends(get_session)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(401, "Mot de passe actuel incorrect.")
    validate_password_strength(payload.new_password)
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    user.updated_at = datetime.now(timezone.utc)
    await record_audit(session, "PASSWORD_CHANGED", user_id=user.id, email_attempt=user.email)
    await session.commit()
    return {"changed": True}


# Modification de l'email de son propre compte (14/08/2026, demande utilisateur) — n'existait
# pas jusqu'ici : seul un admin pouvait changer l'email d'un compte (PATCH /api/users/{id}),
# jamais un utilisateur le sien. Même garde-fou que change-password (mot de passe actuel
# requis) — un email de connexion est une donnée sensible, pas modifiable sur la seule foi
# du cookie de session.
@router.patch("/change-email")
async def change_email(payload: ChangeEmailPayload, user: User = Depends(require_auth),
                        session: AsyncSession = Depends(get_session)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(401, "Mot de passe actuel incorrect.")
    new_email = payload.new_email.strip().lower()
    if not new_email:
        raise HTTPException(400, "L'email est obligatoire.")
    existing = (await session.execute(
        select(User).where(User.email == new_email, User.id != user.id)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Un compte existe déjà avec cet email.")
    old_email = user.email
    user.email = new_email
    user.updated_at = datetime.now(timezone.utc)
    await record_audit(session, "EMAIL_CHANGED", user_id=user.id, email_attempt=old_email,
                        details={"new_email": new_email})
    await session.commit()
    return {"id": str(user.id), "email": user.email, "full_name": user.full_name,
            "role": user.role, "must_change_password": user.must_change_password,
            "allowed_pages": user.allowed_pages}


# Sessions actives de son propre compte (14/08/2026, demande utilisateur) — self-service,
# pendant de POST /api/users/{id}/revoke-sessions (admin, sur un AUTRE compte). Utile pour
# repérer une connexion oubliée (poste partagé) sans devoir demander à un admin.
@router.get("/sessions")
async def list_my_sessions(request: Request, user: User = Depends(require_auth),
                            session: AsyncSession = Depends(get_session)):
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    current_hash = _hash_token(raw_token) if raw_token else None
    rows = (await session.execute(
        select(UserSession).where(UserSession.user_id == user.id).order_by(UserSession.created_at.desc())
    )).scalars().all()
    return {"items": [
        {
            "id": str(r.id),
            "ip_address": r.ip_address,
            "user_agent": r.user_agent,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "is_current": r.session_token_hash == current_hash,
        }
        for r in rows
    ]}


@router.delete("/sessions/{session_id}")
async def revoke_my_session(session_id: str, request: Request, user: User = Depends(require_auth),
                             session: AsyncSession = Depends(get_session)):
    row = await session.get(UserSession, session_id)
    if not row or row.user_id != user.id:
        raise HTTPException(404, "Session introuvable.")
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if raw_token and row.session_token_hash == _hash_token(raw_token):
        raise HTTPException(400, "Utilisez « Se déconnecter » pour la session en cours.")
    await session.delete(row)
    await record_audit(session, "SESSION_REVOKED", user_id=user.id, email_attempt=user.email)
    await session.commit()
    return {"revoked": True}
