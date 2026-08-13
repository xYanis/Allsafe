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
from models import User
from services.auth import (
    MAX_CONCURRENT_SESSIONS,
    count_active_sessions,
    count_recent_failures,
    create_session,
    delete_session,
    hash_password,
    is_locked_out,
    record_audit,
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


class ChangePasswordPayload(BaseModel):
    current_password: str
    new_password: str


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
    if len(payload.new_password) < 16:
        raise HTTPException(400, "Le nouveau mot de passe doit faire au moins 16 caractères.")
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    user.updated_at = datetime.now(timezone.utc)
    await record_audit(session, "PASSWORD_CHANGED", user_id=user.id, email_attempt=user.email)
    await session.commit()
    return {"changed": True}
