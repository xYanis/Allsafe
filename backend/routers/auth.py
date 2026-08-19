"""
routers/auth.py
Login/logout/session courante — seul router de `/api/*` sans dependency d'auth globale
(le login doit rester public). `/logout`, `/me`, `/change-password` se protègent
individuellement via `Depends(require_auth)` sur la route, cf. main.py.
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
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
    is_password_reset_locked_out,
    record_audit,
    validate_password_strength,
    verify_password,
)

# UUID sentinel (18/08/2026, cf. audit/AUDIT_SECURITE.md #22) — utilisé à la place d'un
# vrai user_id quand l'email de /forgot-password ne correspond à aucun compte actif, pour
# que la requête de dédup ci-dessous s'exécute à l'identique (même plan, même coût) dans
# les deux branches plutôt que d'être court-circuitée pour l'une des deux.
_NIL_USER_ID = uuid.UUID(int=0)

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
    # max_length (18/08/2026, cf. audit/AUDIT_SECURITE.md #24) — sans lui, un payload de
    # plusieurs Mo était accepté en 200 (0,31s) : la troncature à 2000 caractères s'appliquait
    # déjà, mais APRÈS que tout le corps ait été bufferisé/parsé. `/login` a le même trou
    # (hors scope ici, endpoint distinct) — l'une des deux seules routes entièrement publiques.
    message: str | None = Field(default=None, max_length=2000)


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
#
# Durci le 18/08/2026 (cf. audit/AUDIT_SECURITE.md #19/#20/#22/#23/#24) — cette route
# n'avait initialement ni rate-limit, ni traçabilité, ni protection anti-course, contrairement
# à /login qui applique scrupuleusement ces trois principes :
# - #20 : verrou anti-spam par IP (is_password_reset_locked_out, réutilise le mécanisme de
#   /login) + journalisation dans auth_audit_logs de TOUTE tentative, y compris email
#   inconnu/inactif (comme /login le fait déjà).
# - #22 : le nombre d'opérations DB est désormais identique entre la branche "email inconnu"
#   et la branche "compte actif existant" (même SELECT de dédup, sur un UUID sentinelle côté
#   inconnu) — sans ça, un écart de ~30ms mesuré permettait de deviner qu'une adresse existe.
# - #19 : la dédup elle-même n'est plus lire-puis-écrire (course possible, 2 lignes pending
#   créées par 15 requêtes concurrentes en conditions réelles) mais protégée par l'index
#   unique partiel `ux_password_reset_pending` (schema_patches.sql) — l'IntegrityError d'un
#   INSERT perdant retombe proprement sur un UPDATE de la ligne déjà créée par le gagnant.
@router.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordPayload, request: Request, session: AsyncSession = Depends(get_session)):
    generic = {"sent": True, "message": "Si un compte existe avec cet email, une demande a été transmise à un administrateur."}
    email = payload.email.strip().lower()
    ip = _client_ip(request)
    user_agent = request.headers.get("User-Agent", "")[:512]

    if await is_password_reset_locked_out(session, ip):
        raise HTTPException(429, "Trop de demandes — réessayez dans quelques minutes.")

    if not email:
        return generic

    user = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    valid_user = user if (user and user.is_active) else None

    # Dédup (#19/#22) — même requête, même coût, que l'email corresponde ou non à un compte
    # actif : évite un signal de timing exploitable pour deviner l'existence d'une adresse.
    dedup_user_id = valid_user.id if valid_user else _NIL_USER_ID
    existing = (await session.execute(
        select(PasswordResetRequest).where(
            PasswordResetRequest.user_id == dedup_user_id, PasswordResetRequest.status == "pending",
        )
    )).scalar_one_or_none()

    message = (payload.message or "").strip()[:2000] or None
    if valid_user:
        if existing:
            existing.message = message
            existing.requested_at = datetime.now(timezone.utc)
        else:
            try:
                async with session.begin_nested():
                    session.add(PasswordResetRequest(user_id=valid_user.id, message=message))
                    await session.flush()
            except IntegrityError:
                # Course perdue contre une requête concurrente (index unique partiel,
                # cf. schema_patches.sql) — la ligne pending existe déjà, on la met à jour.
                existing = (await session.execute(
                    select(PasswordResetRequest).where(
                        PasswordResetRequest.user_id == valid_user.id, PasswordResetRequest.status == "pending",
                    )
                )).scalar_one_or_none()
                if existing:
                    existing.message = message
                    existing.requested_at = datetime.now(timezone.utc)

    await record_audit(session, "PASSWORD_RESET_REQUESTED", user_id=valid_user.id if valid_user else None,
                        email_attempt=email, ip_address=ip, user_agent=user_agent)
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
