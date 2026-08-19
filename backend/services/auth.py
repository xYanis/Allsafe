"""
services/auth.py
Cœur de l'authentification (30/07/2026) : hash de mot de passe, sessions par cookie,
audit + verrou anti-bruteforce. Cf. models.py::User/UserSession/AuthAuditLog et
docs/ARCHITECTURE.md § Authentification.
"""

import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import HTTPException
from sqlalchemy import func, select

from models import AuthAuditLog, User, UserSession

# Politique de mot de passe (14/08/2026, demande utilisateur) : jusqu'ici seule la
# longueur (16 caractères) était vérifiée, dupliquée dans routers/auth.py ET
# routers/users.py — centralisée ici pour que les deux endpoints (changement par soi-même
# et création par un admin) restent alignés. Le frontend calque son indice de force
# (PasswordStrengthHint.jsx) sur exactement ces mêmes règles.
PASSWORD_MIN_LENGTH = 16


def validate_password_strength(password: str) -> None:
    missing = []
    if len(password) < PASSWORD_MIN_LENGTH:
        missing.append(f"au moins {PASSWORD_MIN_LENGTH} caractères")
    if not re.search(r"[A-Z]", password):
        missing.append("une majuscule")
    if not re.search(r"[a-z]", password):
        missing.append("une minuscule")
    if not re.search(r"\d", password):
        missing.append("un chiffre")
    if not re.search(r"[^A-Za-z0-9]", password):
        missing.append("un caractère spécial")
    if missing:
        raise HTTPException(400, "Le mot de passe doit contenir " + ", ".join(missing) + ".")

# Session glissante : chaque requête valide repousse expires_at de SESSION_TTL, mais
# jamais au-delà de created_at + SESSION_ABSOLUTE_TTL (défense en profondeur si un
# cookie fuite — force une réauthentification périodique même si l'app reste ouverte).
SESSION_TTL = timedelta(hours=8)
SESSION_ABSOLUTE_TTL = timedelta(days=7)

# Ne réécrit expires_at que si on est à moins de ce seuil de son horizon — évite un
# UPDATE à chaque requête sur une table lue en continu.
SESSION_RENEW_THRESHOLD = timedelta(minutes=5)

# Anti-bruteforce : fenêtre glissante + seuils par email tenté et par IP (protège aussi
# contre l'énumération d'emails valides depuis un même poste, cf. STATUS.md).
LOCKOUT_WINDOW = timedelta(minutes=15)
LOCKOUT_MAX_PER_EMAIL = 5
LOCKOUT_MAX_PER_IP = 20

# Plafond de connexions simultanées, tous comptes confondus (12/08/2026, demande
# utilisateur) — une même personne connectée sur 2 appareils compte pour 2. Au-delà, le
# login est refusé (pas d'éviction de la session la plus ancienne, choix délibéré : ne
# jamais déconnecter quelqu'un sans prévenir).
MAX_CONCURRENT_SESSIONS = 5


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        return False


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


async def create_session(session, user: User, ip_address: str | None, user_agent: str | None) -> str:
    """Crée une ligne `sessions` et retourne le token brut (à poser en cookie) —
    seul son hash est stocké en base, jamais le token en clair."""
    raw_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    session.add(UserSession(
        user_id=user.id,
        session_token_hash=_hash_token(raw_token),
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=now + SESSION_TTL,
    ))
    return raw_token


async def count_active_sessions(session) -> int:
    """Sessions non expirées, tous comptes confondus — cf. MAX_CONCURRENT_SESSIONS."""
    now = datetime.now(timezone.utc)
    stmt = select(func.count()).select_from(UserSession).where(UserSession.expires_at > now)
    return (await session.execute(stmt)).scalar_one()


async def get_user_by_token(session, raw_token: str) -> User | None:
    """Résout l'utilisateur depuis le token brut du cookie. Rejette une session expirée
    ou dépassant le plafond absolu. Repousse expires_at (session glissante) seulement si
    on approche de l'horizon, pour ne pas écrire à chaque requête."""
    token_hash = _hash_token(raw_token)
    row = (await session.execute(
        select(UserSession).where(UserSession.session_token_hash == token_hash)
    )).scalar_one_or_none()
    if not row:
        return None

    now = datetime.now(timezone.utc)
    if row.expires_at <= now or row.created_at + SESSION_ABSOLUTE_TTL <= now:
        return None

    if row.expires_at - now < SESSION_RENEW_THRESHOLD:
        row.expires_at = now + SESSION_TTL

    user = await session.get(User, row.user_id)
    if not user or not user.is_active:
        return None
    return user


async def delete_session(session, raw_token: str) -> None:
    token_hash = _hash_token(raw_token)
    row = (await session.execute(
        select(UserSession).where(UserSession.session_token_hash == token_hash)
    )).scalar_one_or_none()
    if row:
        await session.delete(row)


async def record_audit(session, event_type: str, user_id=None, email_attempt: str | None = None,
                        ip_address: str | None = None, user_agent: str | None = None,
                        details: dict | None = None) -> None:
    session.add(AuthAuditLog(
        event_type=event_type,
        user_id=user_id,
        email_attempt=email_attempt,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details,
    ))


async def count_recent_failures(
    session, *, email: str | None = None, ip_address: str | None = None, event_type: str = "LOGIN_FAILED",
) -> int:
    """Nombre d'évènements `event_type` dans la fenêtre glissante, par email tenté ou par
    IP — utilisé pour le verrou anti-bruteforce de `/login` (cf. LOCKOUT_MAX_PER_EMAIL/IP
    ci-dessus). `event_type` généralisé (18/08/2026, cf. audit/AUDIT_SECURITE.md #20) pour
    être réutilisé par `/forgot-password` (`PASSWORD_RESET_REQUESTED`), qui n'avait jusqu'ici
    aucun verrou ni trace — contrairement à `/login`, qui journalise même une tentative sur
    un email inexistant."""
    since = datetime.now(timezone.utc) - LOCKOUT_WINDOW
    stmt = select(func.count()).select_from(AuthAuditLog).where(
        AuthAuditLog.event_type == event_type,
        AuthAuditLog.created_at >= since,
    )
    if email is not None:
        stmt = stmt.where(AuthAuditLog.email_attempt == email)
    if ip_address is not None:
        stmt = stmt.where(AuthAuditLog.ip_address == ip_address)
    return (await session.execute(stmt)).scalar_one()


async def is_locked_out(session, email: str, ip_address: str | None) -> bool:
    if await count_recent_failures(session, email=email) >= LOCKOUT_MAX_PER_EMAIL:
        return True
    if ip_address and await count_recent_failures(session, ip_address=ip_address) >= LOCKOUT_MAX_PER_IP:
        return True
    return False


async def is_password_reset_locked_out(session, ip_address: str | None) -> bool:
    """Verrou anti-spam pour `/forgot-password` (18/08/2026, cf. audit/AUDIT_SECURITE.md
    #20) — par IP uniquement, pas par email : contrairement à `/login`, un mauvais acteur ici
    ne "devine" rien par email tenté (aucune boucle de mots de passe), le risque est le
    flood du panneau admin / le canal de timing (#22), les deux proportionnels au volume de
    requêtes émises depuis une même source. Mêmes seuils que `/login` (réutilisés tels
    quels, pas de nouveau réglage à maintenir)."""
    return bool(ip_address) and await count_recent_failures(
        session, ip_address=ip_address, event_type="PASSWORD_RESET_REQUESTED",
    ) >= LOCKOUT_MAX_PER_IP
