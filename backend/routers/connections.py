from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone
from auth_deps import require_admin
from database import get_session
from models import AuthAuditLog, ConnectionLog

router = APIRouter()


# Volontairement PAS de dependency d'auth ici (contrairement au reste de l'API, cf.
# main.py) : ConnectionTracker (frontend/src/App.jsx) journalise CHAQUE chargement de
# l'app, y compris sur /login avant toute connexion — c'est un journal d'accès (qui a
# visité l'app), pas une ressource protégée. La lecture ci-dessous reste réservée admin.
@router.post("")
async def log_connection(request: Request, session: AsyncSession = Depends(get_session)):
    ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.headers.get("X-Real-IP", "")
        or (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "")[:512]
    session.add(ConnectionLog(ip=ip, user_agent=ua, accessed_at=datetime.now(timezone.utc)))
    await session.commit()
    return {"logged": True}


@router.get("")
async def get_connections(session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    rows = (await session.execute(
        select(ConnectionLog).order_by(ConnectionLog.accessed_at.desc()).limit(500)
    )).scalars().all()
    return [
        {
            "id": str(r.id),
            "ip": r.ip,
            "user_agent": r.user_agent,
            "accessed_at": r.accessed_at.isoformat() if r.accessed_at else None,
        }
        for r in rows
    ]


# Journal de connexion PAR UTILISATEUR (12/08/2026, demande utilisateur) — LOGIN_SUCCESS/
# LOGIN_FAILED/LOGOUT/PASSWORD_CHANGED (services/auth.py::record_audit), à distinguer du
# journal d'accès ci-dessus (ConnectionLog : IP + navigateur, anonyme, avant authentification —
# journalise même un simple chargement de /login). Les deux se regroupent dans l'onglet
# "Connexion" côté frontend (ex-"Connexions IP", cf. AdministrationSecurity.jsx), mais
# restent deux endpoints distincts : deux modèles différents, pas de fusion en base.
@router.get("/users")
async def get_user_connections(session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    rows = (await session.execute(
        select(AuthAuditLog).order_by(AuthAuditLog.created_at.desc()).limit(500)
    )).scalars().all()
    return [
        {
            "id": str(r.id),
            "event_type": r.event_type,
            "email": r.email_attempt,
            "ip": r.ip_address,
            "user_agent": r.user_agent,
            "details": r.details,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
