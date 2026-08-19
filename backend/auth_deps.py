"""
auth_deps.py
Dependencies FastAPI d'authentification/autorisation — branchées au niveau de chaque
`app.include_router(..., dependencies=[...])` dans main.py, pas via un middleware global
(cf. docs/ARCHITECTURE.md § Authentification pour le choix). `require_admin` dépend de
`require_auth` : grâce au cache de dépendances FastAPI (une résolution par requête pour un
même callable), les deux ne déclenchent qu'une seule requête SQL de session.
"""

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_session
from models import Agent, User
from services.auth import get_user_by_token

SESSION_COOKIE_NAME = "cbr_session"
INTERNAL_TOKEN_HEADER = "X-Internal-Token"
AGENT_TOKEN_HEADER = "X-Agent-Token"

# Routes jamais bloquées par le garde-fou must_change_password ci-dessous — sans elles,
# un compte forcé à changer son mot de passe ne pourrait jamais appeler l'endpoint qui
# le lui permet (10/08/2026, cf. audit/AUDIT_SECURITE.md #10). `me`/`logout` inclus : la page
# de changement forcé du frontend (ProtectedRoute.jsx) en a besoin pour afficher l'email
# du compte et permettre de se déconnecter sans changer le mot de passe.
_ALLOWED_WHILE_MUST_CHANGE_PASSWORD = {
    ("POST", "/api/auth/change-password"),
    ("POST", "/api/auth/logout"),
    ("GET", "/api/auth/me"),
}


async def require_auth(request: Request, session: AsyncSession = Depends(get_session)) -> User:
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    user = await get_user_by_token(session, raw_token) if raw_token else None
    if not user:
        raise HTTPException(401, "Authentification requise.")
    await session.commit()  # persiste un éventuel renouvellement glissant de la session
    if user.must_change_password and (request.method, request.url.path) not in _ALLOWED_WHILE_MUST_CHANGE_PASSWORD:
        # Avant ce garde-fou (10/08/2026), seul le frontend (ProtectedRoute.jsx) bloquait
        # l'écran tant que must_change_password est vrai — un appel direct à l'API (curl,
        # script) avec des identifiants provisoires (ex: BOOTSTRAP_ADMIN_PASSWORD, censé
        # être changé à la 1ère connexion) donnait un accès complet et permanent, flag
        # ou pas. Cf. audit/AUDIT_SECURITE.md #10.
        raise HTTPException(403, "Changement de mot de passe requis avant de continuer.")
    return user


async def require_admin(user: User = Depends(require_auth)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Réservé aux administrateurs.")
    return user


def require_page(*page_keys: str):
    """Dependency factory (31/07/2026) — un router qui sert plusieurs pages (ex: watch.router
    pour /veille ET /fuite-de-donnees) passe plusieurs clés, accès accordé si le compte a
    au moins l'une d'elles. `role == "admin"` ou `allowed_pages is None` (accès total, défaut à
    la création d'un compte analyst) court-circuitent toujours la vérification — cf.
    services/access_control.py pour la liste des clés valides et models.py::User pour la
    justification de ce contrôle côté serveur (pas seulement côté nav)."""
    async def _dep(user: User = Depends(require_auth)) -> User:
        if user.role == "admin":
            return user
        if user.allowed_pages is not None and not any(k in user.allowed_pages for k in page_keys):
            raise HTTPException(403, "Accès à ce module non autorisé pour votre compte.")
        return user
    return _dep


def require_page_or_internal(*page_keys: str):
    """Comme `require_page`, mais accepte aussi un appel interne authentifié par
    jeton partagé (07/08/2026, en-tête `X-Internal-Token` == `INTERNAL_API_TOKEN`)
    — pour les tâches Celery qui doivent déclencher un endpoint protégé depuis le
    process `worker`, où aucune session utilisateur n'existe (cf.
    tasks/scheduled_tasks.py::patch_check_periodic). Jamais exposé au navigateur :
    `INTERNAL_API_TOKEN` ne vit que dans `.env`, partagé entre `backend`/`worker`
    via docker-compose. Retourne `None` (pas d'objet `User`) pour l'identité
    "système" — les routes qui l'utilisent ne doivent jamais lire d'attribut
    utilisateur (`validated_by`...) sur le retour de cette dependency.

    Le corps duplique volontairement `require_auth`/`require_page` plutôt que de
    les composer : FastAPI résout les `Depends` passés en paramètre par défaut
    **avant** d'exécuter le corps de la fonction — impossible d'essayer le jeton
    interne d'abord et de retomber sur `require_auth` seulement en cas d'échec
    si celui-ci est déclaré en paramètre (son échec lève l'exception plus tôt,
    hors de portée d'un `try/except` ici)."""
    async def _dep(request: Request, session: AsyncSession = Depends(get_session)) -> Optional[User]:
        token = request.headers.get(INTERNAL_TOKEN_HEADER)
        # hmac.compare_digest (10/08/2026, cf. audit/AUDIT_SECURITE.md #12) plutôt que `==` :
        # une comparaison de chaînes standard s'arrête au premier octet différent, ce qui
        # fuit un signal temporel exploitable en théorie pour deviner INTERNAL_API_TOKEN
        # octet par octet. Risque réel faible (jeton interne, jamais exposé au navigateur)
        # mais correctif gratuit.
        if settings.INTERNAL_API_TOKEN and hmac.compare_digest(token or "", settings.INTERNAL_API_TOKEN):
            return None

        raw_token = request.cookies.get(SESSION_COOKIE_NAME)
        user = await get_user_by_token(session, raw_token) if raw_token else None
        if not user:
            raise HTTPException(401, "Authentification requise.")
        await session.commit()
        if user.role == "admin":
            return user
        if user.allowed_pages is not None and not any(k in user.allowed_pages for k in page_keys):
            raise HTTPException(403, "Accès à ce module non autorisé pour votre compte.")
        return user
    return _dep


async def require_admin_or_internal(request: Request, session: AsyncSession = Depends(get_session)) -> Optional[User]:
    """Comme `require_admin`, mais accepte aussi le jeton interne partagé (17/08/2026, même
    mécanisme que `require_page_or_internal` ci-dessus — cf. sa docstring pour le détail du
    jeton) — pour le poller de politiques de scan planifié
    (tasks/scheduled_tasks.py::check_scan_policies), qui déclenche depuis le process worker un
    endpoint normalement réservé admin (`POST /scan-policies/{criticite}/run-now`). Corps
    dupliqué plutôt que composé, même raison que `require_page_or_internal`."""
    token = request.headers.get(INTERNAL_TOKEN_HEADER)
    if settings.INTERNAL_API_TOKEN and hmac.compare_digest(token or "", settings.INTERNAL_API_TOKEN):
        return None

    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    user = await get_user_by_token(session, raw_token) if raw_token else None
    if not user:
        raise HTTPException(401, "Authentification requise.")
    await session.commit()
    if user.role != "admin":
        raise HTTPException(403, "Réservé aux administrateurs.")
    return user


async def require_agent(request: Request, session: AsyncSession = Depends(get_session)) -> Agent:
    """Authentification d'un agent posé sur un poste (12/08/2026, module Sécurité > Agents) —
    identité non-humaine, même forme que `require_auth` mais résout un en-tête (`X-Agent-Token`)
    plutôt que le cookie `cbr_session`. Le jeton présenté est haché (sha256, même idiome que
    `services/auth.py::_hash_token` pour les sessions utilisateur) et comparé au
    `credential_hash` stocké — jamais de secret en clair conservé côté DB.

    Un agent révoqué (`status != "enrolled"`) est rejeté sans distinction avec un agent
    inconnu (même message d'erreur générique) — pas d'énumération possible des identités
    d'agent valides. `last_seen_at` posé à chaque appel réussi, pour que la page Agents
    puisse afficher qui est encore actif."""
    raw_token = request.headers.get(AGENT_TOKEN_HEADER)
    if not raw_token:
        raise HTTPException(401, "Authentification agent requise.")
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    agent = (await session.execute(
        select(Agent).where(Agent.credential_hash == token_hash)
    )).scalar_one_or_none()
    if not agent or agent.status != "enrolled":
        raise HTTPException(401, "Agent inconnu ou révoqué.")
    agent.last_seen_at = datetime.now(timezone.utc)
    await session.commit()
    return agent
