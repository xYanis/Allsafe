"""
routers/agents.py
Module Sécurité > Agents (12/08/2026) — agent Rust posé sur les postes Windows/Linux,
complète le scan centralisé SSH/WinRM existant (`services/asset_scanner.py`) pour les
postes qu'il atteint mal (éteints, hors réseau, VPN). Jamais un remplacement des 80 VM
serveurs — par actif, l'utilisateur choisit la méthode de collecte
(`Asset.collection_method`).

Cinq familles de routes, chacune avec sa propre protection (déclarée par route, pas au
niveau du router — comme `routers/auth.py`/`routers/connections.py` le font déjà pour
leurs routes publiques) :
- Gestion des jetons (admin) : `require_admin`.
- Enrôlement (`POST /enroll`) : protégé par le jeton lui-même dans le corps de requête —
  c'est le tout premier contact de l'agent, aucune session ni credential encore émis.
- Check-in (`POST /checkin`) : `require_agent` (auth_deps.py), résout l'en-tête
  `X-Agent-Token`.
- Liste/révocation/suppression : `require_page("/agents")`/admin.
- Distribution des paquets (`GET /latest/*`, 13/08/2026) : publique, même raisonnement que
  `/enroll` — ces routes sont interrogées par des scripts tournant sur les postes eux-mêmes
  (tâche planifiée/GPO), sans session utilisateur possible, et ne servent que le binaire
  agent (rien de secret dedans). Sert tel quel ce qui a déjà été construit à la main dans
  `agent/dist/` (monté en lecture seule, `AGENT_DIST_DIR`) — le backend ne compile jamais
  rien lui-même, cf. `agent/deploy/README.md`.
"""

import glob
import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_admin, require_agent, require_page
from database import get_session
from models import Agent, AgentEnrollmentToken, Asset, User
from services.asset_scanner import apply_scan_result

router = APIRouter()

AGENT_DIST_DIR = "/app/agent-dist"

# Dernière version publiée du binaire allsafe-agent (`agent/Cargo.toml::version`) — à
# bumper manuellement à chaque release (`cargo deb`/`wixl`, cf. agent/README.md § Build).
# Pas de mécanisme de mise à jour automatique côté agent dans ce MVP : cette constante ne
# sert qu'à comparer côté serveur ce que chaque agent déclare à son dernier check-in
# (`Agent.agent_version`) pour repérer les postes en retard (`_agent_dict::outdated`).
CURRENT_AGENT_VERSION = "0.1.4"


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# ─── Schémas ──────────────────────────────────────────────────────────────────

class EnrollmentTokenCreate(BaseModel):
    asset_id: Optional[str] = None
    label: Optional[str] = None
    # Enrôlement à l'échelle (13/08/2026) — max_uses=1 (défaut) reproduit le comportement
    # historique (usage unique). expires_in_hours configurable : un déploiement de parc via
    # GPO/script peut prendre plus que les 48h fixes d'origine.
    max_uses: int = 1
    expires_in_hours: int = 48


class EnrollRequest(BaseModel):
    token: str
    hostname: str
    os: str   # "windows" | "linux"


class AgentCheckinPayload(BaseModel):
    """Même shape que `asset_scanner.py::_build_result()` — `detected` sert à corriger
    hostname/OS/CPE comme un scan pull classique (cf. `apply_scan_result`). `compliance`
    porte à la fois les checks de durcissement CIS-like existants (parité avec
    `asset_scanner.py`) et les checks propres à l'agent (chiffrement disque, comptes admin
    locaux...) — même forme `{"checks": [{"id","label","status","detail"}]}`, aucune
    distinction faite ici entre les deux origines."""
    reachable: bool = True
    detected: dict = {}
    packages: list = []
    package_count: Optional[int] = None
    hardware: dict = {}
    compliance: dict = {}
    error: Optional[str] = None
    agent_version: Optional[str] = None
    # Rapport de coupure (13/08/2026, cf. agent/src/config.rs::DaemonState) — secondes Unix
    # UTC, absent en fonctionnement normal (posé seulement si le check-in précédent avait
    # échoué au moins une fois côté agent).
    offline_since: Optional[int] = None
    failed_attempts: Optional[int] = None


def _token_dict(t: AgentEnrollmentToken) -> dict:
    return {
        "id": str(t.id),
        "asset_id": str(t.asset_id) if t.asset_id else None,
        "label": t.label,
        "created_by": t.created_by,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "expires_at": t.expires_at.isoformat() if t.expires_at else None,
        "max_uses": t.max_uses,
        "use_count": t.use_count,
    }


def _token_status(token: Optional[AgentEnrollmentToken]) -> str:
    """État du jeton d'enrôlement ayant servi à créer cet agent (17/08/2026, demande
    explicite — colonne "État" de la page Agents, à côté du statut de l'agent lui-même qui
    ne dit rien du jeton). `None` (`Agent.enrollment_token_id` mis à NULL par
    `ON DELETE SET NULL`, cf. `delete_enrollment_token` ci-dessous) : le jeton a été
    explicitement révoqué après coup, distinct d'expiré/épuisé."""
    if token is None:
        return "revoked"
    if token.expires_at and token.expires_at <= datetime.now(timezone.utc):
        return "expired"
    if token.use_count >= token.max_uses:
        return "exhausted"
    return "active"


def _agent_dict(
    a: Agent, asset_name: Optional[str] = None, asset_os: Optional[str] = None,
    asset_os_version: Optional[str] = None, token: Optional[AgentEnrollmentToken] = None,
) -> dict:
    return {
        "id": str(a.id),
        "asset_id": str(a.asset_id) if a.asset_id else None,
        "asset_name": asset_name,
        "hostname": a.hostname,
        "os": a.os,
        # Distribution précise (ex. "Debian"/"12", "Windows Server"/"2019") — distincte de
        # `os` ci-dessus (juste "windows"/"linux", déclaré par l'agent à l'enrôlement) :
        # vient de l'actif rattaché (`Asset.os`/`os_version`, alimenté par le premier scan
        # SSH/WinRM ou check-in agent), absente tant qu'aucun scan n'a encore eu lieu.
        "asset_os": asset_os,
        "asset_os_version": asset_os_version,
        "status": a.status,
        "enrolled_at": a.enrolled_at.isoformat() if a.enrolled_at else None,
        "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
        "agent_version": a.agent_version,
        # None avant tout check-in avec un binaire qui déclare sa version (agent enrôlé
        # avant l'ajout de ce champ) — pas encore comparable, jamais annoncé "périmé".
        "outdated": a.agent_version is not None and a.agent_version != CURRENT_AGENT_VERSION,
        "pending_scan_requested_at": a.pending_scan_requested_at.isoformat() if a.pending_scan_requested_at else None,
        "last_gap_started_at": a.last_gap_started_at.isoformat() if a.last_gap_started_at else None,
        "last_gap_failed_attempts": a.last_gap_failed_attempts,
        "revoked_at": a.revoked_at.isoformat() if a.revoked_at else None,
        "revoked_by": a.revoked_by,
        "token_status": _token_status(token),
    }


# ─── Jetons d'enrôlement (admin) ────────────────────────────────────────────────

@router.post("/enrollment-tokens", status_code=201)
async def create_enrollment_token(
    data: EnrollmentTokenCreate,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
):
    if data.asset_id:
        asset = await session.get(Asset, data.asset_id)
        if not asset:
            raise HTTPException(404, "Actif introuvable.")
        if data.max_uses != 1:
            raise HTTPException(400, "Un jeton lié à un actif précis doit rester à usage unique.")
    if data.max_uses < 1:
        raise HTTPException(400, "max_uses doit être au moins 1.")
    if data.expires_in_hours < 1:
        raise HTTPException(400, "expires_in_hours doit être au moins 1.")

    raw = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    token = AgentEnrollmentToken(
        token_hash=_hash(raw),
        asset_id=data.asset_id,
        label=(data.label or "").strip() or None,
        created_by=admin.full_name,
        expires_at=now + timedelta(hours=data.expires_in_hours),
        max_uses=data.max_uses,
    )
    session.add(token)
    await session.commit()
    await session.refresh(token)
    # Le jeton en clair n'est renvoyé qu'ici, une seule fois — jamais rejoué par
    # aucun autre endpoint (ni loggé : cf. absence de tout logger.info avec `raw`).
    return {**_token_dict(token), "token": raw}


@router.get("/enrollment-tokens")
async def list_enrollment_tokens(session: AsyncSession = Depends(get_session), _admin: User = Depends(require_admin)):
    rows = (await session.execute(
        select(AgentEnrollmentToken).order_by(AgentEnrollmentToken.created_at.desc())
    )).scalars().all()
    return {"items": [_token_dict(t) for t in rows]}


@router.delete("/enrollment-tokens/{token_id}", status_code=204)
async def revoke_enrollment_token(token_id: str, session: AsyncSession = Depends(get_session), _admin: User = Depends(require_admin)):
    """Révocable à tout moment quel que soit `use_count` (13/08/2026) — stoppe les
    enrôlements futurs via ce jeton, n'affecte jamais les postes déjà enrôlés
    (`Agent.enrollment_token_id` passe à NULL, `ON DELETE SET NULL`, mais l'agent lui-même
    reste intact — pour le révoquer, cf. `POST /{agent_id}/revoke`)."""
    token = await session.get(AgentEnrollmentToken, token_id)
    if not token:
        raise HTTPException(404, "Jeton introuvable.")
    await session.delete(token)
    await session.commit()


# ─── Enrôlement (premier contact, pas de session) ──────────────────────────────

@router.post("/enroll", status_code=201)
async def enroll_agent(data: EnrollRequest, session: AsyncSession = Depends(get_session)):
    """Échange un jeton d'enrôlement contre une identité `Agent` propre au poste — même
    principe TOFU que `services/ssh_trust.py` : au-delà de `max_uses` utilisations (1 par
    défaut, cf. `EnrollmentTokenCreate`), ce jeton ne peut plus jamais être rejoué, un
    enrôlement supplémentaire nécessite un nouveau jeton généré explicitement par un admin."""
    if data.os not in ("windows", "linux"):
        raise HTTPException(400, "os doit être 'windows' ou 'linux'.")

    token_hash = _hash(data.token)
    token = (await session.execute(
        select(AgentEnrollmentToken).where(AgentEnrollmentToken.token_hash == token_hash)
    )).scalar_one_or_none()
    if not token:
        raise HTTPException(401, "Jeton d'enrôlement invalide.")
    if token.use_count >= token.max_uses:
        raise HTTPException(409, "Ce jeton a déjà atteint son nombre maximal d'utilisations.")
    if token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(410, "Ce jeton a expiré — demandez-en un nouveau à un administrateur.")

    asset_id = token.asset_id
    if not asset_id:
        # Jeton "libre" (pas lié à un actif existant) : le premier enrôlement crée
        # l'actif — poste encore inconnu d'Allsafe (cf. models.py::AgentEnrollmentToken).
        # `os` volontairement laissé vide (pas "Linux"/"Windows" générique) : le premier
        # check-in le précise via `apply_scan_result` (ne remplit `os` que s'il est vide,
        # cf. asset_scanner.py) — un placeholder générique aurait bloqué cette correction.
        asset = Asset(
            name=data.hostname, hostname=data.hostname,
            asset_type="workstation", source="agent", collection_method="agent",
        )
        session.add(asset)
        await session.flush()
        asset_id = asset.id
    else:
        asset = await session.get(Asset, asset_id)
        asset.collection_method = "agent"

    raw_credential = secrets.token_urlsafe(32)
    agent = Agent(
        asset_id=asset_id, hostname=data.hostname, os=data.os,
        credential_hash=_hash(raw_credential), enrollment_token_id=token.id,
    )
    session.add(agent)
    await session.flush()

    token.use_count += 1

    await session.commit()
    await session.refresh(agent)
    # Le credential en clair n'est renvoyé qu'ici, une seule fois — l'agent doit le
    # persister localement (fichier à permissions restreintes) et le représenter dans
    # l'en-tête X-Agent-Token à chaque check-in ensuite.
    return {"agent_id": str(agent.id), "asset_id": str(asset_id), "credential": raw_credential}


# ─── Distribution des paquets (déploiement centralisé) ─────────────────────────

@router.get("/latest/version")
async def latest_agent_version():
    """Interrogée par `agent/deploy/update-agent.ps1`/`.sh` avant de télécharger quoi que
    ce soit — évite de retélécharger le paquet à chaque exécution planifiée si le poste
    est déjà à jour."""
    return {"version": CURRENT_AGENT_VERSION}


@router.get("/latest/windows")
async def latest_agent_windows():
    path = os.path.join(AGENT_DIST_DIR, "allsafe-agent.msi")
    if not os.path.isfile(path):
        raise HTTPException(404, "Paquet Windows non disponible côté serveur.")
    return FileResponse(path, media_type="application/x-msi", filename="allsafe-agent.msi")


@router.get("/latest/linux")
async def latest_agent_linux():
    # Le nom du .deb porte la version (`cargo-deb`, ex. allsafe-agent_0.2.0-1_amd64.deb) —
    # pas de nom fixe à maintenir en plus de CURRENT_AGENT_VERSION, on sert simplement le
    # plus récemment construit dans AGENT_DIST_DIR.
    candidates = sorted(glob.glob(os.path.join(AGENT_DIST_DIR, "*.deb")), key=os.path.getmtime, reverse=True)
    if not candidates:
        raise HTTPException(404, "Paquet Linux non disponible côté serveur.")
    path = candidates[0]
    return FileResponse(path, media_type="application/vnd.debian.binary-package", filename=os.path.basename(path))


# ─── Scan à la demande (boucle persistante, jamais l'inverse — CLAUDE.md §1) ───

@router.get("/pending")
async def pending_scan(agent: Agent = Depends(require_agent)):
    """Sondée par `agent/src/daemon.rs` à intervalle court (60s par défaut) — lecture
    seule, le flag n'est effacé qu'au check-in qu'il déclenche (`POST /checkin` ci-
    dessous), jamais ici."""
    return {"scan_requested": agent.pending_scan_requested_at is not None}


@router.post("/{agent_id}/request-scan")
async def request_scan(agent_id: str, session: AsyncSession = Depends(get_session), _admin: User = Depends(require_admin)):
    """Pose juste un flag en base — ne se connecte jamais au poste (CLAUDE.md §1).
    L'agent le ramasse à son prochain sondage `GET /pending` et checkin en conséquence."""
    agent = await session.get(Agent, agent_id)
    if not agent:
        raise HTTPException(404, "Agent introuvable.")
    if agent.status != "enrolled":
        raise HTTPException(409, "Cet agent n'est pas actif — impossible de demander un scan.")
    agent.pending_scan_requested_at = datetime.now(timezone.utc)
    await session.commit()
    return _agent_dict(agent)


# ─── Check-in (agent déjà enrôlé) ───────────────────────────────────────────────

@router.post("/checkin")
async def checkin(
    payload: AgentCheckinPayload,
    session: AsyncSession = Depends(get_session),
    agent: Agent = Depends(require_agent),
):
    if not agent.asset_id:
        raise HTTPException(409, "Cet agent n'est rattaché à aucun actif.")
    asset = await session.get(Asset, agent.asset_id)
    if not asset:
        raise HTTPException(404, "Actif introuvable — l'agent est orphelin, contactez un administrateur.")

    if payload.agent_version:
        agent.agent_version = payload.agent_version

    # Rapport de coupure — le dernier connu reste affiché tant qu'un nouveau ne le
    # remplace pas (jamais effacé silencieusement en son absence, cf. models.py::Agent).
    if payload.offline_since is not None:
        agent.last_gap_started_at = datetime.fromtimestamp(payload.offline_since, tz=timezone.utc)
        agent.last_gap_failed_attempts = payload.failed_attempts

    # Tout check-in réussi satisfait une éventuelle demande de scan en attente — que ce
    # soit elle qui l'ait déclenché ou simplement le cycle normal qui soit arrivé entre-temps.
    agent.pending_scan_requested_at = None

    result = payload.model_dump()
    result = await apply_scan_result(asset, result, session)
    return result


# ─── Liste / révocation (lecture module Sécurité) ──────────────────────────────

@router.get("")
async def list_agents(session: AsyncSession = Depends(get_session), _user: User = Depends(require_page("/agents"))):
    rows = (await session.execute(
        select(Agent, Asset.name, Asset.os, Asset.os_version, AgentEnrollmentToken)
        .outerjoin(Asset, Agent.asset_id == Asset.id)
        .outerjoin(AgentEnrollmentToken, Agent.enrollment_token_id == AgentEnrollmentToken.id)
        .order_by(Agent.enrolled_at.desc())
    )).all()
    return {"items": [
        _agent_dict(a, asset_name, asset_os, asset_os_version, token)
        for a, asset_name, asset_os, asset_os_version, token in rows
    ]}


@router.post("/{agent_id}/revoke")
async def revoke_agent(agent_id: str, session: AsyncSession = Depends(get_session), admin: User = Depends(require_admin)):
    agent = await session.get(Agent, agent_id)
    if not agent:
        raise HTTPException(404, "Agent introuvable.")
    agent.status = "revoked"
    agent.revoked_at = datetime.now(timezone.utc)
    agent.revoked_by = admin.full_name
    await session.commit()
    return _agent_dict(agent)


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(agent_id: str, session: AsyncSession = Depends(get_session), _admin: User = Depends(require_admin)):
    """Suppression définitive (13/08/2026) — réservée aux agents déjà `revoked` : la
    révocation reste le geste d'audit trail (cf. `Agent`, "digne d'un audit trail" comme
    `User.is_active`), la suppression ne sert qu'à nettoyer une entrée déjà terminée (poste
    décommissionné, test). Un agent encore `enrolled` doit d'abord être révoqué — pas de
    raccourci qui perdrait la trace qu'il a existé/été actif."""
    agent = await session.get(Agent, agent_id)
    if not agent:
        raise HTTPException(404, "Agent introuvable.")
    if agent.status != "revoked":
        raise HTTPException(409, "Révoquez d'abord l'agent avant de le supprimer.")
    await session.delete(agent)
    await session.commit()
