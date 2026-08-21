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
import io
import os
import secrets
import hashlib
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_admin, require_agent, require_auth, require_page
from database import get_session
from models import Agent, AgentCheckinLog, AgentDeletionLog, AgentEnrollmentToken, AgentSecurityEvent, Asset, User
from services.agent_detection import apply_security_events
from services.asset_scanner import apply_scan_result

router = APIRouter()

AGENT_DIST_DIR = "/app/agent-dist"

# Dernière version publiée, PAR PLATEFORME (19/08/2026, demande explicite — cf.
# agent/src/main.rs::RELEASE_VERSION) — à bumper manuellement à chaque release, mais
# uniquement pour la plateforme qui a réellement changé. Une seule constante partagée
# forçait à bumper les deux à chaque changement, même quand rien n'avait bougé pour l'autre
# OS : l'agent Linux s'affichait "en retard" dans Allsafe après un correctif Windows pur
# (incident réel, même session — cf. STATUS.md). Pas de mécanisme de mise à jour automatique
# poussé par Allsafe dans ce MVP : ces constantes ne servent qu'à comparer côté serveur ce
# que chaque agent déclare à son dernier check-in (`Agent.agent_version`) pour repérer les
# postes en retard (`_agent_dict::outdated`, cf. `_current_version_for` ci-dessous).
CURRENT_AGENT_VERSION_WINDOWS = "0.1.19"
CURRENT_AGENT_VERSION_LINUX = "0.1.9"


def _current_version_for(os_: str) -> str:
    return CURRENT_AGENT_VERSION_WINDOWS if os_ == "windows" else CURRENT_AGENT_VERSION_LINUX


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _short_hostname(hostname: str) -> str:
    """Réduit un hostname à son nom court (avant le premier point) pour comparer un FQDN
    (`armadasenonches.aer.loc`, `Asset.hostname` typique d'un import AD) à un nom court
    (`armadasenonches`, `%COMPUTERNAME%` — c'est tout ce que l'agent Windows sait envoyer,
    cf. `agent/src/collect/windows.rs::hostname`, jamais le FQDN). Utilisé uniquement par le
    garde-fou d'enrôlement ci-dessous (19/08/2026, incident réel — la comparaison stricte
    d'origine, cf. audit/AUDIT_SECURITE.md #16, bloquait tout enrôlement Windows contre un
    actif nommé en FQDN, systématique sur ce parc majoritairement AD)."""
    return hostname.strip().lower().split(".", 1)[0]


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
    # Détection d'évènements sensibles (19/08/2026, cf. docs/AGENT_DETECTION.md) — dict libres
    # (pas de schéma strict clé par clé), plafonnés côté serveur avant tout traitement
    # (services/agent_detection.py) : rien ne garantit qu'un agent compromis/buggé respecte
    # les plafonds déjà posés côté client.
    security_events: list = []   # évènements neufs depuis le dernier check-in réussi
    audit_coverage: dict = {}    # état de l'audit OS constaté côté poste
    state_snapshot: dict = {}    # comptes/admins/persistance pour le diff serveur


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
        "outdated": a.agent_version is not None and a.agent_version != _current_version_for(a.os),
        "pending_scan_requested_at": a.pending_scan_requested_at.isoformat() if a.pending_scan_requested_at else None,
        "last_gap_started_at": a.last_gap_started_at.isoformat() if a.last_gap_started_at else None,
        "last_gap_failed_attempts": a.last_gap_failed_attempts,
        "revoked_at": a.revoked_at.isoformat() if a.revoked_at else None,
        "revoked_by": a.revoked_by,
        "token_status": _token_status(token),
        # Génération du jeton d'enrôlement (par qui/quand) — pour la frise "Historique des
        # contacts" de AgentHistory.jsx, qui remonte jusqu'aux évènements fondateurs (jeton
        # généré → poste enrôlé). None si le jeton a été révoqué/supprimé après coup
        # (`enrollment_token_id` mis à NULL par ON DELETE SET NULL) : l'info est alors perdue,
        # seul `enrolled_at` (sur l'agent lui-même) reste toujours disponible.
        "enrollment_token_created_at": token.created_at.isoformat() if token and token.created_at else None,
        "enrollment_token_created_by": token.created_by if token else None,
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
    now = datetime.now(timezone.utc)

    # Pré-vérification hostname (18/08/2026, cf. audit/AUDIT_SECURITE.md #16) — lecture
    # seule, AVANT toute consommation d'utilisation du jeton (cf. UPDATE...RETURNING
    # ci-dessous) : un jeton lié à un `asset_id` précis engage l'identité de CET actif, un
    # hostname déclaré différent est rejeté. Faite en amont plutôt qu'après l'incrément
    # atomique — sinon un hostname mal renseigné (typo, poste mal identifié) épuiserait le
    # jeton sur un essai raté, forçant l'admin à en regénérer un, sans lien avec la sécurité
    # recherchée par ce garde-fou (cf. sa justification complète plus bas, à l'usage réel du
    # résultat de l'UPDATE).
    #
    # Comparaison sur le nom court (`_short_hostname`, 19/08/2026, incident réel) — pas le
    # hostname en toutes lettres : l'agent Windows ne connaît que `%COMPUTERNAME%` (jamais le
    # FQDN), alors que `Asset.hostname` porte le FQDN complet pour tout actif importé depuis
    # l'AD (la majorité du parc, cf. CLAUDE.md § Contexte). Une égalité stricte bloquait donc
    # systématiquement l'enrôlement Windows dès que l'actif était nommé en FQDN — pas un cas
    # limite, le cas normal sur ce parc.
    preview = (await session.execute(
        select(AgentEnrollmentToken).where(AgentEnrollmentToken.token_hash == token_hash)
    )).scalar_one_or_none()
    if preview and preview.asset_id:
        bound_asset = await session.get(Asset, preview.asset_id)
        if bound_asset and bound_asset.hostname and _short_hostname(bound_asset.hostname) != _short_hostname(data.hostname):
            raise HTTPException(
                403,
                f"Ce jeton est lié à l'actif '{bound_asset.hostname}' — hostname déclaré "
                f"('{data.hostname}') différent, enrôlement refusé.",
            )

    # UPDATE...RETURNING atomique (18/08/2026, cf. audit/AUDIT_SECURITE.md #15) — remplace
    # le lire-puis-écrire précédent (`token.use_count += 1` différé au commit), qui laissait
    # une fenêtre de course : N requêtes concurrentes sur le même jeton `max_uses=1` liraient
    # toutes `use_count=0` avant qu'aucune ne commite, créant N identités agent valides pour
    # un jeton censé n'en autoriser qu'une (reproduit en conditions réelles, 15/15 acceptées).
    # La clause WHERE re-vérifiée par Postgres sous verrou de ligne sérialise les requêtes
    # concurrentes : une seule peut voir `use_count < max_uses` rester vrai à la fois.
    result = await session.execute(
        update(AgentEnrollmentToken)
        .where(
            AgentEnrollmentToken.token_hash == token_hash,
            AgentEnrollmentToken.use_count < AgentEnrollmentToken.max_uses,
            AgentEnrollmentToken.expires_at >= now,
        )
        .values(use_count=AgentEnrollmentToken.use_count + 1)
        .returning(AgentEnrollmentToken)
    )
    token = result.scalar_one_or_none()
    if token is None:
        # Retombe sur une simple lecture pour distinguer invalide/épuisé/expiré dans le
        # message d'erreur — ne réécrit jamais la ligne, uniquement pour le diagnostic.
        existing = (await session.execute(
            select(AgentEnrollmentToken).where(AgentEnrollmentToken.token_hash == token_hash)
        )).scalar_one_or_none()
        if not existing:
            raise HTTPException(401, "Jeton d'enrôlement invalide.")
        if existing.expires_at < now:
            raise HTTPException(410, "Ce jeton a expiré — demandez-en un nouveau à un administrateur.")
        raise HTTPException(409, "Ce jeton a déjà atteint son nombre maximal d'utilisations.")

    asset_id = token.asset_id
    if not asset_id:
        # Jeton "libre" (pas lié à un actif existant) : le premier enrôlement crée
        # l'actif — poste encore inconnu d'Allsafe (cf. models.py::AgentEnrollmentToken).
        # `hostname` porte une contrainte unique (`ix_assets_hostname`) — un poste déjà
        # réenrôlé avec un autre jeton "libre" (jeton perdu, agent.json effacé...) ferait
        # planter un `INSERT` en 500 brut sans cette vérification préalable (constaté en
        # conditions réelles, 18/08/2026, deux enrôlements successifs sur le même hostname
        # `deployapp`) : on rattache le nouvel agent à l'actif existant plutôt que d'en
        # recréer un second en doublon.
        existing = (await session.execute(
            select(Asset).where(Asset.hostname == data.hostname)
        )).scalar_one_or_none()
        if existing:
            asset = existing
            asset.collection_method = "agent"
            asset_id = asset.id
        else:
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
        # Hostname déjà validé par la pré-vérification tout en haut de la fonction (#16) —
        # combiné à une fuite du jeton (interception réseau, ou la race #15 avant correctif),
        # sans elle un tiers aurait pu se faire délivrer un credential pour cet actif précis
        # en lui faisant porter n'importe quel hostname. La garantie "les données auto-
        # déclarées par l'agent restent fiables" doit tenir dès l'enrôlement, pas seulement au
        # check-in (cf. #34, décision de garder la bascule auto sur les CVE HIGH/MEDIUM/LOW
        # détectées par agent : elle ne vaut que si l'identité agent↔actif est fiable).
        asset = await session.get(Asset, asset_id)
        asset.collection_method = "agent"

    raw_credential = secrets.token_urlsafe(32)
    agent = Agent(
        asset_id=asset_id, hostname=data.hostname, os=data.os,
        credential_hash=_hash(raw_credential), enrollment_token_id=token.id,
    )
    session.add(agent)
    await session.flush()

    await session.commit()
    await session.refresh(agent)
    # Le credential en clair n'est renvoyé qu'ici, une seule fois — l'agent doit le
    # persister localement (fichier à permissions restreintes) et le représenter dans
    # l'en-tête X-Agent-Token à chaque check-in ensuite.
    return {"agent_id": str(agent.id), "asset_id": str(asset_id), "credential": raw_credential}


# ─── Distribution des paquets (déploiement centralisé) ─────────────────────────

def _sha256_of(path: str) -> Optional[str]:
    """Empreinte SHA-256 d'un fichier, calculée à la volée (fichiers de quelques Mo, coût
    négligeable face à la fréquence d'appel de `/latest/version` — pas de cache), ou `None`
    si le fichier n'existe pas (rien à hacher)."""
    if not os.path.isfile(path):
        return None
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _latest_deb_path() -> Optional[str]:
    # Le nom du .deb porte la version (`cargo-deb`, ex. allsafe-agent_0.2.0-1_amd64.deb) —
    # pas de nom fixe à maintenir en plus de CURRENT_AGENT_VERSION_LINUX, on sert simplement
    # le plus récemment construit dans AGENT_DIST_DIR.
    candidates = sorted(glob.glob(os.path.join(AGENT_DIST_DIR, "*.deb")), key=os.path.getmtime, reverse=True)
    return candidates[0] if candidates else None


def _built_at(path: Optional[str]) -> Optional[str]:
    """Date de construction du paquet (mtime du fichier sur le disque de distribution),
    ISO 8601 UTC — `None` si le fichier n'existe pas. Affichée à côté de la version sur la
    page Agents (19/08/2026, cf. STATUS.md — confusion réelle constatée : un utilisateur
    téléchargeait un paquet resservi par le cache disque du navigateur, sans pouvoir la
    distinguer d'un paquet à jour rien qu'au nom de fichier/numéro de version affiché)."""
    if not path or not os.path.isfile(path):
        return None
    return datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc).isoformat()


# Pas de cache navigateur sur les 4 routes de distribution ci-dessous (19/08/2026, même
# incident que ci-dessus) : sans en-tête explicite, un navigateur peut resservir un ancien
# téléchargement depuis son cache disque par fraîcheur heuristique (RFC 7234, basée sur
# Last-Modified) sans même recontacter le serveur — constaté en conditions réelles, un
# utilisateur recevait encore le `.deb` buggé (cf. audit/AUDIT_SECURITE.md, incident glibc)
# après le correctif serveur. `no-cache` (pas `no-store`) : force la revalidation à chaque
# téléchargement plutôt que d'interdire toute mise en cache — le client renvoie l'ETag/
# Last-Modified, le serveur répond 304 si rien n'a changé, 200 sinon. Coût négligeable face
# à la fréquence de ces téléchargements (manuels, rares).
_NO_CACHE_HEADERS = {"Cache-Control": "no-cache"}


@router.get("/latest/version")
async def latest_agent_version():
    """Interrogée par `agent/deploy/update-agent.ps1`/`.sh` avant de télécharger quoi que
    ce soit — évite de retélécharger le paquet à chaque exécution planifiée si le poste
    est déjà à jour.

    `sha256_windows`/`sha256_linux` (18/08/2026, cf. audit/AUDIT_SECURITE.md #13) :
    empreinte du `.msi`/`.deb` actuellement publié. Consommées par
    `agent/src/install.rs::apply_update` (Rust, Windows uniquement) et
    `update-agent.ps1`/`.sh` (déploiement de parc, les deux OS) pour refuser d'exécuter un
    paquet dont l'empreinte ne correspond pas — seule protection posée avant qu'une vraie
    signature Authenticode vérifiable (certificat GPO) ne soit en place côté Windows, cf.
    docstring `apply_update`. `None` si aucun paquet n'est disponible côté serveur pour cet
    OS (rien à hacher).

    `built_at_windows`/`built_at_linux` (19/08/2026) : date de construction du paquet
    actuellement publié (mtime sur `AGENT_DIST_DIR`), affichée sur la page Agents à côté de
    chaque option de téléchargement pour lever toute ambiguïté sur ce qui sera reçu — cf.
    `_built_at` ci-dessus.

    `version_windows`/`version_linux` (19/08/2026, remplace l'ancien `version` unique) —
    versionnement séparé par plateforme, cf. `CURRENT_AGENT_VERSION_WINDOWS`/`_LINUX`
    ci-dessus. `agent/src/install.rs::check_update` (Windows) et `update-agent.ps1`/`.sh`
    (déploiement de parc, cf. leur propre lecture de ce champ) lisent chacun uniquement la
    clé qui les concerne."""
    deb_path = _latest_deb_path()
    return {
        "version_windows": CURRENT_AGENT_VERSION_WINDOWS,
        "version_linux": CURRENT_AGENT_VERSION_LINUX,
        "sha256_windows": _sha256_of(os.path.join(AGENT_DIST_DIR, "allsafe-agent.msi")),
        "sha256_linux": _sha256_of(deb_path) if deb_path else None,
        "built_at_windows": _built_at(os.path.join(AGENT_DIST_DIR, "allsafe-agent.msi")),
        "built_at_linux": _built_at(deb_path),
    }


@router.get("/latest/windows")
async def latest_agent_windows():
    path = os.path.join(AGENT_DIST_DIR, "allsafe-agent.msi")
    if not os.path.isfile(path):
        raise HTTPException(404, "Paquet Windows non disponible côté serveur.")
    return FileResponse(path, media_type="application/x-msi", filename="allsafe-agent.msi", headers=_NO_CACHE_HEADERS)


@router.get("/latest/linux")
async def latest_agent_linux():
    path = _latest_deb_path()
    if not path:
        raise HTTPException(404, "Paquet Linux non disponible côté serveur.")
    return FileResponse(path, media_type="application/vnd.debian.binary-package", filename=os.path.basename(path), headers=_NO_CACHE_HEADERS)


@router.get("/latest/windows-exe")
async def latest_agent_windows_exe():
    """`.exe` autonome (18/08/2026, cf. page Agents > téléchargement) — zippé avec
    `WebView2Loader.dll` : l'exe seul ne se lance pas sans ce fichier à côté de lui (cible
    GNU, cf. agent/README.md § Build). Le `.msi` (route ci-dessus) embarque déjà les deux,
    ce zip n'existe que pour l'usage ".exe seul" (poste critique, cf. CLAUDE.md § Agents)."""
    exe_path = os.path.join(AGENT_DIST_DIR, "allsafe-agent.exe")
    dll_path = os.path.join(AGENT_DIST_DIR, "WebView2Loader.dll")
    if not os.path.isfile(exe_path) or not os.path.isfile(dll_path):
        raise HTTPException(404, "Exécutable Windows non disponible côté serveur.")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(exe_path, "allsafe-agent.exe")
        zf.write(dll_path, "WebView2Loader.dll")
    buf.seek(0)
    return StreamingResponse(
        buf, media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="allsafe-agent.zip"', **_NO_CACHE_HEADERS},
    )


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

# Throttle (18/08/2026, cf. audit/AUDIT_SECURITE.md #35) — un agent compromis/buggé
# pouvait spammer /checkin sans aucune limite : chaque appel déclenche une tâche Celery +
# un cycle de patch check complet. La cadence normale (planifiée, `agent/src/daemon.rs::
# CHECKIN_INTERVAL`) est largement au-dessus de la minute — ne gêne ni le cycle horaire ni
# un scan à la demande (ramassé au prochain sondage `/pending`, ≤60s, jamais deux check-ins
# à quelques secondes d'écart en usage normal).
CHECKIN_MIN_INTERVAL_SECONDS = 60
# Même plafond que services/asset_scanner.py (`[:300]`) — l'agent n'a pas cette limite
# aujourd'hui, contrairement au scan pull SSH/WinRM, ce qui autorise un payload démesuré
# stocké tel quel dans des colonnes JSON (cf. #35).
CHECKIN_MAX_ITEMS = 300


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

    last_checkin_at = (await session.execute(
        select(AgentCheckinLog.checked_in_at)
        .where(AgentCheckinLog.agent_id == agent.id)
        .order_by(AgentCheckinLog.checked_in_at.desc())
        .limit(1)
    )).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if last_checkin_at and (now - last_checkin_at).total_seconds() < CHECKIN_MIN_INTERVAL_SECONDS:
        raise HTTPException(429, f"Check-in trop fréquent — au plus un toutes les {CHECKIN_MIN_INTERVAL_SECONDS}s.")

    payload.packages = payload.packages[:CHECKIN_MAX_ITEMS]
    if isinstance(payload.compliance.get("checks"), list):
        payload.compliance["checks"] = payload.compliance["checks"][:CHECKIN_MAX_ITEMS]

    if payload.agent_version:
        agent.agent_version = payload.agent_version

    # Rapport de coupure — le dernier connu reste affiché tant qu'un nouveau ne le
    # remplace pas (jamais effacé silencieusement en son absence, cf. models.py::Agent).
    gap_started_at = None
    if payload.offline_since is not None:
        gap_started_at = datetime.fromtimestamp(payload.offline_since, tz=timezone.utc)
        agent.last_gap_started_at = gap_started_at
        agent.last_gap_failed_attempts = payload.failed_attempts

    # Tout check-in réussi satisfait une éventuelle demande de scan en attente — que ce
    # soit elle qui l'ait déclenché ou simplement le cycle normal qui soit arrivé entre-temps.
    # `on_demand` capturé AVANT l'effacement (18/08/2026) : c'est la seule fenêtre où on peut
    # encore savoir si CE check-in précis a été déclenché par une demande manuelle plutôt que
    # par le cycle horaire normal (cf. models.py::AgentCheckinLog.on_demand).
    on_demand = agent.pending_scan_requested_at is not None
    agent.pending_scan_requested_at = None

    # Journal (18/08/2026, cf. models.py::AgentCheckinLog) — un check-in réussi seulement,
    # jamais le sondage /pending. `checked_in_at` posé ici (pas server_default) : doit
    # correspondre exactement au moment de CE check-in, pas d'un défaut SQL.
    session.add(AgentCheckinLog(
        agent_id=agent.id, checked_in_at=datetime.now(timezone.utc),
        package_count=payload.package_count, agent_version=payload.agent_version,
        gap_started_at=gap_started_at, gap_failed_attempts=payload.failed_attempts,
        on_demand=on_demand,
    ))

    result = payload.model_dump()

    # Détection d'évènements sensibles (19/08/2026, cf. docs/AGENT_DETECTION.md) — fonction
    # dédiée, pas apply_scan_result ci-dessous (shape différent, cf. doc § À vérifier à
    # l'implémentation). Après apply_security_events (agent.audit_coverage déjà posé), avant
    # apply_scan_result (indépendant, ne touche pas aux mêmes colonnes).
    await apply_security_events(agent, result, session)

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


@router.get("/history")
async def agents_history(session: AsyncSession = Depends(get_session), _user: User = Depends(require_page("/agents"))):
    """Historique complet des agents (19/08/2026) — agents actuellement enrôlés/révoqués
    (table `agents`) + agents supprimés (`AgentDeletionLog`, snapshot survivant au hard delete).
    Alimente le badge compteur + la liste "depuis le début" de la page Sécurité > Agents. Le
    compteur démarre aux agents actuels : rien n'est reconstitué avant la mise en place du
    journal (cf. models.AgentDeletionLog). Déclaré AVANT `/{agent_id}` (route statique à un
    segment) sous peine de se faire voler la requête par la route dynamique."""
    live = (await session.execute(
        select(Agent, Asset.name, AgentEnrollmentToken.created_by)
        .outerjoin(Asset, Agent.asset_id == Asset.id)
        .outerjoin(AgentEnrollmentToken, Agent.enrollment_token_id == AgentEnrollmentToken.id)
    )).all()
    deleted = (await session.execute(select(AgentDeletionLog))).scalars().all()

    items = [
        {
            "hostname": a.hostname, "os": a.os, "asset_name": asset_name,
            "enrolled_at": a.enrolled_at.isoformat() if a.enrolled_at else None,
            "enrolled_by": created_by,
            "status": a.status,                       # enrolled | revoked
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
            "revoked_at": a.revoked_at.isoformat() if a.revoked_at else None,
            "revoked_by": a.revoked_by,
            "deleted": False,
        }
        for a, asset_name, created_by in live
    ] + [
        {
            "hostname": d.hostname, "os": d.os, "asset_name": d.asset_name,
            "enrolled_at": d.enrolled_at.isoformat() if d.enrolled_at else None,
            "enrolled_by": d.enrolled_by,
            "status": "deleted",
            "deleted_at": d.deleted_at.isoformat() if d.deleted_at else None,
            "deleted_by": d.deleted_by,
            "deleted": True,
        }
        for d in deleted
    ]
    # Tri du plus récent au plus ancien (date d'enrôlement, nulls en dernier) — les ISO produits
    # par isoformat() sont comparables lexicographiquement, suffisant pour l'affichage.
    items.sort(key=lambda i: i.get("enrolled_at") or "", reverse=True)
    return {
        "total": len(items),
        "live_count": len(live),
        "deleted_count": len(deleted),
        "items": items,
    }


# ─── Détection d'évènements sensibles (19/08/2026, cf. docs/AGENT_DETECTION.md) ────
# Écriture faite par apply_security_events() (services/agent_detection.py) au check-in
# ci-dessus. Ici, uniquement lecture/acquittement — même schéma que routers/security.py
# (déception DB) : réservé admin, SAUF le compteur (badge nav, visible à tout connecté).
#
# ⚠️ Enregistrées AVANT le catch-all `/{agent_id}` ci-dessous (comme `/history` au-dessus) —
# FastAPI/Starlette matche les routes dans l'ordre de déclaration, pas par spécificité :
# après ce catch-all, `GET /agents/security-events` serait intercepté par `get_agent` avec
# `agent_id="security-events"` et ne répondrait jamais.

def _security_event_dict(e: AgentSecurityEvent) -> dict:
    return {
        "id": str(e.id),
        "agent_id": str(e.agent_id) if e.agent_id else None,
        "hostname": e.hostname,
        "os": e.os,
        "category": e.category,
        "severity": e.severity,
        "detection_method": e.detection_method,
        "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
        "reported_at": e.reported_at.isoformat() if e.reported_at else None,
        "native_source": e.native_source,
        "summary": e.summary,
        "detail": e.detail,
        "acknowledged": e.acknowledged,
        "ack_by": e.ack_by,
        "ack_at": e.ack_at.isoformat() if e.ack_at else None,
    }


@router.get("/security-events")
async def list_security_events(
    unack_only: bool = Query(False, description="Ne renvoyer que les évènements non acquittés"),
    limit: int = Query(100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    _admin: User = Depends(require_admin),
):
    """Journal des détections agent, le plus récent d'abord. Réservé admin — le compteur
    ci-dessous reste accessible à tout utilisateur connecté (badge nav Inventaire)."""
    q = select(AgentSecurityEvent).order_by(AgentSecurityEvent.reported_at.desc()).limit(limit)
    if unack_only:
        q = q.where(AgentSecurityEvent.acknowledged.is_(False))
    rows = (await session.execute(q)).scalars().all()
    return {"events": [_security_event_dict(e) for e in rows]}


@router.get("/security-events/count")
async def security_events_count(session: AsyncSession = Depends(get_session), _user: User = Depends(require_auth)):
    """Compteur léger pour le badge nav (poll régulier) — exception délibérée à "réservé
    admin" ci-dessus, même raisonnement que `routers/security.py::events_count`."""
    unack = await session.scalar(
        select(func.count()).select_from(AgentSecurityEvent).where(AgentSecurityEvent.acknowledged.is_(False))
    )
    latest = await session.scalar(
        select(func.max(AgentSecurityEvent.reported_at)).where(AgentSecurityEvent.acknowledged.is_(False))
    )
    return {"unacknowledged": unack or 0, "latest": latest.isoformat() if latest else None}


class AgentEventAckPayload(BaseModel):
    ack_by: Optional[str] = None


@router.post("/security-events/{event_id}/ack")
async def ack_security_event(
    event_id: str, data: AgentEventAckPayload,
    session: AsyncSession = Depends(get_session), _admin: User = Depends(require_admin),
):
    """Acquitter un évènement — jamais une suppression (append-only strict, piste d'audit
    NIS 2, cf. doc § Décisions figées)."""
    e = await session.get(AgentSecurityEvent, event_id)
    if not e:
        raise HTTPException(404, "Évènement introuvable.")
    e.acknowledged = True
    e.ack_by = data.ack_by or None
    e.ack_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(e)
    return _security_event_dict(e)


@router.post("/security-events/ack-all")
async def ack_all_security_events(
    data: AgentEventAckPayload,
    session: AsyncSession = Depends(get_session), _admin: User = Depends(require_admin),
):
    now = datetime.now(timezone.utc)
    res = await session.execute(
        update(AgentSecurityEvent).where(AgentSecurityEvent.acknowledged.is_(False))
        .values(acknowledged=True, ack_by=data.ack_by or None, ack_at=now)
    )
    await session.commit()
    return {"acknowledged": res.rowcount or 0}


@router.get("/{agent_id}")
async def get_agent(agent_id: str, session: AsyncSession = Depends(get_session), _user: User = Depends(require_page("/agents"))):
    """Détail d'un agent — alimente la page d'historique des contacts (chargement direct
    par URL, sans dépendre de la liste déjà chargée côté Sécurité > Agents)."""
    row = (await session.execute(
        select(Agent, Asset.name, Asset.os, Asset.os_version, AgentEnrollmentToken)
        .outerjoin(Asset, Agent.asset_id == Asset.id)
        .outerjoin(AgentEnrollmentToken, Agent.enrollment_token_id == AgentEnrollmentToken.id)
        .where(Agent.id == agent_id)
    )).first()
    if not row:
        raise HTTPException(404, "Agent introuvable.")
    a, asset_name, asset_os, asset_os_version, token = row
    return _agent_dict(a, asset_name, asset_os, asset_os_version, token)


@router.get("/{agent_id}/checkins")
async def agent_checkins(
    agent_id: str,
    limit: int = Query(200, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(require_page("/agents")),
):
    """Historique des check-ins réussis (18/08/2026, cf. models.py::AgentCheckinLog) — le
    plus récent d'abord. `total` distinct de la longueur d'`items` : la page peut afficher
    "X affichés sur Y au total" même quand `limit` tronque la liste."""
    if not await session.get(Agent, agent_id):
        raise HTTPException(404, "Agent introuvable.")
    total = (await session.execute(
        select(func.count()).select_from(AgentCheckinLog).where(AgentCheckinLog.agent_id == agent_id)
    )).scalar_one()
    rows = (await session.execute(
        select(AgentCheckinLog).where(AgentCheckinLog.agent_id == agent_id)
        .order_by(AgentCheckinLog.checked_in_at.desc()).limit(limit)
    )).scalars().all()
    return {
        "total": total,
        "items": [{
            "id": str(r.id),
            "checked_in_at": r.checked_in_at.isoformat() if r.checked_in_at else None,
            "package_count": r.package_count,
            "agent_version": r.agent_version,
            "gap_started_at": r.gap_started_at.isoformat() if r.gap_started_at else None,
            "gap_failed_attempts": r.gap_failed_attempts,
            "on_demand": r.on_demand,
        } for r in rows],
    }


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
    # Journal "agent supprimé" (19/08/2026, cf. models.AgentDeletionLog) : la ligne `agents` va
    # disparaître sans trace (hard delete) — sans ce snapshot, l'historique complet des agents
    # (badge de la page liste) ne pourrait plus compter ce poste. asset_name/enrolled_by résolus
    # best-effort (l'actif ou le jeton d'origine peuvent avoir disparu entre-temps).
    asset_name = await session.scalar(select(Asset.name).where(Asset.id == agent.asset_id)) if agent.asset_id else None
    enrolled_by = (await session.scalar(
        select(AgentEnrollmentToken.created_by).where(AgentEnrollmentToken.id == agent.enrollment_token_id)
    )) if agent.enrollment_token_id else None
    session.add(AgentDeletionLog(
        hostname=agent.hostname, os=agent.os, asset_name=asset_name,
        enrolled_at=agent.enrolled_at, enrolled_by=enrolled_by,
        deleted_at=datetime.now(timezone.utc), deleted_by=_admin.full_name,
    ))
    await session.delete(agent)
    await session.commit()
