import asyncio
import time

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, or_
from sqlalchemy.orm import load_only
from typing import Optional
from datetime import datetime, timedelta, timezone
from database import get_session
from models import Vulnerability, CVE, Asset, VulnerabilityStatusHistory
from services.vuln_history import record_status_change
from services.stats import get_configured_asset_ids
from services.patch_checker import AUTO_VALIDATED_BY_LABELS

router = APIRouter()

# Pagination pour les endpoints "candidats" (awaiting-fix, false-positive,
# critical-review) — même principe que backfill_auto_patch/run_startup_patch_checks
# dans services/patch_checker.py. Incident (28/07/2026) : ces trois endpoints
# chargeaient d'un coup (`.all()`) la quasi-totalité des ~265 000 vulnérabilités
# ouvertes (jointes à CVE + Asset), et false-positive-candidates est en plus
# interrogé toutes les 30s par le Dashboard tant qu'il reste ouvert.
#
# Un premier correctif (rendre la main entre deux LOTS de 2000 lignes) a
# résolu le pic mémoire mais pas le blocage : la boucle Python synchrone de
# `still_matches` sur 2000 lignes d'affilée suffit encore à geler la boucle
# asyncio plusieurs secondes, assez pour faire timeouter les requêtes
# concurrentes du Dashboard (constaté en réel : vague de 500 sur /api/stats,
# /api/assets etc. pendant qu'un scan tournait, alors que ces endpoints ne
# touchent pas du tout au code changé — signe d'un event loop bloqué, pas
# d'une erreur applicative). D'où CANDIDATE_YIELD_EVERY, bien plus fin que
# la taille de page SQL : la main est rendue à l'event loop tous les 50 lignes
# *traitées par l'appelant* (still_matches compris), pas seulement tous les
# 2000 lignes lues en base.
CANDIDATE_BATCH_SIZE = 2000
CANDIDATE_YIELD_EVERY = 50

# Fenêtre par défaut des 3 endpoints "candidats" (28/07/2026) : la quasi-totalité
# des ~265 000 vulnérabilités ouvertes vient du matching CPE initial, dont
# beaucoup de CVE de plusieurs années — pas utile à rescanner à chaque appel pour
# du triage courant. Comme `max_age_years` sur GET /vulnerabilities, borne
# UNIQUEMENT ces listes de travail, jamais le matching/la collecte (cf. son
# commentaire ci-dessous, incident CVE-2022-30190 : une CVE ancienne peut
# redevenir d'actualité sans le moindre signal préalable — la couper à la
# collecte referait perdre ce genre de cas silencieusement).
#
# Levée uniquement quand `asset_id` est fourni (bouton "voir aussi les CVE
# anciennes" côté UI, scopé à un actif à la fois) — jamais globalement, pour ne
# pas réintroduire le volume qu'on vient de borner.
CANDIDATE_MAX_AGE_YEARS = 2

# Mémoïsation process de `false_positive_candidates` (08/08/2026, cf. STATUS.md §
# Points ouverts) : c'est le plus lourd des 3 endpoints "candidats" (~7,5s après
# les optimisations du 28/07, contre <1s pour les deux autres) — reste recalculé
# à chaque appel HTTP alors que le Dashboard le sonde en continu et que le résultat
# ne change quasiment jamais entre deux appels rapprochés. Même schéma que le cache
# process déjà en place pour les blocklists IP (`services/ip_watch.py::_cache`,
# dict + `time.time()`, pas de dépendance Redis pour un simple TTL). Sans risque de
# donnée périmée dangereuse : `bulk_false_positive` revérifie chaque id côté
# serveur avant d'agir (cf. sa docstring), un candidat obsolète affiché ici serait
# simplement rejeté et renvoyé dans "skipped" — jamais qualifié à tort. Clé =
# (asset_id, configured_only), les deux seuls paramètres qui changent le résultat.
FALSE_POSITIVE_CACHE_TTL = 300  # 5 min
_false_positive_cache: dict = {}


def _invalidate_false_positive_cache() -> None:
    """Appelé après toute bascule qui change la liste des candidats (cf.
    `bulk_false_positive` ci-dessous) — sans ça, un lot qu'on vient de qualifier
    resterait affiché comme "encore candidat" jusqu'à expiration du TTL."""
    _false_positive_cache.clear()

# États considérés "traités" pour le badge "déjà résolu ailleurs" (04/08/2026,
# demande explicite) — mêmes trois statuts terminaux que le garde-fou
# apply_patch_result (cf. CLAUDE.md), qui ont chacun une justification à
# réutiliser (validated_by + notes/patch_check_details).
RESOLVED_STATUSES = ("patched", "false_positive", "accepted_risk")


def _candidate_conditions(
    status_in: list[str], asset_id: Optional[str], *extra, configured_asset_ids: Optional[list[str]] = None,
) -> list:
    conditions = [Vulnerability.status.in_(status_in), *extra]
    if asset_id:
        conditions.append(Vulnerability.asset_id == asset_id)
    else:
        cutoff = datetime.now(timezone.utc) - timedelta(days=365 * CANDIDATE_MAX_AGE_YEARS)
        conditions.append(CVE.published >= cutoff)
        # `configured_asset_ids` (07/08/2026) : périmètre "actifs configurés" du
        # dashboard, cf. GET /vulnerabilities?configured_only — appelant
        # responsable de le résoudre (fonction non-async) et de ne le passer que
        # quand pertinent (jamais depuis Vulnerabilities.jsx, catalogue complet).
        if configured_asset_ids is not None:
            conditions.append(Vulnerability.asset_id.in_(configured_asset_ids))
    return conditions


# Colonnes réellement lues par `_vuln_dict` et `still_matches` — tout le reste
# est exclu du SELECT (28/07/2026, cause principale des lenteurs à l'échelle du
# parc réel). `cves.raw_data` (le JSON NVD brut) pèse à lui seul **377 Mo** en
# base, 2,2 Ko par CVE en moyenne et jusqu'à 268 Ko : charger l'entité `CVE`
# complète faisait transférer puis désérialiser en JSON ~190 Mo de données par
# appel — pour un champ qu'aucun de ces trois endpoints ne lit. Diagnostic qui a
# mis sur la piste : PostgreSQL à 3% de CPU pendant que le backend saturait un
# cœur à 101% sur ~6 requêtes/minute — le coût était en Python (désérialisation
# + construction d'objets ORM), pas en SQL, donc invisible pour les index posés
# plus tôt dans la journée.
#
# `raiseload=True` : toute colonne oubliée ici lève une exception explicite au
# lieu de déclencher un SELECT par ligne (N+1 silencieux) — c'est exactement ce
# type de dégradation invisible qui a produit cet incident, autant qu'elle
# échoue bruyamment. Ajouter un champ à `_vuln_dict` impose donc de l'ajouter ici.
_CANDIDATE_LOAD_OPTIONS = (
    load_only(
        Vulnerability.id, Vulnerability.asset_id, Vulnerability.cve_id,
        Vulnerability.status, Vulnerability.risk_score, Vulnerability.detected_at,
        Vulnerability.patched_at, Vulnerability.awaiting_fix_at,
        Vulnerability.false_positive_at, Vulnerability.accepted_risk_until,
        Vulnerability.validated_by, Vulnerability.notes,
        Vulnerability.ai_analysis, Vulnerability.patch_check_result,
        # cvss_bte/cvss_bte_vector (17/08/2026) : _vuln_dict() les lit désormais
        # inconditionnellement (cf. son commentaire) — obligatoires ici sous peine de
        # RaisedException sur ces trois endpoints candidats.
        Vulnerability.cvss_bte, Vulnerability.cvss_bte_vector,
        raiseload=True,
    ),
    load_only(
        CVE.id, CVE.cve_id, CVE.severity, CVE.cvss_score, CVE.epss_score, CVE.published,
        CVE.description, CVE.cpe,          # cpe + description = entrées de still_matches
        # KEV/maturité d'exploit (17/08/2026) : mêmes raisons que cvss_bte ci-dessus.
        CVE.kev, CVE.kev_ransomware, CVE.msf_module, CVE.msf_best_rank,
        raiseload=True,                    # exclut surtout raw_data (377 Mo) et references
    ),
    load_only(
        Asset.id, Asset.name, Asset.os, Asset.os_version, Asset.asset_type,
        Asset.cpe_list, Asset.installed_packages, Asset.tags,
        # scan_reachable/scan_error (pas last_scan_result, cf. ConnectivityDot.jsx) :
        # colonnes dédiées légères, justement pour ne PAS avoir à charger le blob
        # JSON complet (paquets/hardware, jusqu'à plusieurs centaines de Ko pour
        # un serveur Windows chargé) sur cet endpoint où l'incident de perf
        # documenté plus haut s'est produit une première fois.
        Asset.scan_reachable, Asset.scan_error,
        raiseload=True,
    ),
)


class _CveProbe:
    """Porte les deux seuls champs de CVE que lit `still_matches_ctx` (`cpe`,
    `description`), pour évaluer un couple (profil, CVE) sans matérialiser
    l'entité ORM complète — cf. phase 1 de `false_positive_candidates`."""
    __slots__ = ("id", "cpe", "description")

    def __init__(self, id, cpe, description):
        self.id, self.cpe, self.description = id, cpe, description


async def _iter_candidate_rows(session: AsyncSession, *conditions):
    """Parcourt ligne à ligne (Vulnerability, CVE, Asset) filtrées par
    `conditions`, triées par Vulnerability.id croissant — lues par lot de
    CANDIDATE_BATCH_SIZE côté SQL, mais rendues à l'appelant une par une, avec
    un `asyncio.sleep(0)` tous les CANDIDATE_YIELD_EVERY (cf. commentaire
    ci-dessus). Ne charge que les colonnes de `_CANDIDATE_LOAD_OPTIONS`."""
    last_id = None
    n = 0
    while True:
        q = (
            select(Vulnerability, CVE, Asset)
            .join(CVE, Vulnerability.cve_id == CVE.id)
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .options(*_CANDIDATE_LOAD_OPTIONS)
            .where(*conditions)
            .order_by(Vulnerability.id)
            .limit(CANDIDATE_BATCH_SIZE)
        )
        if last_id is not None:
            q = q.where(Vulnerability.id > last_id)
        batch = (await session.execute(q)).all()
        if not batch:
            return
        last_id = batch[-1][0].id
        for row in batch:
            yield row
            n += 1
            if n % CANDIDATE_YIELD_EVERY == 0:
                await asyncio.sleep(0)


class VulnCreate(BaseModel):
    asset_id: str
    cve_db_id: str
    risk_score: Optional[float] = None
    notes: Optional[str] = None


class VulnUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    risk_score: Optional[float] = None
    validated_by: Optional[str] = None
    accepted_risk_until: Optional[datetime] = None  # date de revue obligatoire si status="accepted_risk"


class BulkValidate(BaseModel):
    vuln_ids: list[str]
    validated_by: str


class BulkPatch(BaseModel):
    vuln_ids: list[str]
    validated_by: str
    notes: Optional[str] = None


class BulkFalsePositive(BaseModel):
    vuln_ids: list[str]
    validated_by: str


class BulkAwaitingFix(BaseModel):
    vuln_ids: list[str]
    validated_by: str
    notes: str


class BulkAcceptedRisk(BaseModel):
    vuln_ids: list[str]
    validated_by: str
    notes: str
    accepted_risk_until: datetime


@router.get("")
async def list_vulnerabilities(
    asset_id: Optional[str] = None,
    configured_only: bool = Query(
        False,
        description="Sans asset_id, restreint aux actifs 'entièrement configurés' "
                     "(cf. services/stats.py::get_configured_asset_ids) — dashboard uniquement.",
    ),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    validated_by: Optional[str] = None,
    search: Optional[str] = None,   # recherche sur l'identifiant CVE (ex: deep-link du bandeau de rattrapage)
    max_age_years: Optional[int] = Query(None, ge=1, le=50),
    kev: bool = Query(False, description="Restreindre aux CVE exploitées activement (CISA KEV)"),
    msf_module: bool = Query(False, description="Restreindre aux CVE avec un module Metasploit disponible"),
    sort_by: Optional[str] = Query("score", pattern="^(score|date|severity|cvss_bte)$"),
    sort_dir: Optional[str] = Query("desc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
):
    severity_order = case(
        (CVE.severity == "CRITICAL", 4),
        (CVE.severity == "HIGH", 3),
        (CVE.severity == "MEDIUM", 2),
        (CVE.severity == "LOW", 1),
        else_=0,
    )
    sort_col = {
        "score":    Vulnerability.risk_score,
        "date":     CVE.published,
        "severity": severity_order,
        "cvss_bte": Vulnerability.cvss_bte,
    }.get(sort_by, Vulnerability.risk_score)
    order_expr = sort_col.desc() if sort_dir == "desc" else sort_col.asc()

    q = (
        select(Vulnerability, CVE, Asset)
        .join(CVE, Vulnerability.cve_id == CVE.id)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .order_by(order_expr, CVE.cvss_score.desc())
    )
    if asset_id:
        # Un ou plusieurs UUID séparés par virgule (sélection multiple du filtre
        # "Actifs" du dashboard, cf. AssetDropdown.jsx) — un simple `== asset_id`
        # ne matchait jamais rien dès que plusieurs actifs étaient cochés (bug
        # réel trouvé le 07/08/2026 en câblant `configured_only` ci-dessous).
        ids = [v.strip() for v in asset_id.split(",") if v.strip()]
        q = q.where(Vulnerability.asset_id.in_(ids)) if len(ids) > 1 else q.where(Vulnerability.asset_id == ids[0])
    elif configured_only:
        configured_ids = await get_configured_asset_ids(session)
        q = q.where(Vulnerability.asset_id.in_(configured_ids))
    if status:
        q = q.where(Vulnerability.status == status)
    if severity:
        # Accepte une valeur unique ou plusieurs séparées par virgule (multi-sélection
        # du filtre sévérité côté Dashboard). Rétrocompatible avec l'usage mono-valeur.
        sevs = [s.strip().upper() for s in severity.split(",") if s.strip()]
        if sevs:
            q = q.where(CVE.severity.in_(sevs))
    if validated_by:
        q = q.where(Vulnerability.validated_by == validated_by)
    if search:
        # Recherche sur l'identifiant CVE (insensible à la casse). Sert au
        # deep-link depuis le bandeau de rattrapage : cibler une CVE précise sans
        # dépendre du tri/plafond de la liste (une CVE LOW auto-patchée peut être
        # hors des premières pages triées par score).
        q = q.where(CVE.cve_id.ilike(f"%{search.strip()}%"))
    if max_age_years:
        # Filtre d'affichage uniquement — masque les CVE publiées il y a plus de
        # N ans (défaut proposé : 2 ans côté UI), réversible, ne supprime ni ne
        # désactive rien en base. Sciemment PAS un filtre de collecte/matching :
        # l'âge d'une CVE ne dit rien sur si elle est réellement corrigée sur le
        # parc (cf. incident CVE-2022-30190/rattrapage NVD, session 20/07/2026) —
        # couper à la collecte aurait recréé le même trou qu'on vient de combler.
        cutoff = datetime.now(timezone.utc) - timedelta(days=365 * max_age_years)
        q = q.where(CVE.published >= cutoff)
    if kev:
        q = q.where(CVE.kev.is_(True))
    if msf_module:
        q = q.where(CVE.msf_module.is_(True))

    total = await session.scalar(select(func.count()).select_from(q.subquery()))
    rows = (await session.execute(q.offset((page - 1) * per_page).limit(per_page))).all()

    # "Déjà résolu ailleurs" (04/08/2026) — une seule requête groupée pour toute
    # la page affichée (jamais une par ligne, même souci de performance que
    # les endpoints "candidats" ci-dessus) : combien d'instances de chaque CVE
    # de cette page sont déjà dans un état terminal, tous actifs confondus.
    # Groupé aussi par statut (pas seulement par CVE) pour distinguer "patched"
    # du reste : le badge frontend privilégie le libellé "correctif déjà
    # appliqué" quand c'est le cas, plutôt qu'un "déjà qualifié" trop vague
    # (demande explicite 04/08/2026) — sans requête supplémentaire par ligne.
    resolved_counts: dict = {}
    patched_counts: dict = {}
    cve_ids_on_page = {v.cve_id for v, c, a in rows}
    if cve_ids_on_page:
        count_rows = (await session.execute(
            select(Vulnerability.cve_id, Vulnerability.status, func.count())
            .where(Vulnerability.cve_id.in_(cve_ids_on_page), Vulnerability.status.in_(RESOLVED_STATUSES))
            .group_by(Vulnerability.cve_id, Vulnerability.status)
        )).all()
        for cve_id, vstatus, cnt in count_rows:
            resolved_counts[cve_id] = resolved_counts.get(cve_id, 0) + cnt
            if vstatus == "patched":
                patched_counts[cve_id] = patched_counts.get(cve_id, 0) + cnt

    items = []
    for v, c, a in rows:
        elsewhere = resolved_counts.get(v.cve_id, 0) - (1 if v.status in RESOLVED_STATUSES else 0)
        patched_elsewhere = patched_counts.get(v.cve_id, 0) - (1 if v.status == "patched" else 0)
        items.append(_vuln_dict(
            v, c, a,
            resolved_elsewhere_count=max(elsewhere, 0),
            patched_elsewhere_count=max(patched_elsewhere, 0),
        ))

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": items,
    }


@router.post("", status_code=201)
async def create_vulnerability(data: VulnCreate, session: AsyncSession = Depends(get_session)):
    vuln = Vulnerability(
        asset_id=data.asset_id,
        cve_id=data.cve_db_id,
        risk_score=data.risk_score,
        notes=data.notes,
        detected_at=datetime.now(timezone.utc),
        status="open",
    )
    session.add(vuln)
    await session.commit()
    await session.refresh(vuln)
    return {"id": str(vuln.id), "status": vuln.status}


@router.patch("/{vuln_id}")
async def update_vulnerability(vuln_id: str, data: VulnUpdate, session: AsyncSession = Depends(get_session)):
    vuln = await session.get(Vulnerability, vuln_id)
    if not vuln:
        raise HTTPException(404, "Vulnérabilité introuvable")
    if data.status:
        record_status_change(session, vuln.id, vuln.status, data.status,
                              validated_by=data.validated_by, notes=data.notes)
        vuln.status = data.status
        if data.status == "patched":
            vuln.patched_at = datetime.now(timezone.utc)
            vuln.awaiting_fix_at = None
            vuln.false_positive_at = None
        elif data.status == "awaiting_fix":
            # Vuln annotée "pas de correctif éditeur/distro disponible" (ex: CVE
            # publiée mais pas encore backportée par Debian) — conserve
            # volontairement last_patch_check/patch_check_result (contexte
            # technique utile en plus de l'annotation libre de l'analyste, et
            # préserve le rythme de RECHECK_INTERVAL plutôt que de forcer un
            # recheck immédiat). Incluse dans le cycle de patch check autonome
            # (cf. patch_checker.py) : bascule automatiquement en "patched" dès
            # qu'un correctif est détecté, sans action manuelle.
            # validated_by n'est PAS effacé ici — l'analyste qui marque "en
            # attente"/"faux positif" est requis par la modale d'annotation
            # (AnnotationModal.jsx) et transmis via data.validated_by ci-dessous.
            vuln.awaiting_fix_at = datetime.now(timezone.utc)
            vuln.patched_at = None
            vuln.false_positive_at = None
        elif data.status == "awaiting_fix_partial":
            # Cas mixte (27/07/2026, cf. CLAUDE.md) : même traitement que
            # "awaiting_fix" ci-dessus (conserve last_patch_check/
            # patch_check_result, inclus dans le cycle de recheck autonome) —
            # sans cette branche dédiée, ce statut retombait dans le `else`
            # prévu pour open/in_progress, qui efface validated_by et le
            # résultat du dernier contrôle (incident réel le 27/07/2026, cf.
            # STATUS.md).
            vuln.awaiting_fix_at = datetime.now(timezone.utc)
            vuln.patched_at = None
            vuln.false_positive_at = None
        elif data.status == "false_positive":
            # Vuln annotée "ne concerne en réalité pas cet actif" (erreur de
            # matching CPE/mots-clés, cf. docs/MATCHING.md) — état terminal comme
            # "patched" : contrairement à "awaiting_fix", pas de raison de la
            # revérifier automatiquement (le correctif n'a jamais été le sujet),
            # donc volontairement absente du cycle de patch check autonome.
            vuln.false_positive_at = datetime.now(timezone.utc)
            vuln.patched_at = None
            vuln.awaiting_fix_at = None
        elif data.status == "accepted_risk":
            # État terminal (cf. CLAUDE.md) : jamais modifié automatiquement.
            # Justification + validateur + date de revue obligatoires — sans
            # date de revue, un risque accepté reste invisible indéfiniment
            # (c'est tout le problème que ce statut posait jusqu'ici). La date
            # ne fait JAMAIS rouvrir la vuln toute seule : elle n'alimente
            # qu'un signal "revue en retard" calculé à la volée (cf.
            # `review_overdue` dans _vuln_dict ci-dessous), jamais une bascule
            # automatique de statut.
            if not (data.notes or "").strip():
                raise HTTPException(400, "Une justification est obligatoire pour accepter un risque")
            if not (data.validated_by or "").strip():
                raise HTTPException(400, "Un analyste validateur est obligatoire pour accepter un risque")
            if not data.accepted_risk_until:
                raise HTTPException(400, "Une date de revue est obligatoire pour accepter un risque")
            vuln.accepted_risk_until = data.accepted_risk_until
            vuln.patched_at = None
            vuln.awaiting_fix_at = None
            vuln.false_positive_at = None
        else:
            # open / in_progress : on quitte les états "corrigé", "en attente
            # de correctif", "faux positif" et "risque accepté". Efface
            # l'ancien résultat de check — sinon le prochain rattrapage
            # (backfill_auto_patch, exécuté à chaque démarrage et par le bouton
            # "Patch check global") re-bascule instantanément en patched en se
            # basant sur un résultat périmé, sans relancer un vrai contrôle
            # SSH/WinRM.
            vuln.patched_at = None
            vuln.awaiting_fix_at = None
            vuln.false_positive_at = None
            vuln.accepted_risk_until = None
            vuln.validated_by = None
            vuln.last_patch_check = None
            vuln.patch_check_result = None
    if data.validated_by is not None:
        vuln.validated_by = data.validated_by
    if data.notes is not None:
        vuln.notes = data.notes
    if data.risk_score is not None:
        vuln.risk_score = data.risk_score
    await session.commit()
    return {"id": str(vuln.id), "status": vuln.status}


@router.get("/{vuln_id}/status-history")
async def get_vuln_status_history(vuln_id: str, session: AsyncSession = Depends(get_session)):
    """Historique des transitions de statut (27/07/2026, cf. services/vuln_history.py)
    — prospectif, ne couvre que les transitions survenues depuis sa mise en service."""
    rows = (await session.execute(
        select(VulnerabilityStatusHistory)
        .where(VulnerabilityStatusHistory.vulnerability_id == vuln_id)
        .order_by(VulnerabilityStatusHistory.changed_at.desc())
    )).scalars().all()
    return [{
        "old_status": r.old_status,
        "new_status": r.new_status,
        "changed_at": r.changed_at.isoformat() if r.changed_at else None,
        "validated_by": r.validated_by,
        "notes": r.notes,
    } for r in rows]


@router.get("/{vuln_id}/other-instances")
async def get_vuln_other_instances(vuln_id: str, session: AsyncSession = Depends(get_session)):
    """
    Autres occurrences de la même CVE sur d'autres actifs (04/08/2026, demande
    explicite) — quand une CVE déjà traitée sur un serveur réapparaît sur un
    autre, retrouver directement le diagnostic/la justification posée là-bas
    (ex: "PuTTY 0.81 confirmé patché sur DEPLOYAPP") plutôt que de rechercher
    à nouveau les mêmes informations sur la CVE. Lecture seule.

    Traitées en premier (patched/false_positive/accepted_risk, celles qui ont
    une justification à montrer), puis le reste par date de détection — pas
    de pagination, le nombre d'actifs par CVE reste borné à la taille du parc.
    """
    vuln = await session.get(Vulnerability, vuln_id)
    if not vuln:
        raise HTTPException(404, "Vulnérabilité introuvable")

    rows = (await session.execute(
        select(Vulnerability, Asset)
        .join(Asset, Asset.id == Vulnerability.asset_id)
        .where(Vulnerability.cve_id == vuln.cve_id, Vulnerability.id != vuln.id)
        .order_by(
            case((Vulnerability.status.in_(RESOLVED_STATUSES), 0), else_=1),
            Vulnerability.patched_at.desc(),
        )
    )).all()

    return [{
        "vuln_id": str(v.id),
        "asset_name": a.name,
        "status": v.status,
        "validated_by": v.validated_by,
        "notes": v.notes,
        "patch_check_details": (v.patch_check_result or {}).get("details"),
        "patched_at": v.patched_at.isoformat() if v.patched_at else None,
        "false_positive_at": v.false_positive_at.isoformat() if v.false_positive_at else None,
        "awaiting_fix_at": v.awaiting_fix_at.isoformat() if v.awaiting_fix_at else None,
    } for v, a in rows]


@router.post("/bulk-patch")
async def bulk_mark_patched(data: BulkPatch, session: AsyncSession = Depends(get_session)):
    """
    Marque en masse une sélection de vulnérabilités comme corrigées — même
    geste que le bouton "✓ Corrigé" unitaire (`ValidateDropdown`), répété sur
    la sélection au lieu d'être cliqué une par une. Aucune restriction de
    sévérité ni de signal technique requis : c'est la même action manuelle
    que l'analyste peut déjà déclencher ligne par ligne pour n'importe quelle
    vuln, y compris CRITICAL — un choix humain explicite (sélection + un
    validateur nommé), pas une bascule automatique du système. Ne pas
    confondre avec /bulk-validate, réservé aux candidats CRITICAL déjà
    signalés par un patch check (cf. /critical-review-candidates).
    """
    now = datetime.now(timezone.utc)
    # `notes` reste optionnelle ici, contrairement à bulk-false-positive et
    # bulk-awaiting-fix : corriger une vuln non-CRITICAL est une action rapide,
    # l'annotation n'est qu'un complément.
    notes = data.notes.strip() if data.notes and data.notes.strip() else None
    updated = []
    for vid in data.vuln_ids:
        vuln = await session.get(Vulnerability, vid)
        if not vuln:
            continue
        record_status_change(session, vuln.id, vuln.status, "patched",
                              validated_by=data.validated_by, notes=notes)
        vuln.status = "patched"
        vuln.patched_at = now
        vuln.awaiting_fix_at = None
        vuln.false_positive_at = None
        vuln.validated_by = data.validated_by
        if notes:
            vuln.notes = notes
        updated.append(vid)

    await session.commit()
    return {"updated": updated}


@router.get("/awaiting-fix-candidates")
async def awaiting_fix_candidates(
    asset_id: Optional[str] = Query(None, description="Scope l'analyse à un actif et lève la fenêtre des 2 ans (bouton « CVE anciennes »)"),
    session: AsyncSession = Depends(get_session),
):
    """
    Vulnérabilités ouvertes pour lesquelles **aucun correctif n'est disponible** :
    le Debian Security Tracker déclare la CVE « open » pour la release de l'actif,
    et ce pour *tous* les paquets concernés (`no_fix_available`).

    Il n'y a rien à appliquer sur le serveur — leur place est "en attente de
    correctif", statut qui reste dans le cycle de recheck et bascule seul en
    `patched` dès publication.

    En pratique ce sont surtout des **CRITICAL** : les autres sévérités sont déjà
    basculées automatiquement par `apply_patch_result`. Les cas **mixtes** (un
    paquet sans correctif mais un autre réellement vulnérable) sont exclus par
    construction — `no_fix_available` n'est vrai que si *aucun* paquet concerné
    n'a de correctif.

    Bornée par défaut aux CVE publiées il y a moins de CANDIDATE_MAX_AGE_YEARS
    (2 ans) — cf. commentaire sur cette constante. `asset_id` lève cette fenêtre
    pour l'actif ciblé.

    **Ne modifie rien.**
    """
    items = []
    # `no_fix_available` vient du rapport de patch check (19/08/2026, cf.
    # STATUS.md — mesuré à 3,4s en conditions réelles avant ce correctif) : le
    # filtre ne poussait jusqu'ici que "déjà contrôlée" en SQL
    # (`patch_check_result IS NOT NULL`), la vérification de `no_fix_available`
    # lui-même restant en Python après coup. Correct tant que peu de lignes
    # avaient déjà un rapport (1 244 sur 264 959 le 28/07/2026, cf. commentaire
    # d'origine) — plus vrai aujourd'hui : le cycle de patch check a depuis
    # tourné sur l'essentiel du parc élargi (77 075 lignes avec
    # `patch_check_result IS NOT NULL` mesuré ce jour), toutes matérialisées en
    # objets ORM et parcourues une à une pour ne retenir, in fine, qu'une poignée
    # de lignes. Poussé entièrement en SQL (`->>'no_fix_available'`, opérateur
    # JSON Postgres) — vérifié en conditions réelles : même résultat (0 ligne)
    # que l'ancien filtre Python, sur ce jeu de données.
    conditions = _candidate_conditions(
        ["open", "in_progress"], asset_id,
        Vulnerability.patch_check_result.op("->>")("no_fix_available") == "true",
    )
    async for v, c, a in _iter_candidate_rows(session, *conditions):
        items.append({
            **_vuln_dict(v, c, a),
            "raison": "aucun_correctif",
            "justification": (v.patch_check_result or {}).get("no_fix_reason")
            or "La distribution n'a publié aucun correctif pour cette CVE.",
        })
    items.sort(key=lambda x: x["cve"]["cve_id"])
    return {"total": len(items), "items": items}


@router.post("/bulk-awaiting-fix")
async def bulk_awaiting_fix(data: BulkAwaitingFix, session: AsyncSession = Depends(get_session)):
    """
    Passe en masse une sélection en `awaiting_fix` — annotation et analyste
    obligatoires, comme le geste unitaire. Chaque id est revérifié côté serveur
    (`no_fix_available` toujours vrai, statut encore ouvert) avant application :
    la liste transmise par le client peut être périmée.
    """
    if not data.notes.strip():
        raise HTTPException(400, "Une annotation est obligatoire")
    if not data.validated_by.strip():
        raise HTTPException(400, "Un analyste validateur est obligatoire")

    now = datetime.now(timezone.utc)
    applied, skipped = [], []
    for vid in data.vuln_ids:
        vuln = await session.get(Vulnerability, vid)
        if (not vuln or vuln.status not in ("open", "in_progress")
                or (vuln.patch_check_result or {}).get("no_fix_available") is not True):
            skipped.append(vid)
            continue
        record_status_change(session, vuln.id, vuln.status, "awaiting_fix",
                              validated_by=data.validated_by, notes=data.notes)
        vuln.status = "awaiting_fix"
        vuln.awaiting_fix_at = now
        vuln.patched_at = None
        vuln.false_positive_at = None
        vuln.validated_by = data.validated_by
        vuln.notes = data.notes
        applied.append(vid)

    await session.commit()
    return {"applied": applied, "skipped": skipped}


@router.post("/bulk-accepted-risk")
async def bulk_accepted_risk(data: BulkAcceptedRisk, session: AsyncSession = Depends(get_session)):
    """
    Passe en masse une sélection en `accepted_risk` — même geste que l'action
    unitaire, répété sur la sélection. Aucune restriction de sévérité ni de
    signal technique requis (comme `/bulk-patch`) : c'est une décision humaine
    explicite (sélection + validateur nommé + justification + date de revue),
    pas une bascule automatique. La date de revue n'entraîne jamais de
    réouverture automatique — seulement un signal `review_overdue` calculé à
    la lecture (cf. `_vuln_dict`).
    """
    if not data.notes.strip():
        raise HTTPException(400, "Une justification est obligatoire")
    if not data.validated_by.strip():
        raise HTTPException(400, "Un analyste validateur est obligatoire")

    now = datetime.now(timezone.utc)
    applied = []
    for vid in data.vuln_ids:
        vuln = await session.get(Vulnerability, vid)
        if not vuln:
            continue
        record_status_change(session, vuln.id, vuln.status, "accepted_risk",
                              validated_by=data.validated_by, notes=data.notes)
        vuln.status = "accepted_risk"
        vuln.accepted_risk_until = data.accepted_risk_until
        vuln.patched_at = None
        vuln.awaiting_fix_at = None
        vuln.false_positive_at = None
        vuln.validated_by = data.validated_by
        vuln.notes = data.notes
        applied.append(vid)

    await session.commit()
    _invalidate_false_positive_cache()
    return {"applied": applied}


@router.get("/false-positive-candidates")
async def false_positive_candidates(
    asset_id: Optional[str] = Query(None, description="Scope l'analyse à un actif et lève la fenêtre des 2 ans (bouton « CVE anciennes »)"),
    configured_only: bool = Query(
        False,
        description="Sans asset_id, restreint aux actifs 'entièrement configurés' — dashboard uniquement "
                     "(cf. section 'Faux positifs proposés', même périmètre que configured_only sur GET /vulnerabilities).",
    ),
    session: AsyncSession = Depends(get_session),
):
    """
    Vulnérabilités ouvertes qui **ne concernent pas réellement l'actif**, pour
    deux raisons objectives et vérifiables :

    - `matching_invalide` : le rattachement ne serait plus créé par les règles de
      matching actuelles (ex: CPE NVD dégénéré `-:-:-` sans vendeur ni produit,
      qui matchait tout le parc — cf. docs/MATCHING.md). `run_cpe_matching` ne
      supprimant jamais, ces lignes restent en base après correction d'une règle.
    - `produit_absent` : le patch check a établi qu'aucun paquet visé par la CVE
      n'est installé (`not_applicable`). Ce n'est **pas** un correctif appliqué —
      d'où le classement en faux positif et non en `patched`, distinction qui
      compte pour l'audit NIS 2.

    Bornée par défaut aux CVE publiées il y a moins de CANDIDATE_MAX_AGE_YEARS
    (2 ans) — cf. commentaire sur cette constante. `asset_id` lève cette fenêtre
    pour l'actif ciblé.

    **Ne modifie rien.** Liste seulement : la qualification reste un geste humain
    explicite (annotation + analyste obligatoires, cf. /bulk-false-positive).
    """
    cache_key = (asset_id, configured_only)
    cached = _false_positive_cache.get(cache_key)
    if cached and (time.time() - cached[0]) < FALSE_POSITIVE_CACHE_TTL:
        return cached[1]

    from services.cpe_matcher import asset_match_context, still_matches_ctx, _load_windows_mappings

    windows_mappings = await _load_windows_mappings(session)
    statuses = ["open", "in_progress", "awaiting_fix", "awaiting_fix_partial"]
    configured_ids = await get_configured_asset_ids(session) if (configured_only and not asset_id) else None
    base_conditions = _candidate_conditions(statuses, asset_id, configured_asset_ids=configured_ids)

    # ── Phase 1 : quelles CVE peuvent produire un candidat ? ────────────────
    # `still_matches` est une fonction pure de (profil de matching de l'actif,
    # CVE). Le parc est très homogène — 72 actifs pour une poignée de profils
    # (Windows Server 2019/2022, Debian 12) — et les mêmes CVE reviennent sur
    # beaucoup d'actifs : évaluer le couple distinct plutôt que la ligne ramène
    # ~86 000 tests à quelques milliers. Ne lit ici que les colonnes dont
    # `still_matches` a besoin, sans matérialiser un seul objet ORM complet.
    # Les actifs sont chargés directement (72 lignes) plutôt que via un
    # `IN (sous-requête DISTINCT)` : le parc entier tient largement en mémoire, et
    # la sous-requête corrélée, elle, ne rendait pas la main (>13 min observées).
    asset_q = select(Asset).options(*_CANDIDATE_LOAD_OPTIONS[2:])
    if asset_id:
        asset_q = asset_q.where(Asset.id == asset_id)
    asset_rows = (await session.execute(asset_q)).scalars().all()
    contexts = {a.id: asset_match_context(a, windows_mappings) for a in asset_rows}
    profiles = {ctx["key"]: ctx for ctx in contexts.values()}

    # Deux requêtes simples plutôt qu'une imbriquée : d'abord les identifiants de
    # CVE concernés (DISTINCT sur une seule colonne UUID = agrégat par hachage,
    # rapide), puis leurs colonnes utiles via un `IN` sur une liste Python. La
    # jointure sur `cves` reste indispensable ici — `_candidate_conditions` filtre
    # sur `CVE.published`, et sans elle SQLAlchemy produirait un produit cartésien.
    cve_ids = (await session.execute(
        select(Vulnerability.cve_id)
        .join(CVE, Vulnerability.cve_id == CVE.id)
        .where(*base_conditions)
        .distinct()
    )).scalars().all()

    cve_rows = (await session.execute(
        select(CVE.id, CVE.cpe, CVE.description).where(CVE.id.in_(cve_ids))
    )).all() if cve_ids else []

    # CVE qui ne matcheraient plus pour AU MOINS un profil — seules celles-là
    # peuvent donner un `matching_invalide`, le verdict exact étant revérifié
    # par ligne en phase 2 (une CVE peut être invalide sur un profil, valide sur
    # un autre). Verdicts mémoïsés et réutilisés en phase 2.
    verdicts: dict = {}
    invalid_cve_ids = []
    for n, (cve_id, cpe, description) in enumerate(cve_rows, 1):
        probe = _CveProbe(cve_id, cpe, description)
        invalid_for_any = False
        for key, ctx in profiles.items():
            matches = still_matches_ctx(ctx, probe)
            verdicts[(key, cve_id)] = matches
            invalid_for_any = invalid_for_any or not matches
        if invalid_for_any:
            invalid_cve_ids.append(cve_id)
        # Même raison qu'en phase 2 (cf. CANDIDATE_YIELD_EVERY) : cette boucle est
        # du calcul Python pur, elle gèlerait la boucle asyncio mono-thread — et
        # donc toutes les autres requêtes — si elle ne rendait jamais la main.
        if n % CANDIDATE_YIELD_EVERY == 0:
            await asyncio.sleep(0)

    # ── Phase 2 : ne charger en entier que les lignes réellement candidates ──
    # Soit une CVE repérée en phase 1, soit une vuln déjà contrôlée (seule à
    # pouvoir porter `not_applicable`) — 1 244 lignes sur 264 959 au 28/07/2026.
    items = []
    asset_ctx = contexts
    conditions = [*base_conditions, or_(
        Vulnerability.cve_id.in_(invalid_cve_ids),
        Vulnerability.patch_check_result.isnot(None),
    )]
    async for v, c, a in _iter_candidate_rows(session, *conditions):
        result = v.patch_check_result or {}
        ctx = asset_ctx.get(a.id)
        if ctx is None:
            ctx = asset_ctx[a.id] = asset_match_context(a, windows_mappings)
        verdict_key = (ctx["key"], c.id)
        matches = verdicts.get(verdict_key)
        if matches is None:
            matches = verdicts[verdict_key] = still_matches_ctx(ctx, c)
        if not matches:
            raison, detail = "matching_invalide", (
                "Le rattachement de cette CVE à cet actif ne serait plus créé par les règles "
                "de matching actuelles (CPE NVD n'identifiant aucun produit)."
            )
        elif result.get("not_applicable") is True:
            raison, detail = "produit_absent", (
                result.get("not_applicable_reason")
                or "Aucun paquet visé par cette CVE n'est installé sur l'actif."
            )
        else:
            continue
        items.append({**_vuln_dict(v, c, a), "raison": raison, "justification": detail})

    items.sort(key=lambda x: (x["raison"], x["cve"]["cve_id"]))
    result = {"total": len(items), "items": items}
    _false_positive_cache[cache_key] = (time.time(), result)
    return result


@router.post("/bulk-false-positive")
async def bulk_false_positive(data: BulkFalsePositive, session: AsyncSession = Depends(get_session)):
    """
    Qualifie en masse une sélection en `false_positive` — même geste que le bouton
    "🚫 Faux positif" unitaire, répété sur la sélection. Analyste obligatoire :
    la piste d'audit doit rester exploitable (NIS 2).

    Justification générée automatiquement par CVE (demande explicite, 08/08/2026,
    même principe que /bulk-validate) — reprend exactement le motif calculé par
    /false-positive-candidates (rattachement erroné vs produit absent) pour CETTE
    CVE précise sur CET actif, pas un texte libre unique appliqué à toute la
    sélection : deux vulns d'un même lot n'ont pas forcément la même raison. Le
    seul champ resté manuel est le validateur.

    Revérifie côté serveur que chaque id est bien un candidat légitime (cf.
    /false-positive-candidates) : la liste transmise par le client peut être
    périmée. Tout id ne remplissant plus les conditions est renvoyé dans `skipped`
    plutôt que qualifié à l'aveugle.
    """
    from services.cpe_matcher import still_matches, _load_windows_mappings

    if not data.validated_by.strip():
        raise HTTPException(400, "Un analyste validateur est obligatoire")

    windows_mappings = await _load_windows_mappings(session)
    now = datetime.now(timezone.utc)
    applied, skipped = [], []
    for vid in data.vuln_ids:
        vuln = await session.get(Vulnerability, vid)
        if not vuln or vuln.status not in ("open", "in_progress", "awaiting_fix"):
            skipped.append(vid)
            continue
        cve = await session.get(CVE, vuln.cve_id)
        asset = await session.get(Asset, vuln.asset_id)
        if not cve or not asset:
            skipped.append(vid)
            continue
        result = vuln.patch_check_result or {}
        asset_label = asset.name or asset.hostname or "actif inconnu"
        if not still_matches(asset, cve, windows_mappings):
            notes = (
                f"[{asset_label}] Faux positif — rattachement erroné : le CPE publié par NVD pour cette "
                "CVE n'identifie aucun produit (ni vendeur ni produit renseigné), elle ne désigne donc pas cet actif."
            )
        elif result.get("not_applicable") is True:
            detail = result.get("not_applicable_reason") or "Aucun paquet visé par cette CVE n'est installé sur l'actif."
            notes = f"[{asset_label}] Faux positif — produit absent : {detail}"
        else:
            skipped.append(vid)
            continue
        record_status_change(session, vuln.id, vuln.status, "false_positive",
                              validated_by=data.validated_by, notes=notes)
        vuln.status = "false_positive"
        vuln.false_positive_at = now
        vuln.patched_at = None
        vuln.awaiting_fix_at = None
        vuln.validated_by = data.validated_by
        vuln.notes = notes
        applied.append(vid)

    await session.commit()
    return {"applied": applied, "skipped": skipped}


@router.get("/critical-review-candidates")
async def critical_review_candidates(
    asset_id: Optional[str] = Query(None, description="Scope l'analyse à un actif et lève la fenêtre des 2 ans (bouton « CVE anciennes »)"),
    session: AsyncSession = Depends(get_session),
):
    """
    CVE CRITICAL ouvertes dont le dernier patch check porte un signal positif
    (patch_detected ou heuristique de date, cf. patch_checker.py) — candidates
    probables à une correction déjà effectuée, en attente de validation.

    Ne bascule jamais rien : la règle CLAUDE.md (CRITICAL = toujours validé
    manuellement par un analyste) reste entière. Sert uniquement à regrouper
    ces candidats pour que l'analyste les valide en un minimum de clics via
    /bulk-validate plutôt qu'un par un — le geste de confirmation humain reste
    requis pour chacune.

    Bornée par défaut aux CVE publiées il y a moins de CANDIDATE_MAX_AGE_YEARS
    (2 ans) — cf. commentaire sur cette constante. `asset_id` lève cette fenêtre
    pour l'actif ciblé.
    """
    one_year_ago = datetime.now(timezone.utc) - timedelta(days=365)
    candidates = []
    conditions = _candidate_conditions(
        ["open", "in_progress", "awaiting_fix", "awaiting_fix_partial"],
        asset_id,
        CVE.severity == "CRITICAL",
        Vulnerability.patch_check_result.isnot(None),
    )
    async for v, c, a in _iter_candidate_rows(session, *conditions):
        result = v.patch_check_result or {}
        patch_detected = result.get("patch_detected") is True
        date_heuristic = result.get("date_heuristic") is True
        if not (patch_detected or date_heuristic):
            continue
        published = c.published
        if published and published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        candidates.append({
            **_vuln_dict(v, c, a),
            "signal": "patch_detected" if patch_detected else "date_heuristic",
            "over_a_year": bool(published and published < one_year_ago),
            "patch_check_details": result.get("details"),
        })

    # Priorité d'affichage : signal formel (patch_detected) avant heuristique
    # de date, ancienneté > 1 an en second critère — l'âge seul ne justifie
    # jamais la bascule (cf. filtre max_age_years ci-dessus), il sert ici
    # uniquement à trier les candidats déjà retenus sur signal technique.
    candidates.sort(key=lambda x: (x["signal"] != "patch_detected", not x["over_a_year"]))
    return {"total": len(candidates), "items": candidates}


@router.post("/bulk-validate")
async def bulk_validate(data: BulkValidate, session: AsyncSession = Depends(get_session)):
    """
    Valide en masse une sélection de vulnérabilités CRITICAL choisies
    explicitement par l'analyste (cf. /critical-review-candidates) — même
    geste que le bouton "Marquer comme corrigé" unitaire, répété sur la
    sélection au lieu d'être cliqué une par une.

    Revérifie côté serveur, pour chaque id, que la vuln est bien CRITICAL et
    porte toujours un signal positif : ne fait jamais confiance à la seule
    liste d'ids transmise par le client (résultat pourrait être périmé côté
    UI). Toute vuln ne remplissant plus ces conditions est ignorée (renvoyée
    dans "skipped") plutôt que validée à l'aveugle.

    Justification générée automatiquement (demande explicite, 08/08/2026) —
    plutôt qu'un texte libre unique appliqué à toute la sélection. Reprend le
    détail technique déjà calculé par le patch check pour CETTE CVE précise
    (`patch_check_result.details` — KB installé, version de build comparée,
    paquet concerné…), pas un simple "corrigé sur {actif}" identique pour
    toutes les vulns d'une même machine : deux CVE sur le même actif n'ont pas
    la même preuve technique. Repli sur un texte générique uniquement si le
    patch check n'a pas produit de détail exploitable. Le seul champ resté
    manuel est le validateur (`validated_by`) : la décision humaine porte sur
    qui valide, pas sur la reformulation d'un texte que le patch check
    détermine déjà.
    """
    applied, skipped = [], []
    for vid in data.vuln_ids:
        vuln = await session.get(Vulnerability, vid)
        cve = await session.get(CVE, vuln.cve_id) if vuln else None
        asset = await session.get(Asset, vuln.asset_id) if vuln else None
        result = (vuln.patch_check_result or {}) if vuln else {}
        patch_detected = result.get("patch_detected") is True
        has_signal = patch_detected or result.get("date_heuristic") is True
        if not vuln or not cve or not asset or cve.severity != "CRITICAL" or not has_signal:
            skipped.append(vid)
            continue
        asset_label = asset.name or asset.hostname or "actif inconnu"
        details = (result.get("details") or "").strip()
        if details:
            notes = f"[{asset_label}] {details}"
        else:
            notes = (
                f"Correctif détecté sur {asset_label}" if patch_detected
                else f"Signal indicatif (ancienneté CVE) sur {asset_label}"
            )
        record_status_change(session, vuln.id, vuln.status, "patched", validated_by=data.validated_by, notes=notes)
        vuln.status = "patched"
        vuln.patched_at = datetime.now(timezone.utc)
        vuln.awaiting_fix_at = None
        vuln.false_positive_at = None
        vuln.validated_by = data.validated_by
        vuln.notes = notes
        applied.append(vid)

    await session.commit()
    return {"applied": applied, "skipped": skipped}


@router.get("/auto-bascule-summary")
async def auto_bascule_summary(
    since: datetime = Query(..., description="Horodatage ISO de la dernière visite"),
    limit: int = Query(8, ge=1, le=100, description="Nombre de lignes détaillées renvoyées (`total` reste exact)"),
    session: AsyncSession = Depends(get_session),
):
    """
    Rattrapage — vulnérabilités basculées **automatiquement** (`validated_by` dans
    `patch_checker.AUTO_VALIDATED_BY_LABELS` — `"Auto (patch check)"` ou, pour un actif
    `collection_method="agent"`, `"Auto (patch check, agent-reported)"`, cf.
    audit/AUDIT_SECURITE.md #34) en `patched` ou `false_positive` depuis `since`.

    Deux usages du même endpoint, distingués par `limit` :
    - **Bandeau "depuis votre dernière visite"** (Dashboard, `limit` par défaut
      = 8) : le cycle autonome tourne aussi la nuit (toutes les 6h, cf.
      `tasks/scheduled_tasks.py`) sans que personne ne regarde l'écran — sans
      ce rattrapage, ces bascules ne seraient jamais vues autrement qu'en
      filtrant "traitées" à la main.
    - **Historique des notifications** (🔔, session 22/07/2026, `limit` plus
      large sur une fenêtre de plusieurs jours) : un toast disparaît après 6s
      et ne laisse aucune trace consultable — ce même endpoint, interrogé avec
      une fenêtre plus large, sert de journal de ce qui a été (ou aurait été)
      notifié.

    Pas d'authentification dans CBR (cf. `CLAUDE.md`) : `since` est fourni par
    le client, lu depuis son `localStorage` pour le bandeau ou calculé côté
    client pour l'historique — pas déduit d'une session utilisateur, qui
    n'existe pas. Ne compte que les bascules **automatiques**, jamais les
    validations manuelles de l'analyste : celui-ci sait déjà ce qu'il a
    lui-même cliqué, l'intérêt de cet endpoint est ce qui s'est passé sans lui.
    """
    q = (
        select(Vulnerability, CVE, Asset)
        .join(CVE, Vulnerability.cve_id == CVE.id)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .where(
            Vulnerability.validated_by.in_(AUTO_VALIDATED_BY_LABELS),
            Vulnerability.status.in_(["patched", "false_positive"]),
            or_(Vulnerability.patched_at >= since, Vulnerability.false_positive_at >= since),
        )
        .order_by(func.coalesce(Vulnerability.patched_at, Vulnerability.false_positive_at).desc())
    )
    rows = (await session.execute(q)).all()

    def _row(v: Vulnerability, c: CVE, a: Asset) -> dict:
        at = v.patched_at or v.false_positive_at
        return {
            "cve_id": c.cve_id, "severity": c.severity, "asset_name": a.name,
            "status": v.status, "at": at.isoformat() if at else None,
        }

    patched_count = sum(1 for v, _, _ in rows if v.status == "patched")
    fp_count = len(rows) - patched_count

    return {
        "since": since.isoformat(),
        "total": len(rows),
        "patched_count": patched_count,
        "false_positive_count": fp_count,
        # Échantillon seulement — un cycle de nuit chargé peut basculer des
        # dizaines de lignes, la liste complète appartient au tableau "traitées".
        "items": [_row(v, c, a) for v, c, a in rows[:limit]],
    }


@router.get("/new-since-count")
async def new_vulns_since_count(
    since: datetime = Query(..., description="Horodatage ISO de la dernière visite"),
    limit: int = Query(8, ge=1, le=100, description="Nombre de lignes détaillées renvoyées (`total` reste exact)"),
    session: AsyncSession = Depends(get_session),
):
    """Rattrapage — nouvelles vulnérabilités détectées sur le parc (`detected_at`)
    depuis `since`, tous statuts confondus. Distinct de `/auto-bascule-summary`
    (qui suit l'inverse : des vulns déjà connues qui se RÉSOLVENT seules) — même
    forme de réponse, pour le bandeau "depuis votre dernière visite" du Dashboard."""
    q = (
        select(Vulnerability, CVE, Asset)
        .join(CVE, Vulnerability.cve_id == CVE.id)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .where(Vulnerability.detected_at >= since)
        .order_by(Vulnerability.detected_at.desc())
    )
    rows = (await session.execute(q)).all()

    def _row(v: Vulnerability, c: CVE, a: Asset) -> dict:
        return {"cve_id": c.cve_id, "severity": c.severity, "asset_name": a.name}

    return {
        "since": since.isoformat(),
        "total": len(rows),
        "items": [_row(v, c, a) for v, c, a in rows[:limit]],
    }


def _vuln_dict(
    v: Vulnerability, c: CVE, a: Asset,
    resolved_elsewhere_count: int = 0, patched_elsewhere_count: int = 0,
) -> dict:
    return {
        "id": str(v.id),
        "status": v.status,
        "resolved_elsewhere_count": resolved_elsewhere_count,
        "patched_elsewhere_count": patched_elsewhere_count,
        "risk_score": v.risk_score,
        # CVSS-BTE (17/08/2026) — score CVSS v3.1 Temporal+Environmental réel, coexiste avec
        # risk_score sans le remplacer (cf. docs/MATCHING.md § CVSS-BTE). None tant que
        # services/scoring.py ne l'a pas encore calculé (rescore requis après migration).
        "cvss_bte": v.cvss_bte,
        "cvss_bte_vector": v.cvss_bte_vector,
        "detected_at": v.detected_at.isoformat() if v.detected_at else None,
        "patched_at": v.patched_at.isoformat() if v.patched_at else None,
        "awaiting_fix_at": v.awaiting_fix_at.isoformat() if v.awaiting_fix_at else None,
        "false_positive_at": v.false_positive_at.isoformat() if v.false_positive_at else None,
        "accepted_risk_until": v.accepted_risk_until.isoformat() if v.accepted_risk_until else None,
        # Signal calculé à la volée, jamais stocké ni appliqué automatiquement
        # (accepted_risk reste un état terminal, cf. CLAUDE.md) — même principe
        # que sla_exceeded sur la Veille (routers/watch.py).
        "review_overdue": (
            v.status == "accepted_risk"
            and v.accepted_risk_until is not None
            and v.accepted_risk_until < datetime.now(timezone.utc)
        ),
        "validated_by": v.validated_by,
        "notes": v.notes,
        "has_ai_analysis": v.ai_analysis is not None,
        "patch_detected": (v.patch_check_result or {}).get("patch_detected"),
        "patch_check_details": (v.patch_check_result or {}).get("details"),
        "cve": {
            "id": str(c.id),
            "cve_id": c.cve_id,
            "severity": c.severity,
            "cvss_score": c.cvss_score,
            "epss_score": c.epss_score,
            "published": c.published.isoformat() if c.published else None,
            "description": c.description[:200] if c.description else None,
            # KEV/maturité d'exploit (17/08/2026) — badge de priorisation, cf.
            # components/ExploitBadge.jsx. kev_date_added volontairement omis ici (réservé à
            # CVEs.jsx via _cve_dict full=True), pour ne pas alourdir chaque ligne de vuln.
            "kev": c.kev,
            "kev_ransomware": c.kev_ransomware,
            "msf_module": c.msf_module,
            "msf_best_rank": c.msf_best_rank,
        },
        "asset": {
            "id": str(a.id),
            "name": a.name,
            "os": a.os,
            "asset_type": a.asset_type,
            # Criticité métier (04/08/2026, demande explicite) — même donnée que la page
            # Actifs (CriticiteBadge), réglable depuis là-bas, jamais éditée ici.
            "criticite": (a.tags or {}).get("criticite", "moyenne"),
            # Pastille de connectivité (04/08/2026, ConnectivityDot.jsx) — colonnes dédiées
            # légères (cf. models.py::Asset), pas `last_scan_result` (blob lourd, exclu du
            # load_only(raiseload=True) des endpoints candidats ci-dessous).
            "scan_reachable": a.scan_reachable,
            "scan_error": a.scan_error,
        },
    }
