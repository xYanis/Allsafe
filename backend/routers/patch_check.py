"""
routers/patch_check.py
Vérification read-only si un correctif est détecté sur un actif.
L'analyste reste seul décisionnaire pour marquer la vuln comme corrigée.
"""

import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_

from auth_deps import require_page, require_page_or_internal
from database import get_session
from models import Vulnerability, CVE, Asset, PatchCheckAssetCompletion
from services.patch_checker import (
    check_patch,
    apply_patch_result,
    get_current_check,
    get_last_completed,
    get_cycle_started_at,
    get_asset_progress,
    get_last_cycle_state,
    run_full_patch_check_cycle,
    reset_patch_check_timestamps,
    count_pending_patch_checks,
    is_patch_check_cycle_running,
    RECHECK_INTERVAL,
    MIN_RECHECK_GAP,
)

router = APIRouter()


@router.post("/run", dependencies=[Depends(require_page_or_internal("/dashboard", "/vulnerabilities"))])
async def trigger_patch_check_run(
    force: bool = Query(
        False,
        description="Réévalue TOUTES les vulns ouvertes, y compris contrôlées il y a moins de 24h",
    ),
    asset_id: str = Query(
        None,
        description="Un ou plusieurs ID d'actif séparés par des virgules — restreint le cycle "
                     "à ces actifs plutôt qu'au périmètre par défaut. Absent = actifs 'entièrement "
                     "configurés' uniquement (cf. services/stats.py::get_configured_asset_ids).",
    ),
    session: AsyncSession = Depends(get_session),
):
    """
    Déclenche manuellement le même cycle qu'au démarrage de l'application :
    rattrapage des résultats déjà collectés + contrôle des vulnérabilités
    jamais vérifiées. Tourne en tâche de fond — suivre la progression via
    GET /api/patch-check/status (même mécanisme que le check automatique).

    `force=true` : efface d'abord `last_patch_check` sur les vulns ouvertes
    concernées (périmètre effectif décrit ci-dessous, ou seulement `asset_id`
    si fourni) pour lever le garde-fou RECHECK_INTERVAL (24h). À utiliser après
    l'amélioration d'un signal de détection — sans quoi le stock déjà contrôlé
    garde un résultat calculé par l'ancienne logique (cf.
    `reset_patch_check_timestamps`). Ne modifie ni les statuts, ni les
    validateurs, ni les rapports déjà stockés.

    `asset_id` (04/08/2026, reflète le filtre d'actifs du Dashboard) : un
    "Patch check global" lancé avec un filtre d'actifs actif ne recontrôle que
    les actifs sélectionnés.

    ⚠️ **Périmètre par défaut changé le 07/08/2026** (demande explicite) : sans
    `asset_id`, le cycle ne couvre plus tout le parc mais seulement les actifs
    "entièrement configurés" (au moins un scan SSH/WinRM réussi) — 3 sur 72 au
    moment du changement. Avant ça, le cycle passait le plus clair de son temps
    à tenter (et échouer) des connexions sur des actifs jamais scannés avec
    succès, sans aucun espoir d'y arriver un jour tant qu'ils ne sont pas
    configurés — "tourne dans le vide". Couvre à la fois le déclenchement
    manuel (ce endpoint), le cycle de démarrage (`main.py::_startup_patch_check`)
    et le cycle périodique Celery (`tasks/scheduled_tasks.py::patch_check_periodic`,
    qui appelle ce même endpoint sans `asset_id`).
    """
    # Pas de garde `is_patch_check_cycle_running()` ici (07/08/2026, retirée) :
    # un cycle déjà en cours ne bloque plus la demande, elle est mémorisée pour
    # une passe supplémentaire dès la fin de la passe en cours (cf.
    # run_full_patch_check_cycle § Auto-relance) — sans ça, scanner un actif
    # pendant qu'un cycle tourne déjà n'avait aucun effet avant sa fin.
    if asset_id:
        asset_ids = [a for a in asset_id.split(",") if a]
        reset = await reset_patch_check_timestamps(asset_ids=asset_ids) if force else 0
        asyncio.create_task(run_full_patch_check_cycle(asset_ids=asset_ids))
        # Calculé après le reset (si force) pour refléter le périmètre réel que le
        # cycle va traiter — sert au message de confirmation côté dashboard
        # ("N à vérifier" vs "déjà à jour"), GET /status n'étant pas scopé à
        # asset_ids (cf. count_pending_patch_checks).
        pending_count = await count_pending_patch_checks(asset_ids=asset_ids)
        return {"status": "started", "forced": force, "reset": reset, "asset_ids": asset_ids, "pending_count": pending_count}

    # Sans asset_id : périmètre "actifs configurés", recalculé à chaque passage
    # (`refresh_configured`) plutôt que figé ici — un actif tout juste
    # configuré rejoint la prochaine passe automatiquement.
    from services.stats import get_configured_asset_ids
    scope_ids = await get_configured_asset_ids(session)
    reset = await reset_patch_check_timestamps() if force else 0
    asyncio.create_task(run_full_patch_check_cycle(refresh_configured=True))
    pending_count = await count_pending_patch_checks(asset_ids=scope_ids)
    return {"status": "started", "forced": force, "reset": reset, "asset_ids": "configured_only", "pending_count": pending_count}


@router.get("/status", dependencies=[Depends(require_page("/dashboard", "/vulnerabilities"))])
async def patch_check_status(
    configured_only: bool = Query(
        False,
        description="Restreint le compteur aux actifs 'entièrement configurés' (dashboard) — indépendant "
                     "du paramètre du même nom sur POST /run : ce compteur-ci ne change que l'affichage, "
                     "il ne pilote pas le cycle réel (déjà scopé par défaut côté POST /run, cf. sa doc).",
    ),
    session: AsyncSession = Depends(get_session),
):
    """
    Avancement du contrôle automatique de démarrage (lecture-seule) :
    machine en cours d'analyse, dernier résultat, nombre restant à vérifier.
    Destiné au polling depuis le dashboard.
    """
    base_filter = Vulnerability.status.in_(["open", "in_progress", "awaiting_fix", "awaiting_fix_partial"])
    recheck_cutoff = datetime.now(timezone.utc) - RECHECK_INTERVAL
    needs_check = or_(
        Vulnerability.last_patch_check.is_(None),
        Vulnerability.last_patch_check < recheck_cutoff,
    )
    extra_filter = ()
    query_base = select(func.count()).select_from(Vulnerability)
    if configured_only:
        from services.stats import get_configured_asset_ids
        from services.patch_checker import PATCH_CHECK_MAX_AGE_YEARS
        # CVE trop anciennes exclues (07/08/2026) : le cycle réel (POST /run
        # sans asset_id) ne les vérifie plus (cf. PATCH_CHECK_MAX_AGE_YEARS,
        # services/patch_checker.py) — sans ce même filtre ici, "pending"
        # resterait bloqué au-dessus de 0 pour des vulns que le cycle ne
        # traitera jamais, laissant croire à un blocage plutôt qu'un choix
        # de périmètre assumé.
        age_cutoff = datetime.now(timezone.utc) - timedelta(days=365 * PATCH_CHECK_MAX_AGE_YEARS)
        query_base = query_base.join(CVE, Vulnerability.cve_id == CVE.id)
        extra_filter = (
            Vulnerability.asset_id.in_(await get_configured_asset_ids(session)),
            CVE.published >= age_cutoff,
        )

    pending = (await session.execute(
        query_base.where(base_filter, needs_check, *extra_filter)
    )).scalar_one()

    checked = (await session.execute(
        query_base.where(base_filter, ~needs_check, *extra_filter)
    )).scalar_one()

    last_cycle = await get_last_cycle_state(session)

    return {
        "current": get_current_check(),
        "last_completed": get_last_completed(),
        "checked": checked,
        "pending": pending,
        # Distinct de `pending` (bug corrigé, cf. STATUS.md) : `pending` n'est
        # qu'un décompte du backlog (vulns à revérifier), quasi toujours > 0 sur
        # un vrai parc — utile pour la barre de progression UNE FOIS un cycle
        # confirmé actif, mais faux comme signal d'activité à lui seul (le
        # bandeau "Analyse en cours" restait affiché en permanence, y compris
        # sans aucun cycle en cours). `running` reflète l'état réel du cycle
        # (`_cycle_running`, cf. run_full_patch_check_cycle) — c'est lui, pas
        # `pending`, qui doit piloter l'affichage du bandeau côté frontend.
        "running": is_patch_check_cycle_running(),
        "started_at": get_cycle_started_at(),
        "assets": get_asset_progress(),
        # État persisté du dernier cycle (cf. main.py::_check_interrupted_patch_cycle) —
        # "interrupted" seulement quand un cycle a été coupé par un redémarrage du
        # backend avant de finir, pas à chaque poll normal.
        "last_cycle_status": last_cycle["status"],
        "last_cycle_at": last_cycle["at"],
    }


@router.get("/asset-completions", dependencies=[Depends(require_page("/dashboard", "/vulnerabilities"))])
async def asset_completion_summary(
    since: datetime = Query(..., description="Horodatage ISO — mêmes usages que /vulnerabilities/auto-bascule-summary"),
    limit: int = Query(8, ge=1, le=100, description="Nombre de lignes renvoyées (`total` reste exact)"),
    session: AsyncSession = Depends(get_session),
):
    """
    Rattrapage — actifs ayant fini une passe de contrôle patch depuis `since`
    (`models.py::PatchCheckAssetCompletion`, 11/08/2026). Pendant symétrique de
    `GET /vulnerabilities/auto-bascule-summary` mais pour la notification
    "actif terminé" du Dashboard (toast `pushToast`, disparaît après 6s sans
    laisser de trace consultable jusqu'ici) — endpoint séparé plutôt que fusionné
    dans `auto-bascule-summary` : ce dernier alimente aussi le bandeau "depuis
    votre dernière visite" et le récap `WelcomeOverlay`, tous deux déjà écrits
    en supposant des lignes au format CVE (`cve_id`/`severity`/`asset_name`) —
    y mélanger un format différent aurait cassé ces deux consommateurs.
    """
    q = (
        select(PatchCheckAssetCompletion)
        .where(PatchCheckAssetCompletion.completed_at >= since)
        .order_by(PatchCheckAssetCompletion.completed_at.desc())
    )
    rows = (await session.execute(q)).scalars().all()

    def _row(e: PatchCheckAssetCompletion) -> dict:
        return {
            "asset_name": e.asset_name, "hostname": e.hostname,
            "checked_count": e.checked_count, "auto_bascule_count": e.auto_bascule_count,
            "at": e.completed_at.isoformat() if e.completed_at else None,
        }

    return {
        "since": since.isoformat(),
        "total": len(rows),
        "items": [_row(e) for e in rows[:limit]],
    }


@router.post("/{vuln_id}", dependencies=[Depends(require_page("/dashboard", "/vulnerabilities"))])
async def check_patch_for_vuln(
    vuln_id: str,
    force: bool = Query(False, description="Ignore le cache et relance un vrai contrôle WinRM/SSH"),
    session: AsyncSession = Depends(get_session),
):
    """
    Vérifie (lecture seule) si le correctif d'une vulnérabilité est détecté sur l'actif.

    - Windows : WinRM → Get-HotFix (KB)
    - Linux   : SSH   → dpkg/rpm version

    Retourne un rapport pour l'analyste.

    CRITICAL : signalement seul, l'analyste valide manuellement.
    HIGH/MEDIUM/LOW : bascule automatique en `patched` si patch détecté
    (cf. CLAUDE.md — règle de non-intervention et ses exceptions).

    Si le dernier contrôle date de moins de MIN_RECHECK_GAP, renvoie ce
    résultat déjà en base sans resolliciter l'actif — sauf `force=true`.
    """
    vuln = await session.get(Vulnerability, vuln_id)
    if not vuln:
        raise HTTPException(404, "Vulnérabilité introuvable")

    cve = await session.get(CVE, vuln.cve_id)
    if not cve:
        raise HTTPException(404, "CVE introuvable")

    asset = await session.get(Asset, vuln.asset_id)
    if not asset:
        raise HTTPException(404, "Actif introuvable")

    if not force and vuln.last_patch_check and vuln.patch_check_result:
        age = datetime.now(timezone.utc) - vuln.last_patch_check
        if age < MIN_RECHECK_GAP:
            cached_result = {**vuln.patch_check_result, "cached": True, "cached_age_seconds": int(age.total_seconds())}
            return {
                "vuln_id": str(vuln.id),
                "current_status": vuln.status,
                "check_result": cached_result,
                "auto_patched": False,
                "action_required": "Résultat en cache — contrôlé il y a moins de 5 min, relancez un scan si besoin.",
            }

    from services.cpe_matcher import _load_windows_mappings
    windows_mappings = await _load_windows_mappings(session)
    result = await check_patch(asset, cve, windows_mappings=windows_mappings)
    result["cached"] = False

    auto_patched = apply_patch_result(vuln, cve, result, session)
    await session.commit()

    if auto_patched and result.get("not_applicable") is True:
        action_required = ("Produit non installé sur la machine — vulnérabilité automatiquement "
                           "qualifiée en faux positif (sévérité non-critique).")
    elif result.get("not_applicable") is True:
        action_required = ("Produit non installé sur la machine — CVE CRITICAL : veuillez valider et "
                           "qualifier la vulnérabilité en 'faux positif' manuellement.")
    elif auto_patched:
        action_required = "Patch détecté — vulnérabilité automatiquement marquée comme corrigée (sévérité non-critique)."
    elif result.get("patch_detected") is True:
        action_required = "Patch détecté — CVE CRITICAL : veuillez valider et marquer la vulnérabilité comme 'patched' manuellement."
    else:
        action_required = "Patch non détecté ou indéterminé — vérification manuelle recommandée."

    return {
        "vuln_id": str(vuln.id),
        "current_status": vuln.status,
        "check_result": result,
        "auto_patched": auto_patched,
        "action_required": action_required,
    }
