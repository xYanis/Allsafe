"""
Scoring des vulnérabilités
Formule : risk_score = min(cvss × epss × multiplicateur_criticite, 10.0)
"""

import asyncio
import logging
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import load_only

from database import SessionLocal
from models import Asset, CVE, Vulnerability

logger = logging.getLogger(__name__)

# Pagination + colonnes allégées (11/08/2026, bug réel corrigé — cf. STATUS.md) :
# `recalculate_all_scores` chargeait Vulnerability × CVE × Asset en une seule requête,
# sans pagination ni `load_only`, sur tout le parc (open/in_progress/awaiting_fix*) —
# même anti-pattern que l'incident mémoire déjà vécu et corrigé sur
# services/patch_checker.py/cpe_matcher.py (~265 000 lignes, `CVE.raw_data` — 377 Mo en
# base — chargé une fois PAR VULNÉRABILITÉ rattachée à chaque CVE, pas une fois par CVE).
_RESCORE_BATCH_SIZE = 2000
_RESCORE_YIELD_EVERY = 500

_RESCORE_LOAD_OPTIONS = (
    load_only(Vulnerability.id, Vulnerability.asset_id, Vulnerability.cve_id, Vulnerability.risk_score, raiseload=True),
    load_only(CVE.id, CVE.cvss_score, CVE.epss_score, raiseload=True),
    load_only(Asset.id, Asset.tags, raiseload=True),
)

CRITICITE_MULTIPLIERS: dict[str, float] = {
    "haute": 1.5,
    "moyenne": 1.0,
    "faible": 0.7,
}


def calculate_risk_score(
    cvss_score: float | None,
    epss_score: float | None,
    criticite: str = "moyenne",
) -> float | None:
    """
    Calcule le risk_score d'une vulnérabilité.
    Retourne None si cvss_score absent (CVE sans score CVSS connu).
    """
    if cvss_score is None:
        return None
    epss = epss_score or 0.0
    multiplier = CRITICITE_MULTIPLIERS.get(criticite, 1.0)
    return min(cvss_score * epss * multiplier, 10.0)


# ─────────────────────────────────────────────────────────────────────────────
# Recalcul en base
# ─────────────────────────────────────────────────────────────────────────────

async def recalculate_all_scores(db: AsyncSession | None = None) -> dict:
    """
    Recalcule le risk_score de toutes les vulnérabilités ouvertes.
    Utile après un changement de multiplicateurs ou de scores EPSS.

    Paginé par lot (keyset sur Vulnerability.id, cf. _RESCORE_BATCH_SIZE) plutôt
    qu'une seule requête sur tout le parc, avec `load_only(raiseload=True)` pour
    éviter `CVE.raw_data`/`Asset.installed_packages`/`last_scan_result` — cf.
    commentaire sur _RESCORE_LOAD_OPTIONS plus haut.
    """
    own_session = db is None
    if own_session:
        db = SessionLocal()

    updated = skipped = 0
    n = 0

    try:
        status_filter = Vulnerability.status.in_(["open", "in_progress", "awaiting_fix", "awaiting_fix_partial"])
        last_id = None
        while True:
            filters = [status_filter]
            if last_id is not None:
                filters.append(Vulnerability.id > last_id)
            rows = (await db.execute(
                select(Vulnerability, CVE, Asset)
                .join(CVE, Vulnerability.cve_id == CVE.id)
                .join(Asset, Vulnerability.asset_id == Asset.id)
                .options(*_RESCORE_LOAD_OPTIONS)
                .where(*filters)
                .order_by(Vulnerability.id)
                .limit(_RESCORE_BATCH_SIZE)
            )).all()
            if not rows:
                break
            last_id = rows[-1][0].id

            for vuln, cve, asset in rows:
                criticite = (asset.tags or {}).get("criticite", "moyenne")
                new_score = calculate_risk_score(cve.cvss_score, cve.epss_score, criticite)

                if new_score == vuln.risk_score:
                    skipped += 1
                else:
                    vuln.risk_score = new_score
                    updated += 1

                n += 1
                if n % _RESCORE_YIELD_EVERY == 0:
                    await asyncio.sleep(0)

            # Commit au fil de l'eau, par lot — même raisonnement que patch_checker.py :
            # ne rien perdre si le process est interrompu en cours de route.
            await db.commit()

        logger.info("Recalcul terminé : %d mis à jour, %d inchangés", updated, skipped)

    except Exception:
        await db.rollback()
        raise
    finally:
        if own_session:
            await db.close()

    return {"updated": updated, "skipped": skipped}


async def recalculate_scores_for_asset(asset_id: UUID, db: AsyncSession) -> dict:
    """Recalcule les scores de toutes les vulnérabilités d'un actif donné."""
    asset = (
        await db.execute(select(Asset).where(Asset.id == asset_id))
    ).scalar_one_or_none()

    if asset is None:
        return {"error": "asset_not_found", "updated": 0}

    criticite = (asset.tags or {}).get("criticite", "moyenne")

    # `load_only` (11/08/2026, cf. commentaire sur _RESCORE_LOAD_OPTIONS plus haut) :
    # gravité moindre qu'un recalcul parc entier (borné à un seul actif), mais un
    # actif comme TSTUDIO (4749 vulns ouvertes constaté en réel) chargerait quand
    # même `CVE.raw_data` 4749 fois sans ce filtre.
    result = await db.execute(
        select(Vulnerability, CVE)
        .join(CVE, Vulnerability.cve_id == CVE.id)
        .options(_RESCORE_LOAD_OPTIONS[0], _RESCORE_LOAD_OPTIONS[1])
        .where(Vulnerability.asset_id == asset_id)
        .where(Vulnerability.status.in_(["open", "in_progress", "awaiting_fix", "awaiting_fix_partial"]))
    )

    updated = 0
    for vuln, cve in result.all():
        new_score = calculate_risk_score(cve.cvss_score, cve.epss_score, criticite)
        if new_score != vuln.risk_score:
            vuln.risk_score = new_score
            updated += 1

    await db.commit()
    return {"updated": updated}


async def recalculate_scores_for_cve(cve_id: UUID, db: AsyncSession) -> dict:
    """Recalcule les scores de toutes les vulnérabilités liées à une CVE (ex : mise à jour EPSS)."""
    cve = (
        await db.execute(select(CVE).where(CVE.id == cve_id))
    ).scalar_one_or_none()

    if cve is None:
        return {"error": "cve_not_found", "updated": 0}

    # `load_only` (11/08/2026, cf. commentaire sur _RESCORE_LOAD_OPTIONS plus haut) :
    # une CVE peut toucher tout le parc (jusqu'à 481 actifs) — évite de charger
    # `Asset.installed_packages`/`last_scan_result` (jusqu'à plusieurs centaines de
    # Ko par actif) pour chaque ligne alors que seul `tags` est lu ici.
    result = await db.execute(
        select(Vulnerability, Asset)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .options(_RESCORE_LOAD_OPTIONS[0], _RESCORE_LOAD_OPTIONS[2])
        .where(Vulnerability.cve_id == cve_id)
        .where(Vulnerability.status.in_(["open", "in_progress", "awaiting_fix", "awaiting_fix_partial"]))
    )

    updated = 0
    for vuln, asset in result.all():
        criticite = (asset.tags or {}).get("criticite", "moyenne")
        new_score = calculate_risk_score(cve.cvss_score, cve.epss_score, criticite)
        if new_score != vuln.risk_score:
            vuln.risk_score = new_score
            updated += 1

    await db.commit()
    return {"updated": updated}
