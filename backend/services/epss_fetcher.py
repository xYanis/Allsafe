"""
services/epss_fetcher.py
Scores EPSS (Exploit Prediction Scoring System, FIRST.org) — probabilité qu'une CVE soit
exploitée activement sous 30 jours. Documentation/source : https://www.first.org/epss/data_stats

Contrairement à NVD (API paginée, interrogeable par date de modification), EPSS ne publie
qu'un export CSV complet régénéré chaque jour (~360k CVE, quelques Mo compressé) — pas de
sync incrémentale possible, un fetch retélécharge tout. Met à jour uniquement les CVE déjà
en base (`cves.cve_id`), n'en crée jamais : NVD reste l'unique source de vérité pour la CVE
elle-même (même principe que withsecure_matcher.py/glpi_matcher.py, qui n'enrichissent que
des entités existantes).

Colonne `epss_score` présente depuis la mise en service (cf. models.py) mais jamais peuplée
jusqu'ici — `calculate_risk_score` (services/scoring.py) s'y replie sur 0.0, ce qui a mis
`risk_score` à 0 pour TOUTE vulnérabilité en base sans que rien ne le signale (constaté le
12/08/2026, cf. STATUS.md). Ce fetcher corrige la cause racine ; un appel à
`recalculate_all_scores()` (routers/sync.py::/rescore) corrige l'effet déjà en base.
"""

import csv
import gzip
import io
import logging

import httpx
from sqlalchemy import bindparam, update

from database import SessionLocal
from models import CVE
from services.scoring import recalculate_all_scores

logger = logging.getLogger(__name__)

EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_UPDATE_BATCH_SIZE = 2000


def _parse_epss_csv(content: bytes) -> list[tuple[str, float]]:
    """La 1re ligne est un commentaire de métadonnées (#model_version:...,score_date:...),
    pas du CSV — sautée avant `csv.DictReader`."""
    rows = []
    with gzip.GzipFile(fileobj=io.BytesIO(content)) as gz:
        text_stream = io.TextIOWrapper(gz, encoding="utf-8")
        next(text_stream, None)
        for row in csv.DictReader(text_stream):
            try:
                rows.append((row["cve"], float(row["epss"])))
            except (KeyError, ValueError, TypeError):
                continue
    return rows


async def run_epss_sync(rescore: bool = True) -> dict:
    """Télécharge l'export EPSS complet et met à jour `cves.epss_score` pour les CVE déjà
    en base, par lot (UPDATE bulk lié par `cve_id`, pas une requête par ligne — avec
    ~188k CVE en base, l'anti-pattern un-par-un est exactement le type d'incident de perf
    déjà documenté sur ce projet, cf. cpe_matcher.py/patch_checker.py)."""
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(EPSS_CSV_URL, follow_redirects=True)
        response.raise_for_status()
        content = response.content

    rows = _parse_epss_csv(content)

    # Exécuté via la Connection Core (session.connection()), pas session.execute() :
    # un UPDATE par bindparam exécuté en liste (executemany) sur une classe mappée
    # déclenche par défaut le chemin "ORM Bulk UPDATE by Primary Key" de SQLAlchemy,
    # qui exige alors la PK dans chaque ligne — inutile ici, le filtre porte sur
    # cve_id (unique mais pas la PK). Passer par Core évite cette détection.
    stmt = (
        update(CVE)
        .where(CVE.cve_id == bindparam("_cve_id"))
        .values(epss_score=bindparam("_epss"))
    )

    session = SessionLocal()
    try:
        for i in range(0, len(rows), _UPDATE_BATCH_SIZE):
            batch = rows[i:i + _UPDATE_BATCH_SIZE]
            conn = await session.connection()
            await conn.execute(stmt, [{"_cve_id": cve_id, "_epss": epss} for cve_id, epss in batch])
            await session.commit()

        logger.info("Sync EPSS : %d lignes traitées depuis l'export FIRST.org", len(rows))
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()

    stats = {"fetched": len(rows)}
    if rescore:
        stats["rescore"] = await recalculate_all_scores()
    return stats
