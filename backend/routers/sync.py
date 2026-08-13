from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database import get_session
from models import SyncState, Asset, CVE
from config import settings
from tasks.scheduled_tasks import trigger_manual_sync, get_task_status
from services.asset_importer import run_asset_import
from services.cpe_matcher import run_cpe_matching, run_cpe_matching_for_cve, backfill_component_types
from services.nvd_fetcher import run_nvd_sync_by_id, run_nvd_backfill_by_cpe
from services.scoring import recalculate_all_scores, recalculate_scores_for_cve
from services.epss_fetcher import run_epss_sync

router = APIRouter()


@router.post("/nvd")
async def trigger_nvd_sync(days: int = 7):
    task_id = trigger_manual_sync(days=days)
    return {"task_id": task_id, "status": "started", "days": days}


@router.post("/nvd/{cve_id}")
async def trigger_nvd_sync_by_id(cve_id: str, session: AsyncSession = Depends(get_session)):
    """Récupère/rafraîchit une CVE précise par ID — filet de rattrapage pour
    une CVE passée à travers le trou de la sync incrémentale (cf.
    docs/ARCHITECTURE.md § Sync NVD).

    03/08/2026 : enchaîne matching + rescore *ciblés sur cette seule CVE*
    (`run_cpe_matching_for_cve`/`recalculate_scores_for_cve`, jamais appelées
    ailleurs jusqu'ici — cf. revue de code) plutôt que de renvoyer la main à
    l'analyste pour POST /api/sync/match (matching complet 72 actifs × ~181k
    CVE, l'opération responsable des incidents mémoire déjà documentés,
    minutes + 6 Go de RAM). Pour une seule CVE fraîchement récupérée, la
    version ciblée fait la même chose en quelques ms — même profil de
    sécurité que le cycle horaire déjà automatique : crée des vulns `open`,
    ne qualifie/ferme jamais rien toute seule."""
    result = await run_nvd_sync_by_id(cve_id.upper(), api_key=settings.NVD_API_KEY or None)
    if not result["found"]:
        raise HTTPException(404, f"« {cve_id} » introuvable dans NVD (ID invalide ou CVE rejetée)")

    cve = (await session.execute(select(CVE).where(CVE.cve_id == result["cve_id"]))).scalar_one_or_none()
    if cve is not None:
        result["matching"] = await run_cpe_matching_for_cve(cve.id, session)
        result["rescore"] = await recalculate_scores_for_cve(cve.id, session)
    return result


@router.post("/nvd-backfill")
async def trigger_nvd_backfill(session: AsyncSession = Depends(get_session)):
    """Rattrapage complet — importe toutes les CVE NVD applicables aux CPE
    réellement présents sur le parc (pas un import NVD complet, ~300k CVE
    hors sujet). Complète le fix du curseur incrémental (cf. `/nvd/{cve_id}`)
    qui empêche les futures pertes mais ne comble pas le retard déjà
    accumulé. Peut prendre plusieurs minutes selon le nombre de CPE distincts
    et le volume par CPE (rate-limit NVD, cf. services/nvd_fetcher.py). Ne
    relance pas le matching CPE automatiquement."""
    assets = (await session.execute(
        select(Asset).where(Asset.status == "active")
    )).scalars().all()

    cpes = sorted({cpe for a in assets for cpe in (a.cpe_list or [])})
    if not cpes:
        return {"cpes": [], "results": []}

    results = []
    for cpe in cpes:
        stats = await run_nvd_backfill_by_cpe(cpe, api_key=settings.NVD_API_KEY or None)
        results.append(stats)

    return {"cpes": cpes, "results": results}


@router.get("/status/{task_id}")
async def task_status(task_id: str):
    return get_task_status(task_id)


@router.post("/assets")
async def trigger_asset_import():
    stats = await run_asset_import()
    return stats


@router.post("/match")
async def trigger_cpe_match():
    stats = await run_cpe_matching()
    return stats


@router.post("/backfill-component-types")
async def trigger_backfill_component_types():
    """One-shot (07/08/2026) : classe `component_type` (système/application) sur
    les `Vulnerability` déjà en base créées avant l'introduction de ce champ —
    cf. services/cpe_matcher.py::backfill_component_types. Rejouable sans risque
    (ne touche que les lignes `component_type IS NULL`)."""
    return await backfill_component_types()


@router.get("/match-status")
async def cpe_match_status(session: AsyncSession = Depends(get_session)):
    """Date du dernier matching CPE (manuel via ce bouton, ou automatique au
    démarrage de l'app — cf. main.py `_startup_matching`) — lu au chargement
    de page pour afficher la date de dernière synchronisation sans attendre
    un clic manuel (cf. MatchingCveButton dans Dashboard.jsx)."""
    state = await session.get(SyncState, "cpe_match")
    return {"last_synced_at": state.last_synced_at.isoformat() if state and state.last_synced_at else None}


@router.post("/rescore")
async def trigger_rescore():
    stats = await recalculate_all_scores()
    return stats


@router.post("/epss")
async def trigger_epss_sync():
    """Télécharge l'export EPSS complet (FIRST.org, ~360k CVE régénéré une fois par
    jour) et met à jour cves.epss_score pour les CVE déjà en base, puis relance
    automatiquement le rescore (cf. services/epss_fetcher.py) — sans ça, le rescore
    resterait basé sur les anciens epss_score déjà chargés en mémoire tant qu'un
    /rescore séparé n'est pas déclenché à la main."""
    return await run_epss_sync()
