"""
scheduled_tasks.py
Tâches Celery planifiées pour la collecte automatique des CVE.

Planning par défaut :
  - Toutes les 4h  : synchronisation NVD (CVE des dernières 24h)
  - Toutes les 1h  : collecte flux RSS (CERT-FR, Exploit-DB, GitHub)
  - Tous les jours : synchronisation NVD complète (30 jours, critiques uniquement)
"""

import logging
from celery import Celery
from celery.schedules import crontab
from datetime import datetime, timedelta, timezone

from config import settings
from services.nvd_fetcher import run_nvd_sync
from services.rss_fetcher import run_rss_sync
from services.watch_fetcher import run_watch_sync

logger = logging.getLogger(__name__)

# ─── Initialisation Celery ────────────────────────────────────────────────────

celery_app = Celery(
    "cybervuln",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="Europe/Paris",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,              # Acquittement après exécution (pas avant)
    worker_prefetch_multiplier=1,     # Une tâche à la fois par worker
    result_expires=86400,             # Résultats conservés 24h dans Redis
)

# ─── Planning ─────────────────────────────────────────────────────────────────

celery_app.conf.beat_schedule = {

    # Collecte NVD légère toutes les 4h (CVE des dernières 24h)
    "nvd-sync-recent": {
        "task": "tasks.scheduled_tasks.sync_nvd_recent",
        "schedule": crontab(minute=0, hour="*/4"),
        "options": {"queue": "default"},
    },

    # Collecte NVD quotidienne approfondie à 3h du matin (30 jours, critiques)
    "nvd-sync-daily-critical": {
        "task": "tasks.scheduled_tasks.sync_nvd_critical",
        "schedule": crontab(minute=0, hour=3),
        "options": {"queue": "default"},
    },

    # Collecte flux RSS toutes les heures
    "rss-sync-hourly": {
        "task": "tasks.scheduled_tasks.sync_rss_feeds",
        "schedule": crontab(minute=5),   # À H+5min pour éviter la concurrence avec NVD
        "options": {"queue": "default"},
    },

    # Collecte flux de veille toutes les heures (décalée de 10 min)
    "watch-sync-hourly": {
        "task": "tasks.scheduled_tasks.sync_watch_feeds",
        "schedule": crontab(minute=10),
        "options": {"queue": "default"},
    },

    # Patch check autonome (Windows WinRM + Linux SSH, lecture seule) toutes les
    # 6h — revérifie ce qui n'a jamais été contrôlé ou dont le contrôle a plus de
    # 24h (RECHECK_INTERVAL), pour capter un correctif appliqué après un premier
    # check. Décalé à H+20 pour éviter la concurrence avec les autres tâches.
    "patch-check-periodic": {
        "task": "tasks.scheduled_tasks.patch_check_periodic",
        "schedule": crontab(minute=20, hour="*/6"),
        "options": {"queue": "default"},
    },

    # Rapports hebdomadaires figés (module Rapports) — le lundi à 7h, sur la
    # semaine ISO qui vient de se terminer. Lundi et pas dimanche soir : la
    # semaine doit être close pour que le rapport soit complet (cf.
    # services/weekly_report.py § last_complete_week). 7h évite la sync NVD
    # quotidienne de 3h.
    "weekly-reports": {
        "task": "tasks.scheduled_tasks.generate_weekly_reports_task",
        "schedule": crontab(minute=0, hour=7, day_of_week=1),
        "options": {"queue": "default"},
    },

    # Sauvegarde PostgreSQL quotidienne (pg_dump, cf. services/backup.py) à 4h —
    # après les syncs NVD/veille de la nuit (3h/minuit), pour sauvegarder des
    # données déjà à jour plutôt qu'une photo prise en plein milieu d'une sync.
    "db-backup-daily": {
        "task": "tasks.scheduled_tasks.backup_database",
        "schedule": crontab(minute=0, hour=4),
        "options": {"queue": "default"},
    },

    # WithSecure (correctifs manquants CVE/CVSS, serveurs Windows uniquement,
    # cf. services/withsecure_matcher.py) une fois par jour à 5h30 — créneau
    # libre entre la sauvegarde (4h) et le patch check (créneaux */6h à
    # minute 20). Pas besoin d'une fréquence plus élevée : ces correctifs
    # n'évoluent pas au rythme d'une sync NVD.
    "withsecure-sync-daily": {
        "task": "tasks.scheduled_tasks.sync_withsecure",
        "schedule": crontab(minute=30, hour=5),
        "options": {"queue": "default"},
    },

    # Scores EPSS (services/epss_fetcher.py) — export FIRST.org régénéré une fois
    # par jour, pas d'API incrémentale possible (cf. commentaire du service).
    # 3h30 : créneau libre entre la sync NVD critique (3h) et la sauvegarde (4h).
    # Colonne jamais peuplée jusqu'au 12/08/2026 (constaté via le Dashboard),
    # ce qui gardait risk_score à 0 pour toute vulnérabilité — cf. epss_fetcher.py.
    "epss-sync-daily": {
        "task": "tasks.scheduled_tasks.sync_epss",
        "schedule": crontab(minute=30, hour=3),
        "options": {"queue": "default"},
    },

    # KEV — CISA Known Exploited Vulnerabilities (services/kev_fetcher.py), export JSON
    # régénéré au fil de l'eau côté CISA, pas d'API incrémentale. 3h45 : juste après EPSS
    # (3h30), avant la sauvegarde (4h).
    "kev-sync-daily": {
        "task": "tasks.scheduled_tasks.sync_kev",
        "schedule": crontab(minute=45, hour=3),
        "options": {"queue": "default"},
    },

    # Maturité d'exploit — présence dans Metasploit (services/exploit_maturity_fetcher.py).
    # Hebdomadaire (pas quotidien comme EPSS/KEV) : le catalogue de modules évolue lentement,
    # pas de valeur à reparser ~11 Mo chaque jour. Dimanche 5h45, après WithSecure (5h30).
    "exploit-maturity-sync-weekly": {
        "task": "tasks.scheduled_tasks.sync_exploit_maturity",
        "schedule": crontab(minute=45, hour=5, day_of_week=0),
        "options": {"queue": "default"},
    },
}


# ─── Tâches ───────────────────────────────────────────────────────────────────

@celery_app.task(
    name="tasks.scheduled_tasks.sync_nvd_recent",
    bind=True,
    max_retries=3,
    default_retry_delay=300,    # Retry après 5 minutes
    soft_time_limit=1800,       # 30 min max
    time_limit=2100,            # Kill après 35 min
)
def sync_nvd_recent(self):
    """
    Synchronise les CVE NVD publiées ou modifiées dans les dernières 24h.
    Tâche légère, exécutée toutes les 4h.
    """
    import asyncio
    logger.info("Démarrage sync NVD (dernières 24h)")
    try:
        stats = asyncio.run(
            run_nvd_sync(
                api_key=settings.NVD_API_KEY or None,
                days=1,
            )
        )
        logger.info(f"Sync NVD récente terminée : {stats}")
        return stats

    except Exception as exc:
        logger.error(f"Erreur sync NVD récente: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    name="tasks.scheduled_tasks.sync_nvd_critical",
    bind=True,
    max_retries=2,
    default_retry_delay=600,
    soft_time_limit=7200,       # 2h max (beaucoup de données)
    time_limit=7500,
)
def sync_nvd_critical(self):
    """
    Filet de sécurité quotidien — rebalaie NVD par date de modification sur les
    45 derniers jours (CRITICAL+HIGH), indépendamment du curseur incrémental
    canonique (`since_override`, cf. services/nvd_fetcher.py).

    Avant fix (session 20/07/2026) : cette tâche appelait run_nvd_sync() sans
    `since_override` ni `incremental=False` — elle utilisait donc silencieusement
    le même curseur incrémental que la sync toutes les 4h (`days=30` ignoré,
    ne servant que de repli base-vide), la rendant strictement identique à
    cette dernière. Un filet de sécurité qui ne couvre jamais rien de plus que
    ce qu'il est censé rattraper. Incident découvert via une CVE manquante
    (CVE-2022-30190, Windows Server 2019) révélant ~4750 CVE absentes pour ce
    seul CPE — cf. docs/ARCHITECTURE.md § Sync NVD.
    """
    import asyncio
    since_override = datetime.now(timezone.utc) - timedelta(days=45)
    logger.info(f"Démarrage sync NVD quotidienne (balayage redondant depuis {since_override.isoformat()}, CRITICAL+HIGH)")
    try:
        stats = asyncio.run(
            run_nvd_sync(
                api_key=settings.NVD_API_KEY or None,
                severity_filter=["CRITICAL", "HIGH"],
                since_override=since_override,
            )
        )
        logger.info(f"Sync NVD quotidienne terminée : {stats}")
        return stats

    except Exception as exc:
        logger.error(f"Erreur sync NVD quotidienne: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    name="tasks.scheduled_tasks.sync_rss_feeds",
    bind=True,
    max_retries=3,
    default_retry_delay=120,
    soft_time_limit=300,        # 5 min max
    time_limit=360,
)
def sync_rss_feeds(self):
    """
    Collecte tous les flux RSS/Atom configurés (CERT-FR, Exploit-DB, GitHub).
    Exécutée toutes les heures.
    """
    import asyncio
    logger.info("Démarrage collecte RSS")
    try:
        stats = asyncio.run(run_rss_sync())
        logger.info(f"Collecte RSS terminée : {stats}")
        return stats

    except Exception as exc:
        logger.error(f"Erreur collecte RSS: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    name="tasks.scheduled_tasks.sync_watch_feeds",
    bind=True,
    max_retries=3,
    default_retry_delay=120,
    soft_time_limit=300,
    time_limit=360,
)
def sync_watch_feeds(self):
    """
    Collecte les flux de veille cyber (sources françaises + éditeurs).
    Alimente le registre de veille NIS 2. Exécutée toutes les heures.
    """
    import asyncio
    logger.info("Démarrage collecte veille cyber")
    try:
        stats = asyncio.run(run_watch_sync())
        logger.info(f"Collecte veille terminée : {stats}")
        return stats

    except Exception as exc:
        logger.error(f"Erreur collecte veille: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    name="tasks.scheduled_tasks.sync_nvd_manual",
    bind=True,
    max_retries=1,
    soft_time_limit=3600,
)
def sync_nvd_manual(self, days: int = 7):
    """
    Synchronisation manuelle déclenchée depuis l'API ou le dashboard.
    Accessible via le bouton "Synchroniser" de l'interface.

    Exemple d'appel depuis FastAPI :
        sync_nvd_manual.delay(days=7)
    """
    import asyncio
    logger.info(f"Sync NVD manuelle ({days} jours)")
    try:
        stats = asyncio.run(
            run_nvd_sync(
                api_key=settings.NVD_API_KEY or None,
                days=days,
            )
        )
        return stats
    except Exception as exc:
        logger.error(f"Erreur sync NVD manuelle: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    name="tasks.scheduled_tasks.patch_check_periodic",
    bind=True,
    max_retries=1,
    soft_time_limit=60,
    time_limit=90,
)
def patch_check_periodic(self):
    """
    Déclenche le cycle patch check (lecture seule, WinRM/SSH) via l'API backend
    plutôt que d'appeler le service directement : l'état d'avancement
    (_cycle_running, _current_check, suivi par le dashboard) vit en mémoire dans
    le process FastAPI `backend` — l'invoquer depuis le process `worker` créerait
    un état parallèle invisible au polling du dashboard et sans le verrou anti-
    concurrence avec un cycle déjà en cours (démarrage ou bouton manuel). Le
    cycle lui-même tourne en tâche de fond côté backend (réponse immédiate),
    donc cette tâche Celery se termine vite — pas besoin d'un long time_limit.
    """
    import httpx
    logger.info("Déclenchement patch check périodique")
    try:
        # `X-Internal-Token` (07/08/2026) : cet appel était sans authentification
        # depuis l'introduction du login (30/07/2026) — POST /api/patch-check/run
        # exige une session utilisateur, ce déclenchement échouait donc en 401 à
        # chaque cycle périodique depuis cette date, jamais remarqué (retry Celery
        # silencieux). Cf. auth_deps.py::require_page_or_internal.
        resp = httpx.post(
            "http://backend:8000/api/patch-check/run", timeout=30,
            headers={"X-Internal-Token": settings.INTERNAL_API_TOKEN or ""},
        )
        resp.raise_for_status()
        result = resp.json()
        logger.info(f"Patch check périodique déclenché : {result}")
        return result
    except Exception as exc:
        logger.error(f"Erreur déclenchement patch check périodique: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    name="tasks.scheduled_tasks.generate_weekly_reports_task",
    bind=True,
    max_retries=2,
    default_retry_delay=600,
    soft_time_limit=600,
    time_limit=900,
)
def generate_weekly_reports_task(self):
    """
    Génère les rapports hebdomadaires figés de la dernière semaine ISO complète.

    Appelle le service directement (comme les tâches de sync) plutôt que de
    passer par HTTP comme `patch_check_periodic` : cette génération ne s'appuie
    sur aucun état en mémoire du process backend, une session base suffit.

    Ne réécrit jamais un rapport déjà archivé (`force=False`) — si la tâche
    rejoue pour une raison quelconque, l'instantané d'origine est conservé.
    """
    import asyncio
    logger.info("Démarrage génération des rapports hebdomadaires")
    try:
        async def _run():
            from database import SessionLocal
            from services.weekly_report import generate_weekly_reports
            async with SessionLocal() as session:
                return await generate_weekly_reports(session, force=False)

        result = asyncio.run(_run())
        logger.info(f"Rapports hebdomadaires : {result}")
        return result
    except Exception as exc:
        logger.error(f"Erreur génération rapports hebdomadaires: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    name="tasks.scheduled_tasks.run_cpe_matching_for_asset_task",
    bind=True,
    max_retries=1,
    soft_time_limit=120,
)
def run_cpe_matching_for_asset_task(self, asset_id: str):
    """
    Matching CPE/paquets pour un seul actif, après un scan ou une création/
    modification manuelle (`routers/assets.py`). Déporté sur le worker Celery
    (27/07/2026) après un premier essai raté avec `asyncio.create_task` dans le
    process API : mesuré à ~30s pour un actif avec ~950 CVE déjà rattachées
    (parcourt tout le référentiel CVE), un calcul **CPU-bound**, pas de l'I/O —
    `create_task` partage la même boucle événementielle qu'uvicorn et la bloque
    pendant toute cette durée. Résultat constaté : backend à 99% CPU, API
    entière inutilisable le temps du matching, pas seulement le scan concerné.
    Le worker Celery tourne dans un process/conteneur séparé : aucun impact sur
    la réactivité de l'API, quelle que soit la durée du matching.

    Déclenche aussi le patch check (07/08/2026, demande explicite) une fois le
    matching terminé — un actif qui vient d'être scanné avec succès pour la
    première fois (donc tout juste "configuré", cf. services/stats.py) doit
    être vérifié sans attendre une relance manuelle ou le cycle périodique
    (jusqu'à 6h plus tard). Même raison que `patch_check_periodic` ci-dessous
    pour passer par l'API plutôt qu'un appel direct au service : l'état du
    cycle vit en mémoire côté process `backend`, pas `worker`. `refresh_configured`
    (cf. run_full_patch_check_cycle) fait qu'un cycle déjà en cours sur d'autres
    actifs se relance automatiquement pour couvrir celui-ci plutôt que d'ignorer
    la demande.
    """
    import asyncio
    logger.info(f"Matching CPE en tâche de fond pour l'actif {asset_id}")
    try:
        async def _run():
            from database import SessionLocal
            from services.cpe_matcher import run_cpe_matching_for_asset
            async with SessionLocal() as session:
                return await run_cpe_matching_for_asset(asset_id, session)

        result = asyncio.run(_run())
        logger.info(f"Matching CPE terminé pour {asset_id} : {result}")

        import httpx
        try:
            resp = httpx.post(
                "http://backend:8000/api/patch-check/run", timeout=10,
                headers={"X-Internal-Token": settings.INTERNAL_API_TOKEN or ""},
            )
            resp.raise_for_status()
        except Exception as exc:
            # Non bloquant : le matching lui-même a réussi, le patch check sera
            # de toute façon retenté au prochain cycle périodique (6h).
            logger.warning(f"Déclenchement patch check post-scan échoué pour {asset_id}: {exc}")

        return result
    except Exception as exc:
        logger.error(f"Erreur matching CPE asset {asset_id}: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    name="tasks.scheduled_tasks.backup_database",
    bind=True,
    max_retries=2,
    default_retry_delay=300,
    soft_time_limit=600,
    time_limit=660,
)
def backup_database(self):
    """
    Sauvegarde complète de la base (pg_dump) — cf. services/backup.py pour le
    format et la politique de rétention. Retry en cas d'échec (DB temporairement
    injoignable) plutôt que de silencieusement manquer une nuit de sauvegarde.
    """
    logger.info("Démarrage sauvegarde PostgreSQL")
    try:
        from services.backup import run_backup
        result = run_backup()
        logger.info(f"Sauvegarde PostgreSQL terminée : {result}")
        return result
    except Exception as exc:
        logger.error(f"Erreur sauvegarde PostgreSQL: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    name="tasks.scheduled_tasks.sync_withsecure",
    bind=True,
    max_retries=2,
    default_retry_delay=600,
    soft_time_limit=900,        # 15 min max (appels NVD de rattrapage inclus)
    time_limit=960,
)
def sync_withsecure(self):
    """
    Appelle le service directement (comme le matching CPE) plutôt que de passer
    par HTTP comme patch_check_periodic : aucun état en mémoire du process
    backend n'est impliqué ici, une session base suffit. Si
    WITHSECURE_API_CLIENT_ID/SECRET ne sont pas configurés, le service renvoie
    {"error": "withsecure_not_configured"} sans lever d'exception — pas de
    retry inutile dans ce cas.
    """
    import asyncio
    logger.info("Démarrage synchronisation WithSecure")
    try:
        from services.withsecure_matcher import sync_windows_vulnerabilities
        stats = asyncio.run(sync_windows_vulnerabilities())
        logger.info(f"Synchronisation WithSecure terminée : {stats}")
        return stats
    except Exception as exc:
        logger.error(f"Erreur synchronisation WithSecure: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    name="tasks.scheduled_tasks.sync_epss",
    bind=True,
    max_retries=2,
    default_retry_delay=600,
    soft_time_limit=300,
    time_limit=360,
)
def sync_epss(self):
    """Appelle le service directement (comme WithSecure/matching CPE) — un UPDATE bulk
    en base suffit, aucun état en mémoire du process backend impliqué."""
    import asyncio
    logger.info("Démarrage synchronisation EPSS")
    try:
        from services.epss_fetcher import run_epss_sync
        stats = asyncio.run(run_epss_sync())
        logger.info(f"Synchronisation EPSS terminée : {stats}")
        return stats
    except Exception as exc:
        logger.error(f"Erreur synchronisation EPSS: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    name="tasks.scheduled_tasks.sync_kev",
    bind=True,
    max_retries=2,
    default_retry_delay=600,
    soft_time_limit=300,
    time_limit=360,
)
def sync_kev(self):
    import asyncio
    logger.info("Démarrage synchronisation KEV")
    try:
        from services.kev_fetcher import run_kev_sync
        stats = asyncio.run(run_kev_sync())
        logger.info(f"Synchronisation KEV terminée : {stats}")
        return stats
    except Exception as exc:
        logger.error(f"Erreur synchronisation KEV: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    name="tasks.scheduled_tasks.sync_exploit_maturity",
    bind=True,
    max_retries=2,
    default_retry_delay=600,
    soft_time_limit=600,
    time_limit=720,
)
def sync_exploit_maturity(self):
    """soft_time_limit/time_limit plus larges que les autres tâches de ce fichier : le fichier
    de métadonnées Metasploit (~11 Mo, ~7000 modules) est plus long à télécharger/parser qu'un
    export EPSS/KEV."""
    import asyncio
    logger.info("Démarrage synchronisation maturité d'exploit (Metasploit)")
    try:
        from services.exploit_maturity_fetcher import run_exploit_maturity_sync
        stats = asyncio.run(run_exploit_maturity_sync())
        logger.info(f"Synchronisation maturité d'exploit terminée : {stats}")
        return stats
    except Exception as exc:
        logger.error(f"Erreur synchronisation maturité d'exploit: {exc}")
        raise self.retry(exc=exc)


# ─── Utilitaire : déclenchement immédiat depuis le router FastAPI ─────────────

def trigger_manual_sync(days: int = 7) -> str:
    """
    Déclenche une synchronisation manuelle asynchrone.
    Retourne l'ID de la tâche Celery pour suivi via GET /api/tasks/{task_id}.
    """
    task = sync_nvd_manual.apply_async(args=[days], queue='default')
    logger.info(f"Sync manuelle déclenchée : task_id={task.id}")
    return task.id


def get_task_status(task_id: str) -> dict:
    """Retourne le statut d'une tâche Celery (pour polling frontend)."""
    from celery.result import AsyncResult
    result = AsyncResult(task_id, app=celery_app)
    return {
        "task_id": task_id,
        "status": result.status,           # PENDING | STARTED | SUCCESS | FAILURE
        "result": result.result if result.ready() else None,
        "traceback": result.traceback if result.failed() else None,
    }
