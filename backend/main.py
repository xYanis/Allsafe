"""
main.py
Point d'entrée de l'application CyberVuln — FastAPI.

Routes disponibles :
  /api/cves           — Gestion des CVE
  /api/assets         — Gestion des actifs
  /api/vulnerabilities — Liaisons actifs ↔ CVE
  /api/analysis       — Analyse IA via Claude
  /api/reports        — Génération de rapports
  /api/sync           — Déclenchement manuel des synchronisations
  /api/stats          — KPIs pour le dashboard
  /api/backup         — Sauvegarde PostgreSQL (pg_dump)
"""

import asyncio
import logging
from contextlib import asynccontextmanager

import asyncpg
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError

from auth_deps import require_admin, require_auth, require_page
from config import settings
from database import SessionLocal, init_db
from models import User, SyncState
from routers import cves, assets, vulnerabilities, analysis, reports, sync, stats, remediation, patch_check, connections, watch, identities, security, backup, withsecure, meraki, prtg, glpi, vsphere, incidents, analysts, auth, users, windows_app_mappings, crises, organization_roles, services, documents, audits, notes, agents, integrations
from services.auth import hash_password
from services.cpe_matcher import run_cpe_matching
from services.patch_checker import run_full_patch_check_cycle, PATCH_CYCLE_STATE_KEY

logger = logging.getLogger(__name__)


async def _startup_matching():
    try:
        result = await run_cpe_matching()
        logger.info("Matching CVE au démarrage terminé : %s", result)
    except Exception:
        logger.exception("Erreur matching CVE au démarrage")


async def _startup_patch_check():
    # Restreint aux actifs "entièrement configurés" (07/08/2026, demande
    # explicite) — même définition et même raison que routers/patch_check.py::
    # trigger_patch_check_run : sans ça, le cycle passe l'essentiel de son temps
    # à échouer des connexions sur des actifs jamais scannés avec succès.
    # `refresh_configured=True` (cf. services/patch_checker.py) : un actif
    # configuré pendant que ce cycle de démarrage tourne encore rejoint la
    # passe suivante automatiquement, pas seulement au prochain redémarrage.
    try:
        result = await run_full_patch_check_cycle(refresh_configured=True)
        logger.info("Patch check au démarrage terminé : %s", result)
    except Exception:
        logger.exception("Erreur patch check au démarrage")


async def _check_interrupted_patch_cycle():
    """Un cycle qui laisse `status="running"` en base n'a jamais atteint son retour
    normal (services/patch_checker.py::run_full_patch_check_cycle, qui écrit
    "completed" juste avant de rendre la main) — le seul moyen d'en finir sur
    "running", c'est que le process ait été tué en plein milieu (--reload en dev à
    chaque edit backend, OOM, redémarrage manuel...). L'état en mémoire qui pilotait
    la barre de progression du dashboard est reparti à zéro avec le process, donc
    rien d'autre ne peut jamais le constater que ce contrôle au démarrage suivant.
    Marque juste "interrupted" pour affichage (cf. GET /api/patch-check/status) —
    aucune donnée de vulnérabilité perdue, un nouveau cycle (démarrage ou périodique)
    reprend de toute façon là où last_patch_check s'est arrêté."""
    async with SessionLocal() as session:
        state = await session.get(SyncState, PATCH_CYCLE_STATE_KEY)
        if state and state.status == "running":
            logger.warning(
                "Cycle de patch check interrompu par le redémarrage précédent du backend "
                "(process tué en cours de cycle) — un nouveau cycle va reprendre."
            )
            state.status = "interrupted"
            await session.commit()


async def _bootstrap_admin():
    """Crée le premier compte admin si la table `users` est vide et que
    BOOTSTRAP_ADMIN_EMAIL/PASSWORD sont renseignés — idempotent (ne fait plus rien dès
    qu'un compte existe). Pas de fail-fast si absent : un environnement de dev sans auth
    encore configurée doit pouvoir démarrer, juste un avertissement explicite."""
    async with SessionLocal() as session:
        count = (await session.execute(select(func.count()).select_from(User))).scalar_one()
        if count > 0:
            return
        if not settings.BOOTSTRAP_ADMIN_EMAIL or not settings.BOOTSTRAP_ADMIN_PASSWORD:
            logger.warning(
                "Aucun compte utilisateur en base et BOOTSTRAP_ADMIN_EMAIL/PASSWORD non "
                "renseignés — définir ces variables dans .env ou créer un compte manuellement."
            )
            return
        session.add(User(
            email=settings.BOOTSTRAP_ADMIN_EMAIL.strip().lower(),
            full_name="Administrateur",
            password_hash=hash_password(settings.BOOTSTRAP_ADMIN_PASSWORD),
            role="admin",
            must_change_password=True,
        ))
        await session.commit()
        logger.info("Premier compte admin créé (%s) — changement de mot de passe forcé à la première connexion.",
                    settings.BOOTSTRAP_ADMIN_EMAIL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await _bootstrap_admin()
    await _check_interrupted_patch_cycle()

    # Les deux tâches de démarrage écrivent en base (création de vulnérabilités,
    # bascule de statuts). Conditionnées pour pouvoir redémarrer le backend sans
    # effet de bord — cf. STARTUP_MATCHING / STARTUP_PATCH_CHECK dans config.py.
    # Elles restent déclenchables à la main : POST /api/sync/match et
    # POST /api/patch-check/run.
    if settings.STARTUP_MATCHING:
        await _startup_matching()
    else:
        logger.info("Matching CVE au démarrage désactivé (STARTUP_MATCHING=false)")

    if settings.STARTUP_PATCH_CHECK:
        # Tâche de fond : ne bloque pas la disponibilité de l'API. Rattrapage +
        # contrôle des vulns jamais vérifiées — le même cycle est réutilisable
        # manuellement via POST /api/patch-check/run.
        app.state.patch_check_task = asyncio.create_task(_startup_patch_check())
    else:
        logger.info("Patch check au démarrage désactivé (STARTUP_PATCH_CHECK=false)")

    yield


app = FastAPI(
    title="CyberVuln API",
    description="Gestionnaire de vulnérabilités on-premise",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request, call_next):
    """En-têtes de réponse (10/08/2026, cf. AUDIT_SECURITE.md #11) — les pièces jointes
    (Documentation/Incidents/Audits) ne valident que la signature magique des premiers
    octets, pas le contenu entier ; servies en Content-Disposition: inline pour PDF/images,
    `nosniff` empêche un navigateur de re-deviner un type MIME différent du `Content-Type`
    explicite posé par l'API. `X-Frame-Options: DENY` : aucune page de CBR n'a besoin
    d'être embarquée dans un iframe, ferme le clickjacking par défaut."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.exception_handler(DBAPIError)
async def handle_malformed_id_param(request: Request, exc: DBAPIError):
    """404 propre plutôt qu'un 500 (10/08/2026, trouvé par fuzzing schemathesis en amont
    du passage en prod, cf. AUDIT_SECURITE.md) : un ID de chemin qui n'est pas un UUID
    syntaxiquement valide (ex. `/api/documents/0/download`) fait planter `session.get(...)`
    avec une exception asyncpg non interceptée — 79 usages de ce genre dans les routers,
    un handler global plutôt que patcher chaque route une par une (cf. principe "penser
    scalable", CLAUDE.md).

    `exc.orig` est déjà lui-même un wrapper (`AsyncAdapt_asyncpg_dbapi.Error`, pas
    l'exception asyncpg d'origine) — la vraie classe d'erreur asyncpg vit dans
    `exc.orig.__cause__` (chaînée via `raise ... from ...`), constaté en conditions
    réelles. Ne traite QUE ce cas précis (`asyncpg.exceptions.DataError`, ex: mauvais
    format d'UUID/entier) — toute autre `DBAPIError` (contrainte violée, connexion perdue...)
    est relevée telle quelle, comportement 500 inchangé pour ces cas-là."""
    cause = getattr(exc.orig, "__cause__", None)
    if isinstance(cause, asyncpg.exceptions.DataError):
        return JSONResponse(status_code=404, content={"detail": "Ressource introuvable (identifiant invalide)."})
    raise exc


# Authentification (30/07/2026) : dependencies= posé explicitement sur chaque router
# plutôt qu'un middleware global — reste visible dans app.routes/OpenAPI, cohérent avec
# le style du reste du repo (GRANT explicites, flags STARTUP_* explicites plutôt
# qu'implicites). auth.router n'a volontairement PAS de dependency ici : /login doit
# rester public, /logout /me /change-password se protègent individuellement dans
# routers/auth.py. connections.router non plus : POST /api/connections (journal
# d'accès, ConnectionTracker) doit rester joignable même sans session, y compris depuis
# /login — seul GET y est réservé admin, en per-route dans routers/connections.py.
# security.router : dependencies=_authed en base (badge /events/count visible à tout
# utilisateur connecté), le détail/les actions d'acquittement sont élevés à require_admin
# en per-route dans routers/security.py (fermeture du trou hérité du faux verrou côté
# client d'AdministrationSecurity.jsx, cf. STATUS.md).
_authed = [Depends(require_auth)]
_admin_only = [Depends(require_admin)]

# Droits d'accès par module/page (31/07/2026, cf. models.py::User.allowed_pages,
# services/access_control.py) — require_page(...) remplace _authed sur les routers dont le
# contenu appartient clairement à une ou plusieurs pages précises de la nav. Plusieurs clés =
# router partagé par plusieurs pages (même router, même données) : accès accordé si l'une
# d'elles est autorisée. Restent volontairement en _authed simple (accessibles à tout compte
# connecté quelle que soit sa restriction de modules), CE CHANTIER-CI ne les couvre PAS :
# - assets.router / vulnerabilities.router : lus en cross-référence par de nombreuses AUTRES
#   pages (Dashboard, Incidents, Reports, Watch pour les noms d'actifs/vulns) en plus de leurs
#   pages "propriétaires" (Actifs/Inventaire, Vulnérabilités) — les gater casserait ces pages-là
#   pour un analyste qui n'a pas accès à Inventaire/CyberVuln. Un vrai découpage lecture-référence
#   vs page-propriétaire endpoint par endpoint reste à faire si ce niveau de granularité est
#   nécessaire un jour.
# - analysts/organization-roles/services/windows-app-mappings/security/backup/withsecure/
#   meraki/prtg/glpi/vsphere/connections : registres transverses ou pages Administration (déjà
#   réservée admin), sans page dédiée dans la nav — hors du périmètre de ce contrôle par module.
app.include_router(auth.router,            prefix="/api/auth",            tags=["Authentification"])
app.include_router(users.router,           prefix="/api/users",           tags=["Utilisateurs"], dependencies=_admin_only)
app.include_router(cves.router,            prefix="/api/cves",            tags=["CVE"],                    dependencies=[Depends(require_page("/cves"))])
app.include_router(assets.router,          prefix="/api/assets",          tags=["Actifs"],                 dependencies=_authed)
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities",  tags=["Vulnérabilités"],         dependencies=_authed)
app.include_router(analysis.router,        prefix="/api/analysis",        tags=["Analyse IA"],             dependencies=[Depends(require_page("/dashboard", "/vulnerabilities"))])
app.include_router(reports.router,         prefix="/api/reports",         tags=["Rapports"],               dependencies=[Depends(require_page("/reports", "/rapport-veille", "/rapport-surveillance", "/inventaire"))])
app.include_router(sync.router,            prefix="/api/sync",            tags=["Synchronisation"],        dependencies=[Depends(require_page("/cves", "/dashboard"))])
app.include_router(stats.router,           prefix="/api/stats",           tags=["Statistiques"],           dependencies=[Depends(require_page("/dashboard"))])
app.include_router(remediation.router,     prefix="/api/remediation",     tags=["Correctifs"],             dependencies=[Depends(require_page("/dashboard", "/vulnerabilities"))])
app.include_router(patch_check.router,     prefix="/api/patch-check",     tags=["Vérification patches"])
# Pas de dependency globale ci-dessus (07/08/2026, retiré) : POST /run doit rester
# joignable par le worker Celery sans session utilisateur (cf. auth_deps.py::
# require_page_or_internal) — chaque route de routers/patch_check.py porte donc sa
# propre dependency plutôt qu'un blanket ici, même schéma que routers/auth.py.
app.include_router(connections.router,     prefix="/api/connections",     tags=["Connexions"])
app.include_router(watch.router,           prefix="/api/watch",           tags=["Veille cyber"],           dependencies=[Depends(require_page("/veille", "/fuite-de-donnees"))])
app.include_router(identities.router,      prefix="/api/identities",      tags=["Surveillance Identités"], dependencies=[Depends(require_page("/surveillance-identites"))])
app.include_router(security.router,        prefix="/api/security",        tags=["Déception / Sécurité"],   dependencies=_authed)
app.include_router(backup.router,          prefix="/api/backup",          tags=["Sauvegarde"],             dependencies=_authed)
app.include_router(withsecure.router,      prefix="/api/withsecure",      tags=["WithSecure"],             dependencies=_authed)
app.include_router(meraki.router,          prefix="/api/meraki",          tags=["Meraki"],                 dependencies=_authed)
app.include_router(prtg.router,            prefix="/api/prtg",            tags=["PRTG"],                   dependencies=_authed)
app.include_router(glpi.router,            prefix="/api/glpi",            tags=["GLPI"],                   dependencies=_authed)
app.include_router(vsphere.router,         prefix="/api/vsphere",         tags=["vSphere"],                dependencies=_authed)
app.include_router(incidents.router,       prefix="/api/incidents",       tags=["Incidents"],              dependencies=[Depends(require_page("/incidents", "/crises", "/rapport-incidents"))])
app.include_router(crises.router,          prefix="/api/crises",          tags=["Gestion de crise"],       dependencies=[Depends(require_page("/incidents", "/crises"))])
app.include_router(analysts.router,        prefix="/api/analysts",        tags=["Analystes"],              dependencies=_authed)
app.include_router(organization_roles.router, prefix="/api/organization-roles", tags=["Rôles"],           dependencies=_authed)
app.include_router(services.router,        prefix="/api/services",        tags=["Services"],               dependencies=_authed)
app.include_router(documents.router,       prefix="/api",                 tags=["Documentation"],           dependencies=[Depends(require_page("/documentation"))])
app.include_router(notes.router,           prefix="/api/notes",           tags=["Notes"],                   dependencies=[Depends(require_page("/notes"))])
app.include_router(windows_app_mappings.router, prefix="/api/windows-app-mappings", tags=["Correspondances Windows"], dependencies=_authed)
app.include_router(audits.router,          prefix="/api/audits",          tags=["Audits"],                 dependencies=[Depends(require_page("/audits"))])
# Pas de dependencies au niveau du router (comme auth.router/connections.router) : /enroll
# (jeton, pas de session) et /checkin (require_agent, en-tête X-Agent-Token) ont chacun leur
# propre schéma d'auth, incompatible avec un garde-fou uniforme posé ici — cf. routers/agents.py.
app.include_router(agents.router,          prefix="/api/agents",          tags=["Agents"])
app.include_router(integrations.router,    prefix="/api/integrations",    tags=["Intégrations"],           dependencies=_authed)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
