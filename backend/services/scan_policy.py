"""
services/scan_policy.py
Politiques de scan planifié par criticité (17/08/2026, cf. models.py::ScanPolicy) — un groupe
d'actifs par valeur de `asset.tags.criticite` (critique/haute/moyenne/faible), chacun avec sa
propre fréquence/heure (voir `tasks/scheduled_tasks.py::check_scan_policies` pour le
déclenchement effectif).

⚠️ Ce module tourne TOUJOURS dans le process `backend`, jamais directement depuis un worker
Celery : `apply_scan_result()` (services/asset_scanner.py) déclenche le patch check via
`asyncio.create_task(...)` sur la boucle d'événements de l'appelant — dans un worker, cette
tâche serait exécutée sur la boucle éphémère créée par `asyncio.run()` d'une tâche Celery, et
serait annulée dès la fin de cette tâche (bien avant que le patch check n'ait fini). C'est
exactement le problème déjà résolu pour `patch_checker.py` via l'indirection HTTP +
`X-Internal-Token` (cf. `patch_check_periodic`) — le poller horaire appelle donc
`POST /api/scan-policies/{criticite}/run-now` plutôt que ce module directement, et cette
fonction n'est appelée que depuis `routers/scan_policies.py` (process backend).

Périmètre : uniquement les actifs `collection_method == "service_account"` (scan SSH/WinRM
classique, via `services/asset_scanner.py`) et `asset_type == "website"` (durcissement web,
`services/web_hardening.py`, pilotable par une simple requête HTTP). Les équipements réseau
(Meraki/PRTG) restent 100% manuels (cf. docs/ARCHITECTURE.md § Planning Celery Beat) et les
actifs agent ne sont pas pilotables sur planning (ils poussent leurs données eux-mêmes) — seul
un signal de fraîcheur leur est appliqué côté frontend (Durcissement.jsx).

Exécution séquentielle, pas concurrente — même précédent que `patch_checker.py` ("évite de
partager une AsyncSession entre coroutines concurrentes... prudent vis-à-vis des 80 serveurs
on-premise")."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import SessionLocal
from models import Asset, SyncState
from services.asset_scanner import scan_asset, apply_scan_result
from services.crypto import decrypt_password
from services.web_hardening import run_all_website_checks

logger = logging.getLogger(__name__)

# Verrou anti-chevauchement par criticité (même esprit que _matching_running dans
# cpe_matcher.py) — deux politiques peuvent tomber la même heure (ex. dimanche minuit =
# critique quotidien + reste hebdomadaire), chacune a son propre verrou indépendant.
_running: dict[str, bool] = {}


def is_policy_running(criticite: str) -> bool:
    return _running.get(criticite, False)


async def get_assets_for_criticite(session: AsyncSession, criticite: str) -> list[Asset]:
    """Actifs serveur (collection_method=service_account) dont la criticité effective
    (`tags.criticite`, défaut "moyenne" si absent — même repli que partout ailleurs dans le
    code, ex. scoring.py/cpe_matcher.py) correspond. Filtré en Python plutôt qu'en SQL JSON :
    aucun autre endroit du projet ne filtre `tags` côté base, et le parc (~80 actifs) rend le
    coût négligeable."""
    assets = (await session.execute(
        select(Asset).where(Asset.collection_method == "service_account", Asset.status == "active")
    )).scalars().all()
    return [a for a in assets if (a.tags or {}).get("criticite", "moyenne") == criticite]


async def get_website_ids_for_criticite(session: AsyncSession, criticite: str) -> list[str]:
    assets = (await session.execute(
        select(Asset).where(Asset.asset_type == "website", Asset.status == "active")
    )).scalars().all()
    return [str(a.id) for a in assets if (a.tags or {}).get("criticite", "moyenne") == criticite]


async def _set_last_run(criticite: str, status: str) -> None:
    session = SessionLocal()
    try:
        key = f"scan_policy_{criticite}"
        state = await session.get(SyncState, key)
        if not state:
            state = SyncState(key=key)
            session.add(state)
        state.status = status
        state.last_synced_at = datetime.now(timezone.utc)
        await session.commit()
    finally:
        await session.close()


async def run_scan_for_criticite(criticite: str) -> dict:
    """Scanne séquentiellement tous les actifs serveur du groupe `criticite`, puis lance le
    durcissement web des sites web du même groupe. Reproduit exactement l'enchaînement de
    l'endpoint manuel `POST /assets/{id}/scan` (scan_asset -> apply_scan_result, qui déclenche
    lui-même le matching CPE et le patch check pour l'actif — cf. routers/assets.py)."""
    if _running.get(criticite):
        return {"status": "already_running"}
    _running[criticite] = True
    await _set_last_run(criticite, "running")
    scanned, failed = 0, 0
    try:
        session = SessionLocal()
        try:
            assets = await get_assets_for_criticite(session, criticite)
            website_ids = await get_website_ids_for_criticite(session, criticite)
            logger.info(
                "Politique de scan '%s' : %d actif(s) serveur, %d site(s) web",
                criticite, len(assets), len(website_ids),
            )
            for asset in assets:
                try:
                    password = decrypt_password(asset.scan_password_encrypted) if asset.scan_password_encrypted else None
                    result = await scan_asset(asset, username=asset.scan_username, password=password)
                    await apply_scan_result(asset, result, session)
                    if result.get("reachable"):
                        scanned += 1
                    else:
                        failed += 1
                except Exception:
                    logger.exception("Politique de scan '%s' : échec sur l'actif %s", criticite, asset.id)
                    failed += 1
        finally:
            await session.close()

        if website_ids:
            await run_all_website_checks(asset_ids=website_ids)

        await _set_last_run(criticite, "completed")
        return {"status": "done", "scanned": scanned, "failed": failed, "websites": len(website_ids)}
    except Exception:
        logger.exception("Politique de scan '%s' : échec du cycle", criticite)
        await _set_last_run(criticite, "error")
        raise
    finally:
        _running[criticite] = False
