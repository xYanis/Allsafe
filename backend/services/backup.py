"""
services/backup.py
Sauvegarde PostgreSQL — pg_dump vers un volume dédié, rétention automatique.

N'affecte jamais la base elle-même (pg_dump est lecture seule côté serveur).
Connexion directe au service `db` via le réseau Docker (pas de session
SQLAlchemy applicative) — indépendant du rôle `cbr_app` à privilèges réduits :
on sauvegarde avec le superuser `cybervuln`, seul à voir tous les objets
(y compris les vues/rôles de déception, cf. `backend/db/legacy_views.sql`).
"""

import logging
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import settings

logger = logging.getLogger(__name__)

BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", "/app/backups"))
RETENTION_DAYS = int(os.environ.get("BACKUP_RETENTION_DAYS", "14"))


def _run_pg_dump() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dump_path = BACKUP_DIR / f"cybervuln-{stamp}.dump"

    env = os.environ.copy()
    env["PGPASSWORD"] = settings.DB_PASSWORD
    cmd = [
        "pg_dump",
        "-h", settings.DB_HOST,
        "-U", settings.DB_USER,
        "-d", settings.DB_NAME,
        "-Fc",              # format "custom" : compressé, restauration sélective (pg_restore -l / --table=)
        "-f", str(dump_path),
    ]
    result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        # Ne jamais laisser un dump tronqué/corrompu passer pour une sauvegarde
        # valide — un fichier partiel serait pire qu'une absence de fichier
        # (fausse confiance au moment où on en aurait justement besoin).
        dump_path.unlink(missing_ok=True)
        raise RuntimeError(f"pg_dump a échoué (code {result.returncode}) : {result.stderr.strip()}")
    return dump_path


def _prune_old_backups() -> list[str]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    removed = []
    for f in sorted(BACKUP_DIR.glob("cybervuln-*.dump")):
        mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
        if mtime < cutoff:
            f.unlink()
            removed.append(f.name)
    return removed


def run_backup() -> dict:
    """
    Sauvegarde complète (schéma + données) au format pg_dump "custom" (`-Fc`).
    La purge des sauvegardes de plus de `RETENTION_DAYS` jours n'a lieu
    qu'après un dump réussi — un échec ne doit jamais faire disparaître la
    dernière sauvegarde valide.
    """
    dump_path = _run_pg_dump()
    size_mb = round(dump_path.stat().st_size / (1024 * 1024), 2)
    removed = _prune_old_backups()
    logger.info("Sauvegarde DB terminée : %s (%.2f Mo)", dump_path.name, size_mb)
    if removed:
        logger.info("Sauvegardes expirées supprimées (> %d j) : %s", RETENTION_DAYS, removed)
    return {"file": dump_path.name, "size_mb": size_mb, "removed": removed}


def list_backups() -> list[dict]:
    """Liste les sauvegardes présentes sur le volume, la plus récente d'abord."""
    if not BACKUP_DIR.exists():
        return []
    items = []
    for f in BACKUP_DIR.glob("cybervuln-*.dump"):
        stat = f.stat()
        items.append({
            "file": f.name,
            "size_mb": round(stat.st_size / (1024 * 1024), 2),
            "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        })
    return sorted(items, key=lambda x: x["created_at"], reverse=True)
