"""
routers/backup.py
Sauvegarde PostgreSQL — déclenchement manuel et consultation, la sauvegarde
planifiée elle-même tourne côté worker Celery (cf. tasks/scheduled_tasks.py).

Le déclenchement manuel passe par Celery (`.apply_async`) plutôt que d'exécuter
pg_dump directement dans le process `backend` : le client `postgresql-client-16`
et le volume de sauvegarde sont montés sur `backend` et `worker`, mais
l'exécution reste toujours sur le worker pour ne jamais bloquer l'API le temps
du dump (même raisonnement que le matching CPE, cf. STATUS.md 27/07/2026).
"""

from fastapi import APIRouter

from services.backup import list_backups

router = APIRouter()


@router.get("/list")
async def get_backups():
    """Liste les sauvegardes présentes sur le volume, la plus récente d'abord."""
    return {"backups": list_backups()}


@router.post("/run")
async def trigger_backup():
    """
    Déclenche une sauvegarde immédiate (pg_dump) sur le worker Celery. Suivre
    la progression via GET /api/sync/status/{task_id} (cf. routers/sync.py).
    """
    from tasks.scheduled_tasks import backup_database
    task = backup_database.apply_async(queue="default")
    return {"task_id": task.id}
