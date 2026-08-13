"""
routers/vsphere.py
Déclenchement manuel + statut de la synchronisation vSphere/ESXi (inventaire hôtes + CPE
pour le matching CVE hyperviseur, cf. services/vsphere_matcher.py). Même schéma que
routers/meraki.py.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from models import SyncState
from services.vsphere_matcher import SYNC_STATE_KEY, sync_esxi_hosts

router = APIRouter()


@router.post("/run")
async def trigger_vsphere_sync(import_new_assets: bool = False):
    """
    Hôtes ESXi vus par vCenter → actifs Allsafe → CPE (cpe:2.3:o:vmware:esxi:{version}) →
    matching CVE. N'écrit jamais côté vCenter/ESXi (lecture seule). Retourne
    "vsphere_not_configured" si VCENTER_URL/USER/PASSWORD sont absents de .env.

    `import_new_assets` : crée un Asset (`asset_type="server"`, `source="vsphere"`,
    `collection_method="vsphere_api"`) pour chaque hôte sans correspondance déjà dans
    Allsafe, au lieu de le laisser invisible. Défaut `False` — même précédent que
    Meraki/PRTG.
    """
    return await sync_esxi_hosts(import_new_assets=import_new_assets)


@router.get("/status")
async def vsphere_sync_status(session: AsyncSession = Depends(get_session)):
    """Date de la dernière synchronisation vSphere — même mécanisme que GET /api/meraki/status."""
    state = await session.get(SyncState, SYNC_STATE_KEY)
    return {"last_synced_at": state.last_synced_at.isoformat() if state and state.last_synced_at else None}
