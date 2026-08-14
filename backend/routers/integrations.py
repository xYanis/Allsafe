"""
routers/integrations.py
Statut agrégé des intégrations externes (14/08/2026, demande utilisateur) — configuré/non
configuré (présence de la config, JAMAIS la valeur du secret) + dernière synchro connue,
pour la page Settings > Intégrations. Lit directement `sync_state` plutôt que de rappeler
chaque routers/<service>.py::status (withsecure/meraki/prtg/glpi/vsphere ont chacun déjà
leur propre GET /status sur la même table) — un seul appel réseau côté frontend plutôt que
cinq, pour un simple tableau récapitulatif au chargement de la page.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_auth
from config import settings
from database import get_session
from models import SyncState, User

router = APIRouter()


def _iso(dt):
    return dt.isoformat() if dt else None


@router.get("/status")
async def integrations_status(user: User = Depends(require_auth), session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(select(SyncState))).scalars().all()
    last_synced = {r.key: r.last_synced_at for r in rows}

    items = [
        {"key": "nvd", "label": "NVD (CVE)",
         "configured": bool(settings.NVD_API_KEY),
         "last_synced_at": _iso(last_synced.get("nvd"))},
        {"key": "github", "label": "GitHub (recherche domaine)",
         "configured": bool(settings.GITHUB_TOKEN),
         "last_synced_at": None},
        {"key": "ad", "label": "Active Directory",
         "configured": bool(settings.AD_SERVER),
         "last_synced_at": None},
        {"key": "ssh", "label": "SSH (postes Linux)",
         "configured": bool(settings.LINUX_HOSTS),
         "last_synced_at": None},
        {"key": "withsecure", "label": "WithSecure Elements",
         "configured": bool(settings.WITHSECURE_API_CLIENT_ID and settings.WITHSECURE_API_CLIENT_SECRET),
         "last_synced_at": _iso(last_synced.get("withsecure_missing_updates"))},
        {"key": "meraki", "label": "Meraki Dashboard",
         "configured": bool(settings.MERAKI_API_KEY),
         "last_synced_at": _iso(last_synced.get("meraki_network_status"))},
        {"key": "prtg", "label": "PRTG Network Monitor",
         "configured": bool(settings.PRTG_URL and settings.PRTG_API_TOKEN),
         "last_synced_at": _iso(last_synced.get("prtg_network_status"))},
        {"key": "glpi", "label": "GLPI (CMDB)",
         "configured": bool(settings.GLPI_URL and settings.GLPI_APP_TOKEN and settings.GLPI_USER_TOKEN),
         "last_synced_at": _iso(last_synced.get("glpi_inventory"))},
        {"key": "vsphere", "label": "vSphere / ESXi",
         "configured": bool(settings.VCENTER_URL),
         "last_synced_at": _iso(last_synced.get("vsphere_esxi"))},
    ]
    return {"items": items}
