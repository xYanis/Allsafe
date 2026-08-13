"""
services/vsphere_matcher.py
Associe les hôtes ESXi vus par vCenter aux actifs Allsafe existants (par hostname/nom), crée
un Asset pour un hôte non reconnu si demandé, et pose le CPE vSphere/ESXi pour que le matching
CVE (services/cpe_matcher.py) le prenne en compte comme n'importe quel autre actif.

Même schéma que services/meraki_matcher.py (match-or-create, `import_new_assets` défaut
False) — seule différence structurelle : Meraki/PRTG alimentent `NetworkStatus` (en ligne/
hors ligne), cette intégration alimente `Asset.cpe_list` (CVE hyperviseur) — pas de table
NetworkStatus pour une intégration serveur, cohérent avec le fait qu'un hôte ESXi devient un
Asset `asset_type="server"` comme n'importe quel serveur scanné.

L'inventaire VM par hôte (`hardware.esxi_vms`) reste purement informatif — aucune VM n'est
créée comme Asset et aucun rapprochement hostname VM↔Asset n'est tenté dans cette passe
(extension naturelle mais hors scope, cf. docs/ARCHITECTURE.md).

Durcissement (13/08/2026, cf. services/vsphere_hardening.py) : chaque sync pose aussi
`Asset.last_scan_result.compliance.checks` à partir des faits bruts collectés via l'API
vSphere (jamais de SSH sur l'hôte) — même champ que le durcissement CIS-like des serveurs
scannés classiquement, aucun changement frontend nécessaire (Durcissement.jsx route déjà
tout actif non-network vers ce champ).
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import SessionLocal
from models import Asset, SyncState
from services import vsphere_client
from services.vsphere_hardening import build_checks as build_hardening_checks
from services.asset_importer import _build_cpe
from tasks.scheduled_tasks import run_cpe_matching_for_asset_task

logger = logging.getLogger(__name__)

SYNC_STATE_KEY = "vsphere_esxi"


def _normalize_hostname(raw: Optional[str]) -> Optional[str]:
    """Même normalisation que meraki_matcher.py/withsecure_matcher.py (nom court,
    insensible à la casse)."""
    if not raw:
        return None
    return raw.strip().split(".")[0].lower() or None


async def match_hosts_to_assets(hosts: list[dict], db: AsyncSession) -> tuple[dict[str, Asset], list[dict]]:
    """Retourne {host["name"]: Asset} pour les hôtes matchés par hostname/nom normalisé
    (essayés dans cet ordre : Asset.hostname puis Asset.name), et la liste des hôtes sans
    actif Allsafe correspondant."""
    assets = (await db.execute(select(Asset).where(Asset.status == "active"))).scalars().all()
    assets_by_hostname = {h: a for a in assets if (h := _normalize_hostname(a.hostname))}
    assets_by_name = {h: a for a in assets if (h := _normalize_hostname(a.name))}

    matched: dict[str, Asset] = {}
    unmatched: list[dict] = []
    for host in hosts:
        name = host.get("name")
        if not name:
            continue
        candidate = _normalize_hostname(name)
        asset = assets_by_hostname.get(candidate) or assets_by_name.get(candidate)
        if asset is not None:
            matched[name] = asset
        else:
            unmatched.append(host)

    return matched, unmatched


def _hardware_patch(host: dict) -> dict:
    return {
        "vendor": host.get("vendor"),
        "model": host.get("model"),
        "uuid": host.get("uuid"),
        "cpu_model": host.get("cpu_model"),
        "cpu_cores": host.get("cpu_cores"),
        "ram_gb": host.get("ram_gb"),
        "esxi_build": host.get("build"),
        "esxi_vms": host.get("vms") or [],
    }


def _asset_from_vsphere_host(host: dict) -> Asset:
    """Construit un nouvel Asset à partir d'un hôte ESXi non reconnu. `hostname` laissé vide
    (même raison que Meraki/PRTG : colonne UNIQUE, `host["name"]` côté vCenter n'est pas
    garanti être un FQDN résolvable) — le rapprochement d'un futur cycle se fera par `name`."""
    return Asset(
        name=host["name"],
        hostname=None,
        ip_address=host.get("management_ip"),
        os="VMware ESXi",
        os_version=host.get("version"),
        asset_type="server",
        tags={"criticite": "moyenne"},
        source="vsphere",
        collection_method="vsphere_api",
        status="active",
        hardware=_hardware_patch(host),
    )


async def sync_esxi_hosts(db: Optional[AsyncSession] = None, import_new_assets: bool = False) -> dict:
    """Point d'entrée principal : hôtes vus par vCenter → actifs Allsafe → CPE → matching CVE.
    Lecture seule côté vCenter, écriture uniquement dans la base Allsafe.

    `import_new_assets` : crée un Asset pour chaque hôte sans correspondance existante au lieu
    de le laisser dans `unmatched_hosts` — défaut False, un cycle ne doit jamais créer d'actif
    silencieusement (même précédent que Meraki/PRTG)."""
    if not vsphere_client.is_configured():
        return {"error": "vsphere_not_configured"}

    own_session = db is None
    if own_session:
        db = SessionLocal()

    stats = {
        "hosts_total": 0,
        "matched_assets": 0,
        "assets_created": 0,
        "unmatched_hosts": [],
        "updated": 0,
        "vms_total": 0,
    }

    try:
        hosts = await asyncio.get_event_loop().run_in_executor(None, vsphere_client.get_hosts)
        stats["hosts_total"] = len(hosts)
        stats["vms_total"] = sum(len(h.get("vms") or []) for h in hosts)

        matched, unmatched = await match_hosts_to_assets(hosts, db)
        hosts_by_name = {h["name"]: h for h in hosts if h.get("name")}

        if import_new_assets and unmatched:
            for host in unmatched:
                new_asset = _asset_from_vsphere_host(host)
                db.add(new_asset)
                await db.flush()  # obtenir new_asset.id avant de le référencer plus bas
                matched[host["name"]] = new_asset
                stats["assets_created"] += 1
            unmatched = []

        stats["matched_assets"] = len(matched)
        stats["unmatched_hosts"] = [{"name": h.get("name"), "version": h.get("version")} for h in unmatched]

        now = datetime.now(timezone.utc)
        touched_ids: list[str] = []
        for name, asset in matched.items():
            host = hosts_by_name[name]
            asset.hardware = _hardware_patch(host)
            if host.get("version"):
                asset.os_version = host["version"]
            cpe = _build_cpe("esxi", host.get("version") or "")
            if cpe:
                asset.cpe_list = [cpe]
            # Durcissement (13/08/2026, cf. services/vsphere_hardening.py) : écrase
            # last_scan_result en entier plutôt que de fusionner — contrairement aux switches
            # (network_compliance, deux producteurs possibles : PRTG/Meraki ET ce module), un
            # hôte ESXi n'a qu'un seul producteur de last_scan_result (cette sync ; le scan
            # SSH/WinRM classique est bloqué dessus par le garde-fou de scan_asset_endpoint).
            asset.last_scan_result = {"compliance": {"checks": build_hardening_checks(host.get("hardening") or {})}}
            asset.last_scan = now
            touched_ids.append(str(asset.id))
            stats["updated"] += 1
        state = await db.get(SyncState, SYNC_STATE_KEY)
        if state is None:
            state = SyncState(key=SYNC_STATE_KEY)
            db.add(state)
        state.last_synced_at = now

        await db.commit()
        logger.info(
            "vSphere sync : %d hôtes, %d actifs matchés, %d VM recensées",
            stats["hosts_total"], stats["matched_assets"], stats["vms_total"],
        )

        # Après commit seulement (les CVE matchées côté worker relisent l'actif tel que
        # persisté) — même ordre que asset_scanner.py::apply_scan_result.
        for asset_id in touched_ids:
            run_cpe_matching_for_asset_task.apply_async(args=[asset_id], queue='default')

    except Exception:
        await db.rollback()
        raise
    finally:
        if own_session:
            await db.close()

    return stats
