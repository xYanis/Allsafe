"""
services/prtg_matcher.py
Associe les devices PRTG aux actifs CBR existants (par host/hostname/nom), puis met à
jour `NetworkStatus` (état en ligne/hors ligne + métriques). Même schéma que
services/meraki_matcher.py, y compris `import_new_assets` (04/08/2026, décision revue
en cours de session après un premier essai en base — 410 devices PRTG interrogés,
seuls 67 déjà connus de CBR par hostname, les 343 autres — routeurs de sites, bornes
Wi-Fi... — restaient invisibles) : crée un `Asset` (`asset_type="network"`,
`source="prtg"`) pour chaque device sans correspondance, sur demande explicite,
jamais par défaut. Un seul cas exclu structurellement (pas une liste codée en dur de
noms) : device sans `host` ni IP exploitable (objet interne PRTG lui-même, ex.
« Serveur central PRTG ») ou en loopback (127.0.0.1, la sonde PRTG elle-même) — ce
ne sont pas des équipements du réseau surveillé.

`NetworkStatus.metrics.status_since` (07/08/2026) : date de la dernière bascule
En ligne/Hors ligne côté PRTG — pas une transition détectée par CBR lui-même
(PRTG poll en continu, CBR ne sync que sur demande/planification, donc une
transition calculée côté CBR daterait du dernier sync plutôt que de la bascule
réelle). Vient du capteur de joignabilité du device (Ping en priorité, repli
SNMP/WMI uptime — cf. prtg_client.CONNECTIVITY_SENSOR_TYPE_PRIORITY),
`content=devices` ne portant pas `lastup_raw`/`lastdown_raw` (vérifié en
conditions réelles). None pour un statut `dormant` ou un device sans capteur de
joignabilité reconnu.
"""

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import SessionLocal
from models import Asset, NetworkStatus, SyncState
from services import prtg_client

logger = logging.getLogger(__name__)

SOURCE = "prtg"

# Codes numériques PRTG (colonne "status_raw", documentation API PRTG) → vocabulaire
# partagé de network_status (online/offline/alerting/dormant, cf.
# models.py::NetworkStatus). Le code numérique est utilisé plutôt que le libellé
# texte ("status") : constaté en conditions réelles (04/08/2026) que ce dernier est
# renvoyé **localisé selon la langue de l'interface PRTG** ("OK" au lieu de "Up",
# "En pause (...)" au lieu de "Paused" sur ce serveur configuré en français) — le
# faire correspondre à un texte anglais codé en dur aurait silencieusement classé
# tous les devices "up" comme "dormant" par défaut. Tous les "Paused*"/"No Probe"
# rejoignent "dormant" (même esprit que "Veille" côté badge : surveillance
# volontairement suspendue ou infra de sonde en cause, pas un incident sur le
# device lui-même). Code non reconnu → "dormant" aussi, jamais "En ligne"/"Hors
# ligne" pour un état PRTG non confirmé.
STATUS_RAW_MAP = {
    1: "dormant",   # Unknown
    2: "dormant",   # Scanning / collecte en cours
    3: "online",    # Up
    4: "alerting",  # Warning
    5: "offline",   # Down
    6: "dormant",   # No Probe
    7: "dormant",   # Paused by User
    8: "dormant",   # Paused by Dependency
    9: "dormant",   # Paused by Schedule
    10: "alerting", # Unusual
    11: "dormant",  # Not Licensed
    12: "dormant",  # Paused Until
    13: "offline",  # Down (Acknowledged)
    14: "offline",  # Down (Partial)
}


def _normalize_status(raw: Optional[int]) -> str:
    try:
        return STATUS_RAW_MAP.get(int(raw), "dormant")
    except (TypeError, ValueError):
        return "dormant"


def _normalize_hostname(raw: Optional[str]) -> Optional[str]:
    """'SRV-PROD-01.aer.loc' / 'srv-prod-01' → 'srv-prod-01' — même normalisation que
    meraki_matcher.py (nom court, insensible à la casse)."""
    if not raw:
        return None
    return raw.strip().split(".")[0].lower() or None


def _is_ip(raw: Optional[str]) -> bool:
    if not raw:
        return False
    try:
        ipaddress.ip_address(raw.strip())
        return True
    except ValueError:
        return False


async def match_devices_to_assets(
    devices: list[dict], db: AsyncSession
) -> tuple[dict[int, Asset], list[dict]]:
    """Retourne {objid: Asset} pour les devices matchés, essayés dans cet ordre :
    `host` PRTG contre `Asset.ip_address` (si host est une IP) ou `Asset.hostname`
    normalisé (sinon) ; à défaut `device` (nom d'affichage) contre `Asset.hostname`
    puis `Asset.name` normalisés. Et la liste des devices sans actif CBR correspondant."""
    assets = (await db.execute(select(Asset).where(Asset.status == "active"))).scalars().all()
    assets_by_hostname = {h: a for a in assets if (h := _normalize_hostname(a.hostname))}
    assets_by_name = {h: a for a in assets if (h := _normalize_hostname(a.name))}
    assets_by_ip = {a.ip_address: a for a in assets if a.ip_address}

    matched: dict[int, Asset] = {}
    unmatched: list[dict] = []
    for device in devices:
        objid = device.get("objid")
        if objid is None:
            continue

        host = (device.get("host") or "").strip()
        asset = None
        if host:
            asset = assets_by_ip.get(host) if _is_ip(host) else assets_by_hostname.get(_normalize_hostname(host))

        if asset is None:
            candidate = _normalize_hostname(device.get("device"))
            asset = assets_by_hostname.get(candidate) or assets_by_name.get(candidate)

        if asset is not None:
            matched[objid] = asset
        else:
            unmatched.append({"objid": objid, "device": device.get("device"), "host": host})

    return matched, unmatched


def _asset_from_prtg_device(device: dict, vendor_hint: Optional[str] = None) -> Asset:
    """Construit un nouvel Asset à partir d'un device PRTG sans correspondance.
    `hostname` laissé vide (même raison que meraki_matcher.py : pas de garantie de
    DNS résolvable pour un équipement réseau, et la colonne est UNIQUE côté Asset) —
    le rapprochement d'un futur cycle se fera par `name`/`ip_address`.
    `hardware` réutilise le même champ JSON que l'inventaire matériel des serveurs
    (cf. Asset.hardware, module Inventaire) avec des clés propres à PRTG plutôt que
    cpu/ram/disks, qui n'ont pas de sens ici. `vendor_hint` (cf.
    prtg_client.get_sensor_vendor_hints) alimente la Veille technologique, absent
    pour la grande majorité des devices (aucune donnée vendor exploitable côté PRTG
    en dehors de quelques types de capteurs connus). `prtg_icon` (17/08/2026) :
    nom de fichier de l'icône PRTG du device (cf. prtg_client.py::DEVICE_COLUMNS) —
    catégorie affichée plus précise que le générique "Équipement réseau" côté
    frontend (utils/assetCategory.js), sans jamais renommer/reclasser l'actif lui-même."""
    host = (device.get("host") or "").strip()
    return Asset(
        name=device.get("device") or host or f"PRTG-{device['objid']}",
        hostname=None,
        ip_address=host if _is_ip(host) else None,
        asset_type="network",
        tags={"criticite": "moyenne"},
        source="prtg",
        status="active",
        hardware={
            "prtg_objid": device.get("objid"),
            "prtg_host": host or None,
            "prtg_group": device.get("group"),
            "prtg_probe": device.get("probe"),
            "vendor_hint": vendor_hint,
            "prtg_icon": device.get("icon"),
        },
    )


def _is_prtg_internal(device: dict) -> bool:
    """Objets internes à la plateforme PRTG elle-même (sonde, serveur central) —
    jamais des équipements du réseau surveillé. Exclusion structurelle (host vide ou
    loopback), pas une liste de noms codée en dur : générique quelle que soit
    l'installation PRTG."""
    host = (device.get("host") or "").strip()
    if not host:
        return True
    return _is_ip(host) and ipaddress.ip_address(host) == ipaddress.ip_address("127.0.0.1")


async def sync_network_status(db: Optional[AsyncSession] = None, import_new_assets: bool = False) -> dict:
    """Point d'entrée principal : devices PRTG → actifs CBR → NetworkStatus. Lecture
    seule côté PRTG, écriture uniquement dans la base CBR.

    `import_new_assets` : cf. docstring du module — crée un Asset pour chaque device
    sans correspondance existante (hors objets internes PRTG, cf. _is_prtg_internal)
    au lieu de le laisser dans `unmatched_devices`."""
    if not prtg_client.is_configured():
        return {"error": "prtg_not_configured"}

    own_session = db is None
    if own_session:
        db = SessionLocal()

    stats = {
        "devices_total": 0,
        "matched_assets": 0,
        "assets_created": 0,
        "unmatched_devices": [],
        "updated": 0,
    }

    try:
        devices = await prtg_client.get_device_statuses()
        stats["devices_total"] = len(devices)

        # Un seul fetch content=sensors, deux dérivations (cf. prtg_client.py) :
        # - vendor_hints : utilisé uniquement pour enrichir les actifs créés PAR ce
        #   module (source="prtg") — jamais pour écraser le hardware d'un actif
        #   AD/SSH matché (cpu/ram/disks réels du scan, sans rapport). Alimente la
        #   Veille technologique, catégorie "Matériel / Constructeurs".
        # - ssl_certificates : écrit dans NetworkStatus.metrics pour TOUT actif
        #   matché quelle que soit sa source (donnée PRTG pure, jamais le hardware
        #   d'un actif — aucun risque d'écraser une donnée d'un autre scan).
        sensors = await prtg_client.get_sensors()
        vendor_hints = prtg_client.vendor_hints_from_sensors(sensors)
        ssl_certificates = prtg_client.ssl_certificates_from_sensors(sensors)
        connectivity_timestamps = prtg_client.connectivity_timestamps_from_sensors(sensors)

        matched, unmatched = await match_devices_to_assets(devices, db)
        devices_by_objid = {d["objid"]: d for d in devices if d.get("objid") is not None}

        if import_new_assets and unmatched:
            still_unmatched = []
            for info in unmatched:
                device = devices_by_objid[info["objid"]]
                if _is_prtg_internal(device):
                    still_unmatched.append(info)
                    continue
                new_asset = _asset_from_prtg_device(device, vendor_hints.get(info["objid"]))
                db.add(new_asset)
                await db.flush()  # obtenir new_asset.id avant d'écrire son NetworkStatus
                matched[info["objid"]] = new_asset
                stats["assets_created"] += 1
            unmatched = still_unmatched

        stats["matched_assets"] = len(matched)
        stats["unmatched_devices"] = unmatched

        now = datetime.now(timezone.utc)

        for objid, asset in matched.items():
            device = devices_by_objid[objid]

            # Rafraîchit le vendor hint sur les cycles suivants (un capteur peut être
            # ajouté côté PRTG après la création initiale de l'actif) — uniquement
            # pour les actifs créés par ce module : jamais le hardware d'un actif
            # AD/SSH matché par hostname (cpu/ram/disks réels, sans rapport).
            if asset.source == "prtg":
                vendor = vendor_hints.get(objid)
                if vendor and (asset.hardware or {}).get("vendor_hint") != vendor:
                    asset.hardware = {**(asset.hardware or {}), "vendor_hint": vendor}
                # prtg_icon (17/08/2026) : peut changer côté PRTG (device réassigné à une
                # autre icône) — même raisonnement de rafraîchissement que vendor_hint ci-dessus.
                icon = device.get("icon")
                if icon and (asset.hardware or {}).get("prtg_icon") != icon:
                    asset.hardware = {**(asset.hardware or {}), "prtg_icon": icon}

            row = (await db.execute(
                select(NetworkStatus).where(
                    NetworkStatus.asset_id == asset.id, NetworkStatus.source == SOURCE
                )
            )).scalar_one_or_none()
            if row is None:
                row = NetworkStatus(asset_id=asset.id, source=SOURCE)
                db.add(row)

            status = _normalize_status(device.get("status_raw"))
            # "Depuis quand" : lastup_raw pour un device en ligne, lastdown_raw pour
            # hors ligne/alerte (la dernière bascule Down couvre aussi "Warning", cf.
            # STATUS_RAW_MAP — le device est descendu avant de remonter en alerte).
            # `dormant` (Paused/Unknown/No Probe) laissé à None : la surveillance est
            # suspendue ou incertaine, "depuis quand" n'a pas de sens fiable dans ce cas.
            # Vient du capteur de joignabilité (Ping/uptime, cf.
            # connectivity_timestamps_from_sensors) — `content=devices` ne porte pas
            # ces colonnes (constaté en conditions réelles 07/08/2026). Absent du
            # dict si le device n'a aucun capteur de ce type.
            status_since = None
            timestamps = connectivity_timestamps.get(objid)
            if timestamps:
                if status == "online":
                    status_since = prtg_client.parse_prtg_date(timestamps.get("lastup_raw"))
                elif status in ("offline", "alerting"):
                    status_since = prtg_client.parse_prtg_date(timestamps.get("lastdown_raw"))

            row.status = status
            row.last_reported_at = now
            # Champ libre pour scaler vers d'autres métriques plus tard (bande passante,
            # CPU...) déjà annoncé par l'utilisateur — cf. models.py::NetworkStatus.
            # "raw_status"/"raw_status_code" gardés à titre informatif (le libellé texte
            # est localisé, cf. STATUS_RAW_MAP ci-dessus — pas la source de la normalisation).
            row.metrics = {
                "objid": objid,
                "group": device.get("group"),
                "probe": device.get("probe"),
                "raw_status": device.get("status"),
                "raw_status_code": device.get("status_raw"),
                "status_since": status_since.isoformat() if status_since else None,
                **({"ssl_certificates": certs} if (certs := ssl_certificates.get(objid)) else {}),
            }
            row.updated_at = now
            stats["updated"] += 1

        state = await db.get(SyncState, "prtg_network_status")
        if state is None:
            state = SyncState(key="prtg_network_status")
            db.add(state)
        state.last_synced_at = now

        await db.commit()
        logger.info(
            "PRTG sync : %d devices, %d actifs matchés, %d NetworkStatus mis à jour",
            stats["devices_total"], stats["matched_assets"], stats["updated"],
        )

    except Exception:
        await db.rollback()
        raise
    finally:
        if own_session:
            await db.close()

    return stats
