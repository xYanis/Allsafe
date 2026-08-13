"""
services/meraki_matcher.py
Associe les équipements Meraki aux actifs CBR existants (par hostname/nom), puis met à
jour `NetworkStatus` (état en ligne/hors ligne + métriques).

Constaté en conditions réelles (04/08/2026) : l'API Meraki liste des équipements réseau
purs (bornes Wi-Fi/pare-feux MR/MX, noms de sites type "AP_Senonches_...") qui n'ont
**aucun** équivalent dans le parc CBR actuel (serveurs Windows/Debian) — un rapprochement
par hostname/nom ne trouve donc rien tant qu'aucun de ces équipements n'est aussi suivi
comme `Asset`. Contrairement à `services/withsecure_matcher.py` (qui enrichit des
serveurs déjà importés via AD/SSH, jamais de création), `import_new_assets=True`
(demande explicite de l'utilisateur, pour voir le badge réseau en conditions réelles)
crée un `Asset` pour chaque équipement non reconnu — `asset_type="network"`,
`source="meraki"`. Défaut `False` : un cycle planifié ne doit jamais se mettre à créer
des actifs silencieusement sans qu'on le lui demande explicitement à chaque fois.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import SessionLocal
from models import Asset, NetworkStatus, SyncState
from services import meraki_client

logger = logging.getLogger(__name__)


def _normalize_hostname(raw: Optional[str]) -> Optional[str]:
    """'SWITCH-01.aer.loc' / 'switch-01' → 'switch-01' — même normalisation que
    withsecure_matcher.py (nom court, insensible à la casse)."""
    if not raw:
        return None
    return raw.strip().split(".")[0].lower() or None


def _parse_meraki_datetime(raw: Optional[str]):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


async def match_devices_to_assets(
    devices: list[dict], db: AsyncSession
) -> tuple[dict[str, Asset], list[dict]]:
    """Retourne {serial: Asset} pour les équipements matchés par hostname/nom normalisé
    (essayés dans cet ordre : `Asset.hostname` puis `Asset.name`), et la liste des
    équipements sans actif CBR correspondant."""
    assets = (await db.execute(select(Asset).where(Asset.status == "active"))).scalars().all()
    assets_by_hostname = {h: a for a in assets if (h := _normalize_hostname(a.hostname))}
    assets_by_name = {h: a for a in assets if (h := _normalize_hostname(a.name))}

    matched: dict[str, Asset] = {}
    unmatched: list[dict] = []
    for device in devices:
        serial = device.get("serial")
        if not serial:
            continue
        candidate = _normalize_hostname(device.get("name"))
        asset = assets_by_hostname.get(candidate) or assets_by_name.get(candidate)
        if asset is not None:
            matched[serial] = asset
        else:
            unmatched.append({"serial": serial, "name": device.get("name"), "model": device.get("model")})

    return matched, unmatched


def _asset_from_meraki_device(device: dict) -> Asset:
    """Construit un nouvel Asset à partir d'un équipement Meraki non reconnu. `hostname`
    laissé vide (pas de DNS pour un boîtier réseau, et la colonne est UNIQUE côté Asset) —
    le rapprochement d'un futur cycle se fera par `name` (cf. match_devices_to_assets).
    `hardware` réutilise le même champ JSON que l'inventaire matériel des serveurs
    (cf. Asset.hardware, module Inventaire) avec des clés propres au réseau plutôt que
    cpu/ram/disks, qui n'ont pas de sens ici."""
    return Asset(
        name=device.get("name") or device["serial"],
        hostname=None,
        ip_address=device.get("lanIp") or device.get("publicIp"),
        os=device.get("model"),
        asset_type="network",
        tags={"criticite": "moyenne"},
        source="meraki",
        status="active",
        hardware={
            "mac": device.get("mac"),
            "product_type": device.get("productType"),
            "network_id": device.get("networkId"),
            "meraki_tags": device.get("tags") or [],
        },
    )


async def sync_network_status(db: Optional[AsyncSession] = None, import_new_assets: bool = False) -> dict:
    """Point d'entrée principal : équipements Meraki → actifs CBR → NetworkStatus.
    Lecture seule côté Meraki, écriture uniquement dans la base CBR.

    `import_new_assets` : cf. docstring du module — crée un Asset pour chaque
    équipement sans correspondance existante au lieu de le laisser dans
    `unmatched_devices`."""
    if not meraki_client.is_configured():
        return {"error": "meraki_not_configured"}

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
        devices = await meraki_client.get_device_statuses()
        stats["devices_total"] = len(devices)

        matched, unmatched = await match_devices_to_assets(devices, db)
        devices_by_serial = {d["serial"]: d for d in devices if d.get("serial")}

        if import_new_assets and unmatched:
            for info in unmatched:
                new_asset = _asset_from_meraki_device(devices_by_serial[info["serial"]])
                db.add(new_asset)
                await db.flush()  # obtenir new_asset.id avant d'écrire son NetworkStatus
                matched[info["serial"]] = new_asset
                stats["assets_created"] += 1
            unmatched = []

        stats["matched_assets"] = len(matched)
        stats["unmatched_devices"] = unmatched

        now = datetime.now(timezone.utc)

        for serial, asset in matched.items():
            device = devices_by_serial[serial]
            row = (await db.execute(
                select(NetworkStatus).where(
                    NetworkStatus.asset_id == asset.id, NetworkStatus.source == "meraki"
                )
            )).scalar_one_or_none()
            if row is None:
                row = NetworkStatus(asset_id=asset.id, source="meraki")
                db.add(row)

            row.status = device.get("status")
            row.last_reported_at = _parse_meraki_datetime(device.get("lastReportedAt"))
            # Champ libre pour scaler vers d'autres métriques plus tard (bande passante,
            # CPU...) sans nouvelle migration — cf. models.py::NetworkStatus.
            row.metrics = {
                "serial": serial,
                "model": device.get("model"),
                "product_type": device.get("productType"),
                "public_ip": device.get("publicIp"),
            }
            row.updated_at = now
            stats["updated"] += 1

        state = await db.get(SyncState, "meraki_network_status")
        if state is None:
            state = SyncState(key="meraki_network_status")
            db.add(state)
        state.last_synced_at = now

        await db.commit()
        logger.info(
            "Meraki sync : %d équipements, %d actifs matchés, %d NetworkStatus mis à jour",
            stats["devices_total"], stats["matched_assets"], stats["updated"],
        )

    except Exception:
        await db.rollback()
        raise
    finally:
        if own_session:
            await db.close()

    return stats
