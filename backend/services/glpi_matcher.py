"""
services/glpi_matcher.py
Associe les Computer GLPI aux actifs Allsafe existants (par hostname/nom), puis enrichit
`Asset.hardware` avec les données de patrimoine GLPI (modèle, n° de série, n° d'inventaire,
fabricant, localisation). Réutilise le même champ JSON que l'inventaire matériel des scans
SSH/WinRM (cf. Asset.hardware, module Inventaire), avec des clés préfixées `glpi_` pour ne
jamais entrer en collision avec cpu/cores/ram_gb/disks — même principe que
services/prtg_matcher.py::vendor_hint.

⚠️ Contrairement à services/meraki_matcher.py / prtg_matcher.py et leur `import_new_assets` :
**aucune création d'actif ici, jamais** — décision explicite de l'utilisateur (11/08/2026).
GLPI est un CMDB déjà tenu à jour côté client, pas un outil de découverte réseau ; un
Computer GLPI sans correspondance reste seulement listé dans `unmatched_computers`.

L'utilisateur assigné (`users_id` côté GLPI) n'est délibérément pas repris ici : c'est une
donnée nominative, et contrairement à `OrganizationRole` (Paramètres > Rôles), ce module n'a
pas encore de plomberie d'anonymisation pour le mode Présentation — à ajouter si besoin plus
tard plutôt que d'exposer un nom en dur dans `hardware`.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import SessionLocal
from models import Asset, SyncState
from services import glpi_client

logger = logging.getLogger(__name__)

SYNC_STATE_KEY = "glpi_inventory"


def _normalize_hostname(raw):
    """'SRV-PROD-01.aer.loc' / 'srv-prod-01' → 'srv-prod-01' — même normalisation que
    prtg_matcher.py/meraki_matcher.py (nom court, insensible à la casse)."""
    if not raw:
        return None
    return raw.strip().split(".")[0].lower() or None


async def match_computers_to_assets(
    computers: list[dict], db: AsyncSession
) -> tuple[dict[int, Asset], list[dict]]:
    """Retourne {id GLPI: Asset} pour les computers matchés — `name` GLPI contre
    `Asset.hostname` normalisé, puis `Asset.name` en repli — et la liste des computers
    sans actif Allsafe correspondant."""
    assets = (await db.execute(select(Asset).where(Asset.status == "active"))).scalars().all()
    assets_by_hostname = {h: a for a in assets if (h := _normalize_hostname(a.hostname))}
    assets_by_name = {h: a for a in assets if (h := _normalize_hostname(a.name))}

    matched: dict[int, Asset] = {}
    unmatched: list[dict] = []
    for computer in computers:
        computer_id = computer.get("id")
        if computer_id is None:
            continue

        candidate = _normalize_hostname(computer.get("name"))
        asset = assets_by_hostname.get(candidate) or assets_by_name.get(candidate)

        if asset is not None:
            matched[computer_id] = asset
        else:
            unmatched.append({"id": computer_id, "name": computer.get("name")})

    return matched, unmatched


def _hardware_patch(computer: dict) -> dict:
    """Champs de patrimoine GLPI à fusionner dans Asset.hardware. `computermodels_id`/
    `manufacturers_id`/`locations_id` sont déjà résolus en texte côté client
    (expand_dropdowns=true, cf. glpi_client.COMPUTER_PARAMS) — pas de nouvel appel
    nécessaire ici."""
    return {
        "glpi_id": computer.get("id"),
        "glpi_serial": computer.get("serial") or None,
        "glpi_inventory_number": computer.get("otherserial") or None,
        "glpi_model": computer.get("computermodels_id") or None,
        "glpi_manufacturer": computer.get("manufacturers_id") or None,
        "glpi_location": computer.get("locations_id") or None,
    }


async def sync_inventory(db: Optional[AsyncSession] = None) -> dict:
    """Point d'entrée principal : Computer GLPI → actifs Allsafe déjà connus →
    enrichissement de `Asset.hardware`. Lecture seule côté GLPI, écriture uniquement
    dans la base Allsafe, jamais de création d'actif (cf. docstring du module)."""
    if not glpi_client.is_configured():
        return {"error": "glpi_not_configured"}

    own_session = db is None
    if own_session:
        db = SessionLocal()

    stats = {
        "computers_total": 0,
        "matched_assets": 0,
        "unmatched_computers": [],
        "updated": 0,
    }

    try:
        computers = await glpi_client.get_computers()
        stats["computers_total"] = len(computers)

        matched, unmatched = await match_computers_to_assets(computers, db)
        computers_by_id = {c["id"]: c for c in computers if c.get("id") is not None}

        stats["matched_assets"] = len(matched)
        stats["unmatched_computers"] = unmatched

        now = datetime.now(timezone.utc)
        for glpi_id, asset in matched.items():
            computer = computers_by_id[glpi_id]
            patch = _hardware_patch(computer)
            # N'écrit (et n'incrémente `updated`) que si au moins un champ a réellement
            # changé — évite un UPDATE + une entrée SQLAlchemy "dirty" à chaque sync
            # pour un patrimoine qui ne bouge quasiment jamais entre deux passages.
            if any((asset.hardware or {}).get(k) != v for k, v in patch.items()):
                asset.hardware = {**(asset.hardware or {}), **patch}
                stats["updated"] += 1

        state = await db.get(SyncState, SYNC_STATE_KEY)
        if state is None:
            state = SyncState(key=SYNC_STATE_KEY)
            db.add(state)
        state.last_synced_at = now

        await db.commit()
        logger.info(
            "GLPI sync : %d computers, %d actifs matchés, %d enrichis",
            stats["computers_total"], stats["matched_assets"], stats["updated"],
        )

    except Exception:
        await db.rollback()
        raise
    finally:
        if own_session:
            await db.close()

    return stats
