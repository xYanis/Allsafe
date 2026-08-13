"""
services/withsecure_matcher.py
Associe les appareils WithSecure aux actifs CBR existants (par hostname), puis
crée des Vulnerability à partir des correctifs manquants CVE/CVSS remontés
(cf. services/withsecure_client.get_missing_updates).

Ne crée jamais d'actif : les serveurs sont déjà importés via AD/SSH
(services/asset_importer.py). Ce module enrichit les actifs existants, il ne
duplique pas l'inventaire.

Confirmé Windows uniquement (28/07/2026, test en direct) — ne traite que les
appareils dont le type d'abonnement WithSecure contient "server" ET dont l'OS
est Windows. Les VM Linux restent hors du périmètre de ce module, cf.
services/patch_checker.py / debian_tracker.py pour elles.

Suit exactement le même schéma de création que services/cpe_matcher.py
(vérification d'existence par couple asset_id/cve_id avant insertion,
calculate_risk_score, status="open") — une vulnérabilité détectée par
WithSecure passe par le même cycle de qualification manuelle/automatique que
les autres (cf. CLAUDE.md § Non-intervention : CRITICAL toujours manuel,
HIGH/MEDIUM/LOW réouvrable).
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import SessionLocal
from models import Asset, CVE, Vulnerability, SyncState
from services import withsecure_client
from services.nvd_fetcher import run_nvd_sync_by_id
from services.scoring import calculate_risk_score

logger = logging.getLogger(__name__)

# Même logique que nvd_fetcher.py (DELAY_NO_KEY/DELAY_WITH_KEY) : un CVE
# manquant en base déclenche un fetch_by_id NVD à l'unité, potentiellement
# plusieurs fois par cycle — respecter le rate limit NVD plutôt que le
# découvrir en prod (5 req/30s sans clé, 50 req/30s avec).
_NVD_DELAY = 0.7 if settings.NVD_API_KEY else 6.5


def _normalize_hostname(raw: Optional[str]) -> Optional[str]:
    """'PORT-1956.AER.LOC' / 'port-1956' → 'port-1956'. Ne garde que le nom
    court : l'import AD stocke parfois le FQDN, parfois le nom court selon la
    source (cf. asset_importer.py) — on ne peut pas supposer un format fixe
    côté CBR ni côté WithSecure (dnsAddress est toujours un FQDN)."""
    if not raw:
        return None
    return raw.strip().split(".")[0].lower() or None


def _is_windows_server_device(device: dict) -> bool:
    variant = ((device.get("subscription") or {}).get("productVariant") or "").lower()
    os_name = ((device.get("os") or {}).get("name") or "").lower()
    return "server" in variant and "windows" in os_name


async def match_devices_to_assets(
    devices: list[dict], db: AsyncSession
) -> tuple[dict[str, Asset], list[dict]]:
    """Retourne {device_id: Asset} pour les appareils matchés par hostname
    normalisé, et la liste des devices sans actif CBR correspondant (visibilité
    sur la couverture réelle, cf. écart 60 devices WithSecure vs actifs CBR
    constaté en session)."""
    assets = (await db.execute(select(Asset).where(Asset.status == "active"))).scalars().all()
    assets_by_hostname = {
        h: a for a in assets if (h := _normalize_hostname(a.hostname))
    }

    matched: dict[str, Asset] = {}
    unmatched: list[dict] = []
    for device in devices:
        candidates = (
            _normalize_hostname(device.get("name")),
            _normalize_hostname(device.get("dnsAddress")),
        )
        asset = next((assets_by_hostname[c] for c in candidates if c in assets_by_hostname), None)
        if asset is not None:
            matched[device["id"]] = asset
        else:
            unmatched.append({"id": device.get("id"), "name": device.get("name"), "dnsAddress": device.get("dnsAddress")})

    return matched, unmatched


async def _ensure_cve_local(cve_id: str, db: AsyncSession) -> Optional[CVE]:
    """CVE déjà en base (sync NVD normale) → réutilisée telle quelle. Sinon,
    tentative de rattrapage via fetch_by_id (même filet que le matching CPE
    pour une CVE tombée dans le trou de la sync incrémentale). Ne crée jamais
    de CVE "à la main" depuis les seules données WithSecure (pas de
    description, pas d'EPSS) — NVD reste l'unique source de vérité pour la
    table cves."""
    cve = (await db.execute(select(CVE).where(CVE.cve_id == cve_id))).scalar_one_or_none()
    if cve is not None:
        return cve

    result = await run_nvd_sync_by_id(cve_id, api_key=settings.NVD_API_KEY)
    await asyncio.sleep(_NVD_DELAY)
    if not result.get("found"):
        logger.warning("CVE %s signalée par WithSecure introuvable sur NVD, ignorée", cve_id)
        return None

    return (await db.execute(select(CVE).where(CVE.cve_id == cve_id))).scalar_one_or_none()


async def sync_windows_vulnerabilities(db: Optional[AsyncSession] = None) -> dict:
    """Point d'entrée principal : appareils serveurs Windows WithSecure → actifs
    CBR → Vulnerability. Lecture seule côté WithSecure (scope connect.api.read),
    écriture uniquement dans la base CBR."""
    if not withsecure_client.is_configured():
        return {"error": "withsecure_not_configured"}

    own_session = db is None
    if own_session:
        db = SessionLocal()

    stats = {
        "devices_total": 0,
        "windows_server_devices": 0,
        "matched_assets": 0,
        "unmatched_devices": [],
        "vulnerabilities_created": 0,
        "vulnerabilities_skipped_existing": 0,
        "cve_not_found_on_nvd": 0,
    }

    try:
        devices = await withsecure_client.get_devices()
        stats["devices_total"] = len(devices)

        windows_servers = [d for d in devices if _is_windows_server_device(d)]
        stats["windows_server_devices"] = len(windows_servers)

        matched, unmatched = await match_devices_to_assets(windows_servers, db)
        stats["matched_assets"] = len(matched)
        stats["unmatched_devices"] = unmatched

        for device_id, asset in matched.items():
            criticite = (asset.tags or {}).get("criticite", "moyenne")
            items = await withsecure_client.get_missing_updates(device_id)

            seen_cve_ids: set[str] = set()
            for item in items:
                for cve_ref in item.get("cve", []):
                    cve_id = cve_ref.get("id")
                    if cve_id:
                        seen_cve_ids.add(cve_id)

            for cve_id in seen_cve_ids:
                cve = await _ensure_cve_local(cve_id, db)
                if cve is None:
                    stats["cve_not_found_on_nvd"] += 1
                    continue

                exists = (await db.execute(
                    select(Vulnerability).where(
                        and_(Vulnerability.asset_id == asset.id, Vulnerability.cve_id == cve.id)
                    )
                )).scalar_one_or_none()

                if exists is not None:
                    stats["vulnerabilities_skipped_existing"] += 1
                    continue

                db.add(Vulnerability(
                    asset_id=asset.id,
                    cve_id=cve.id,
                    status="open",
                    risk_score=calculate_risk_score(cve.cvss_score, cve.epss_score, criticite),
                    detected_at=datetime.now(timezone.utc),
                ))
                stats["vulnerabilities_created"] += 1

        now = datetime.now(timezone.utc)
        state = await db.get(SyncState, "withsecure_missing_updates")
        if state is None:
            state = SyncState(key="withsecure_missing_updates")
            db.add(state)
        state.last_synced_at = now

        await db.commit()
        logger.info(
            "WithSecure sync : %d devices, %d serveurs Windows, %d actifs matchés, %d vulnérabilités créées",
            stats["devices_total"], stats["windows_server_devices"], stats["matched_assets"], stats["vulnerabilities_created"],
        )

    except Exception:
        await db.rollback()
        raise
    finally:
        if own_session:
            await db.close()

    return stats
