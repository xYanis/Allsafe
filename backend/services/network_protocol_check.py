"""
services/network_protocol_check.py
Test de connexion TCP passif (07/08/2026) sur les actifs réseau (switches/pare-feux
importés via PRTG/Meraki, asset_type="network") pour repérer des protocoles
d'administration non chiffrés encore actifs (Telnet, HTTP) — CBR n'a aucun accès
identifiant à ces équipements, contrairement aux serveurs (SSH/WinRM) : sans ce
module, rien ne dit si un switch/pare-feu expose encore une CLI Telnet ou une
interface web en HTTP simple.

Volontairement limité à un `connect()` TCP qui se referme aussitôt, sans jamais
envoyer ni négocier quoi que ce soit ensuite (pas de login Telnet, pas de requête
HTTP, pas de test SNMP avec une community string) — "le port répond-il ?", rien de
plus. Un test SNMP actif a été explicitement écarté (07/08/2026, discuté avec
l'utilisateur) : ce serait une action offensive, contraire au principe déjà posé
pour le module Audits ("CBR héberge et trace, n'exécute jamais rien d'offensif" —
cf. CLAUDE.md) et au périmètre de non-intervention retenu pour les serveurs.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import SessionLocal
from models import Asset

logger = logging.getLogger(__name__)

# Ports d'administration non chiffrés recherchés — mêmes protocoles que le principe
# déjà appliqué aux serveurs (_RISKY_PORTS, services/asset_scanner.py), réduits aux
# deux qui concernent une interface d'admin réseau (CLI Telnet, interface web) ;
# FTP/rexec/rlogin/rsh de la liste serveur n'ont pas de sens sur un switch/pare-feu.
RISKY_MGMT_PORTS = {
    23: "Telnet (CLI non chiffrée)",
    80: "HTTP non chiffré (interface web d'admin)",
}

CONNECT_TIMEOUT = 3.0
CHECK_ID = "network_protocols"
CHECK_LABEL = "Protocoles d'admin non chiffrés"

# Beaucoup de pare-feux/switches laissent tomber silencieusement une connexion
# refusée plutôt que d'envoyer un TCP RESET — chaque `connect()` sur un port fermé
# peut donc coûter le CONNECT_TIMEOUT complet, pas juste un aller-retour rapide.
# Avec ~400 actifs réseau réels (cf. STATUS.md, import PRTG) et un traitement
# strictement séquentiel actif par actif, un run a mis **plusieurs minutes** à se
# terminer (constaté en conditions réelles, 07/08/2026) — corrigé en testant tous
# les actifs en parallèle, borné par ce sémaphore plutôt que sans limite (éviter
# d'ouvrir des centaines de sockets TCP simultanées d'un coup).
MAX_CONCURRENT_ASSETS = 50


async def _port_open(host: str, port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT)
    except (asyncio.TimeoutError, OSError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


async def check_asset(asset: Asset) -> dict:
    """{"checks": [...], "checked_at": iso} pour un actif — "unknown" si aucune IP
    exploitable (rien à tester), sinon "warn" dès qu'un port de RISKY_MGMT_PORTS
    répond, "ok" sinon."""
    now = datetime.now(timezone.utc).isoformat()
    host = asset.ip_address
    if not host:
        return {
            "checks": [{"id": CHECK_ID, "label": CHECK_LABEL, "status": "unknown",
                        "detail": "Aucune adresse IP connue pour cet actif"}],
            "checked_at": now,
        }

    ports = list(RISKY_MGMT_PORTS.items())
    open_results = await asyncio.gather(*(_port_open(host, port) for port, _ in ports))
    open_ports = [(port, label) for (port, label), is_open in zip(ports, open_results) if is_open]

    if open_ports:
        detail = ", ".join(f"{label} (port {port})" for port, label in open_ports)
        status = "warn"
    else:
        detail = "Ni Telnet ni HTTP non chiffré détectés en écoute"
        status = "ok"

    return {"checks": [{"id": CHECK_ID, "label": CHECK_LABEL, "status": status, "detail": detail}], "checked_at": now}


async def check_all_network_assets(db: Optional[AsyncSession] = None) -> dict:
    """Point d'entrée principal : tous les actifs `asset_type="network"` actifs,
    testés en parallèle (borné par MAX_CONCURRENT_ASSETS), un seul commit à la fin
    plutôt qu'un par actif — cohérent avec le reste des cycles de sync du projet
    (PRTG/Meraki)."""
    own_session = db is None
    if own_session:
        db = SessionLocal()

    stats = {"checked": 0, "warnings": 0, "skipped_no_ip": 0}
    try:
        assets = (await db.execute(
            select(Asset).where(Asset.asset_type == "network", Asset.status == "active")
        )).scalars().all()

        semaphore = asyncio.Semaphore(MAX_CONCURRENT_ASSETS)

        async def _check_bounded(asset: Asset) -> dict:
            async with semaphore:
                return await check_asset(asset)

        results = await asyncio.gather(*(_check_bounded(a) for a in assets))

        for asset, result in zip(assets, results):
            asset.network_compliance = result
            stats["checked"] += 1
            if not asset.ip_address:
                stats["skipped_no_ip"] += 1
            elif result["checks"][0]["status"] == "warn":
                stats["warnings"] += 1

        await db.commit()
        logger.info(
            "Test protocoles réseau : %d actifs vérifiés, %d avertissements, %d sans IP",
            stats["checked"], stats["warnings"], stats["skipped_no_ip"],
        )
    except Exception:
        await db.rollback()
        raise
    finally:
        if own_session:
            await db.close()

    return stats
