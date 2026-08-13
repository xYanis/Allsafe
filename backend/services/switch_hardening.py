"""
services/switch_hardening.py
Durcissement/conformité des switches Cisco IOS/IOS-XE (13/08/2026) — même esprit que le
durcissement CIS-like des serveurs (asset_scanner.py) mais côté réseau, credentialed (SSH),
contrairement au test TCP passif de services/network_protocol_check.py qui n'a aucun accès
identifiant aux équipements.

Cible `asset_type="network"` **avec identifiants renseignés** (`Asset.scan_username`) — pas
tous les actifs réseau ne sont des switches Cisco administrables en SSH, le filtre au niveau
requête SQL fait l'opt-in : un actif sans identifiants n'apparaît simplement jamais dans le lot
traité, rien à gérer en plus pour "ignorer silencieusement".

Parc réseau confirmé majoritairement Cisco (13/08/2026) — les commandes ci-dessous ciblent
IOS/IOS-XE spécifiquement, pas une abstraction multi-vendor. Un équipement d'une autre marque
retombera simplement sur des checks "unknown" (sortie non reconnue), jamais une erreur
bloquante.

⚠️ Prérequis de provisioning à connaître : `show running-config` exige le mode privilégié
(prompt `#`). Si le compte `scan_username` n'a que l'accès utilisateur (`>`), tous les checks
resteront "unknown" — pas un bug de ce module, un prérequis côté compte switch (accès niveau
15 via AAA sur la session SSH, cf. docs/ARCHITECTURE.md).
"""

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import SessionLocal
from models import Asset
from services.crypto import decrypt_password
from services.network_cli import InteractiveShellError, run_commands

logger = logging.getLogger(__name__)

CMD_LINES = "show running-config | section line"
CMD_SNMP = "show running-config | include ^snmp-server community"
CMD_PWENC = "show running-config | include ^service password-encryption"
CMD_AAA = "show running-config | include ^aaa new-model"
CMD_BANNER = "show running-config | include ^banner motd"
CMD_SYSLOG = "show running-config | include ^logging host"
CMD_NTP = "show running-config | include ^ntp server"

COMMANDS = [CMD_LINES, CMD_SNMP, CMD_PWENC, CMD_AAA, CMD_BANNER, CMD_SYSLOG, CMD_NTP]

CHECK_LABELS = {
    "telnet_disabled": "Telnet désactivé sur les lignes VTY",
    "console_vty_timeout": "Timeout d'inactivité configuré (VTY)",
    "snmp_default_community": "Communauté SNMP par défaut",
    "password_encryption": "Chiffrement des mots de passe (service password-encryption)",
    "aaa_authentication": "Authentification centralisée (AAA)",
    "banner_motd": "Bannière légale de connexion",
    "syslog_configured": "Journalisation centralisée (syslog)",
    "ntp_configured": "Synchronisation horaire (NTP)",
}

MAX_CONCURRENT_ASSETS = 10  # session SSH interactive complète par actif — plus coûteux que le
                            # simple connect() TCP de network_protocol_check.py (50 là-bas)


def _check(id_: str, status: str, detail: str) -> dict:
    return {"id": id_, "label": CHECK_LABELS[id_], "status": status, "detail": detail}


def _is_error_output(output: str) -> bool:
    first = next((l.strip() for l in output.splitlines() if l.strip()), "")
    return first.startswith("%")


def _parse_line_stanzas(output: str) -> list[dict]:
    """Découpe `show running-config | section line` en stanzas (une par `line ...`), chacune
    avec ses directives `transport input`/`exec-timeout` internes."""
    stanzas: list[dict] = []
    current: Optional[dict] = None
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if not line.startswith(" ") and line.strip().startswith("line "):
            current = {"header": line.strip(), "transport_input": None, "exec_timeout": None}
            stanzas.append(current)
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.startswith("transport input"):
            current["transport_input"] = stripped[len("transport input"):].strip()
        elif stripped.startswith("exec-timeout"):
            current["exec_timeout"] = stripped[len("exec-timeout"):].strip()
    return stanzas


def _check_telnet_and_timeout(output: str) -> tuple[dict, dict]:
    if _is_error_output(output):
        detail = "Sortie non exploitable (droits insuffisants ou commande rejetée)"
        return _check("telnet_disabled", "unknown", detail), _check("console_vty_timeout", "unknown", detail)

    vty_stanzas = [s for s in _parse_line_stanzas(output) if s["header"].startswith("line vty")]
    if not vty_stanzas:
        detail = "Aucune ligne VTY trouvée dans la configuration lue"
        return _check("telnet_disabled", "unknown", detail), _check("console_vty_timeout", "unknown", detail)

    telnet_open = []
    no_timeout = []
    for s in vty_stanzas:
        transport = (s["transport_input"] or "").lower()
        # Pas de directive transport input = défaut IOS historique = telnet ET ssh autorisés.
        if transport in ("", "all") or "telnet" in transport:
            telnet_open.append(s["header"])
        if (s["exec_timeout"] or "").strip() == "0 0":
            no_timeout.append(s["header"])

    telnet_check = _check(
        "telnet_disabled",
        "warn" if telnet_open else "ok",
        f"Telnet autorisé sur : {', '.join(telnet_open)}" if telnet_open
        else "SSH uniquement sur toutes les lignes VTY lues",
    )
    timeout_check = _check(
        "console_vty_timeout",
        "warn" if no_timeout else "ok",
        f"exec-timeout 0 0 (jamais de coupure) sur : {', '.join(no_timeout)}" if no_timeout
        else "Timeout d'inactivité actif (ou valeur par défaut IOS) sur toutes les lignes VTY lues",
    )
    return telnet_check, timeout_check


def _snmp_check(output: str) -> dict:
    if _is_error_output(output):
        return _check("snmp_default_community", "unknown", "Sortie non exploitable (droits insuffisants ou commande rejetée)")
    lines = [l.strip() for l in output.splitlines() if l.strip()]
    defaults = [l for l in lines if re.search(r"\b(public|private)\b", l, re.IGNORECASE)]
    if defaults:
        return _check("snmp_default_community", "warn", f"Communauté par défaut détectée : {defaults[0]}")
    if lines:
        return _check("snmp_default_community", "ok", "Communautés SNMP configurées, aucune par défaut détectée")
    return _check("snmp_default_community", "ok", "Aucune communauté SNMP configurée")


def _presence_check(id_: str, output: str, ok_detail: str, warn_detail: str) -> dict:
    if _is_error_output(output):
        return _check(id_, "unknown", "Sortie non exploitable (droits insuffisants ou commande rejetée)")
    present = any(l.strip() for l in output.splitlines())
    return _check(id_, "ok" if present else "warn", ok_detail if present else warn_detail)


def _build_checks(output: dict[str, str]) -> list[dict]:
    telnet_check, timeout_check = _check_telnet_and_timeout(output.get(CMD_LINES, ""))
    return [
        telnet_check,
        timeout_check,
        _snmp_check(output.get(CMD_SNMP, "")),
        _presence_check(
            "password_encryption", output.get(CMD_PWENC, ""),
            "service password-encryption actif",
            "service password-encryption absent — mots de passe stockés en clair dans la configuration",
        ),
        _presence_check(
            "aaa_authentication", output.get(CMD_AAA, ""),
            "aaa new-model actif",
            "aaa new-model absent — authentification locale uniquement",
        ),
        _presence_check(
            "banner_motd", output.get(CMD_BANNER, ""),
            "Bannière motd configurée",
            "Aucune bannière motd configurée",
        ),
        _presence_check(
            "syslog_configured", output.get(CMD_SYSLOG, ""),
            "Au moins un serveur syslog configuré",
            "Aucun serveur syslog configuré",
        ),
        _presence_check(
            "ntp_configured", output.get(CMD_NTP, ""),
            "Au moins un serveur NTP configuré",
            "Aucun serveur NTP configuré",
        ),
    ]


async def check_switch(asset: Asset) -> dict:
    """{"checks": [...], "checked_at": iso} pour un actif — "unknown" partout si aucune IP ou
    si la connexion SSH échoue, jamais une exception qui remonte."""
    now = datetime.now(timezone.utc).isoformat()
    host = asset.ip_address
    if not host:
        detail = "Aucune adresse IP connue pour cet actif"
        return {"checks": [_check(cid, "unknown", detail) for cid in CHECK_LABELS], "checked_at": now}

    password = decrypt_password(asset.scan_password_encrypted) if asset.scan_password_encrypted else None
    try:
        output = await run_commands(host, asset.scan_username, password, COMMANDS)
    except InteractiveShellError as exc:
        detail = f"Connexion impossible : {exc}"
        return {"checks": [_check(cid, "unknown", detail) for cid in CHECK_LABELS], "checked_at": now}

    return {"checks": _build_checks(output), "checked_at": now}


async def run_switch_hardening_checks(db: Optional[AsyncSession] = None) -> dict:
    """Point d'entrée principal : tous les actifs `asset_type="network"` actifs avec
    `scan_username` renseigné, vérifiés en parallèle (borné par MAX_CONCURRENT_ASSETS), un
    seul commit à la fin — cohérent avec network_protocol_check.py et les cycles de sync
    Meraki/PRTG."""
    own_session = db is None
    if own_session:
        db = SessionLocal()

    stats = {"checked": 0, "warnings": 0, "unreachable": 0}
    try:
        assets = (await db.execute(
            select(Asset).where(
                Asset.asset_type == "network",
                Asset.status == "active",
                Asset.scan_username.isnot(None),
            )
        )).scalars().all()

        semaphore = asyncio.Semaphore(MAX_CONCURRENT_ASSETS)

        async def _check_bounded(asset: Asset) -> dict:
            async with semaphore:
                return await check_switch(asset)

        results = await asyncio.gather(*(_check_bounded(a) for a in assets))

        now = datetime.now(timezone.utc)
        for asset, result in zip(assets, results):
            # Fusion par id, jamais écrasement complet : network_protocol_check.py, lui, écrase
            # network_compliance en entier (asset.network_compliance = result) — un même switch
            # peut très bien être suivi à la fois par PRTG/Meraki (donc passer par ce module-là)
            # ET avoir des identifiants SSH (donc passer aussi par celui-ci). Sans la fusion,
            # lancer l'un après l'autre effacerait silencieusement les checks de l'autre.
            # Asymétrie assumée : si network_protocol_check.py tourne APRÈS ce service sur le
            # même actif, il écrasera toujours tout — non corrigé de ce côté-là dans cette passe.
            existing = {c["id"]: c for c in (asset.network_compliance or {}).get("checks", [])}
            for c in result["checks"]:
                existing[c["id"]] = c
            asset.network_compliance = {"checks": list(existing.values()), "checked_at": result["checked_at"]}
            # Contrairement à network_protocol_check.py (jamais credentialed), ce service ouvre
            # une vraie session SSH authentifiée — un "dernier scan" a un sens ici.
            asset.last_scan = now

            stats["checked"] += 1
            statuses = [c["status"] for c in result["checks"]]
            if "warn" in statuses:
                stats["warnings"] += 1
            if statuses and all(s == "unknown" for s in statuses):
                stats["unreachable"] += 1

        await db.commit()
        logger.info(
            "Durcissement switches : %d actifs vérifiés, %d avec avertissements, %d injoignables",
            stats["checked"], stats["warnings"], stats["unreachable"],
        )
    except Exception:
        await db.rollback()
        raise
    finally:
        if own_session:
            await db.close()

    return stats
