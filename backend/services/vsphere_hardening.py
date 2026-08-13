"""
services/vsphere_hardening.py
Construit les checks de durcissement ESXi (13/08/2026) à partir des faits bruts collectés par
services/vsphere_client.py::_hardening_facts — API vSphere uniquement, jamais de SSH sur
l'hôte (contrairement aux switches, où SSH était la seule voie disponible, cf.
services/switch_hardening.py). Même shape que le reste du projet :
{"id","label","status":"ok"|"warn"|"unknown","detail"}.

Écrit dans Asset.last_scan_result.compliance.checks (pas network_compliance) : un hôte ESXi
est `asset_type="server"` (décision volontaire, cf. docs/ARCHITECTURE.md § Intégration
vSphere) — Durcissement.jsx::checksFor() route déjà tout actif non-network vers ce champ,
aucun changement frontend nécessaire pour l'affichage.
"""

CHECK_LABELS = {
    "lockdown_mode": "Mode verrouillage (Lockdown Mode)",
    "ssh_service": "Service SSH désactivé",
    "ntp_configured": "Synchronisation horaire (NTP)",
    "syslog_configured": "Journalisation distante (syslog)",
    "account_lockout": "Verrouillage de compte après échecs",
}

_UNREADABLE = "Non lisible (droits insuffisants ou propriété absente sur cette version d'ESXi)"


def _check(id_: str, status: str, detail: str) -> dict:
    return {"id": id_, "label": CHECK_LABELS[id_], "status": status, "detail": detail}


def build_checks(hardening: dict) -> list[dict]:
    """`hardening` = dict retourné par vsphere_client.py::_hardening_facts. Chaque check est
    indépendant des autres — un fait manquant (`None`) ne bascule que le check concerné en
    "unknown", jamais toute la liste."""
    checks = []

    lockdown = hardening.get("lockdown_mode")
    if lockdown is None:
        checks.append(_check("lockdown_mode", "unknown", _UNREADABLE))
    elif lockdown == "lockdownDisabled":
        checks.append(_check("lockdown_mode", "warn", "Désactivé — accès direct (DCUI/vSphere Client local) non restreint"))
    else:
        checks.append(_check("lockdown_mode", "ok", f"Actif ({lockdown})"))

    ssh_running = hardening.get("ssh_running")
    if ssh_running is None:
        checks.append(_check("ssh_service", "unknown", _UNREADABLE))
    elif ssh_running:
        checks.append(_check("ssh_service", "warn", "Service SSH (TSM-SSH) actif"))
    else:
        checks.append(_check("ssh_service", "ok", "Service SSH inactif"))

    ntp = hardening.get("ntp_servers")
    if ntp is None:
        checks.append(_check("ntp_configured", "unknown", _UNREADABLE))
    elif ntp:
        checks.append(_check("ntp_configured", "ok", f"{len(ntp)} serveur(s) NTP configuré(s) : {', '.join(ntp)}"))
    else:
        checks.append(_check("ntp_configured", "warn", "Aucun serveur NTP configuré"))

    syslog = hardening.get("syslog_host")
    if syslog is None:
        checks.append(_check("syslog_configured", "unknown", _UNREADABLE))
    elif syslog.strip():
        checks.append(_check("syslog_configured", "ok", f"Syslog.global.logHost = {syslog}"))
    else:
        checks.append(_check("syslog_configured", "warn", "Syslog.global.logHost vide — aucune journalisation distante"))

    lockout = hardening.get("account_lock_failures")
    if lockout is None:
        checks.append(_check("account_lockout", "unknown", _UNREADABLE))
    elif isinstance(lockout, int) and lockout > 0:
        checks.append(_check("account_lockout", "ok", f"Verrouillage après {lockout} échec(s)"))
    else:
        checks.append(_check("account_lockout", "warn", "Security.AccountLockFailures = 0 — pas de verrouillage de compte"))

    return checks
