"""
asset_scanner.py
Scan read-only d'un actif : vérifie la fiabilité des infos déclarées (hostname,
OS, version) contre ce qui est réellement détecté sur la machine, collecte la
liste des applications/paquets installés, et les specs matérielles (CPU, RAM,
disques) pour le module Inventaire. Jamais d'écriture sur le serveur.

Windows : WinRM read-only → registre + $env + appel natif GlobalMemoryStatusEx
          (le compte de service n'a pas les droits WMI/CIM, cf. commentaires ci-dessous)
Linux   : SSH read-only  → hostname/os-release + dpkg/rpm + lscpu/free/df
"""

import re
import json
import logging
import asyncio
import asyncssh
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from services.ssh_trust import connect_trusted
from models import Asset
from services.patch_checker import _winrm_session, run_full_patch_check_cycle, reset_patch_check_timestamps
from services.asset_importer import _build_cpe
from tasks.scheduled_tasks import run_cpe_matching_for_asset_task

logger = logging.getLogger(__name__)

_WIN_YEAR_RE = re.compile(r"\b(19|20)\d{2}\b")

# "curl/stable 7.88.1-10+deb12u5 amd64 [upgradable from: 7.88.1-10+deb12u4]" →
# groupe 1 = nom du paquet, groupe 2 = version candidate (07/08/2026, "upgradable").
_APT_UPGRADABLE_RE = re.compile(r"^([^/\s]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:")


def _extract_windows_version(caption: str) -> str:
    """Extrait l'année de version depuis le Caption Win32_OperatingSystem (ex: 2019)."""
    match = _WIN_YEAR_RE.search(caption or "")
    if match:
        return match.group(0)
    for token in ("10", "11"):
        if re.search(rf"\bWindows {token}\b", caption or ""):
            return token
    return ""


def _format_macs(raw: Optional[str]) -> str:
    """Formate des adresses MAC brutes (ex: '005056ACB5C0,AABBCC112233') en 'XX-XX-XX-XX-XX-XX' groupées par virgule."""
    if not raw:
        return ""
    return ", ".join(
        "-".join(mac[i:i + 2] for i in range(0, 12, 2))
        for mac in raw.split(",") if len(mac) == 12
    )


_ARCH_LABELS = {
    "amd64": "64 bits (x64)", "x86_64": "64 bits (x64)", "x64": "64 bits (x64)",
    "arm64": "64 bits (ARM64)", "aarch64": "64 bits (ARM64)",
    "ia64": "64 bits (Itanium)",
    "x86": "32 bits (x86)", "i386": "32 bits (x86)", "i486": "32 bits (x86)",
    "i586": "32 bits (x86)", "i686": "32 bits (x86)",
    "armv7l": "32 bits (ARM)", "armv6l": "32 bits (ARM)", "arm": "32 bits (ARM)",
}


def _format_arch(raw: Optional[str]) -> str:
    """Normalise l'architecture brute (PROCESSOR_ARCHITECTURE Windows / `uname -m`
    Linux) en libellé lisible '32 bits'/'64 bits' — retourne la valeur brute si
    non reconnue plutôt que de la masquer."""
    if not raw:
        return ""
    return _ARCH_LABELS.get(raw.strip().lower(), raw.strip())


def _parse_ports(raw) -> list:
    """Parse une liste de ports bruts (str 'CSV' côté Windows, list d'int côté Linux) en liste d'int triée."""
    if not raw:
        return []
    if isinstance(raw, str):
        parts = raw.split(",")
    else:
        parts = raw
    ports = set()
    for p in parts:
        try:
            ports.add(int(p))
        except (TypeError, ValueError):
            continue
    return sorted(ports)


# ─── Durcissement / conformité (lecture seule) ─────────────────────────────────
# Contrôles inspirés CIS Benchmark, volontairement limités à ce qui est lisible
# sans droits élevés ni WMI (cf. contrainte non-intervention, CLAUDE.md). Chaque
# check renvoie "ok"/"warn"/"unknown" plutôt que de faire échouer le scan — un
# droit insuffisant (ex: sudo non configuré) est un résultat légitime, pas une
# erreur.

_RISKY_PORTS = {
    21: "FTP (non chiffré)", 23: "Telnet (non chiffré)", 69: "TFTP (non authentifié)",
    512: "rexec (non chiffré)", 513: "rlogin (non chiffré)", 514: "rsh (non chiffré)",
    # Étendu 17/08/2026 (retour utilisateur, référence Cyberwatch "ports risqués") : services
    # historiquement exposés sans chiffrement/authentification forte quand accessibles depuis
    # le réseau — même esprit que la liste ci-dessus, pas une tentative de couvrir tous les
    # ports possibles (ex. 3389/RDP a déjà son propre check dédié `rdp_nla`, pas dupliqué ici).
    110: "POP3 (non chiffré)", 143: "IMAP (non chiffré)",
    1433: "MSSQL exposé", 3306: "MySQL exposé", 5900: "VNC (souvent sans chiffrement)",
}


def _check(id_: str, label: str, status: str, detail: str) -> dict:
    return {"id": id_, "label": label, "status": status, "detail": detail}


# Algos SSH cassés/dépréciés (SHA1 collision-prone, RC4 biaisé, CBC vulnérable au
# padding oracle type Terrapin, MD5/troncature MAC falsifiables) — équivalent Linux
# des checks signature/chiffrement SMB côté Windows : même famille de risque
# (downgrade/relais), même mécanisme (sshd -T, déjà utilisé pour root_login/password_auth).
_WEAK_SSH_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}
_WEAK_SSH_CIPHERS = {"arcfour", "arcfour128", "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc",
                      "3des-cbc", "blowfish-cbc", "cast128-cbc", "rijndael-cbc@lysator.liu.se"}
_WEAK_SSH_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96",
                   "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-sha1-96-etm@openssh.com"}


def _check_exposed_ports(open_ports: list) -> list:
    found = [(p, name) for p, name in _RISKY_PORTS.items() if p in (open_ports or [])]
    if not found:
        return [_check("exposed_ports", "Services exposés à risque", "ok", "Aucun service historiquement non sécurisé détecté sur les ports en écoute")]
    detail = ", ".join(f"{name} (port {p})" for p, name in found)
    return [_check("exposed_ports", "Services exposés à risque", "warn", detail)]


def _build_compliance_linux(logindefs_raw: str, sshd_raw: str, open_ports: list) -> dict:
    values = {}
    for line in (logindefs_raw or "").splitlines():
        parts = line.split()
        if len(parts) == 2:
            values[parts[0]] = parts[1]

    checks = []

    max_days = values.get("PASS_MAX_DAYS")
    if max_days is None:
        checks.append(_check("password_max_age", "Âge maximal du mot de passe", "unknown", "PASS_MAX_DAYS absent de /etc/login.defs"))
    else:
        try:
            days = int(max_days)
            status = "ok" if 0 < days <= 90 else "warn"
            checks.append(_check("password_max_age", "Âge maximal du mot de passe", status, f"{days} jours (PASS_MAX_DAYS)"))
        except ValueError:
            checks.append(_check("password_max_age", "Âge maximal du mot de passe", "unknown", f"Valeur non interprétable : {max_days}"))

    min_len = values.get("PASS_MIN_LEN")
    if min_len is None:
        checks.append(_check("password_min_length", "Longueur minimale du mot de passe", "unknown", "PASS_MIN_LEN absent de /etc/login.defs (souvent délégué à pam_pwquality)"))
    else:
        try:
            length = int(min_len)
            checks.append(_check("password_min_length", "Longueur minimale du mot de passe", "ok" if length >= 8 else "warn", f"{length} caractères (PASS_MIN_LEN)"))
        except ValueError:
            checks.append(_check("password_min_length", "Longueur minimale du mot de passe", "unknown", f"Valeur non interprétable : {min_len}"))

    sshd_values = {}
    for line in (sshd_raw or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            sshd_values[parts[0].strip().lower()] = parts[1].strip().lower()

    if not sshd_values:
        checks.append(_check("ssh_root_login", "Connexion SSH root directe", "unknown", "sshd -T inaccessible (droits insuffisants sans sudo)"))
        checks.append(_check("ssh_password_auth", "Authentification SSH par mot de passe", "unknown", "sshd -T inaccessible (droits insuffisants sans sudo)"))
        checks.append(_check("ssh_weak_algos", "Algorithmes SSH faibles", "unknown", "sshd -T inaccessible (droits insuffisants sans sudo)"))
    else:
        root_login = sshd_values.get("permitrootlogin")
        checks.append(_check("ssh_root_login", "Connexion SSH root directe", "ok" if root_login == "no" else "warn", f"PermitRootLogin={root_login or '?'}"))
        pass_auth = sshd_values.get("passwordauthentication")
        checks.append(_check("ssh_password_auth", "Authentification SSH par mot de passe", "ok" if pass_auth == "no" else "warn", f"PasswordAuthentication={pass_auth or '?'}"))

        weak_algos = []
        for key, weak_set in (("kexalgorithms", _WEAK_SSH_KEX), ("ciphers", _WEAK_SSH_CIPHERS), ("macs", _WEAK_SSH_MACS)):
            configured = {a.strip() for a in (sshd_values.get(key) or "").split(",") if a.strip()}
            weak_algos.extend(sorted(configured & weak_set))
        checks.append(_check(
            "ssh_weak_algos", "Algorithmes SSH faibles", "warn" if weak_algos else "ok",
            f"Encore acceptés : {', '.join(weak_algos)}" if weak_algos else "Aucun algo faible (échange de clé/chiffrement/MAC) accepté",
        ))

    checks.extend(_check_exposed_ports(open_ports))
    return {"checks": checks}


# `net accounts` est la seule source non-WMI pour la stratégie de mot de passe,
# mais son texte dépend de la langue d'installation Windows — motifs FR/EN
# tolérés, "indéterminé" si aucun des deux ne matche (mieux qu'un mauvais parsing
# silencieux). Constaté en direct sur DEPLOYAPP (WinRM/console distante) :
# l'encodage des caractères accentués est corrompu (é/è → "�") et le libellé
# FR réel est "Durée de vie maximale..." (pas "Ancienneté..."). `[^:]*` plutôt
# que `\s*` entre le libellé et `:` absorbe aussi bien les espaces normaux que
# ce caractère corrompu ; `.` remplace chaque lettre accentuée pour matcher
# quel que soit le résultat du décodage.
_NET_ACCOUNTS_MIN_LEN_RE = re.compile(r"(?:longueur minimale du mot de passe|minimum password length)[^:]*:\s*(\d+)", re.IGNORECASE)
_NET_ACCOUNTS_MAX_AGE_RE = re.compile(r"(?:dur.e de vie maximale du mot de passe|maximum password age)[^:]*:\s*(\d+|jamais|illimit.e?|never|unlimited)", re.IGNORECASE)


def _parse_net_accounts(raw: Optional[str]) -> dict:
    text = raw or ""
    result = {"min_len": None, "max_age_days": None}
    m = _NET_ACCOUNTS_MIN_LEN_RE.search(text)
    if m:
        result["min_len"] = int(m.group(1))
    m = _NET_ACCOUNTS_MAX_AGE_RE.search(text)
    if m:
        val = m.group(1)
        result["max_age_days"] = int(val) if val.isdigit() else -1
    return result


def _build_compliance_windows(data: dict, open_ports: list) -> dict:
    checks = []
    net_accounts = _parse_net_accounts(data.get("NA"))

    min_len = net_accounts["min_len"]
    checks.append(_check("password_min_length", "Longueur minimale du mot de passe", "unknown", "Stratégie de mot de passe non interprétable (net accounts)") if min_len is None
                  else _check("password_min_length", "Longueur minimale du mot de passe", "ok" if min_len >= 8 else "warn", f"{min_len} caractères"))

    max_age = net_accounts["max_age_days"]
    if max_age is None:
        checks.append(_check("password_max_age", "Âge maximal du mot de passe", "unknown", "Stratégie de mot de passe indisponible"))
    elif max_age < 0:
        checks.append(_check("password_max_age", "Âge maximal du mot de passe", "warn", "N'expire jamais"))
    else:
        checks.append(_check("password_max_age", "Âge maximal du mot de passe", "ok" if max_age <= 90 else "warn", f"{max_age} jours"))

    rdp_nla = data.get("Rdp")
    checks.append(_check("rdp_nla", "Authentification niveau réseau (RDP/NLA)", "unknown", "Clé de registre absente") if rdp_nla is None
                  else _check("rdp_nla", "Authentification niveau réseau (RDP/NLA)", "ok" if rdp_nla == 1 else "warn", "Activée" if rdp_nla == 1 else "Désactivée"))

    smb1 = data.get("Smb1")
    checks.append(_check("smb1", "SMBv1 activé", "unknown", "Clé de registre absente (SMBv1 désactivé par défaut sur les versions récentes)") if smb1 is None
                  else _check("smb1", "SMBv1 activé", "warn" if smb1 == 1 else "ok", "Activé" if smb1 == 1 else "Désactivé"))

    smb_srv_sign = data.get("SmbSrvSign")
    checks.append(_check("smb_signing_server", "Signature SMB requise (serveur)", "unknown", "Clé de registre absente (non forcée par défaut)") if smb_srv_sign is None
                  else _check("smb_signing_server", "Signature SMB requise (serveur)", "ok" if smb_srv_sign == 1 else "warn", "Requise" if smb_srv_sign == 1 else "Non requise — expose au relais SMB entrant"))

    smb_cli_sign = data.get("SmbCliSign")
    checks.append(_check("smb_signing_client", "Signature SMB requise (client)", "unknown", "Clé de registre absente (non forcée par défaut)") if smb_cli_sign is None
                  else _check("smb_signing_client", "Signature SMB requise (client)", "ok" if smb_cli_sign == 1 else "warn", "Requise" if smb_cli_sign == 1 else "Non requise — expose au relais SMB sortant"))

    restrict_anon = data.get("RestrictAnon")
    checks.append(_check("smb_restrict_anonymous", "Sessions anonymes restreintes", "unknown", "Clé de registre absente") if restrict_anon is None
                  else _check("smb_restrict_anonymous", "Sessions anonymes restreintes", "ok" if restrict_anon >= 1 else "warn", "Restreintes" if restrict_anon >= 1 else "Non restreintes — énumération sans authentification possible"))

    guest_auth = data.get("GuestAuth")
    checks.append(_check("smb_guest_auth", "Connexions invité non sécurisées", "unknown", "Clé de registre absente (désactivées par défaut depuis Windows 10 1709 / Server 2019)") if guest_auth is None
                  else _check("smb_guest_auth", "Connexions invité non sécurisées", "warn" if guest_auth == 1 else "ok", "Autorisées" if guest_auth == 1 else "Bloquées"))

    smb_encrypt = data.get("SmbEncrypt")
    checks.append(_check("smb_encryption", "Chiffrement SMB", "unknown", "Clé de registre absente (non activé par défaut)") if smb_encrypt is None
                  else _check("smb_encryption", "Chiffrement SMB", "ok" if smb_encrypt == 1 else "warn", "Activé" if smb_encrypt == 1 else "Désactivé"))

    llmnr = data.get("Llmnr")
    checks.append(_check("llmnr", "LLMNR désactivé", "unknown", "Stratégie de groupe absente (LLMNR activé par défaut si non configuré)") if llmnr is None
                  else _check("llmnr", "LLMNR désactivé", "ok" if llmnr == 0 else "warn", "Désactivé" if llmnr == 0 else "Activé — expose au poisoning LLMNR/NBT-NS (type Responder)"))

    wdigest = data.get("Wdigest")
    checks.append(_check("wdigest", "WDigest désactivé", "unknown", "Clé de registre absente (désactivé par défaut depuis Windows 8.1 / Server 2012 R2)") if wdigest is None
                  else _check("wdigest", "WDigest désactivé", "warn" if wdigest == 1 else "ok", "Activé — mots de passe en clair exposés en mémoire (dump LSASS)" if wdigest == 1 else "Désactivé"))

    ntlm_level = data.get("NtlmLevel")
    checks.append(_check("ntlm_level", "Niveau NTLM (LmCompatibilityLevel)", "unknown", "Clé de registre absente (valeur par défaut du système)") if ntlm_level is None
                  else _check("ntlm_level", "Niveau NTLM (LmCompatibilityLevel)", "ok" if ntlm_level >= 3 else "warn", f"Niveau {ntlm_level} (NTLMv2 uniquement)" if ntlm_level >= 3 else f"Niveau {ntlm_level} — NTLMv1 accepté, crackable/relayable"))

    fw = data.get("Fw")
    checks.append(_check("firewall", "Pare-feu Windows (profil standard)", "unknown", "Clé de registre absente") if fw is None
                  else _check("firewall", "Pare-feu Windows (profil standard)", "ok" if fw == 1 else "warn", "Activé" if fw == 1 else "Désactivé"))

    checks.extend(_check_exposed_ports(open_ports))
    return {"checks": checks}


def _compare(declared: Optional[str], detected: Optional[str]) -> Optional[bool]:
    """
    Compare une info déclarée à ce qui est détecté. Retourne None si l'info
    déclarée est absente (rien à comparer) — jamais bloquant, juste informatif.
    """
    if not declared:
        return None
    if not detected:
        return False
    d, r = declared.strip().lower(), detected.strip().lower()
    return d in r or r in d


def _build_result(
    asset: Asset,
    detected_hostname: str,
    detected_os: str,
    detected_version: str,
    detected_ip: str,
    packages: list,
    hardware: Optional[dict] = None,
    compliance: Optional[dict] = None,
) -> dict:
    return {
        "reachable": True,
        "declared": {"hostname": asset.hostname, "os": asset.os, "os_version": asset.os_version, "ip_address": asset.ip_address},
        "detected": {"hostname": detected_hostname, "os": detected_os, "os_version": detected_version, "ip_address": detected_ip},
        "hostname_match": _compare(asset.hostname, detected_hostname),
        "os_match": _compare(asset.os, detected_os),
        "os_version_match": _compare(asset.os_version, detected_version),
        "ip_match": _compare(asset.ip_address, detected_ip),
        "packages": packages,
        "package_count": len(packages),
        "hardware": hardware or {},
        "compliance": compliance or {"checks": []},
    }


# ─── Windows via WinRM ─────────────────────────────────────────────────────────

def _scan_windows(asset: Asset) -> dict:
    host = asset.ip_address or asset.hostname
    if not host:
        return {"reachable": False, "error": "Adresse IP / hostname manquant"}
    if not (settings.WINRM_USER or settings.AD_USER):
        return {"reachable": False, "error": "WINRM_USER non configuré"}

    try:
        session = _winrm_session(host)

        # Registre + $env + appels natifs (kernel32/.NET) uniquement : le compte de
        # service n'a PAS les droits WMI/DCOM (Get-WmiObject/Get-CimInstance/
        # systeminfo → "Accès refusé"). CPU via registre, RAM via GlobalMemoryStatusEx
        # (P/Invoke direct sur kernel32.dll, contourne WMI), disques via
        # [System.IO.DriveInfo] (.NET, contourne WMI également).
        ps_script = """
$compName = $env:COMPUTERNAME
$cc = "HKLM:\\SYSTEM\\CurrentControlSet"
$di = gp "$cc\\Services\\Tcpip\\Parameters" -ea 0
$fqdn = if ($di.Domain) { "$compName.$($di.Domain)" } else { $compName }
$oi = gp "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" -ea 0
$caption = if ($oi.ProductName) { "$($oi.ProductName) (build $($oi.CurrentBuildNumber))" } else { "" }
$apps = @()
$paths = @(
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
)
gp -Path $paths -ea 0 |
  Where-Object { $_.DisplayName } |
  ForEach-Object { $apps += [PSCustomObject]@{ Name = $_.DisplayName; Version = $_.DisplayVersion } }
$cpu = gp "HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" -ea 0
$drives = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and $_.DriveType -eq "Fixed" } | ForEach-Object {
    [PSCustomObject]@{ Name = $_.Name; TotalGB = [math]::Round($_.TotalSize/1GB,1); FreeGB = [math]::Round($_.AvailableFreeSpace/1GB,1) }
}
$nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.OperationalStatus -eq "Up" -and $_.NetworkInterfaceType -ne "Loopback" }
$macJoined = ($nics | ForEach-Object { $_.GetPhysicalAddress().ToString() } | Where-Object { $_ -and $_ -ne "000000000000" } | Select-Object -Unique) -join ','
$ipJoined = ($nics | ForEach-Object { $_.GetIPProperties().UnicastAddresses } | Where-Object { $_.Address.AddressFamily -eq "InterNetwork" } | ForEach-Object { $_.Address.ToString() } | Select-Object -Unique) -join ','
$portsJoined = (([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()).GetActiveTcpListeners() | ForEach-Object Port | Sort-Object -Unique) -join ','
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class CVMem{[StructLayout(LayoutKind.Sequential)]public struct S{public uint a;public uint b;public ulong c;public ulong d;public ulong e;public ulong f;public ulong g;public ulong h;public ulong i;}[DllImport("kernel32.dll",EntryPoint="GlobalMemoryStatusEx")]public static extern bool G(ref S s);}'
$m = New-Object CVMem+S
$m.a = [System.Runtime.InteropServices.Marshal]::SizeOf($m)
[void][CVMem]::G([ref]$m)
$totalRamGB = [math]::Round($m.c/1GB,1)
$na = (net accounts) -join "`n"
[PSCustomObject]@{
    Hostname = $fqdn
    Caption  = $caption
    Apps     = $apps
    CPU      = $cpu.ProcessorNameString
    Arch     = $env:PROCESSOR_ARCHITECTURE
    Cores    = [int]$env:NUMBER_OF_PROCESSORS
    RamGB    = $totalRamGB
    Disks    = $drives
    MAC      = $macJoined
    IP       = $ipJoined
    Ports    = $portsJoined
    NA  = $na
} | ConvertTo-Json -Compress -Depth 4
"""

        ps_compliance_script = """
$cc = "HKLM:\\SYSTEM\\CurrentControlSet"
$rdpNla = (gp "$cc\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -ea 0).UserAuthentication
$lm = gp "$cc\\Services\\LanmanServer\\Parameters" -ea 0
$smb1 = $lm.SMB1
$smbSrvSign = $lm.RequireSecuritySignature
$smbEncrypt = $lm.EncryptData
$lw = gp "$cc\\Services\\LanmanWorkstation\\Parameters" -ea 0
$smbCliSign = $lw.RequireSecuritySignature
$guestAuth = $lw.AllowInsecureGuestAuth
$lsa = gp "$cc\\Control\\Lsa" -ea 0
$restrictAnon = $lsa.RestrictAnonymous
$ntlmLevel = $lsa.LmCompatibilityLevel
$wdigest = (gp "$cc\\Control\\SecurityProviders\\WDigest" -ea 0).UseLogonCredential
$llmnr = (gp "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" -ea 0).EnableMulticast
$fw = (gp "$cc\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile" -ea 0).EnableFirewall
[PSCustomObject]@{
    Rdp = $rdpNla
    Smb1 = $smb1
    SmbSrvSign = $smbSrvSign
    SmbCliSign = $smbCliSign
    RestrictAnon = $restrictAnon
    GuestAuth = $guestAuth
    SmbEncrypt = $smbEncrypt
    Llmnr = $llmnr
    Wdigest = $wdigest
    NtlmLevel = $ntlmLevel
    Fw = $fw
} | ConvertTo-Json -Compress -Depth 2
"""

        result = session.run_ps(ps_script)

        if result.status_code != 0:
            err = result.std_err.decode("utf-8", errors="replace").strip()
            return {"reachable": False, "error": f"WinRM erreur : {err}"}

        output = result.std_out.decode("utf-8", errors="replace").strip()
        if not output:
            return {"reachable": False, "error": "Aucune donnée retournée"}

        data = json.loads(output)
        detected_hostname = (data.get("Hostname") or "").rstrip(".").lower()
        detected_os = data.get("Caption") or ""
        detected_version = _extract_windows_version(detected_os)
        detected_ip = (data.get("IP") or "").replace(",", ", ")

        apps = data.get("Apps") or []
        if isinstance(apps, dict):
            apps = [apps]
        packages = [
            {"name": a.get("Name"), "version": a.get("Version")}
            for a in apps if a.get("Name")
        ][:300]

        disks = data.get("Disks") or []
        if isinstance(disks, dict):
            disks = [disks]
        hardware = {
            "cpu": data.get("CPU") or "",
            "arch": _format_arch(data.get("Arch")),
            "cores": data.get("Cores"),
            "ram_gb": data.get("RamGB"),
            "disks": [
                {"name": d.get("Name"), "total_gb": d.get("TotalGB"), "free_gb": d.get("FreeGB")}
                for d in disks
            ],
            "ip": detected_ip,
            "mac": _format_macs(data.get("MAC")),
            "open_ports": _parse_ports(data.get("Ports")),
        }

        # Appel WinRM séparé (budget de commande encodée dédié, cf. docs/ARCHITECTURE.md
        # § Note taille de commande WinRM) : regrouper conformité + inventaire dans un seul
        # script a déjà dépassé la limite de ~8191 caractères à plusieurs reprises à mesure
        # que des checks s'ajoutent — deux scripts focalisés scalent, un seul script qu'on
        # recompacte à chaque ajout ne scale pas.
        compliance_data = {}
        result2 = session.run_ps(ps_compliance_script)
        if result2.status_code == 0:
            output2 = result2.std_out.decode("utf-8", errors="replace").strip()
            if output2:
                compliance_data = json.loads(output2)
        else:
            logger.warning(f"Scan WinRM {host} — conformité indisponible : "
                            f"{result2.std_err.decode('utf-8', errors='replace').strip()}")

        compliance = _build_compliance_windows(compliance_data, hardware["open_ports"])

        return _build_result(asset, detected_hostname, detected_os, detected_version, detected_ip, packages, hardware, compliance)

    except Exception as e:
        logger.error(f"Scan WinRM {host} erreur : {e}")
        return {"reachable": False, "error": str(e)}


# ─── Linux via SSH ─────────────────────────────────────────────────────────────

async def _scan_linux(asset: Asset, username: Optional[str] = None, password: Optional[str] = None) -> dict:
    host = asset.ip_address or asset.hostname
    if not host:
        return {"reachable": False, "error": "Adresse IP / hostname manquant"}

    # Identifiants ponctuels (non persistés) si fournis pour ce scan — sinon la
    # clé SSH partagée du parc (SSH_USER/SSH_KEY_PATH).
    ssh_user = username or settings.SSH_USER
    if not ssh_user:
        return {"reachable": False, "error": "Identifiants manquants (ni SSH_USER configuré, ni utilisateur fourni)"}

    connect_kwargs = dict(username=ssh_user, connect_timeout=15)
    if password:
        connect_kwargs["password"] = password
    else:
        connect_kwargs["client_keys"] = [settings.SSH_KEY_PATH] if settings.SSH_KEY_PATH else None

    try:
        async with await connect_trusted(host, **connect_kwargs) as conn:
            # Les 15 commandes sont indépendantes (aucune ne dépend du résultat d'une
            # autre) — lancées par petits lots concurrents plutôt qu'enchaînées une par
            # une : chaque `await` séquentiel payait la latence réseau en plus du temps
            # d'exécution distant, principal facteur de lenteur perçue du scan (signalé
            # par l'utilisateur, 27/07/2026). Lots de 5 plutôt que les 14 d'un coup :
            # `asyncio.gather` sur la totalité dépasse `MaxSessions` (souvent 10 par
            # défaut dans sshd_config, nombre de canaux ouverts simultanément sur UNE
            # connexion) → `open failed` sur les canaux en trop, constaté en direct
            # contre gitlab.aer.loc avant ce correctif.
            commands = {
                "hostname": "hostname -f",
                "pretty": "cat /etc/os-release | grep '^PRETTY_NAME=' | cut -d= -f2 | tr -d '\"'",
                "version": "cat /etc/os-release | grep '^VERSION_ID=' | cut -d= -f2 | tr -d '\"'",
                "pkgs": (
                    "dpkg -l 2>/dev/null | awk 'NR>5 {print $2\",\"$3}' "
                    "|| rpm -qa --queryformat '%{NAME},%{VERSION}\\n' 2>/dev/null"
                ),
                # Version candidate disponible par paquet (07/08/2026, "dernière version
                # disponible" à côté de la version installée, demande explicite) — lit
                # le cache apt local tel quel, ne lance JAMAIS `apt update` (écrirait sur
                # le disque de l'actif, contraire à la règle de non-intervention) : le
                # résultat dépend donc de la fraîcheur du cache apt du serveur lui-même
                # (mise à jour périodique via cron/unattended-upgrades, hors contrôle de
                # CBR), cohérent avec l'esprit lecture-seule du reste du scan. `grep
                # 'upgradable from'` plutôt que `tail -n +2` : la ligne "Listing..." part
                # sur stdout ou stderr selon la version d'apt, un filtre sur le contenu
                # réel est plus robuste qu'un filtre positionnel. apt-only (Debian/Ubuntu) —
                # vide sur RPM, pas d'équivalent branché pour l'instant.
                "upgradable": "apt list --upgradable 2>/dev/null | grep 'upgradable from'",
                # LC_ALL=C force les libellés lscpu en anglais ("Model name:") quel que
                # soit le paramètre régional du serveur (ex: fr_FR.UTF-8 → "Nom de
                # modèle :") — sans ça, le grep sur le libellé anglais ne matche jamais
                # et le CPU remonte vide sur toute machine en locale non-anglaise.
                "cpu": "LC_ALL=C lscpu 2>/dev/null | grep '^Model name:' | sed 's/Model name:\\s*//'",
                "arch": "uname -m 2>/dev/null",
                "cores": "nproc 2>/dev/null",
                "ram": "free -b 2>/dev/null | awk '/^Mem:/{print $2}'",
                "disks": (
                    "df -BG --output=target,size,avail -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -n +2"
                ),
                "mac": "cat /sys/class/net/*/address 2>/dev/null | grep -v '00:00:00:00:00:00' | sort -u",
                "ip": "hostname -I 2>/dev/null",
                "ports": "ss -tuln 2>/dev/null | awk 'NR>1{n=split($5,a,\":\"); print a[n]}' | sort -un",
                # Durcissement (lecture seule) : /etc/login.defs est world-readable sur
                # la quasi-totalité des distros. `sshd -T` nécessite généralement root —
                # `sudo -n` échoue silencieusement (pas de prompt, pas de hang) si
                # NOPASSWD n'est pas configuré ; le check remonte alors "unknown".
                "logindefs": "grep -E '^(PASS_MAX_DAYS|PASS_MIN_LEN)\\s' /etc/login.defs 2>/dev/null",
                "sshd": "sudo -n sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication) '",
            }
            keys = list(commands.keys())
            results = {}
            BATCH_SIZE = 5
            for i in range(0, len(keys), BATCH_SIZE):
                batch = keys[i:i + BATCH_SIZE]
                batch_results = await asyncio.gather(
                    *(conn.run(commands[k], check=False) for k in batch)
                )
                results.update(zip(batch, batch_results))

            hostname_r, pretty_r, version_r = results["hostname"], results["pretty"], results["version"]
            pkgs_r, cpu_r, arch_r, cores_r = results["pkgs"], results["cpu"], results["arch"], results["cores"]
            ram_r, disks_r, mac_r, ip_r = results["ram"], results["disks"], results["mac"], results["ip"]
            ports_r, logindefs_r, sshd_r = results["ports"], results["logindefs"], results["sshd"]
            upgradable_r = results["upgradable"]

            detected_hostname = (hostname_r.stdout or "").strip().lower()
            detected_os = (pretty_r.stdout or "").strip()
            detected_version = (version_r.stdout or "").strip()
            detected_ip = ", ".join((ip_r.stdout or "").split())

            # {nom du paquet: version candidate} — cf. commande "upgradable" ci-dessus.
            # Format d'une ligne : "curl/stable 7.88.1-10+deb12u5 amd64 [upgradable
            # from: 7.88.1-10+deb12u4]" ; on ne garde que le nom (avant "/") et la
            # version candidate (2e champ) — la version "from" fait déjà doublon avec
            # celle de `dpkg -l` juste en dessous.
            available_versions: dict[str, str] = {}
            for line in (upgradable_r.stdout or "").splitlines():
                m = _APT_UPGRADABLE_RE.match(line.strip())
                if m:
                    available_versions[m.group(1)] = m.group(2)

            packages = []
            for line in (pkgs_r.stdout or "").splitlines()[:300]:
                parts = line.split(",", 1)
                if len(parts) == 2 and parts[0]:
                    pkg = {"name": parts[0], "version": parts[1]}
                    candidate = available_versions.get(parts[0])
                    if candidate:
                        pkg["available_version"] = candidate
                    packages.append(pkg)

            disks = []
            for line in (disks_r.stdout or "").splitlines():
                parts = line.split()
                if len(parts) == 3:
                    disks.append({
                        "name": parts[0],
                        "total_gb": float(parts[1].rstrip("G") or 0),
                        "free_gb": float(parts[2].rstrip("G") or 0),
                    })

            try:
                cores = int((cores_r.stdout or "").strip())
            except ValueError:
                cores = None
            try:
                ram_gb = round(float((ram_r.stdout or "").strip()) / (1024 ** 3), 1)
            except ValueError:
                ram_gb = None

            macs = [line.strip() for line in (mac_r.stdout or "").splitlines() if line.strip()]

            hardware = {
                "cpu": (cpu_r.stdout or "").strip(),
                "arch": _format_arch((arch_r.stdout or "").strip()),
                "cores": cores,
                "ram_gb": ram_gb,
                "disks": disks,
                "ip": detected_ip,
                "mac": ", ".join(macs),
                "open_ports": _parse_ports((ports_r.stdout or "").split()),
            }

            compliance = _build_compliance_linux(logindefs_r.stdout, sshd_r.stdout, hardware["open_ports"])

            return _build_result(asset, detected_hostname, detected_os, detected_version, detected_ip, packages, hardware, compliance)

    except Exception as e:
        logger.error(f"Scan SSH {host} erreur : {e}")
        return {"reachable": False, "error": str(e)}


# ─── Point d'entrée unifié ─────────────────────────────────────────────────────

async def scan_asset(asset: Asset, username: Optional[str] = None, password: Optional[str] = None) -> dict:
    """
    Vérifie (lecture seule) la fiabilité des infos déclarées et collecte la liste
    des applications installées. Ne modifie jamais rien sur le serveur.

    `username`/`password` : identifiants ponctuels pour ce scan (Linux uniquement,
    jamais persistés) — utile pour une machine qui n'a pas encore la clé SSH
    partagée du parc. Ignorés côté Windows (compte de service WinRM partagé).
    """
    os_lower = (asset.os or "").lower()
    if "windows" in os_lower:
        result = await asyncio.get_event_loop().run_in_executor(None, _scan_windows, asset)
    else:
        result = await _scan_linux(asset, username=username, password=password)
    return result


# ─── Application d'un résultat de scan à l'actif ────────────────────────────────

async def apply_scan_result(asset: Asset, result: dict, session: AsyncSession) -> dict:
    """Persiste un résultat de scan sur `asset` et déclenche la suite (matching CPE,
    cycle patch check) — extrait de `routers/assets.py::scan_asset_endpoint` (12/08/2026,
    module Agents) pour être partagé par DEUX producteurs de `result` au même shape
    (cf. `_build_result` plus haut) : le scan pull SSH/WinRM existant, et le push d'un
    agent posé sur un poste (`routers/agents.py::checkin`). Les deux doivent aboutir
    exactement au même traitement côté données, sans dupliquer cette logique.

    `result` peut porter des checks `compliance.checks` au-delà de ceux produits par
    `_build_compliance_windows`/`_build_compliance_linux` ci-dessus (ex: BitLocker/LUKS,
    comptes admin locaux — spécifiques à l'agent, absents du scan SSH/WinRM) : cette
    fonction ne filtre jamais la liste, elle la stocke telle quelle."""
    if result.get("reachable"):
        asset.last_scan = datetime.now(timezone.utc)
        asset.installed_packages = result.get("packages", [])
        asset.last_scan_result = result
        asset.hardware = result.get("hardware") or {}
        asset.scan_reachable = True
        asset.scan_error = None

        detected = result.get("detected") or {}

        detected_hostname = (detected.get("hostname") or "").strip()
        if detected_hostname and detected_hostname.lower() != (asset.hostname or "").strip().lower():
            old_name = asset.name
            asset.hostname = detected_hostname
            asset.name = detected_hostname
            result["name_corrected"] = {"from": old_name, "to": detected_hostname}

        detected_version = (detected.get("os_version") or "").strip()
        if detected_version and detected_version != (asset.os_version or "").strip():
            asset.os_version = detected_version
        if not (asset.os or "").strip() and detected.get("os"):
            asset.os = detected["os"]

        cpe = _build_cpe(detected.get("os") or asset.os or "", detected.get("os_version") or asset.os_version or "")
        if cpe:
            asset.cpe_list = [cpe]

        try:
            await session.commit()
        except IntegrityError:
            # Un autre actif porte déjà ce hostname (doublon probable) — on garde le
            # reste du scan (paquets, hardware, CPE) mais on renonce à la correction
            # du nom pour ne pas provoquer de collision.
            await session.rollback()
            # rollback() expire tous les attributs de `asset` — un refresh() explicite
            # est nécessaire avant de les relire ci-dessous (`asset.os_version` ligne
            # suivante) : un accès direct sur un attribut expiré hors d'un appel de
            # session awaité plante en MissingGreenlet (pas de greenlet actif pour le
            # lazy-load implicite), constaté en conditions réelles au check-in agent.
            await session.refresh(asset)
            asset.last_scan = datetime.now(timezone.utc)
            asset.installed_packages = result.get("packages", [])
            asset.last_scan_result = result
            asset.hardware = result.get("hardware") or {}
            asset.scan_reachable = True
            asset.scan_error = None
            if detected_version and detected_version != (asset.os_version or "").strip():
                asset.os_version = detected_version
            if not (asset.os or "").strip() and detected.get("os"):
                asset.os = detected["os"]
            if cpe:
                asset.cpe_list = [cpe]
            result.pop("name_corrected", None)
            result["name_correction_error"] = f"Un autre actif utilise déjà le hostname '{detected_hostname}'."
            await session.commit()

        run_cpe_matching_for_asset_task.apply_async(args=[str(asset.id)], queue='default')
        await reset_patch_check_timestamps(asset_ids=[str(asset.id)])
        asyncio.create_task(run_full_patch_check_cycle(asset_ids=[str(asset.id)]))
    else:
        asset.last_scan = datetime.now(timezone.utc)
        asset.last_scan_result = result
        asset.scan_reachable = False
        asset.scan_error = result.get("error")
        await session.commit()

    return result
