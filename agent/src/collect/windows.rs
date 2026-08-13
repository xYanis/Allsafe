//! Collecte Windows — parité registre avec `asset_scanner.py::_scan_windows` (mêmes clés,
//! mêmes checks de durcissement CIS-like) + checks propres à l'agent listés dans
//! `docs/vulnerabilites_securite.md` §3.7 (BitLocker, comptes admin locaux, verrouillage
//! d'écran, restriction USB, journalisation PowerShell). L'agent tourne localement
//! (Planificateur de tâches, généralement SYSTEM) : accès direct au registre HKLM sans les
//! limites WMI/DCOM du compte de service WinRM distant (cf. commentaire `_scan_windows`).
//! Matériel/réseau via `sysinfo` (cross-platform, mieux testé qu'un P/Invoke maison) plutôt
//! que le registre — seuls les checks de durcissement et l'inventaire applicatif, illisibles
//! autrement en lecture seule, passent par le registre.

use crate::model::{Check, CheckinPayload, Compliance, Detected, Disk, Hardware, Package};
use std::process::Command;
use sysinfo::{Disks, Networks, System};
use winreg::enums::*;
use winreg::RegKey;

fn hklm() -> RegKey {
    RegKey::predef(HKEY_LOCAL_MACHINE)
}

fn reg_string(path: &str, name: &str) -> Option<String> {
    hklm().open_subkey_with_flags(path, KEY_READ).ok()?.get_value(name).ok()
}

fn reg_dword(path: &str, name: &str) -> Option<u32> {
    hklm().open_subkey_with_flags(path, KEY_READ).ok()?.get_value(name).ok()
}

fn run(cmd: &str) -> Option<String> {
    let output = Command::new("cmd").args(["/C", cmd]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_lossy(cmd: &str) -> String {
    run(cmd).unwrap_or_default()
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default().to_lowercase()
}

/// Même règle que `asset_scanner.py::_extract_windows_version` : année à 4 chiffres dans
/// le Caption, sinon jeton "Windows 10"/"Windows 11" explicite.
fn extract_windows_version(caption: &str) -> String {
    let bytes = caption.as_bytes();
    for i in 0..bytes.len().saturating_sub(3) {
        if let Ok(slice) = std::str::from_utf8(&bytes[i..i + 4]) {
            if let Ok(year) = slice.parse::<u32>() {
                if (1900..2100).contains(&year) {
                    return slice.to_string();
                }
            }
        }
    }
    for token in ["10", "11"] {
        if caption.contains(&format!("Windows {token}")) {
            return token.to_string();
        }
    }
    String::new()
}

fn os_caption() -> (String, String) {
    let path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let product_name = reg_string(path, "ProductName").unwrap_or_default();
    let build = reg_string(path, "CurrentBuildNumber").unwrap_or_default();
    let caption = if product_name.is_empty() { String::new() } else { format!("{product_name} (build {build})") };
    let version = extract_windows_version(&caption);
    (caption, version)
}

fn fqdn() -> String {
    let comp = hostname();
    let domain = reg_string(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Domain").unwrap_or_default();
    if domain.is_empty() { comp } else { format!("{comp}.{domain}") }
}

/// Inventaire applicatif — mêmes clés `Uninstall` (64 et 32 bits) que le scan WinRM
/// (`Get-ItemProperty` sur les deux chemins), énumérées directement plutôt que via WinRM.
fn installed_apps() -> Vec<Package> {
    let mut packages = Vec::new();
    for path in [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ] {
        let Ok(key) = hklm().open_subkey_with_flags(path, KEY_READ) else { continue };
        for subkey_name in key.enum_keys().filter_map(|k| k.ok()) {
            let Ok(subkey) = key.open_subkey_with_flags(&subkey_name, KEY_READ) else { continue };
            let name: String = match subkey.get_value("DisplayName") {
                Ok(v) => v,
                Err(_) => continue,
            };
            if name.is_empty() {
                continue;
            }
            let version: String = subkey.get_value("DisplayVersion").unwrap_or_default();
            packages.push(Package { name, version, available_version: None });
            if packages.len() >= 300 {
                return packages;
            }
        }
    }
    packages
}

fn hardware_and_network() -> Hardware {
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu = sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_default();
    let cores = u32::try_from(sys.cpus().len()).ok();
    let ram_gb = Some((sys.total_memory() as f64 / 1024_f64.powi(3) * 10.0).round() / 10.0);
    let arch = std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_default();

    let disks_list = Disks::new_with_refreshed_list();
    let disks: Vec<Disk> = disks_list
        .iter()
        .filter(|d| !d.is_removable())
        .map(|d| Disk {
            name: d.mount_point().to_string_lossy().to_string(),
            total_gb: (d.total_space() as f64 / 1024_f64.powi(3) * 10.0).round() / 10.0,
            free_gb: (d.available_space() as f64 / 1024_f64.powi(3) * 10.0).round() / 10.0,
        })
        .collect();

    let networks = Networks::new_with_refreshed_list();
    let mut macs: Vec<String> = Vec::new();
    let mut ips: Vec<String> = Vec::new();
    for (_name, data) in networks.iter() {
        let mac = data.mac_address().to_string();
        if !mac.is_empty() && mac != "00:00:00:00:00:00" && !macs.contains(&mac) {
            macs.push(mac);
        }
        for ip in data.ip_networks() {
            if ip.addr.is_ipv4() && !ip.addr.is_loopback() {
                let s = ip.addr.to_string();
                if !ips.contains(&s) {
                    ips.push(s);
                }
            }
        }
    }

    let open_ports = open_ports();

    Hardware {
        cpu,
        arch: format_arch(&arch),
        cores,
        ram_gb,
        disks,
        ip: ips.join(", "),
        mac: macs.join(", "),
        open_ports,
    }
}

fn format_arch(raw: &str) -> String {
    match raw.to_uppercase().as_str() {
        "AMD64" => "64 bits (x64)".to_string(),
        "ARM64" => "64 bits (ARM64)".to_string(),
        "X86" => "32 bits (x86)".to_string(),
        other if other.is_empty() => String::new(),
        other => other.to_string(),
    }
}

/// Ports TCP en écoute — `netstat` plutôt qu'un appel WMI (droits suffisants en local,
/// mais WMI reste plus lourd à câbler sans dépendance COM dédiée pour un simple listing).
fn open_ports() -> Vec<u32> {
    let out = run_lossy("netstat -ano -p TCP");
    let mut ports = std::collections::HashSet::new();
    for line in out.lines() {
        if !line.contains("LISTENING") {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Format: "  TCP    0.0.0.0:135   0.0.0.0:0   LISTENING   1234"
        if fields.len() >= 2 {
            if let Some(port_str) = fields[1].rsplit(':').next() {
                if let Ok(port) = port_str.parse::<u32>() {
                    ports.insert(port);
                }
            }
        }
    }
    let mut sorted: Vec<u32> = ports.into_iter().collect();
    sorted.sort_unstable();
    sorted
}

// ─── Durcissement (registre) — parité avec `_build_compliance_windows` ────────────────

fn password_policy_checks() -> Vec<Check> {
    // `net accounts` reste la seule source non-WMI pour la stratégie de mot de passe côté
    // agent aussi — même limite de dépendance à la langue d'installation que le scan WinRM.
    let raw = run_lossy("net accounts");
    let mut checks = Vec::new();

    let min_len = raw.lines().find_map(|l| {
        let lower = l.to_lowercase();
        if lower.contains("longueur minimale du mot de passe") || lower.contains("minimum password length") {
            l.rsplit(':').next()?.trim().parse::<u32>().ok()
        } else {
            None
        }
    });
    checks.push(match min_len {
        None => Check::new("password_min_length", "Longueur minimale du mot de passe", "unknown", "Stratégie de mot de passe non interprétable (net accounts)"),
        Some(len) => Check::new("password_min_length", "Longueur minimale du mot de passe", if len >= 8 { "ok" } else { "warn" }, format!("{len} caractères")),
    });

    let max_age_raw = raw.lines().find_map(|l| {
        let lower = l.to_lowercase();
        if lower.contains("de vie maximale du mot de passe") || lower.contains("maximum password age") {
            l.rsplit(':').next().map(|s| s.trim().to_string())
        } else {
            None
        }
    });
    checks.push(match max_age_raw {
        None => Check::new("password_max_age", "Âge maximal du mot de passe", "unknown", "Stratégie de mot de passe indisponible"),
        Some(v) if v.parse::<u32>().is_err() => Check::new("password_max_age", "Âge maximal du mot de passe", "warn", "N'expire jamais"),
        Some(v) => {
            let days: u32 = v.parse().unwrap();
            Check::new("password_max_age", "Âge maximal du mot de passe", if days <= 90 { "ok" } else { "warn" }, format!("{days} jours"))
        }
    });

    checks
}

fn registry_bool_check(id: &str, label: &str, path: &str, name: &str, ok_value: u32, absent_detail: &str, ok_detail: &str, warn_detail: &str) -> Check {
    match reg_dword(path, name) {
        None => Check::new(id, label, "unknown", absent_detail),
        Some(v) if v == ok_value => Check::new(id, label, "ok", ok_detail),
        Some(_) => Check::new(id, label, "warn", warn_detail),
    }
}

fn hardening_checks(open_ports: &[u32]) -> Vec<Check> {
    let mut checks = password_policy_checks();

    checks.push(registry_bool_check(
        "rdp_nla", "Authentification niveau réseau (RDP/NLA)",
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 1,
        "Clé de registre absente", "Activée", "Désactivée",
    ));

    checks.push(registry_bool_check(
        "smb1", "SMBv1 activé",
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0,
        "Clé de registre absente (SMBv1 désactivé par défaut sur les versions récentes)", "Désactivé", "Activé",
    ));

    checks.push(registry_bool_check(
        "smb_signing_server", "Signature SMB requise (serveur)",
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", 1,
        "Clé de registre absente (non forcée par défaut)", "Requise", "Non requise — expose au relais SMB entrant",
    ));

    checks.push(registry_bool_check(
        "smb_signing_client", "Signature SMB requise (client)",
        r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", 1,
        "Clé de registre absente (non forcée par défaut)", "Requise", "Non requise — expose au relais SMB sortant",
    ));

    checks.push(match reg_dword(r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous") {
        None => Check::new("smb_restrict_anonymous", "Sessions anonymes restreintes", "unknown", "Clé de registre absente"),
        Some(v) if v >= 1 => Check::new("smb_restrict_anonymous", "Sessions anonymes restreintes", "ok", "Restreintes"),
        Some(_) => Check::new("smb_restrict_anonymous", "Sessions anonymes restreintes", "warn", "Non restreintes — énumération sans authentification possible"),
    });

    checks.push(registry_bool_check(
        "smb_guest_auth", "Connexions invité non sécurisées",
        r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "AllowInsecureGuestAuth", 0,
        "Clé de registre absente (désactivées par défaut depuis Windows 10 1709 / Server 2019)", "Bloquées", "Autorisées",
    ));

    checks.push(registry_bool_check(
        "smb_encryption", "Chiffrement SMB",
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EncryptData", 1,
        "Clé de registre absente (non activé par défaut)", "Activé", "Désactivé",
    ));

    checks.push(registry_bool_check(
        "llmnr", "LLMNR désactivé",
        r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0,
        "Stratégie de groupe absente (LLMNR activé par défaut si non configuré)", "Désactivé",
        "Activé — expose au poisoning LLMNR/NBT-NS (type Responder)",
    ));

    checks.push(match reg_dword(r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential") {
        None => Check::new("wdigest", "WDigest désactivé", "unknown", "Clé de registre absente (désactivé par défaut depuis Windows 8.1 / Server 2012 R2)"),
        Some(1) => Check::new("wdigest", "WDigest désactivé", "warn", "Activé — mots de passe en clair exposés en mémoire (dump LSASS)"),
        Some(_) => Check::new("wdigest", "WDigest désactivé", "ok", "Désactivé"),
    });

    checks.push(match reg_dword(r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel") {
        None => Check::new("ntlm_level", "Niveau NTLM (LmCompatibilityLevel)", "unknown", "Clé de registre absente (valeur par défaut du système)"),
        Some(level) if level >= 3 => Check::new("ntlm_level", "Niveau NTLM (LmCompatibilityLevel)", "ok", format!("Niveau {level} (NTLMv2 uniquement)")),
        Some(level) => Check::new("ntlm_level", "Niveau NTLM (LmCompatibilityLevel)", "warn", format!("Niveau {level} — NTLMv1 accepté, crackable/relayable")),
    });

    checks.push(registry_bool_check(
        "firewall", "Pare-feu Windows (profil standard)",
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall", 1,
        "Clé de registre absente", "Activé", "Désactivé",
    ));

    let risky: &[(u32, &str)] = &[
        (21, "FTP (non chiffré)"), (23, "Telnet (non chiffré)"), (69, "TFTP (non authentifié)"),
        (512, "rexec (non chiffré)"), (513, "rlogin (non chiffré)"), (514, "rsh (non chiffré)"),
    ];
    let found: Vec<String> = risky.iter().filter(|(p, _)| open_ports.contains(p)).map(|(p, n)| format!("{n} (port {p})")).collect();
    checks.push(if found.is_empty() {
        Check::new("exposed_ports", "Services exposés à risque", "ok", "Aucun service historiquement non sécurisé détecté sur les ports en écoute")
    } else {
        Check::new("exposed_ports", "Services exposés à risque", "warn", found.join(", "))
    });

    checks
}

// ─── Checks propres à l'agent (§3.7) — illisibles par le compte de service WinRM ───────

/// BitLocker — `manage-bde -status` (outil intégré, pas de dépendance WMI/PowerShell
/// requise). Cherche "Protection Status" à "Protection On" sur au moins un volume.
fn bitlocker_check() -> Check {
    let out = run("manage-bde -status");
    match out {
        None => Check::new("bitlocker", "Chiffrement disque (BitLocker)", "unknown", "manage-bde indisponible (édition Windows sans BitLocker ?)"),
        Some(text) => {
            if text.to_lowercase().contains("protection on") {
                Check::new("bitlocker", "Chiffrement disque (BitLocker)", "ok", "Au moins un volume protégé par BitLocker")
            } else {
                Check::new("bitlocker", "Chiffrement disque (BitLocker)", "warn", "Aucun volume protégé par BitLocker détecté")
            }
        }
    }
}

/// Comptes membres du groupe Administrateurs locaux — `net localgroup administrators`.
fn local_admins_check() -> Check {
    let Some(out) = run("net localgroup administrators") else {
        return Check::new("privileged_accounts", "Comptes administrateurs locaux", "unknown", "net localgroup indisponible");
    };
    let members: Vec<&str> = out
        .lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with("Alias name")
                && !l.starts_with("Nom d'alias")
                && !l.starts_with("Comment")
                && !l.starts_with("Commentaire")
                && !l.starts_with("Members")
                && !l.starts_with("Membres")
                && !l.starts_with("The command completed")
                && !l.starts_with("La commande s'est")
                && !l.chars().all(|c| c == '-')
        })
        .collect();
    if members.is_empty() {
        return Check::new("privileged_accounts", "Comptes administrateurs locaux", "unknown", "Aucun membre détecté (sortie non interprétable)");
    }
    Check::new("privileged_accounts", "Comptes administrateurs locaux", "ok", format!("{} compte(s) : {}", members.len(), members.join(", ")))
}

/// Verrouillage d'écran — stratégie de groupe `InactivityTimeoutSecs` (HKLM, s'applique à
/// tous les utilisateurs) plutôt que la valeur HKCU de l'utilisateur courant : l'agent
/// tourne généralement en tâche planifiée sous SYSTEM, sans session interactive HKCU fiable.
fn screen_lock_check() -> Check {
    match reg_dword(r"SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop", "InactivityTimeoutSecs") {
        None => Check::new("screen_lock", "Verrouillage d'écran automatique", "unknown", "Stratégie InactivityTimeoutSecs absente (non configurée par GPO)"),
        Some(0) => Check::new("screen_lock", "Verrouillage d'écran automatique", "warn", "Timeout à 0 — verrouillage automatique désactivé"),
        Some(secs) => Check::new("screen_lock", "Verrouillage d'écran automatique", if secs <= 900 { "ok" } else { "warn" }, format!("{secs} secondes d'inactivité avant verrouillage")),
    }
}

/// Restriction USB — clé `USBSTOR\Start` (3 = démarrage automatique du pilote de
/// stockage de masse USB, 4 = désactivé/restreint), même mécanisme que la stratégie de
/// groupe "Empêcher l'installation de disques amovibles".
fn usb_policy_check() -> Check {
    match reg_dword(r"SYSTEM\CurrentControlSet\Services\USBSTOR", "Start") {
        None => Check::new("usb_policy", "Restriction des périphériques USB", "unknown", "Clé de registre USBSTOR absente"),
        Some(4) => Check::new("usb_policy", "Restriction des périphériques USB", "ok", "Stockage de masse USB désactivé (USBSTOR Start=4)"),
        Some(v) => Check::new("usb_policy", "Restriction des périphériques USB", "warn", format!("Stockage de masse USB autorisé (USBSTOR Start={v})")),
    }
}

/// Journalisation des blocs de script PowerShell — visibilité forensique de première
/// ligne en cas d'exécution malveillante (living-off-the-land), absente par défaut.
fn powershell_logging_check() -> Check {
    match reg_dword(r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging") {
        None => Check::new("powershell_logging", "Journalisation PowerShell (ScriptBlockLogging)", "warn", "Stratégie absente — non activée par défaut"),
        Some(1) => Check::new("powershell_logging", "Journalisation PowerShell (ScriptBlockLogging)", "ok", "Activée"),
        Some(_) => Check::new("powershell_logging", "Journalisation PowerShell (ScriptBlockLogging)", "warn", "Désactivée"),
    }
}

/// Transcription PowerShell (13/08/2026) — complète ScriptBlockLogging ci-dessus : capture
/// le texte intégral de chaque session (entrées + sorties) dans des fichiers journaux,
/// pas seulement les blocs de script exécutés.
fn powershell_transcription_check() -> Check {
    match reg_dword(r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting") {
        None => Check::new("powershell_transcription", "Journalisation PowerShell (Transcription)", "warn", "Stratégie absente — non activée par défaut"),
        Some(1) => Check::new("powershell_transcription", "Journalisation PowerShell (Transcription)", "ok", "Activée"),
        Some(_) => Check::new("powershell_transcription", "Journalisation PowerShell (Transcription)", "warn", "Désactivée"),
    }
}

/// Protection temps réel Windows Defender (13/08/2026) — proxy EDR minimal et honnête :
/// détecte si Defender est explicitement désactivé, ne prétend pas identifier un antivirus
/// tiers (WithSecure et consorts n'exposent pas cette clé) — `unknown`/`ok` par défaut,
/// jamais un faux "aucun EDR" quand un tiers gère en fait la protection.
fn defender_realtime_check() -> Check {
    match reg_dword(r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring") {
        None => Check::new("defender_realtime", "Protection temps réel (Windows Defender)", "ok", "Active par défaut (clé de désactivation absente)"),
        Some(0) => Check::new("defender_realtime", "Protection temps réel (Windows Defender)", "ok", "Active"),
        Some(_) => Check::new("defender_realtime", "Protection temps réel (Windows Defender)", "warn", "Désactivée — vérifier qu'un antivirus tiers (EDR) prend bien le relais"),
    }
}

/// Contrôle de compte utilisateur (UAC) — registre plutôt que via `_build_compliance_windows`
/// (les 14 checks partagés avec le scan WinRM ci-dessus) : nouveau check agent-only
/// (13/08/2026), jamais rétroporté vers le compte de service (même principe que BitLocker/
/// comptes locaux/USB déjà agent-only).
fn uac_enabled_check() -> Check {
    registry_bool_check(
        "uac_enabled", "Contrôle de compte utilisateur (UAC)",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1,
        "Clé de registre absente (UAC activé par défaut si non configuré)", "Activé",
        "Désactivé — élévation de privilèges silencieuse possible",
    )
}

/// Compte administrateur intégré (SID -500) renommé — via `Get-LocalUser`, pas de clé de
/// registre directe pour ce nom. Cible évidente pour un brute-force RDP/SMB s'il garde son
/// nom par défaut ("Administrateur"/"Administrator" selon la langue d'installation).
fn admin_account_renamed_check() -> Check {
    let Some(out) = run(r#"powershell -NoProfile -Command "(Get-LocalUser | Where-Object {$_.SID -like '*-500'}).Name""#) else {
        return Check::new("admin_account_renamed", "Compte administrateur intégré renommé", "unknown", "Get-LocalUser indisponible");
    };
    let name = out.trim();
    if name.is_empty() {
        return Check::new("admin_account_renamed", "Compte administrateur intégré renommé", "unknown", "Compte SID -500 introuvable (sortie non interprétable)");
    }
    if name.eq_ignore_ascii_case("Administrateur") || name.eq_ignore_ascii_case("Administrator") {
        Check::new("admin_account_renamed", "Compte administrateur intégré renommé", "warn", format!("Toujours nommé « {name} » — cible évidente pour un brute-force"))
    } else {
        Check::new("admin_account_renamed", "Compte administrateur intégré renommé", "ok", format!("Renommé en « {name} »"))
    }
}

/// Partages réseau accordant Modifier/Contrôle total à "Tout le monde"/Everyone — exclut
/// les partages administratifs par défaut (ADMIN$/C$/D$/IPC$, Everyone y figure par
/// conception Windows, pas un signe de mauvaise configuration).
fn network_shares_everyone_check() -> Check {
    let cmd = r#"powershell -NoProfile -Command "Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('ADMIN$','C$','D$','IPC$') } | ForEach-Object { Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue } | Where-Object { $_.AccountName -like '*Everyone*' } | Select-Object -ExpandProperty Name -Unique""#;
    let Some(out) = run(cmd) else {
        return Check::new("network_shares_everyone", "Partages réseau ouverts à \"Tout le monde\"", "unknown", "Get-SmbShare indisponible");
    };
    let shares: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if shares.is_empty() {
        Check::new("network_shares_everyone", "Partages réseau ouverts à \"Tout le monde\"", "ok", "Aucun partage non-administratif n'accorde d'accès à Tout le monde")
    } else {
        Check::new("network_shares_everyone", "Partages réseau ouverts à \"Tout le monde\"", "warn", format!("Partage(s) concerné(s) : {}", shares.join(", ")))
    }
}

pub fn collect() -> CheckinPayload {
    let (caption, version) = os_caption();
    let hardware = hardware_and_network();

    let mut checks = hardening_checks(&hardware.open_ports);
    checks.push(bitlocker_check());
    checks.push(local_admins_check());
    checks.push(screen_lock_check());
    checks.push(usb_policy_check());
    checks.push(powershell_logging_check());
    // Backlog complété (13/08/2026, docs/vulnerabilites_securite.md §3.7).
    checks.push(uac_enabled_check());
    checks.push(powershell_transcription_check());
    checks.push(defender_realtime_check());
    checks.push(admin_account_renamed_check());
    checks.push(network_shares_everyone_check());

    let packages = installed_apps();
    let package_count = packages.len() as u32;
    let ip = hardware.ip.clone();

    CheckinPayload {
        reachable: true,
        detected: Detected { hostname: fqdn().to_lowercase(), os: caption, os_version: version, ip_address: ip },
        packages,
        package_count,
        hardware,
        compliance: Compliance { checks },
        error: None,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        offline_since: None,
        failed_attempts: None,
    }
}
