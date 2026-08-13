//! Collecte Linux — parité avec `asset_scanner.py::_scan_linux` (mêmes commandes, mêmes
//! checks de durcissement CIS-like) + les checks propres à l'agent listés dans
//! `docs/vulnerabilites_securite.md` §3.7 (chiffrement disque, comptes privilégiés,
//! verrouillage d'écran, restriction USB). Contrairement au scan SSH distant, l'agent
//! tourne déjà localement avec les droits nécessaires : pas de `sudo -n` requis pour
//! `sshd -T` — si la commande échoue quand même (agent lancé sans droits suffisants),
//! le check remonte "unknown" plutôt que de faire échouer toute la collecte.

use crate::model::{Check, CheckinPayload, Compliance, Detected, Disk, Hardware, Package};
use std::collections::{HashMap, HashSet};
use std::process::Command;

fn run(cmd: &str) -> Option<String> {
    let output = Command::new("sh").arg("-c").arg(cmd).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_lossy(cmd: &str) -> String {
    run(cmd).unwrap_or_default()
}

const ARCH_LABELS: &[(&str, &str)] = &[
    ("x86_64", "64 bits (x64)"), ("amd64", "64 bits (x64)"), ("x64", "64 bits (x64)"),
    ("aarch64", "64 bits (ARM64)"), ("arm64", "64 bits (ARM64)"),
    ("i386", "32 bits (x86)"), ("i486", "32 bits (x86)"), ("i586", "32 bits (x86)"), ("i686", "32 bits (x86)"), ("x86", "32 bits (x86)"),
    ("armv7l", "32 bits (ARM)"), ("armv6l", "32 bits (ARM)"), ("arm", "32 bits (ARM)"),
];

fn format_arch(raw: &str) -> String {
    let lower = raw.trim().to_lowercase();
    ARCH_LABELS.iter().find(|(k, _)| *k == lower).map(|(_, v)| v.to_string()).unwrap_or_else(|| raw.trim().to_string())
}

const RISKY_PORTS: &[(u32, &str)] = &[
    (21, "FTP (non chiffré)"), (23, "Telnet (non chiffré)"), (69, "TFTP (non authentifié)"),
    (512, "rexec (non chiffré)"), (513, "rlogin (non chiffré)"), (514, "rsh (non chiffré)"),
];

const WEAK_SSH_KEX: &[&str] = &["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"];
const WEAK_SSH_CIPHERS: &[&str] = &[
    "arcfour", "arcfour128", "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "3des-cbc", "blowfish-cbc", "cast128-cbc", "rijndael-cbc@lysator.liu.se",
];
const WEAK_SSH_MACS: &[&str] = &[
    "hmac-md5", "hmac-md5-96", "hmac-sha1-96",
    "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
];

fn exposed_ports_check(open_ports: &[u32]) -> Check {
    let found: Vec<String> = RISKY_PORTS.iter()
        .filter(|(p, _)| open_ports.contains(p))
        .map(|(p, name)| format!("{name} (port {p})"))
        .collect();
    if found.is_empty() {
        Check::new("exposed_ports", "Services exposés à risque", "ok", "Aucun service historiquement non sécurisé détecté sur les ports en écoute")
    } else {
        Check::new("exposed_ports", "Services exposés à risque", "warn", found.join(", "))
    }
}

fn parse_login_defs(raw: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in raw.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 {
            values.insert(parts[0].to_string(), parts[1].to_string());
        }
    }
    values
}

fn parse_sshd_t(raw: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once(char::is_whitespace) {
            values.insert(k.trim().to_lowercase(), v.trim().to_lowercase());
        }
    }
    values
}

fn password_checks(logindefs_raw: &str) -> Vec<Check> {
    let values = parse_login_defs(logindefs_raw);
    let mut checks = Vec::new();

    match values.get("PASS_MAX_DAYS") {
        None => checks.push(Check::new("password_max_age", "Âge maximal du mot de passe", "unknown", "PASS_MAX_DAYS absent de /etc/login.defs")),
        Some(v) => match v.parse::<i64>() {
            Ok(days) => {
                let status = if days > 0 && days <= 90 { "ok" } else { "warn" };
                checks.push(Check::new("password_max_age", "Âge maximal du mot de passe", status, format!("{days} jours (PASS_MAX_DAYS)")));
            }
            Err(_) => checks.push(Check::new("password_max_age", "Âge maximal du mot de passe", "unknown", format!("Valeur non interprétable : {v}"))),
        },
    }

    match values.get("PASS_MIN_LEN") {
        None => checks.push(Check::new("password_min_length", "Longueur minimale du mot de passe", "unknown", "PASS_MIN_LEN absent de /etc/login.defs (souvent délégué à pam_pwquality)")),
        Some(v) => match v.parse::<i64>() {
            Ok(len) => {
                let status = if len >= 8 { "ok" } else { "warn" };
                checks.push(Check::new("password_min_length", "Longueur minimale du mot de passe", status, format!("{len} caractères (PASS_MIN_LEN)")));
            }
            Err(_) => checks.push(Check::new("password_min_length", "Longueur minimale du mot de passe", "unknown", format!("Valeur non interprétable : {v}"))),
        },
    }

    checks
}

fn ssh_checks(sshd_raw: &str) -> Vec<Check> {
    let values = parse_sshd_t(sshd_raw);
    if values.is_empty() {
        return vec![
            Check::new("ssh_root_login", "Connexion SSH root directe", "unknown", "sshd -T inaccessible (droits insuffisants)"),
            Check::new("ssh_password_auth", "Authentification SSH par mot de passe", "unknown", "sshd -T inaccessible (droits insuffisants)"),
            Check::new("ssh_weak_algos", "Algorithmes SSH faibles", "unknown", "sshd -T inaccessible (droits insuffisants)"),
        ];
    }

    let mut checks = Vec::new();
    let root_login = values.get("permitrootlogin").map(|s| s.as_str()).unwrap_or("?");
    checks.push(Check::new("ssh_root_login", "Connexion SSH root directe", if root_login == "no" { "ok" } else { "warn" }, format!("PermitRootLogin={root_login}")));

    let pass_auth = values.get("passwordauthentication").map(|s| s.as_str()).unwrap_or("?");
    checks.push(Check::new("ssh_password_auth", "Authentification SSH par mot de passe", if pass_auth == "no" { "ok" } else { "warn" }, format!("PasswordAuthentication={pass_auth}")));

    let mut weak_algos: Vec<String> = Vec::new();
    for (key, weak_set) in [("kexalgorithms", WEAK_SSH_KEX), ("ciphers", WEAK_SSH_CIPHERS), ("macs", WEAK_SSH_MACS)] {
        let weak: HashSet<&str> = weak_set.iter().copied().collect();
        if let Some(configured) = values.get(key) {
            let mut found: Vec<String> = configured.split(',').map(str::trim).filter(|a| weak.contains(a)).map(str::to_string).collect();
            weak_algos.append(&mut found);
        }
    }
    weak_algos.sort();
    checks.push(Check::new(
        "ssh_weak_algos", "Algorithmes SSH faibles",
        if weak_algos.is_empty() { "ok" } else { "warn" },
        if weak_algos.is_empty() { "Aucun algo faible (échange de clé/chiffrement/MAC) accepté".to_string() } else { format!("Encore acceptés : {}", weak_algos.join(", ")) },
    ));

    checks
}

/// Chiffrement disque (LUKS) — spécifique agent, illisible par un compte SSH distant sans
/// droits élevés. `/etc/crypttab` non vide (hors commentaires) OU au moins un volume
/// `TYPE="crypt"` via `lsblk` : les deux sources sont redondantes en pratique, la seconde
/// couvre les rares cas de conteneurs LUKS montés hors `crypttab`.
fn disk_encryption_check() -> Check {
    let crypttab = run_lossy("grep -vE '^\\s*#|^\\s*$' /etc/crypttab 2>/dev/null");
    if !crypttab.trim().is_empty() {
        return Check::new("disk_encryption", "Chiffrement disque (LUKS)", "ok", "Volume(s) chiffré(s) déclaré(s) dans /etc/crypttab");
    }
    let lsblk = run_lossy("lsblk -no TYPE 2>/dev/null");
    if lsblk.lines().any(|l| l.trim() == "crypt") {
        return Check::new("disk_encryption", "Chiffrement disque (LUKS)", "ok", "Volume LUKS actif détecté (lsblk)");
    }
    Check::new("disk_encryption", "Chiffrement disque (LUKS)", "warn", "Aucun volume chiffré détecté (/etc/crypttab, lsblk)")
}

/// Comptes membres du groupe `sudo`/`wheel` (Debian/Ubuntu vs RHEL/Fedora) — surface
/// d'élévation locale, invisible par un scan SSH sans énumération explicite des comptes.
fn privileged_accounts_check() -> Check {
    let sudo_members = run_lossy("getent group sudo 2>/dev/null | cut -d: -f4");
    let wheel_members = run_lossy("getent group wheel 2>/dev/null | cut -d: -f4");
    let members: Vec<&str> = sudo_members.split(',').chain(wheel_members.split(','))
        .map(str::trim).filter(|s| !s.is_empty()).collect();
    if members.is_empty() {
        return Check::new("privileged_accounts", "Comptes administrateurs locaux", "unknown", "Groupes sudo/wheel introuvables ou vides");
    }
    let mut unique: Vec<&str> = members.into_iter().collect();
    unique.sort();
    unique.dedup();
    Check::new("privileged_accounts", "Comptes administrateurs locaux", "ok", format!("{} compte(s) : {}", unique.len(), unique.join(", ")))
}

/// Verrouillage d'écran — best-effort, dépend de l'environnement de bureau (GNOME testé
/// via gsettings ; KDE/autres non couverts dans ce MVP) : reste "unknown" plutôt que
/// d'affirmer une absence de politique quand elle est simplement indétectable ici.
fn screen_lock_check() -> Check {
    if let Some(out) = run("gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null") {
        if !out.is_empty() {
            let status = if out.contains("true") { "ok" } else { "warn" };
            return Check::new("screen_lock", "Verrouillage d'écran automatique", status, format!("GNOME lock-enabled={out}"));
        }
    }
    Check::new("screen_lock", "Verrouillage d'écran automatique", "unknown", "Environnement de bureau non détecté ou non couvert (GNOME uniquement dans ce MVP)")
}

/// Restriction USB — présence de règles udev bloquant le stockage de masse USB
/// (politique courante : règle `SUBSYSTEM=="usb"` avec action de rejet). Détection
/// heuristique par mot-clé, pas une validation sémantique complète des règles udev.
fn usb_policy_check() -> Check {
    let rules = run_lossy("grep -rlE 'usb.*(block|deny|drop)|ACTION==\"add\".*usb.*ATTR\\{authorized\\}' /etc/udev/rules.d/ 2>/dev/null");
    if !rules.trim().is_empty() {
        return Check::new("usb_policy", "Restriction des périphériques USB", "ok", "Règle(s) udev de restriction USB détectée(s)");
    }
    Check::new("usb_policy", "Restriction des périphériques USB", "warn", "Aucune règle udev de restriction USB détectée — stockage de masse USB probablement autorisé sans contrôle")
}

/// Élévation sudo sans mot de passe — directive `NOPASSWD` dans `/etc/sudoers`/`sudoers.d`
/// (13/08/2026, `docs/vulnerabilites_securite.md` §3.7). Heuristique par mot-clé, pas une
/// validation sémantique complète des règles (une ligne commentée matcherait aussi
/// `grep -E`, mais `-v '^\s*#'` en amont exclut déjà les lignes commentées entières).
fn sudo_nopasswd_check() -> Check {
    let found = run_lossy("grep -rlE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null");
    if found.trim().is_empty() {
        Check::new("sudo_nopasswd", "Élévation sudo sans mot de passe", "ok", "Aucune directive NOPASSWD trouvée dans /etc/sudoers(.d)")
    } else {
        Check::new("sudo_nopasswd", "Élévation sudo sans mot de passe", "warn", format!("NOPASSWD trouvé dans : {}", found.replace('\n', ", ")))
    }
}

/// Permissions de `~root/.ssh/authorized_keys` (13/08/2026) — devrait rester 600 (lecture/
/// écriture propriétaire uniquement) ; trop permissif expose la liste des clés autorisées à
/// modification par d'autres comptes locaux.
fn ssh_authorized_keys_perms_check() -> Check {
    let path = "/root/.ssh/authorized_keys";
    match run(&format!("stat -c '%a' {path} 2>/dev/null")) {
        None => Check::new("ssh_authorized_keys_perms", "Permissions authorized_keys (root)", "unknown", format!("{path} absent ou illisible")),
        Some(perm) => {
            let status = if perm == "600" || perm == "400" { "ok" } else { "warn" };
            Check::new("ssh_authorized_keys_perms", "Permissions authorized_keys (root)", status, format!("Permissions actuelles : {perm} (attendu 600)"))
        }
    }
}

/// Fichiers modifiables par tous (13/08/2026) — `chmod 777`/bit world-writable sur des
/// répertoires sensibles. Périmètre volontairement borné (`/etc /usr/local /opt`, pas tout
/// le système de fichiers) : rapide et pertinent, un `find /` complet serait lent et bruité
/// par des faux positifs attendus ailleurs (`/tmp`, `/var/tmp`, sockets...).
fn world_writable_files_check() -> Check {
    let found = run_lossy("find /etc /usr/local /opt -xdev -type f -perm -0002 2>/dev/null | head -10");
    if found.trim().is_empty() {
        Check::new("world_writable_files", "Fichiers modifiables par tous", "ok", "Aucun fichier world-writable détecté dans /etc, /usr/local, /opt")
    } else {
        let count = found.lines().count();
        let sample: Vec<&str> = found.lines().take(3).collect();
        Check::new("world_writable_files", "Fichiers modifiables par tous", "warn", format!("{count}+ fichier(s), ex. : {}", sample.join(", ")))
    }
}

/// Secrets en clair dans l'historique shell (13/08/2026) — ne recopie jamais le contenu
/// trouvé dans `detail` (stocké en base, affiché en clair côté UI) : juste un décompte, le
/// contenu réel reste à vérifier manuellement sur la machine.
fn shell_history_secrets_check() -> Check {
    let path = "/root/.bash_history";
    if run(&format!("test -f {path}")).is_none() {
        return Check::new("shell_history_secrets", "Secrets dans l'historique shell", "unknown", format!("{path} introuvable"));
    }
    let matches = run_lossy(&format!(
        "grep -iE 'password=|passwd |secret|api[_-]?key|BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY|AWS_SECRET' {path} 2>/dev/null"
    ));
    if matches.trim().is_empty() {
        Check::new("shell_history_secrets", "Secrets dans l'historique shell", "ok", format!("Aucun motif suspect détecté dans {path}"))
    } else {
        let count = matches.lines().count();
        Check::new("shell_history_secrets", "Secrets dans l'historique shell", "warn", format!("{count} ligne(s) correspondant à un motif sensible dans {path} — contenu non recopié ici, à vérifier manuellement"))
    }
}

fn parse_ports(raw: &str) -> Vec<u32> {
    let mut ports: Vec<u32> = raw.split_whitespace().filter_map(|p| p.parse().ok()).collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub fn hostname() -> String {
    run_lossy("hostname -f 2>/dev/null || hostname").to_lowercase()
}

pub fn collect() -> CheckinPayload {
    let hostname = self::hostname();
    let pretty = run_lossy("grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"'");
    let version = run_lossy("grep '^VERSION_ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"'");
    let ip = run_lossy("hostname -I 2>/dev/null").split_whitespace().collect::<Vec<_>>().join(", ");

    let pkgs_raw = run_lossy(
        "dpkg -l 2>/dev/null | awk 'NR>5 {print $2\",\"$3}' \
         || rpm -qa --queryformat '%{NAME},%{VERSION}\\n' 2>/dev/null",
    );
    // Nom → version candidate (apt uniquement, même limite assumée que le scan SSH —
    // aucun `apt update` déclenché, lecture seule du cache existant).
    let upgradable_raw = run_lossy("apt list --upgradable 2>/dev/null | grep 'upgradable from'");
    let mut available_versions: HashMap<String, String> = HashMap::new();
    for line in upgradable_raw.lines() {
        if let Some((name_part, rest)) = line.split_once('/') {
            if let Some(version_field) = rest.split_whitespace().nth(1) {
                available_versions.insert(name_part.trim().to_string(), version_field.trim().to_string());
            }
        }
    }
    let packages: Vec<Package> = pkgs_raw
        .lines()
        .take(300)
        .filter_map(|line| {
            let (name, version) = line.split_once(',')?;
            if name.is_empty() {
                return None;
            }
            let available_version = available_versions.get(name).cloned();
            Some(Package { name: name.to_string(), version: version.to_string(), available_version })
        })
        .collect();

    let cpu = run_lossy("LC_ALL=C lscpu 2>/dev/null | grep '^Model name:' | sed 's/Model name:\\s*//'");
    let arch = format_arch(&run_lossy("uname -m 2>/dev/null"));
    let cores: Option<u32> = run("nproc 2>/dev/null").and_then(|s| s.parse().ok());
    let ram_gb: Option<f64> = run("free -b 2>/dev/null | awk '/^Mem:/{print $2}'")
        .and_then(|s| s.parse::<f64>().ok())
        .map(|bytes| (bytes / 1024_f64.powi(3) * 10.0).round() / 10.0);

    let disks_raw = run_lossy("df -BG --output=target,size,avail -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -n +2");
    let disks: Vec<Disk> = disks_raw
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() != 3 {
                return None;
            }
            Some(Disk {
                name: parts[0].to_string(),
                total_gb: parts[1].trim_end_matches('G').parse().unwrap_or(0.0),
                free_gb: parts[2].trim_end_matches('G').parse().unwrap_or(0.0),
            })
        })
        .collect();

    let mac = run_lossy("cat /sys/class/net/*/address 2>/dev/null | grep -v '00:00:00:00:00:00' | sort -u")
        .lines().collect::<Vec<_>>().join(", ");

    let open_ports = parse_ports(&run_lossy("ss -tuln 2>/dev/null | awk 'NR>1{n=split($5,a,\":\"); print a[n]}'"));

    let logindefs_raw = run_lossy("grep -E '^(PASS_MAX_DAYS|PASS_MIN_LEN)\\s' /etc/login.defs 2>/dev/null");
    // Pas de `sudo -n` : l'agent tourne déjà avec les droits nécessaires localement
    // (contrairement au compte de service SSH distant), cf. plan §5.
    let sshd_raw = run_lossy("sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication) '");

    let mut checks = password_checks(&logindefs_raw);
    checks.extend(ssh_checks(&sshd_raw));
    checks.push(exposed_ports_check(&open_ports));
    // Checks propres à l'agent (§3.7) — au-delà de ce qu'un scan SSH distant peut lire.
    checks.push(disk_encryption_check());
    checks.push(privileged_accounts_check());
    checks.push(screen_lock_check());
    checks.push(usb_policy_check());
    // Backlog complété (13/08/2026, docs/vulnerabilites_securite.md §3.7).
    checks.push(sudo_nopasswd_check());
    checks.push(ssh_authorized_keys_perms_check());
    checks.push(world_writable_files_check());
    checks.push(shell_history_secrets_check());

    let package_count = packages.len() as u32;

    CheckinPayload {
        reachable: true,
        detected: Detected { hostname, os: pretty, os_version: version, ip_address: ip.clone() },
        packages,
        package_count,
        hardware: Hardware { cpu, arch, cores, ram_gb, disks, ip, mac, open_ports },
        compliance: Compliance { checks },
        error: None,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        offline_since: None,
        failed_attempts: None,
    }
}
