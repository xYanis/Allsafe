//! Auto-installation Windows (17/08/2026) — remplace le `.msi`/`wixl` pour le cas "poste
//! isolé, sans script à côté" (cf. docs/AGENTS.md § Installation rapide) : un seul fichier
//! `allsafe-agent.exe` à copier sur le poste, une commande (`install --token ... --server
//! ...`) ou la fenêtre graphique (`gui.rs`, lancée sans argument) fait le reste — copie
//! vers un emplacement stable, service Windows, `PATH` système, enrôlement.
//!
//! Le `.msi` (`wix/main.wxs`) reste le chemin recommandé pour un déploiement GPO
//! "Installation de logiciels" natif ou pour garder le suivi "Programmes et
//! fonctionnalités" — ce module ne le remplace pas, il comble le cas où aucun des deux
//! (`.msi` ou script `agent/deploy/update-agent.*`) n'est disponible sur place.
//!
//! ✅ **Vérifié par compilation croisée réelle** (17/08/2026, toolchain mingw-w64/wixl
//! assemblée manuellement, sans root, dans l'environnement de build) — compile et
//! **link** correctement contre les vraies crates `windows-service`/`winreg` pour
//! `x86_64-pc-windows-gnu`. **Reste non vérifié** : le comportement runtime sur un vrai
//! poste Windows (élévation, écriture registre, SCM) — cf. docs/AGENTS.md § Vérification.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const SERVICE_NAME: &str = "AllsafeAgent";
const INSTALL_DIR: &str = r"C:\Program Files\Allsafe Agent";

/// Même emplacement que `wix/main.wxs::INSTALLFOLDER` — garde une seule vérité sur
/// "où vit l'agent installé", que ce soit via le `.msi` ou cette voie directe (les scripts
/// `agent/deploy/update-agent.*` et `docs/AGENTS.md` référencent déjà ce chemin en dur).
fn install_exe_path() -> PathBuf {
    PathBuf::from(INSTALL_DIR).join("allsafe-agent.exe")
}

/// `net session` échoue avec "Accès refusé" sous un jeton non-élevé — astuce Windows
/// classique pour détecter l'élévation sans dépendance FFI supplémentaire (pas de crate
/// `windows`/`winapi` ajoutée juste pour ça). Mêmes conséquences qu'un `msiexec`/
/// `Uninstall-Package` non élevé (cf. `agent/deploy/update-agent.ps1`) : le service et la
/// clé de registre PATH exigent tous les deux des droits admin.
pub fn is_elevated() -> bool {
    std::process::Command::new("net")
        .args(["session"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn require_elevated() -> Result<()> {
    if !is_elevated() {
        anyhow::bail!(
            "droits administrateur requis (service Windows + PATH système). \
             Relancer depuis un PowerShell/terminal \"Exécuter en tant qu'administrateur\"."
        );
    }
    Ok(())
}

/// Copie l'exécutable courant vers l'emplacement d'installation stable si nécessaire —
/// le service Windows a besoin d'un `binPath` qui ne bouge pas (contrairement à
/// `C:\Temp` ou un dossier de téléchargement que l'utilisateur peut nettoyer ensuite).
fn ensure_installed_exe() -> Result<PathBuf> {
    let current = std::env::current_exe().context("chemin de l'exécutable courant")?;
    let target = install_exe_path();

    if current == target {
        return Ok(target);
    }

    // Un service déjà actif verrouille son binaire en écriture — on tente de l'arrêter
    // avant d'écraser le fichier (cas d'une réinstallation/mise à jour manuelle). Échec
    // ignoré si le service n'existe pas encore (première installation, cas normal).
    let _ = stop_existing_service();

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("création de {}", parent.display()))?;
    }
    std::fs::copy(&current, &target)
        .with_context(|| format!("copie de {} vers {}", current.display(), target.display()))?;
    Ok(target)
}

fn stop_existing_service() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
    }
    Ok(())
}

/// Enregistre (ou ouvre s'il existe déjà — réinstallation) le service Windows, puis le
/// démarre s'il n'est pas déjà `Running`. ⚠️ Limite assumée : si le service existe déjà
/// avec un `binPath` différent (poste réinstallé à un autre emplacement par le passé), ce
/// code ne le corrige pas — seul un nouveau `create_service` (poste vierge) pose le bon
/// chemin. Même limite que le `.msi` avant lui (pas d'équivalent `<MajorUpgrade>`, cf.
/// `agent/deploy/update-agent.ps1`).
fn register_and_start_service(exe_path: &Path) -> Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let manager = ServiceManager::local_computer(None::<&str>, manager_access)
        .context("ouverture du Service Control Manager (droits admin requis)")?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("Allsafe Agent"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path.to_path_buf(),
        launch_arguments: vec![OsString::from("service-run")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service = match manager.create_service(&service_info, ServiceAccess::START | ServiceAccess::QUERY_STATUS) {
        Ok(service) => service,
        Err(_) => manager
            .open_service(SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
            .context("le service AllsafeAgent existe déjà mais n'a pas pu être ouvert")?,
    };

    if service.query_status().context("lecture du statut du service")?.current_state != ServiceState::Running {
        service.start::<&std::ffi::OsStr>(&[]).context("démarrage du service AllsafeAgent")?;
    }
    Ok(())
}

/// Ajoute `dir` au `PATH` système (`HKLM\...\Environment`), sans dupliquer s'il y est déjà.
/// ⚠️ Le `PATH` système est de type `REG_EXPAND_SZ` (documenté Microsoft) — écrire une
/// simple chaîne changerait son type en `REG_SZ` et casserait l'expansion de toute entrée
/// existante utilisant une variable (`%SystemRoot%\...`, quasi toujours présente) :
/// `set_raw_value` avec le bon `vtype` est utilisé exprès plutôt que le `set_value::<String,
/// _>` générique de `winreg`. Comme pour l'équivalent `wix/main.wxs::Environment`, une
/// fenêtre déjà ouverte ne relit pas le `PATH` — il en faut une nouvelle après l'install.
fn add_to_system_path(dir: &Path) -> Result<()> {
    use winreg::enums::{RegType, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
    use winreg::{RegKey, RegValue};

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let env = hklm
        .open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            KEY_READ | KEY_WRITE,
        )
        .context("ouverture de la clé PATH système (droits admin requis)")?;

    let current: String = env.get_value("Path").unwrap_or_default();
    let dir_str = dir.to_string_lossy();
    let already_present = current
        .split(';')
        .any(|p| p.trim().trim_end_matches('\\').eq_ignore_ascii_case(dir_str.trim_end_matches('\\')));
    if already_present {
        return Ok(());
    }

    let new_path = if current.trim().is_empty() { dir_str.to_string() } else { format!("{current};{dir_str}") };
    let mut wide: Vec<u16> = new_path.encode_utf16().collect();
    wide.push(0);
    let bytes = wide.iter().flat_map(|c| c.to_le_bytes()).collect();
    env.set_raw_value("Path", &RegValue { bytes, vtype: RegType::REG_EXPAND_SZ })
        .context("écriture du PATH système")?;
    Ok(())
}

/// Point d'entrée commun CLI (`main.rs::Commands::Install`) et GUI (`gui.rs`). `token`/
/// `server` optionnels : `None` installe le service + PATH sans enrôler (utile pour
/// préparer un poste à l'avance, `enroll` restant utilisable séparément ensuite).
pub async fn install(token: Option<String>, server: Option<String>) -> Result<()> {
    require_elevated()?;

    let exe_path = ensure_installed_exe()?;
    add_to_system_path(&PathBuf::from(INSTALL_DIR)).context("ajout au PATH système")?;
    register_and_start_service(&exe_path).context("enregistrement du service Windows")?;

    if let (Some(token), Some(server)) = (token, server) {
        enroll(token, server).await?;
        // Redémarre pour que la boucle persistante prenne en compte l'identité qui vient
        // d'être écrite sur disque, plutôt que d'attendre son prochain sondage `pending`
        // (elle recharge déjà `AgentConfig` à chaque tour, cf. daemon.rs, mais autant ne
        // pas dépendre de ce détail de timing).
        let _ = stop_existing_service();
        register_and_start_service(&exe_path)?;
    }

    Ok(())
}

async fn enroll(token: String, server: String) -> Result<()> {
    let hostname = crate::collect::hostname();
    if hostname.is_empty() {
        anyhow::bail!("impossible de déterminer le nom d'hôte local");
    }
    let os = crate::collect::os_name();
    let resp = crate::api::enroll(&server, &token, &hostname, os).await.context("échec de l'enrôlement")?;
    let cfg = crate::config::AgentConfig { server, credential: resp.credential, hostname, os: os.to_string() };
    cfg.save().context("échec de la sauvegarde de la configuration locale")?;
    Ok(())
}

/// URL déjà connue si ce poste est déjà enrôlé (`agent.json`) — préremplit le champ
/// serveur de l'écran "Mise à jour" (gui.rs) pour ne pas la retaper alors qu'elle est
/// déjà sur disque. `None` sur un poste jamais enrôlé, l'utilisateur la saisit lui-même.
pub fn known_server() -> Option<String> {
    crate::config::AgentConfig::load().ok().map(|c| c.server)
}

/// Compare la version compilée (`CARGO_PKG_VERSION`) à celle publiée par le serveur
/// (`GET /latest/version`, même route que `agent/deploy/update-agent.*`). `Ok(Some(v))`
/// si une version différente est disponible, `Ok(None)` si déjà à jour.
pub async fn check_update(server: &str) -> Result<Option<String>> {
    #[derive(serde::Deserialize)]
    struct VersionResponse {
        version: String,
    }
    let url = format!("{}/api/agents/latest/version", server.trim_end_matches('/'));
    let resp = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("construction du client HTTP")?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("réponse inattendue du serveur ({})", resp.status());
    }
    let latest = resp.json::<VersionResponse>().await.context("réponse de version invalide")?.version;
    let current = env!("CARGO_PKG_VERSION");
    Ok((latest != current).then_some(latest))
}

/// Télécharge le `.msi` publié (`GET /latest/windows`) et l'exécute silencieusement
/// (`msiexec /qn`) — même mécanisme que `agent/deploy/update-agent.ps1`, réutilisé ici
/// plutôt que dupliqué en Rust : le `.msi` gère déjà l'arrêt/redémarrage du service au bon
/// moment de sa séquence (`wix/main.wxs::ServiceControl`), pas la peine de le refaire à la
/// main. ⚠️ Si ce binaire est lui-même l'installation en cours d'exécution (lancé depuis
/// `Program Files\Allsafe Agent`, pas un `.exe` fraîchement téléchargé), `msiexec` peut ne
/// pas réussir à remplacer un fichier verrouillé par son propre process — cas non géré
/// ici, limite assumée (cf. `Program Files` vs poste de téléchargement, docs/AGENTS.md).
pub async fn apply_update(server: &str) -> Result<()> {
    require_elevated()?;

    let url = format!("{}/api/agents/latest/windows", server.trim_end_matches('/'));
    let bytes = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .context("construction du client HTTP")?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .bytes()
        .await
        .context("téléchargement du .msi")?;

    let tmp = std::env::temp_dir().join("allsafe-agent-update.msi");
    std::fs::write(&tmp, &bytes).with_context(|| format!("écriture de {}", tmp.display()))?;

    let log = std::env::temp_dir().join("allsafe-agent-update-install.log");
    let status = std::process::Command::new("msiexec")
        .arg("/i")
        .arg(&tmp)
        .arg("/qn")
        .arg("/l*v")
        .arg(&log)
        .status()
        .context("lancement de msiexec")?;
    let _ = std::fs::remove_file(&tmp);

    if !status.success() {
        anyhow::bail!("msiexec a échoué (code {:?}) — détail dans {}", status.code(), log.display());
    }
    Ok(())
}

/// Arrête et désenregistre le service + retire l'entrée `PATH`. Ne supprime **pas** les
/// fichiers (`Program Files\Allsafe Agent`, `%ProgramData%\allsafe-agent`) — un
/// exécutable Windows ne peut pas se supprimer lui-même pendant qu'il tourne ; laissé à
/// l'utilisateur (message affiché) plutôt qu'une astuce fragile de suppression différée
/// (script `cmd` détaché, planificateur de tâches...).
pub fn uninstall() -> Result<()> {
    require_elevated()?;

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    )
    .context("ouverture du Service Control Manager (droits admin requis)")?;

    if let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS) {
        if service.query_status()?.current_state != ServiceState::Stopped {
            service.stop().context("arrêt du service AllsafeAgent")?;
        }
        service.delete().context("suppression du service AllsafeAgent")?;
    }

    remove_from_system_path(&PathBuf::from(INSTALL_DIR)).context("retrait du PATH système")?;

    println!(
        "Service désinstallé. Supprimer manuellement \"{INSTALL_DIR}\" et \
         \"%ProgramData%\\allsafe-agent\" si besoin (l'exécutable ne peut pas se supprimer lui-même)."
    );
    Ok(())
}

fn remove_from_system_path(dir: &Path) -> Result<()> {
    use winreg::enums::{RegType, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
    use winreg::{RegKey, RegValue};

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let env = hklm
        .open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            KEY_READ | KEY_WRITE,
        )
        .context("ouverture de la clé PATH système (droits admin requis)")?;

    let current: String = env.get_value("Path").unwrap_or_default();
    let dir_str = dir.to_string_lossy();
    let filtered: Vec<&str> = current
        .split(';')
        .filter(|p| !p.trim().trim_end_matches('\\').eq_ignore_ascii_case(dir_str.trim_end_matches('\\')))
        .collect();
    let new_path = filtered.join(";");

    let mut wide: Vec<u16> = new_path.encode_utf16().collect();
    wide.push(0);
    let bytes = wide.iter().flat_map(|c| c.to_le_bytes()).collect();
    env.set_raw_value("Path", &RegValue { bytes, vtype: RegType::REG_EXPAND_SZ })
        .context("écriture du PATH système")?;
    Ok(())
}
