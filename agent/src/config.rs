//! Identité locale de l'agent (serveur + credential émis à l'enrôlement), persistée
//! dans un fichier à emplacement système fixe — pas de Credential Manager/DPAPI Windows
//! ni de coffre équivalent Linux dans ce MVP (limite assumée, cf. plan). Le fichier
//! porte des permissions restreintes sur Linux (`chmod 600`) ; sur Windows, ACL posée
//! sur `%ProgramData%\allsafe-agent` (18/08/2026, cf. audit/AUDIT_SECURITE.md #18 —
//! avant ce correctif, `agent.json` héritait des ACL par défaut de `%ProgramData%`, pas
//! garanti illisible par un utilisateur standard).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct AgentConfig {
    pub server: String,
    pub credential: String,
    pub hostname: String,
    pub os: String,
}

#[cfg(target_os = "windows")]
fn config_path() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
        .join("allsafe-agent")
        .join("agent.json")
}

#[cfg(not(target_os = "windows"))]
fn config_path() -> PathBuf {
    PathBuf::from("/etc/allsafe-agent/agent.json")
}

impl AgentConfig {
    pub fn load() -> Result<Self> {
        let path = config_path();
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("lecture de {} — l'agent est-il enrôlé ? (allsafe-agent enroll)", path.display()))?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("création de {}", parent.display()))?;
        }
        let raw = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, raw).with_context(|| format!("écriture de {}", path.display()))?;
        restrict_permissions(&path)?;
        Ok(())
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &PathBuf) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {}", path.display()))
}

/// ACL Windows (18/08/2026, cf. audit/AUDIT_SECURITE.md #18) — `%ProgramData%\allsafe-
/// agent\agent.json` contient le credential agent en clair ; sous les ACL héritées par
/// défaut, rien ne garantissait qu'un utilisateur standard du poste ne pouvait pas le lire
/// (contrairement à Linux, `chmod 600` ci-dessus). Restreint le **dossier parent** (pas
/// juste le fichier appelant) à SYSTEM + Administrators via `icacls` — couvre du même coup
/// `daemon-state.json`, écrit au même endroit (cf. `state_path` plus bas).
///
/// `*S-1-5-32-544` (SID bien connu du groupe Administrators local) plutôt que le nom du
/// groupe : évite la dépendance à la langue d'installation Windows (`Administrateurs` en
/// FR, `Administrators` en EN...). Best-effort et non bloquant à dessein — un échec
/// `icacls` (droits insuffisants, commande absente d'une image Windows minimale) ne doit
/// jamais empêcher l'agent de fonctionner, juste laisser les ACL héritées en place et le
/// signaler.
#[cfg(not(unix))]
fn restrict_permissions(path: &PathBuf) -> Result<()> {
    let Some(dir) = path.parent() else { return Ok(()) };
    let status = std::process::Command::new("icacls")
        .arg(dir)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("SYSTEM:(OI)(CI)F")
        .arg("/grant:r")
        .arg("*S-1-5-32-544:(OI)(CI)F")
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!(
            "⚠️  icacls a échoué (code {:?}) sur {} — permissions par défaut conservées.",
            s.code(),
            dir.display()
        ),
        Err(e) => eprintln!(
            "⚠️  icacls introuvable ({e}) — permissions par défaut conservées sur {}.",
            dir.display()
        ),
    }
    Ok(())
}

/// État local de la boucle persistante (`daemon.rs`) — mémorise une coupure réseau pour
/// la signaler au serveur au prochain check-in réussi ("rapport de coupure", pas une file
/// d'attente qui rejouerait des snapshots complets : le backend n'a pas de table
/// d'historique de conformité à alimenter avec ça, cf. plan §Unité 1). Épargne volontaire
/// d'une dépendance chrono supplémentaire : `offline_since` en secondes Unix (UTC), pas en
/// texte RFC3339 — converti côté serveur.
#[derive(Serialize, Deserialize, Default)]
pub struct DaemonState {
    pub offline_since: Option<i64>,
    pub failed_attempts: u32,
}

fn state_path() -> PathBuf {
    config_path().with_file_name("daemon-state.json")
}

impl DaemonState {
    pub fn load() -> Self {
        std::fs::read_to_string(state_path())
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    /// Posé à la première tentative échouée seulement (`offline_since` non écrasé par les
    /// suivantes) — sinon on perdrait le vrai début de la coupure.
    pub fn record_failure() {
        let mut state = Self::load();
        if state.offline_since.is_none() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            state.offline_since = Some(now);
        }
        state.failed_attempts += 1;
        let _ = state.save();
    }

    pub fn clear() {
        let _ = std::fs::remove_file(state_path());
    }

    fn save(&self) -> Result<()> {
        let path = state_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("création de {}", parent.display()))?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("écriture de {}", path.display()))?;
        restrict_permissions(&path)?;
        Ok(())
    }
}
