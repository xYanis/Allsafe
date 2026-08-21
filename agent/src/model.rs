//! Shapes miroir de `backend/routers/agents.py` (`EnrollRequest`/`AgentCheckinPayload`)
//! et de `backend/services/asset_scanner.py::_build_result` (`detected`/`hardware`/
//! `compliance`) — le check-in doit produire exactement la même forme que le scan pull
//! SSH/WinRM existant pour être traité par `apply_scan_result()` sans branche dédiée.

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct EnrollRequest {
    pub token: String,
    pub hostname: String,
    pub os: String,
}

#[derive(Deserialize)]
pub struct EnrollResponse {
    pub agent_id: String,
    pub asset_id: String,
    pub credential: String,
}

/// status: "ok" | "warn" | "unknown" — même vocabulaire que `asset_scanner.py::_check()`.
#[derive(Serialize, Clone)]
pub struct Check {
    pub id: String,
    pub label: String,
    pub status: String,
    pub detail: String,
}

impl Check {
    pub fn new(id: &str, label: &str, status: &str, detail: impl Into<String>) -> Self {
        Self { id: id.to_string(), label: label.to_string(), status: status.to_string(), detail: detail.into() }
    }
}

#[derive(Serialize, Default)]
pub struct Compliance {
    pub checks: Vec<Check>,
}

#[derive(Serialize, Default)]
pub struct Package {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_version: Option<String>,
}

#[derive(Serialize, Default)]
pub struct Disk {
    pub name: String,
    pub total_gb: f64,
    pub free_gb: f64,
}

#[derive(Serialize, Default)]
pub struct Hardware {
    pub cpu: String,
    pub arch: String,
    pub cores: Option<u32>,
    pub ram_gb: Option<f64>,
    pub disks: Vec<Disk>,
    pub ip: String,
    pub mac: String,
    pub open_ports: Vec<u32>,
}

#[derive(Serialize, Default)]
pub struct Detected {
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub ip_address: String,
}

#[derive(Serialize)]
pub struct CheckinPayload {
    pub reachable: bool,
    pub detected: Detected,
    pub packages: Vec<Package>,
    pub package_count: u32,
    pub hardware: Hardware,
    pub compliance: Compliance,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Version du binaire (`CARGO_PKG_VERSION`, cf. `main.rs`) — permet à Allsafe de
    /// repérer les postes qui tournent une version périmée de l'agent (pas de mécanisme
    /// de mise à jour automatique dans ce MVP, cf. `docs/AGENTS.md` § Mise à jour).
    pub agent_version: String,
    /// Rapport de coupure (13/08/2026, `config::DaemonState`) — posé seulement si le
    /// check-in précédent avait échoué au moins une fois : depuis quand (secondes Unix
    /// UTC) et combien de tentatives. Absent en fonctionnement normal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_since: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_attempts: Option<u32>,
    /// Détection d'évènements sensibles (19/08/2026, cf. docs/AGENT_DETECTION.md) — miroir de
    /// `routers/agents.py::AgentCheckinPayload.security_events/audit_coverage/state_snapshot`.
    /// `#[serde(default)]` côté Rust n'est pas nécessaire ici (jamais désérialisé, seulement
    /// envoyé), mais `skip_serializing_if` évite de gonfler chaque check-in normal (aucune
    /// détection neuve) d'un tableau/objet vide.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub security_events: Vec<SecurityEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_coverage: Option<AuditCoverage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_snapshot: Option<StateSnapshot>,
}

/// Un évènement du journal natif (Event Log Security / auditd), déjà catégorisé et résumé
/// côté agent — le serveur ne fait aucune interprétation, juste stockage + dédoublonnage sur
/// `native_event_id` (cf. `services/agent_detection.py`, backend).
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SecurityEvent {
    pub category: String,             // cf. docs/AGENT_DETECTION.md § Catégories
    pub severity: String,             // info | warning | critical
    pub summary: String,              // résumé humain, ex. "nmap lancé par root"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
    /// Horodatage de l'évènement côté POSTE (secondes Unix UTC) — indicatif, falsifiable
    /// par un attaquant local. Le serveur pose sa propre horloge fiable à la réception
    /// (`reported_at`, jamais transmis ici).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_source: Option<String>,   // windows_security_log | linux_auditd | linux_authlog
    /// RecordID Windows / clé ausearch Linux — dédoublonnage serveur, `None` non pertinent
    /// ici (SecurityEvent = toujours du journal natif, jamais du state_diff, calculé côté
    /// serveur à partir de `state_snapshot` ci-dessous, pas envoyé par l'agent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_event_id: Option<String>,
}

/// État constaté de l'audit OS (19/08/2026) — l'agent CONSTATE, ne l'active jamais lui-même
/// (écriture système, hors non-intervention). Laisse le serveur/l'UI afficher "détection
/// partielle" plutôt que de faire croire à une couverture totale.
///
/// Dict libre (`HashMap`), pas une struct à champs fixes — miroir exact de
/// `routers/agents.py::AgentCheckinPayload.audit_coverage: dict` (backend, aucun schéma
/// strict clé par clé) : Linux et Windows n'ont pas les mêmes signaux à constater
/// (`auditd_installed`/`auditd_running` côté Linux, `process_auditing`/`command_line_logging`
/// côté Windows, cf. `collect/linux.rs`/`collect/windows.rs`) — une struct à champs fixes
/// aurait forcé les deux plateformes à partager des noms de clé qui n'ont de sens que pour
/// l'une des deux.
pub type AuditCoverage = std::collections::HashMap<String, bool>;

#[derive(Serialize, Default, Clone)]
pub struct LocalUser {
    pub name: String,
    pub sid_or_uid: String,
    pub enabled: bool,
}

#[derive(Serialize, Default, Clone)]
pub struct PersistenceEntry {
    #[serde(rename = "type")]
    pub kind: String,   // cron | systemd_unit | scheduled_task | service
    pub name: String,
}

/// Comptes/admins/persistance constatés à ce check-in — comparé côté serveur au dernier
/// snapshot connu pour générer les détections `state_diff` (cf. `services/agent_detection.py`,
/// backend). L'agent ne diffe rien lui-même : il envoie l'état brut à chaque check-in, le
/// serveur garde la mémoire (`AgentStateSnapshot`) et fait la comparaison — plus simple qu'un
/// diff local à synchroniser avec un serveur qui pourrait avoir raté un check-in.
#[derive(Serialize, Default)]
pub struct StateSnapshot {
    pub local_users: Vec<LocalUser>,
    pub admin_members: Vec<String>,
    pub persistence: Vec<PersistenceEntry>,
}

/// Réponse de `GET /api/agents/pending` — interrogée par la boucle persistante
/// (`daemon.rs`) à intervalle court, jamais l'inverse (cf. CLAUDE.md §1).
#[derive(Deserialize)]
pub struct PendingResponse {
    pub scan_requested: bool,
    #[serde(default)]
    pub ping_requested: bool,
}
