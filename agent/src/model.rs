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
}

/// Réponse de `GET /api/agents/pending` — interrogée par la boucle persistante
/// (`daemon.rs`) à intervalle court, jamais l'inverse (cf. CLAUDE.md §1).
#[derive(Deserialize)]
pub struct PendingResponse {
    pub scan_requested: bool,
}
