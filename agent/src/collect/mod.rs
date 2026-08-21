//! Point d'entrée de la collecte, dispatché par OS à la compilation (`#[cfg(target_os)]`)
//! — un seul binaire, pas deux codebases séparées. Chaque implémentation OS doit rester
//! un strict sur-ensemble de ce que `asset_scanner.py` collecte déjà par SSH/WinRM (cf.
//! plan § Contexte) : mêmes checks de durcissement, plus les checks propres à l'agent
//! (accès local qu'un compte de service distant n'a pas).

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

use crate::model::{CheckinPayload, SecurityEvent};

pub fn os_name() -> &'static str {
    if cfg!(target_os = "windows") { "windows" } else { "linux" }
}

pub fn hostname() -> String {
    #[cfg(target_os = "linux")]
    {
        linux::hostname()
    }
    #[cfg(target_os = "windows")]
    {
        windows::hostname()
    }
}

pub fn collect() -> CheckinPayload {
    #[cfg(target_os = "linux")]
    {
        linux::collect()
    }
    #[cfg(target_os = "windows")]
    {
        windows::collect()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        compile_error!("allsafe-agent ne supporte que Linux et Windows");
    }
}

/// Lit les journaux d'audit natifs depuis les curseurs donnés et retourne les nouveaux
/// évènements + les curseurs mis à jour (Windows Security + System log).
/// No-op sur Linux (pas de Security Event Log) : retourne vecteur vide, curseurs inchangés.
/// `None` sur l'un ou l'autre curseur = premier run → initialisation sans backfill.
pub fn read_security_events(
    sec_cursor: Option<u64>,
    sys_cursor: Option<u64>,
) -> (Vec<SecurityEvent>, u64, u64) {
    #[cfg(target_os = "windows")]
    {
        windows::read_security_events(sec_cursor, sys_cursor)
    }
    #[cfg(not(target_os = "windows"))]
    {
        (vec![], sec_cursor.unwrap_or(0), sys_cursor.unwrap_or(0))
    }
}
