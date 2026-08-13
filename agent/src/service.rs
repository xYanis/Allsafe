//! Point d'entrée Windows Service (13/08/2026) — invoqué par le Service Control Manager
//! via `allsafe-agent service-run` (sous-commande cachée, `binPath` posé par
//! `wix/main.wxs::ServiceInstall`, jamais destinée à un usage manuel). `windows_service::
//! service_dispatcher::start()` est **bloquant et doit s'exécuter avant toute création de
//! runtime tokio** — c'est pourquoi `main.rs` intercepte cette sous-commande avant même de
//! construire son propre runtime (contrairement à `Commands::Run`, qui tourne déjà dedans).
//! La boucle métier elle-même (`daemon::run`) est identique à celle du mode interactif/
//! systemd — seul l'habillage SCM (statut, réponse à Stop/Shutdown) change ici.

use std::sync::mpsc;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

const SERVICE_NAME: &str = "AllsafeAgent";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

pub fn run() -> anyhow::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| anyhow::anyhow!("{e}"))
}

fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service() {
        eprintln!("allsafe-agent: erreur service Windows : {e:#}");
    }
}

fn run_service() -> anyhow::Result<()> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    // Le SCM notifie l'arrêt via ce handler, appelé sur un thread séparé par Windows —
    // on se contente de réveiller le canal, la boucle async (spawn_blocking ci-dessous)
    // s'arrête d'elle-même dès réception.
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    set_status(&status_handle, ServiceState::Running, ServiceControlAccept::STOP)?;

    // Runtime tokio construit ICI seulement (jamais avant `service_dispatcher::start`,
    // cf. commentaire d'en-tête) — dédié à cette seule boucle, le temps de vie du service.
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        tokio::select! {
            _ = crate::daemon::run() => {}
            _ = tokio::task::spawn_blocking(move || shutdown_rx.recv()) => {}
        }
    });

    set_status(&status_handle, ServiceState::Stopped, ServiceControlAccept::empty())?;
    Ok(())
}

fn set_status(
    handle: &windows_service::service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    accept: ServiceControlAccept,
) -> anyhow::Result<()> {
    handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(|e| anyhow::anyhow!("{e}"))
}
