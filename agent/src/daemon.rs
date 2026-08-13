//! Boucle persistante (`allsafe-agent run` interactif/systemd, ou service Windows via
//! `service.rs`) — remplace la planification externe cron/GPO comme mode par défaut
//! recommandé (celle-ci reste utilisable, cf. `agent/deploy/README.md`). Sonde un flag
//! "scan demandé" à intervalle court sans jamais laisser le serveur initier le contact
//! (`api::pending`, lecture seule) : c'est toujours le poste qui vient chercher, jamais
//! Allsafe qui pousse (cf. `CLAUDE.md` §1) — même principe que `agent/deploy/update-
//! agent.*` pour les mises à jour.

use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::api;
use crate::collect;
use crate::config::{AgentConfig, DaemonState};

const POLL_INTERVAL: Duration = Duration::from_secs(60);
const CHECKIN_INTERVAL: Duration = Duration::from_secs(3600);

/// Ne retourne jamais — la boucle s'arrête uniquement par arrêt du process (Ctrl+C en
/// interactif, `systemctl stop`, ou l'événement Stop du Service Control Manager côté
/// Windows, géré par `service.rs`).
pub async fn run() -> ! {
    let mut last_checkin: Option<Instant> = None;

    loop {
        let cfg = match AgentConfig::load() {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("allsafe-agent: agent non enrôlé, nouvelle tentative dans {}s ({e:#})", POLL_INTERVAL.as_secs());
                sleep(POLL_INTERVAL).await;
                continue;
            }
        };

        let due = last_checkin.map(|t| t.elapsed() >= CHECKIN_INTERVAL).unwrap_or(true);
        // Échec de sondage traité comme "rien en attente" (cf. api::pending) — ne bloque
        // jamais le check-in normal, juste rate un scan à la demande jusqu'au prochain tick.
        let pending = api::pending(&cfg.server, &cfg.credential).await.unwrap_or(false);

        if due || pending {
            match do_checkin(&cfg).await {
                Ok(package_count) => {
                    last_checkin = Some(Instant::now());
                    DaemonState::clear();
                    println!("allsafe-agent: check-in envoyé ({package_count} paquet(s)){}.", if pending { " — scan à la demande satisfait" } else { "" });
                }
                Err(e) => {
                    eprintln!("allsafe-agent: échec du check-in : {e:#}");
                    DaemonState::record_failure();
                }
            }
        }

        sleep(POLL_INTERVAL).await;
    }
}

async fn do_checkin(cfg: &AgentConfig) -> anyhow::Result<u32> {
    let mut payload = collect::collect();
    let state = DaemonState::load();
    payload.offline_since = state.offline_since;
    payload.failed_attempts = (state.failed_attempts > 0).then_some(state.failed_attempts);

    api::checkin(&cfg.server, &cfg.credential, &payload).await?;
    Ok(payload.package_count)
}
