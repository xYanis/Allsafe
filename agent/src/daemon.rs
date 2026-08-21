//! Boucle persistante (`allsafe-agent run` interactif/systemd, ou service Windows via
//! `service.rs`) — remplace la planification externe cron/GPO comme mode par défaut
//! recommandé (celle-ci reste utilisable, cf. `agent/deploy/README.md`). Sonde un flag
//! "scan demandé" à intervalle court sans jamais laisser le serveur initier le contact
//! (`api::pending`, lecture seule) : c'est toujours le poste qui vient chercher, jamais
//! Allsafe qui pousse (cf. `CLAUDE.md` §1) — même principe que `agent/deploy/update-
//! agent.*` pour les mises à jour.

use std::time::{Duration, Instant};
use anyhow::Context;
use tokio::time::sleep;

use crate::api;
use crate::collect;
use crate::config::{AgentConfig, DaemonState};
use crate::model::SecurityEvent;

/// Taille maximale du buffer d'évènements pendant une coupure réseau. Au-delà, les
/// évènements les plus anciens sont supprimés et un `buffer_overflow` synthétique est
/// inséré (cf. docs/AGENT_DETECTION.md § Mécanique agent piège #3). MAX_BUFFER - 1 slots
/// pour les vrais évènements + 1 pour l'évènement synthétique = MAX_BUFFER au total.
const MAX_BUFFER_EVENTS: usize = 200;

// 5 s (21/08/2026, ping agent) — court pour que le pong réponde en < 5s,
// sans pour autant imposer un check-in complet à cette cadence (celui-ci reste horaire).
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const CHECKIN_INTERVAL: Duration = Duration::from_secs(3600);

/// Ne retourne jamais — la boucle s'arrête uniquement par arrêt du process (Ctrl+C en
/// interactif, `systemctl stop`, ou l'événement Stop du Service Control Manager côté
/// Windows, géré par `service.rs`).
pub async fn run() -> ! {
    let mut last_checkin: Option<Instant> = None;

    loop {
        let cfg = match load_or_bootstrap().await {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("allsafe-agent: agent non enrôlé, nouvelle tentative dans {}s ({e:#})", POLL_INTERVAL.as_secs());
                sleep(POLL_INTERVAL).await;
                continue;
            }
        };

        let due = last_checkin.map(|t| t.elapsed() >= CHECKIN_INTERVAL).unwrap_or(true);
        // Échec de sondage traité comme "rien en attente" — ne bloque pas le check-in normal.
        let pending_resp = api::pending(&cfg.server, &cfg.credential).await
            .unwrap_or(crate::model::PendingResponse { scan_requested: false, ping_requested: false });

        // Ping admin : réponse légère immédiate, jamais un check-in complet.
        if pending_resp.ping_requested {
            if let Err(e) = api::pong(&cfg.server, &cfg.credential).await {
                eprintln!("allsafe-agent: échec du pong : {e:#}");
            }
        }

        if due || pending_resp.scan_requested {
            match do_checkin(&cfg).await {
                Ok(package_count) => {
                    last_checkin = Some(Instant::now());
                    println!("allsafe-agent: check-in envoyé ({package_count} paquet(s)){}.", if pending_resp.scan_requested { " — scan à la demande satisfait" } else { "" });
                }
                Err(e) => {
                    eprintln!("allsafe-agent: échec du check-in : {e:#}");
                }
            }
        }

        sleep(POLL_INTERVAL).await;
    }
}

/// Jeton "bulk" pré-rempli (17/08/2026, `.msi` de déploiement pour un parc non-critique,
/// cf. docs/AGENTS.md § Installation rapide) — si aucune identité n'existe encore
/// (première exécution du service) et qu'un fichier `enroll-defaults.json` est présent à
/// côté de l'exécutable, l'agent s'enrôle seul avec son contenu. Absent par défaut : ni le
/// `.msi` "normal" ni l'`.exe` autonome (`install.rs`) n'en embarquent — seul un build
/// "bulk" dédié en ajoute un, cf. § Build bulk dans agent/README.md.
async fn load_or_bootstrap() -> anyhow::Result<AgentConfig> {
    if let Ok(cfg) = AgentConfig::load() {
        return Ok(cfg);
    }
    bootstrap_from_defaults().await
}

async fn bootstrap_from_defaults() -> anyhow::Result<AgentConfig> {
    let exe = std::env::current_exe().context("chemin de l'exécutable courant")?;
    let defaults_path = exe.with_file_name("enroll-defaults.json");
    let raw = std::fs::read_to_string(&defaults_path)
        .with_context(|| format!("agent non enrôlé et pas de {} (poste isolé — enrôler manuellement)", defaults_path.display()))?;

    #[derive(serde::Deserialize)]
    struct EnrollDefaults {
        server: String,
        token: String,
    }
    let defaults: EnrollDefaults = serde_json::from_str(&raw).context("enroll-defaults.json invalide")?;

    let hostname = collect::hostname();
    if hostname.is_empty() {
        anyhow::bail!("impossible de déterminer le nom d'hôte local");
    }
    let os = collect::os_name();
    let resp = api::enroll(&defaults.server, &defaults.token, &hostname, os)
        .await
        .context("échec de l'auto-enrôlement via enroll-defaults.json")?;

    let cfg = AgentConfig { server: defaults.server, credential: resp.credential, hostname, os: os.to_string() };
    cfg.save().context("échec de la sauvegarde de la configuration locale")?;
    println!("allsafe-agent: auto-enrôlé via enroll-defaults.json (agent_id={}).", resp.agent_id);
    Ok(cfg)
}

async fn do_checkin(cfg: &AgentConfig) -> anyhow::Result<u32> {
    let mut state = DaemonState::load();

    // Lire les nouveaux évènements du journal natif depuis le curseur stocké.
    // Premier appel (curseurs None) : init sans backfill — retourne [], curseurs = max actuel.
    // Les curseurs avancent AVANT l'envoi : en cas d'échec réseau, les évènements sont
    // mis en buffer, pas re-lus au prochain cycle (ce qui les doublerait).
    let (new_events, new_sec_cursor, new_sys_cursor) =
        collect::read_security_events(state.security_log_cursor, state.system_log_cursor);
    state.security_log_cursor = Some(new_sec_cursor);
    state.system_log_cursor = Some(new_sys_cursor);

    // Fusionner buffer (coupure précédente) + nouveaux évènements → envoi groupé.
    let mut events_to_send = std::mem::take(&mut state.buffered_events);
    events_to_send.extend(new_events.iter().cloned());

    let mut payload = collect::collect();
    payload.offline_since = state.offline_since;
    payload.failed_attempts = (state.failed_attempts > 0).then_some(state.failed_attempts);
    payload.security_events = events_to_send.clone();

    match api::checkin(&cfg.server, &cfg.credential, &payload).await {
        Ok(()) => {
            state.buffered_events.clear();
            state.offline_since = None;
            state.failed_attempts = 0;
            let _ = state.save();
            Ok(payload.package_count)
        }
        Err(e) => {
            // Envoi échoué : remettre tous les évènements en buffer pour le prochain cycle.
            let mut buffer = events_to_send;
            if buffer.len() > MAX_BUFFER_EVENTS {
                let dropped = buffer.len() - (MAX_BUFFER_EVENTS - 1);
                // Garder les MAX_BUFFER_EVENTS - 1 évènements les plus récents.
                buffer.drain(..dropped);
                buffer.insert(0, SecurityEvent {
                    category: "buffer_overflow".to_string(),
                    severity: "warning".to_string(),
                    summary: format!("{dropped} évènement(s) perdus — buffer saturé pendant coupure réseau"),
                    detail: Some(serde_json::json!({ "dropped_count": dropped })),
                    occurred_at: None,
                    native_source: None,
                    native_event_id: None,
                });
            }
            state.buffered_events = buffer;
            if state.offline_since.is_none() {
                state.offline_since = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0),
                );
            }
            state.failed_attempts += 1;
            let _ = state.save();
            Err(e)
        }
    }
}
