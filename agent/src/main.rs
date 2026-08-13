//! allsafe-agent — agent Allsafe (lecture seule) pour postes Windows/Linux.
//! Complète le scan centralisé SSH/WinRM (`backend/services/asset_scanner.py`) sur les
//! postes qu'il atteint mal (éteints, hors réseau, VPN) — jamais un remplacement des
//! serveurs. Sous-commandes :
//!   - `enroll` : échange un jeton d'enrôlement à usage unique (ou réutilisable, cf.
//!     module Agents) contre une identité propre au poste, persistée localement
//!     (cf. `config.rs`).
//!   - `checkin` : collecte (cf. `collect/`) et pousse le résultat au serveur, une fois.
//!   - `run` (13/08/2026) : boucle persistante — sonde un scan à la demande à intervalle
//!     court et checkin toutes les heures (cf. `daemon.rs`). Mode recommandé, invoqué en
//!     interactif/systemd sur Linux ; `service-run` en est l'équivalent Windows, piloté
//!     par le Service Control Manager (jamais un usage manuel, cf. `service.rs`).

mod api;
mod collect;
mod config;
mod daemon;
mod model;
#[cfg(target_os = "windows")]
mod service;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::AgentConfig;

#[derive(Parser)]
#[command(name = "allsafe-agent", version, about = "Agent Allsafe (lecture seule) pour postes Windows/Linux")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Échange un jeton d'enrôlement (généré depuis Allsafe > Sécurité > Agents) contre
    /// une identité propre à ce poste.
    Enroll {
        /// Jeton d'enrôlement (usage unique ou réutilisable selon le jeton généré)
        #[arg(long)]
        token: String,
        /// URL de base du serveur Allsafe, ex: https://allsafe.exemple.local
        #[arg(long)]
        server: String,
    },
    /// Collecte l'inventaire et les checks de durcissement, puis les pousse au serveur —
    /// une seule fois (cf. `run` pour le mode persistant recommandé).
    Checkin,
    /// Lance la boucle persistante (interactif ou systemd) — vérifie périodiquement un
    /// scan demandé et pousse un check-in complet toutes les heures. Ne se termine jamais
    /// de lui-même.
    Run,
    /// Point d'entrée invoqué par le Service Control Manager Windows (`wix/main.wxs`,
    /// `ServiceInstall`) — jamais un usage direct en ligne de commande.
    #[cfg(target_os = "windows")]
    #[command(hide = true)]
    ServiceRun,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Le dispatch SCM (`service_dispatcher::start`, cf. service.rs) est bloquant et doit
    // s'exécuter AVANT toute création de runtime tokio — sinon panique ("Cannot start a
    // runtime from within a runtime") une fois `run_service()` construit le sien en
    // interne. D'où l'interception ici, hors de tout contexte async.
    #[cfg(target_os = "windows")]
    if matches!(cli.command, Commands::ServiceRun) {
        return service::run().context("échec du service Windows");
    }

    let rt = tokio::runtime::Runtime::new().context("construction du runtime tokio")?;
    rt.block_on(run(cli.command))
}

async fn run(command: Commands) -> Result<()> {
    match command {
        Commands::Enroll { token, server } => {
            let hostname = collect::hostname();
            if hostname.is_empty() {
                anyhow::bail!("impossible de déterminer le nom d'hôte local");
            }
            let os = collect::os_name();
            println!("Enrôlement de « {hostname} » ({os}) auprès de {server}…");

            let resp = api::enroll(&server, &token, &hostname, os).await.context("échec de l'enrôlement")?;

            let cfg = AgentConfig { server, credential: resp.credential, hostname, os: os.to_string() };
            cfg.save().context("échec de la sauvegarde de la configuration locale")?;

            println!("Enrôlé avec succès (agent_id={}, asset_id={}).", resp.agent_id, resp.asset_id);
            println!("Prochaine étape : `allsafe-agent run` (mode persistant) ou une planification externe (cron/GPO).");
            Ok(())
        }
        Commands::Checkin => {
            let cfg = AgentConfig::load().context("agent non enrôlé")?;
            println!("Collecte en cours sur « {} »…", cfg.hostname);
            let payload = collect::collect();
            api::checkin(&cfg.server, &cfg.credential, &payload).await.context("échec du check-in")?;
            println!("Check-in envoyé ({} paquet(s) détecté(s), agent v{}).", payload.package_count, payload.agent_version);
            Ok(())
        }
        Commands::Run => {
            daemon::run().await;
        }
        #[cfg(target_os = "windows")]
        Commands::ServiceRun => unreachable!("interceptée avant la création du runtime tokio, cf. main()"),
    }
}
