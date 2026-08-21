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
mod gui;
#[cfg(target_os = "windows")]
mod install;
#[cfg(target_os = "windows")]
mod service;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::AgentConfig;

/// Version publiée, **par plateforme** (19/08/2026, demande explicite) — remplace
/// `env!("CARGO_PKG_VERSION")` (celui-là reste la version du *crate*, un seul artefact
/// de compilation Cargo.toml, partagé par construction entre les deux cibles). `.exe`/`.msi`
/// (même binaire Windows, ne peuvent jamais diverger l'un de l'autre — le `.msi` embarque
/// littéralement le même fichier compilé, cf. `wix/main.wxs`) et `.deb` sont des artefacts
/// de release souvent modifiés indépendamment (un correctif MSI ne touche jamais au binaire
/// Linux, et réciproquement) : les lier à une seule version crate forçait à "bumper" les deux
/// à chaque changement, même quand rien n'avait réellement changé pour l'autre plateforme —
/// l'agent Linux s'affichait "en retard" dans Allsafe sans raison après un correctif Windows
/// pur. À bumper manuellement UNIQUEMENT quand la plateforme concernée change réellement (cf.
/// `agent/README.md` § Mise à jour, `backend/routers/agents.py::CURRENT_AGENT_VERSION_*`
/// côté serveur, `wix/main.wxs::Version` côté `.msi`).
#[cfg(target_os = "windows")]
pub const RELEASE_VERSION: &str = "0.1.19";
#[cfg(target_os = "linux")]
pub const RELEASE_VERSION: &str = "0.1.9";

#[derive(Parser)]
#[command(name = "allsafe-agent", version = RELEASE_VERSION, about = "Agent Allsafe (lecture seule) pour postes Windows/Linux")]
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
    /// Auto-installation (17/08/2026, cf. install.rs) : copie l'exécutable vers un
    /// emplacement stable, enregistre le service Windows + le PATH système, puis enrôle
    /// si `--token`/`--server` sont fournis. Sans eux, ouvre la fenêtre graphique de
    /// saisie (gui.rs) — comme un lancement sans aucun argument (double-clic).
    #[cfg(target_os = "windows")]
    Install {
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        server: Option<String>,
    },
    /// Arrête et désenregistre le service Windows + retire l'entrée PATH (ne supprime pas
    /// les fichiers, cf. install.rs).
    #[cfg(target_os = "windows")]
    Uninstall,
}

fn main() -> Result<()> {
    // Lancement sans aucun argument (double-clic sur l'exe, cf. gui.rs) — interceptée
    // avant `Cli::parse()` puisque `Commands` exige normalement une sous-commande et
    // échouerait avec une erreur clap plutôt que d'ouvrir la fenêtre graphique.
    #[cfg(target_os = "windows")]
    if std::env::args().len() <= 1 {
        return gui::run_install_wizard();
    }

    let cli = Cli::parse();

    // Le dispatch SCM (`service_dispatcher::start`, cf. service.rs) est bloquant et doit
    // s'exécuter AVANT toute création de runtime tokio — sinon panique ("Cannot start a
    // runtime from within a runtime") une fois `run_service()` construit le sien en
    // interne. D'où l'interception ici, hors de tout contexte async.
    #[cfg(target_os = "windows")]
    if matches!(cli.command, Commands::ServiceRun) {
        return service::run().context("échec du service Windows");
    }

    // `install`/`uninstall` gèrent eux-mêmes leur runtime tokio (`gui.rs` en construit un
    // ponctuel par clic, `install::install` est appelée directement ici) — même raisonnement
    // que `ServiceRun` ci-dessus, pas de dépendance à celui construit plus bas pour `run()`.
    #[cfg(target_os = "windows")]
    match &cli.command {
        Commands::Install { token: None, server: None } => return gui::run_install_wizard(),
        Commands::Install { token: Some(_), server: None } | Commands::Install { token: None, server: Some(_) } => {
            anyhow::bail!(
                "--token et --server doivent être fournis ensemble (ou aucun des deux pour ouvrir la fenêtre graphique)."
            );
        }
        Commands::Install { token, server } => {
            let rt = tokio::runtime::Runtime::new().context("construction du runtime tokio")?;
            return rt.block_on(install::install(token.clone(), server.clone()));
        }
        Commands::Uninstall => return install::uninstall(),
        _ => {}
    }

    let rt = tokio::runtime::Runtime::new().context("construction du runtime tokio")?;
    rt.block_on(run(cli.command))
}

async fn run(command: Commands) -> Result<()> {
    match command {
        Commands::Enroll { token, server } => {
            let server = api::normalize_server(&server);
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
        #[cfg(target_os = "windows")]
        Commands::Install { .. } | Commands::Uninstall => unreachable!("interceptée avant `run()`, cf. main()"),
    }
}
