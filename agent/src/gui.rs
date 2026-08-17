//! Fenêtre graphique minimale (17/08/2026) — affichée quand `allsafe-agent.exe` est lancé
//! sans argument (double-clic), pour saisir serveur + jeton sans ouvrir de terminal. Reste
//! volontairement une simple fenêtre Win32 via `native-windows-gui`, pas un vrai assistant
//! multi-écrans — cf. `install.rs` pour la logique effective (service, PATH, enrôlement),
//! identique à celle utilisée par `install --token ... --server ...` en ligne de commande.
//!
//! ✅ **Vérifié par compilation + link croisés réels** (17/08/2026, `x86_64-pc-windows-gnu`,
//! toolchain mingw-w64 assemblée manuellement dans l'environnement de build) — la macro
//! `#[derive(NwgUi)]`/les attributs `nwg_control`/`nwg_events` compilent et l'exécutable
//! produit est un PE valide. **Reste non vérifié** : le rendu et le comportement réels de
//! la fenêtre sur un vrai poste Windows — cf. docs/AGENTS.md § Vérification.

use native_windows_derive as nwd;
use native_windows_gui as nwg;
use nwd::NwgUi;
use nwg::NativeUi;

#[derive(Default, NwgUi)]
pub struct InstallWindow {
    #[nwg_control(size: (420, 260), position: (300, 300), title: "Allsafe Agent — Installation", flags: "WINDOW|VISIBLE")]
    #[nwg_events( OnWindowClose: [InstallWindow::on_close] )]
    window: nwg::Window,

    #[nwg_control(parent: window, text: "URL du serveur Allsafe (ex: http://192.168.1.10:3000) :", position: (10, 10), size: (400, 20))]
    label_server: nwg::Label,

    #[nwg_control(parent: window, text: "http://", position: (10, 32), size: (400, 24), focus: true)]
    input_server: nwg::TextInput,

    #[nwg_control(parent: window, text: "Jeton d'enrôlement :", position: (10, 66), size: (400, 20))]
    label_token: nwg::Label,

    #[nwg_control(parent: window, position: (10, 88), size: (400, 24))]
    input_token: nwg::TextInput,

    #[nwg_control(parent: window, text: "", position: (10, 124), size: (400, 60))]
    status: nwg::Label,

    #[nwg_control(parent: window, text: "Installer", position: (10, 192), size: (190, 32))]
    #[nwg_events( OnButtonClick: [InstallWindow::on_install] )]
    btn_install: nwg::Button,

    #[nwg_control(parent: window, text: "Fermer", position: (220, 192), size: (190, 32))]
    #[nwg_events( OnButtonClick: [InstallWindow::on_close] )]
    btn_close: nwg::Button,
}

impl InstallWindow {
    fn on_install(&self) {
        let server = self.input_server.text().trim().to_string();
        let token = self.input_token.text().trim().to_string();

        if server.is_empty() || token.is_empty() {
            self.status.set_text("Le serveur et le jeton sont obligatoires.");
            return;
        }
        if !install::is_elevated() {
            self.status.set_text(
                "Droits administrateur requis — relancer via clic droit > Exécuter en tant qu'administrateur.",
            );
            return;
        }

        self.status.set_text("Installation en cours…");
        self.btn_install.set_enabled(false);

        // Fenêtre GUI = thread non-async (boucle de messages Win32 classique) : on
        // construit un runtime tokio dédié à cet appel plutôt que de faire tourner toute
        // l'appli dans un contexte async — un seul appel bloquant de quelques centaines de
        // ms (enrôlement réseau), acceptable pour une action déclenchée par un clic.
        let result = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt.block_on(crate::install::install(Some(token), Some(server))),
            Err(e) => Err(anyhow::anyhow!("construction du runtime : {e}")),
        };

        match result {
            Ok(()) => {
                self.status.set_text("Installation réussie — le poste apparaît dans Inventaire > Agents.");
            }
            Err(e) => {
                self.status.set_text(&format!("Échec : {e:#}"));
                self.btn_install.set_enabled(true);
            }
        }
    }

    fn on_close(&self) {
        nwg::stop_thread_dispatch();
    }
}

use crate::install;

/// Point d'entrée appelé depuis `main.rs` quand l'exécutable est lancé sans argument, ou
/// via `allsafe-agent install` sans `--token`/`--server`.
pub fn run_install_wizard() -> anyhow::Result<()> {
    nwg::init().map_err(|e| anyhow::anyhow!("initialisation de l'interface graphique : {e}"))?;
    let _app = InstallWindow::build_ui(Default::default())
        .map_err(|e| anyhow::anyhow!("construction de la fenêtre : {e}"))?;
    nwg::dispatch_thread_events();
    Ok(())
}
