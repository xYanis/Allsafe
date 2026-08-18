//! Fenêtre graphique (17/08/2026, refonte visuelle du 17/08/2026 — demande explicite : un
//! vrai menu façon installeur Windows plutôt qu'un simple formulaire) — affichée quand
//! `allsafe-agent.exe` est lancé sans argument (double-clic). Quatre écrans derrière un
//! menu (Installation/Réparation/Mise à jour/Désinstallation), chacun un `nwg::Frame`
//! affiché/masqué (`set_visible`) plutôt que des fenêtres séparées — la logique effective
//! reste entièrement dans `install.rs`, ce module ne fait que la saisie et l'affichage du
//! résultat.
//!
//! ✅ **Vérifié par compilation + link croisés réels** (toolchain mingw-w64 système, cf.
//! docs/AGENTS.md § Vérification) — API `native-windows-gui`/`native-windows-derive`
//! (`nwg_control`/`nwg_resource`/`nwg_events`, `background_color` sur `Label`, ressource
//! `Font` référencée par les autres contrôles) confirmée contre le code source de la crate,
//! pas seulement sa documentation. **Reste non vérifié** : le rendu réel sur un poste
//! Windows (positions/tailles choisies à l'aveugle, sans retour visuel possible ici).

use native_windows_derive as nwd;
use native_windows_gui as nwg;
use nwd::NwgUi;
use nwg::NativeUi;

// Couleur Inventaire (module qui héberge la page Agents, cf. CLAUDE.md) — reprise pour le
// bandeau du haut, seul repère de marque qu'un installeur Win32 classique puisse porter
// sans dépendance graphique supplémentaire (pas de logo : pas de fichier .ico converti).
const BRAND_COLOR: [u8; 3] = [0x39, 0xc5, 0xcf];

// Même position/taille pour les quatre écrans (menu + 3 actions) : évite les écarts de
// pixel entre écrans copiés-collés, la seule différence visible au clic doit être le
// contenu, pas un décalage de cadre.
const PAGE_POS: (i32, i32) = (20, 78);
const PAGE_SIZE: (i32, i32) = (440, 342);

#[derive(Default, NwgUi)]
pub struct InstallWindow {
    #[nwg_control(size: (480, 460), position: (300, 300), title: "Allsafe Agent", flags: "WINDOW|VISIBLE", center: true)]
    #[nwg_events( OnWindowClose: [InstallWindow::on_close] )]
    window: nwg::Window,

    #[nwg_resource(family: "Segoe UI", size: 24, weight: 700)]
    title_font: nwg::Font,

    #[nwg_resource(family: "Segoe UI", size: 15, weight: 700)]
    subtitle_font: nwg::Font,

    #[nwg_control(parent: window, text: "Allsafe Agent", position: (0, 0), size: (480, 64),
        background_color: Some(BRAND_COLOR), font: Some(&data.title_font),
        h_align: nwg::HTextAlign::Center, v_align: nwg::VTextAlign::Center)]
    banner: nwg::Label,

    // ─── Menu ────────────────────────────────────────────────────────────────────
    #[nwg_control(parent: window, position: PAGE_POS, size: PAGE_SIZE, flags: "VISIBLE")]
    page_menu: nwg::Frame,

    #[nwg_control(parent: page_menu, text: "Que veux-tu faire ?", position: (0, 0), size: (400, 24), font: Some(&data.subtitle_font))]
    menu_title: nwg::Label,

    #[nwg_control(parent: page_menu, text: "Installation", position: (0, 48), size: (400, 46))]
    #[nwg_events( OnButtonClick: [InstallWindow::show_install] )]
    btn_menu_install: nwg::Button,

    #[nwg_control(parent: page_menu, text: "Réparation", position: (0, 104), size: (400, 46))]
    #[nwg_events( OnButtonClick: [InstallWindow::show_repair] )]
    btn_menu_repair: nwg::Button,

    #[nwg_control(parent: page_menu, text: "Mise à jour", position: (0, 160), size: (400, 46))]
    #[nwg_events( OnButtonClick: [InstallWindow::show_update] )]
    btn_menu_update: nwg::Button,

    #[nwg_control(parent: page_menu, text: "Désinstallation", position: (0, 216), size: (400, 46))]
    #[nwg_events( OnButtonClick: [InstallWindow::show_uninstall] )]
    btn_menu_uninstall: nwg::Button,

    #[nwg_control(parent: page_menu, text: "Fermer", position: (0, 296), size: (400, 36))]
    #[nwg_events( OnButtonClick: [InstallWindow::on_close] )]
    btn_menu_close: nwg::Button,

    // ─── Installation ───────────────────────────────────────────────────────────
    #[nwg_control(parent: window, position: PAGE_POS, size: PAGE_SIZE, flags: "BORDER")]
    page_install: nwg::Frame,

    #[nwg_control(parent: page_install, text: "Installation", position: (0, 0), size: (400, 24), font: Some(&data.subtitle_font))]
    install_title: nwg::Label,

    #[nwg_control(parent: page_install, text: "URL du serveur Allsafe (ex: http://192.168.1.10:3000) :", position: (0, 34), size: (400, 20))]
    label_install_server: nwg::Label,

    #[nwg_control(parent: page_install, text: "http://", position: (0, 56), size: (400, 24))]
    input_install_server: nwg::TextInput,

    #[nwg_control(parent: page_install, text: "Jeton d'enrôlement :", position: (0, 90), size: (400, 20))]
    label_install_token: nwg::Label,

    #[nwg_control(parent: page_install, position: (0, 112), size: (400, 24))]
    input_install_token: nwg::TextInput,

    #[nwg_control(parent: page_install, text: "", position: (0, 148), size: (400, 84))]
    status_install: nwg::Label,

    #[nwg_control(parent: page_install, text: "Installer", position: (0, 296), size: (190, 36))]
    #[nwg_events( OnButtonClick: [InstallWindow::on_install_go] )]
    btn_install_go: nwg::Button,

    #[nwg_control(parent: page_install, text: "Retour", position: (210, 296), size: (190, 36))]
    #[nwg_events( OnButtonClick: [InstallWindow::show_menu] )]
    btn_install_back: nwg::Button,

    // ─── Réparation ─────────────────────────────────────────────────────────────
    #[nwg_control(parent: window, position: PAGE_POS, size: PAGE_SIZE, flags: "BORDER")]
    page_repair: nwg::Frame,

    #[nwg_control(parent: page_repair, text: "Réparation", position: (0, 0), size: (400, 24), font: Some(&data.subtitle_font))]
    repair_title: nwg::Label,

    #[nwg_control(parent: page_repair, position: (0, 34), size: (400, 90),
        text: "Réenregistre le service Windows et corrige le PATH système, sans toucher à l'enrôlement existant (le jeton n'est pas redemandé). À utiliser si le service ne démarre plus ou si allsafe-agent n'est plus reconnu en ligne de commande.")]
    label_repair_info: nwg::Label,

    #[nwg_control(parent: page_repair, text: "", position: (0, 134), size: (400, 60))]
    status_repair: nwg::Label,

    #[nwg_control(parent: page_repair, text: "Réparer", position: (0, 296), size: (190, 36))]
    #[nwg_events( OnButtonClick: [InstallWindow::on_repair_go] )]
    btn_repair_go: nwg::Button,

    #[nwg_control(parent: page_repair, text: "Retour", position: (210, 296), size: (190, 36))]
    #[nwg_events( OnButtonClick: [InstallWindow::show_menu] )]
    btn_repair_back: nwg::Button,

    // ─── Mise à jour ────────────────────────────────────────────────────────────
    #[nwg_control(parent: window, position: PAGE_POS, size: PAGE_SIZE, flags: "BORDER")]
    page_update: nwg::Frame,

    #[nwg_control(parent: page_update, text: "Mise à jour", position: (0, 0), size: (400, 24), font: Some(&data.subtitle_font))]
    update_title: nwg::Label,

    #[nwg_control(parent: page_update, text: "URL du serveur Allsafe :", position: (0, 34), size: (400, 20))]
    label_update_server: nwg::Label,

    #[nwg_control(parent: page_update, text: "http://", position: (0, 56), size: (400, 24))]
    input_update_server: nwg::TextInput,

    #[nwg_control(parent: page_update, text: "", position: (0, 92), size: (400, 100))]
    status_update: nwg::Label,

    #[nwg_control(parent: page_update, text: "Vérifier", position: (0, 296), size: (120, 36))]
    #[nwg_events( OnButtonClick: [InstallWindow::on_update_check] )]
    btn_update_check: nwg::Button,

    #[nwg_control(parent: page_update, text: "Mettre à jour", position: (130, 296), size: (150, 36), enabled: false)]
    #[nwg_events( OnButtonClick: [InstallWindow::on_update_go] )]
    btn_update_go: nwg::Button,

    #[nwg_control(parent: page_update, text: "Retour", position: (290, 296), size: (110, 36))]
    #[nwg_events( OnButtonClick: [InstallWindow::show_menu] )]
    btn_update_back: nwg::Button,

    // ─── Désinstallation ────────────────────────────────────────────────────────
    #[nwg_control(parent: window, position: PAGE_POS, size: PAGE_SIZE, flags: "BORDER")]
    page_uninstall: nwg::Frame,

    #[nwg_control(parent: page_uninstall, text: "Désinstallation", position: (0, 0), size: (400, 24), font: Some(&data.subtitle_font))]
    uninstall_title: nwg::Label,

    #[nwg_control(parent: page_uninstall, position: (0, 34), size: (400, 90),
        text: "Arrête et désenregistre le service Windows, retire l'entrée PATH. Les fichiers (Program Files\\Allsafe Agent, %ProgramData%\\allsafe-agent) ne sont pas supprimés automatiquement — un exécutable ne peut pas se supprimer lui-même en cours d'exécution.")]
    label_uninstall_warn: nwg::Label,

    #[nwg_control(parent: page_uninstall, text: "", position: (0, 134), size: (400, 60))]
    status_uninstall: nwg::Label,

    #[nwg_control(parent: page_uninstall, text: "Désinstaller", position: (0, 296), size: (190, 36))]
    #[nwg_events( OnButtonClick: [InstallWindow::on_uninstall_go] )]
    btn_uninstall_go: nwg::Button,

    #[nwg_control(parent: page_uninstall, text: "Retour", position: (210, 296), size: (190, 36))]
    #[nwg_events( OnButtonClick: [InstallWindow::show_menu] )]
    btn_uninstall_back: nwg::Button,
}

impl InstallWindow {
    // ─── Navigation — un seul écran visible à la fois, le menu masque tout le reste ───

    fn show_menu(&self) {
        self.page_install.set_visible(false);
        self.page_repair.set_visible(false);
        self.page_update.set_visible(false);
        self.page_uninstall.set_visible(false);
        self.page_menu.set_visible(true);
    }

    fn show_install(&self) {
        self.page_menu.set_visible(false);
        self.page_install.set_visible(true);
    }

    fn show_repair(&self) {
        self.page_menu.set_visible(false);
        self.page_repair.set_visible(true);
    }

    fn show_update(&self) {
        self.page_menu.set_visible(false);
        self.page_update.set_visible(true);
    }

    fn show_uninstall(&self) {
        self.page_menu.set_visible(false);
        self.page_uninstall.set_visible(true);
    }

    fn on_close(&self) {
        nwg::stop_thread_dispatch();
    }

    // ─── Installation ───────────────────────────────────────────────────────────

    fn on_install_go(&self) {
        let server = self.input_install_server.text().trim().to_string();
        let token = self.input_install_token.text().trim().to_string();

        if server.is_empty() || token.is_empty() {
            self.status_install.set_text("Le serveur et le jeton sont obligatoires.");
            return;
        }
        if !install::is_elevated() {
            self.status_install.set_text(
                "Droits administrateur requis — relancer via clic droit > Exécuter en tant qu'administrateur.",
            );
            return;
        }

        self.status_install.set_text("Installation en cours…");
        self.btn_install_go.set_enabled(false);

        let result = run_async(install::install(Some(token), Some(server)));
        match result {
            Ok(()) => self.status_install.set_text("Installation réussie — le poste apparaît dans Inventaire > Agents."),
            Err(e) => {
                self.status_install.set_text(&format!("Échec : {e:#}"));
                self.btn_install_go.set_enabled(true);
            }
        }
    }

    // ─── Réparation ─────────────────────────────────────────────────────────────

    fn on_repair_go(&self) {
        if !install::is_elevated() {
            self.status_repair.set_text(
                "Droits administrateur requis — relancer via clic droit > Exécuter en tant qu'administrateur.",
            );
            return;
        }
        self.status_repair.set_text("Réparation en cours…");
        self.btn_repair_go.set_enabled(false);

        let result = run_async(install::install(None, None));
        match result {
            Ok(()) => self.status_repair.set_text("Service et PATH réparés."),
            Err(e) => self.status_repair.set_text(&format!("Échec : {e:#}")),
        }
        self.btn_repair_go.set_enabled(true);
    }

    // ─── Mise à jour ────────────────────────────────────────────────────────────

    fn on_update_check(&self) {
        let server = self.input_update_server.text().trim().to_string();
        if server.is_empty() {
            self.status_update.set_text("L'URL du serveur est obligatoire.");
            return;
        }
        self.status_update.set_text("Vérification…");
        self.btn_update_go.set_enabled(false);

        match run_async(install::check_update(&server)) {
            Ok(Some(version)) => {
                self.status_update.set_text(&format!("Nouvelle version disponible : {version}"));
                self.btn_update_go.set_enabled(true);
            }
            Ok(None) => self.status_update.set_text("Déjà à jour."),
            Err(e) => self.status_update.set_text(&format!("Échec : {e:#}")),
        }
    }

    fn on_update_go(&self) {
        let server = self.input_update_server.text().trim().to_string();
        if !install::is_elevated() {
            self.status_update.set_text(
                "Droits administrateur requis — relancer via clic droit > Exécuter en tant qu'administrateur.",
            );
            return;
        }
        self.status_update.set_text("Mise à jour en cours…");
        self.btn_update_go.set_enabled(false);

        match run_async(install::apply_update(&server)) {
            Ok(()) => self.status_update.set_text("Mise à jour installée avec succès."),
            Err(e) => {
                self.status_update.set_text(&format!("Échec : {e:#}"));
                self.btn_update_go.set_enabled(true);
            }
        }
    }

    // ─── Désinstallation ────────────────────────────────────────────────────────

    fn on_uninstall_go(&self) {
        if !install::is_elevated() {
            self.status_uninstall.set_text(
                "Droits administrateur requis — relancer via clic droit > Exécuter en tant qu'administrateur.",
            );
            return;
        }
        self.status_uninstall.set_text("Désinstallation en cours…");
        self.btn_uninstall_go.set_enabled(false);

        match install::uninstall() {
            Ok(()) => self.status_uninstall.set_text("Service désinstallé."),
            Err(e) => {
                self.status_uninstall.set_text(&format!("Échec : {e:#}"));
                self.btn_uninstall_go.set_enabled(true);
            }
        }
    }
}

// Fenêtre GUI = thread non-async (boucle de messages Win32 classique) : un runtime tokio
// ponctuel par action plutôt que de faire tourner toute l'appli dans un contexte async —
// chaque appel est bloquant quelques centaines de ms (réseau), acceptable pour une action
// déclenchée par un clic.
fn run_async<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Runtime::new().expect("construction du runtime tokio").block_on(fut)
}

use crate::install;

/// Point d'entrée appelé depuis `main.rs` quand l'exécutable est lancé sans argument, ou
/// via `allsafe-agent install` sans `--token`/`--server`.
pub fn run_install_wizard() -> anyhow::Result<()> {
    // L'exe reste subsystem "console" (la CLI `enroll`/`checkin`/`install --token...` a
    // besoin que sa sortie s'affiche dans le terminal appelant) — Windows alloue donc quand
    // même une console au lancement, y compris ici, laissant une fenêtre noire vide visible
    // derrière la fenêtre graphique tant qu'on ne s'en détache pas explicitement (constaté
    // en conditions réelles). Sans effet si on arrive ici via `allsafe-agent install` tapé
    // dans un terminal existant : cette console appartient à ce terminal, pas à ce process,
    // `FreeConsole` ne fait que nous en désolidariser, ne la ferme pas.
    unsafe { winapi::um::wincon::FreeConsole(); }

    nwg::init().map_err(|e| anyhow::anyhow!("initialisation de l'interface graphique : {e}"))?;
    let app = InstallWindow::build_ui(Default::default())
        .map_err(|e| anyhow::anyhow!("construction de la fenêtre : {e}"))?;

    // Préremplit l'écran "Mise à jour" si ce poste est déjà enrôlé (agent.json présent) —
    // évite de retaper une URL déjà connue du poste. Pas de prérempli équivalent côté
    // Installation (jamais de jeton déjà connu) ni Réparation/Désinstallation (aucun champ).
    if let Some(server) = install::known_server() {
        app.input_update_server.set_text(&server);
    }

    nwg::dispatch_thread_events();
    Ok(())
}
