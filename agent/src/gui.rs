//! Fenêtre graphique (17/08/2026, remplacée par Tauri le 18/08/2026) — affichée quand
//! `allsafe-agent.exe` est lancé sans argument (double-clic). Quatre écrans derrière un
//! menu (Installation/Réparation/Mise à jour/Désinstallation, cf. `ui/index.html`), un seul
//! visible à la fois (`ui/app.js::showView`) — la logique effective reste entièrement dans
//! `install.rs`, ce module ne fait que le pont entre l'UI web et ces fonctions
//! (`#[tauri::command]`, appelées depuis `ui/app.js` via `invoke(...)`).
//!
//! Remplace l'ancienne implémentation `native-windows-gui` (rendu Win32 classique,
//! plafonnait à un thème "Windows 7 correct" au mieux — Common Controls v6 n'apporte jamais
//! le rendu Fluent/moderne, testé en conditions réelles) : `tauri` rend l'interface en
//! HTML/CSS via le WebView2 déjà présent nativement sur Windows 10 (1803+)/11.
//!
//! ✅ Vérifié par compilation + link croisés réels (toolchain mingw-w64, conteneur,
//! 18/08/2026) — l'arbre `tauri`/`wry`/`webview2-com` compile et link pour
//! `x86_64-pc-windows-gnu`. **Reste non vérifié** : comportement runtime réel du WebView2
//! (chargement de la page, `invoke` JS → Rust) sur un vrai poste Windows.
//!
//! ⚠️ Conséquence assumée de cette cible GNU (cf. Cargo.toml) : `WebView2Loader.dll` doit
//! être présent à côté de l'exe (généré automatiquement par `tauri-build` dans le même
//! dossier que le binaire compilé) — plus un "seul .exe" strictement parlant, mais toujours
//! zéro script/logique à lancer à la main, juste un fichier compagnon statique.

use crate::install;

#[tauri::command]
async fn cmd_install(server: String, token: String) -> Result<(), String> {
    install::install(Some(token), Some(server)).await.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn cmd_repair() -> Result<(), String> {
    install::install(None, None).await.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn cmd_check_update(server: String) -> Result<Option<String>, String> {
    install::check_update(&server).await.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn cmd_apply_update(server: String) -> Result<(), String> {
    install::apply_update(&server).await.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn cmd_uninstall() -> Result<(), String> {
    install::uninstall().map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn cmd_known_server() -> Option<String> {
    install::known_server()
}

/// Version du binaire actuellement en train de tourner (19/08/2026, demande explicite —
/// affichée dans le bandeau) : sans ça, rien dans la fenêtre ne dit quelle version est
/// réellement active, seul `allsafe-agent --version` en ligne de commande le révélait.
#[tauri::command]
fn cmd_version() -> &'static str {
    crate::RELEASE_VERSION
}

#[tauri::command]
fn cmd_quit(app: tauri::AppHandle) {
    app.exit(0);
}

/// Point d'entrée appelé depuis `main.rs` quand l'exécutable est lancé sans argument, ou
/// via `allsafe-agent install` sans `--token`/`--server`. Toujours appelé AVANT la
/// construction d'un runtime tokio dans `main.rs` (comme `service::run`, cf. commentaire
/// d'en-tête de `main.rs`) — `tauri::Builder::run` construit et gère le sien en interne.
pub fn run_install_wizard() -> anyhow::Result<()> {
    // L'exe reste subsystem "console" (la CLI `enroll`/`checkin`/`install --token...` a
    // besoin que sa sortie s'affiche dans le terminal appelant) — Windows alloue donc quand
    // même une console au lancement, y compris ici, laissant une fenêtre noire vide visible
    // derrière la fenêtre graphique tant qu'on ne s'en détache pas explicitement (constaté
    // en conditions réelles). Sans effet si on arrive ici via `allsafe-agent install` tapé
    // dans un terminal existant : cette console appartient à ce terminal, pas à ce process,
    // `FreeConsole` ne fait que nous en désolidariser, ne la ferme pas.
    unsafe {
        winapi::um::wincon::FreeConsole();
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            cmd_install,
            cmd_repair,
            cmd_check_update,
            cmd_apply_update,
            cmd_uninstall,
            cmd_known_server,
            cmd_quit,
            cmd_version,
        ])
        .run(tauri::generate_context!())
        .map_err(|e| anyhow::anyhow!("erreur Tauri : {e}"))
}
