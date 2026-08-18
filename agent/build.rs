// Manifeste Windows `requireAdministrator` (17/08/2026) — embarqué dans l'exécutable pour
// que Windows déclenche l'UAC automatiquement au lancement (double-clic ou ligne de
// commande), sans dépendre de l'utilisateur pour ouvrir un PowerShell "en administrateur"
// (cause de l'échec silencieux constaté sur le poste aos12, cf. docs/AGENTS.md).
// Cohérent avec le service Windows (`service-run`, toujours lancé par le SCM en
// LocalSystem, jamais soumis à l'UAC) et avec Linux où `enroll`/les checks de durcissement
// exigent déjà `root` (cf. agent/README.md).
//
// 18/08/2026 — `tauri_build` remplace l'appel `winres` manuel précédent : il gère lui-même
// l'icône (`icons/icon.ico`, obligatoire) et le manifeste (dont notre `requireAdministrator`
// injecté via `WindowsAttributes::app_manifest`) en un seul appel, plus fiable qu'une
// double gestion manuelle. `dpiAware` gardé dans le manifeste (rendu net des éléments de
// chrome de fenêtre — le contenu WebView2 lui-même gère déjà son propre scaling HiDPI,
// mais la fenêtre/bordure Win32 autour en dépend toujours).
//
// ⚠️ **Dépendance `Microsoft.Windows.Common-Controls` réintroduite** (retirée par erreur au
// passage à Tauri, en supposant qu'elle ne servait qu'au thème des contrôles Win32 classiques
// — sans objet avec un rendu WebView2). Faux : testé en conditions réelles sur un poste,
// erreur au lancement `Le point d'entrée de procédure TaskDialogIndirect est introuvable
// dans... allsafe-agent.exe` — `TaskDialogIndirect` n'existe que dans comctl32.dll v6+
// (Vista et après), utilisée en interne par `tao`/`muda` (fenêtrage/menus sous Tauri),
// indépendamment de ce que WebView2 rend à l'écran. Sans cette dépendance, Windows charge la
// comctl32.dll v5.x par défaut pour tout exe sans manifeste la réclamant explicitement — pas
// juste un rendu "non thémé" comme avec native-windows-gui, mais carrément un plantage au
// démarrage.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let windows = tauri_build::WindowsAttributes::new().app_manifest(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*" />
    </dependentAssembly>
  </dependency>
  <asmv3:application xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
    <asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
      <dpiAware>true</dpiAware>
    </asmv3:windowsSettings>
  </asmv3:application>
</assembly>
"#,
        );
        let attrs = tauri_build::Attributes::new().windows_attributes(windows);
        if let Err(e) = tauri_build::try_build(attrs) {
            println!("cargo:warning=échec de tauri_build (icons/icon.ico manquant ? windres/mingw-w64 manquant ?) : {e}");
        }
    } else {
        // Hors Windows, `tauri_build::build()` ne fait rien d'utile pour ce projet (pas de
        // cible Linux/macOS pour l'app graphique, `gui.rs`/`install.rs` sont `#[cfg(windows)]`)
        // — no-op explicite plutôt que d'appeler `tauri_build` sans raison.
    }
}
