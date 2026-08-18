// Manifeste Windows `requireAdministrator` (17/08/2026) — embarqué dans l'exécutable pour
// que Windows déclenche l'UAC automatiquement au lancement (double-clic ou ligne de
// commande), sans dépendre de l'utilisateur pour ouvrir un PowerShell "en administrateur"
// (cause de l'échec silencieux constaté sur le poste aos12, cf. docs/AGENTS.md).
// Cohérent avec le service Windows (`service-run`, toujours lancé par le SCM en
// LocalSystem, jamais soumis à l'UAC) et avec Linux où `enroll`/les checks de durcissement
// exigent déjà `root` (cf. agent/README.md).
//
// `build.rs` compile toujours pour l'hôte qui build (même en cross-compilation vers
// Windows depuis Linux, cf. agent/README.md § Build) — le `if` ci-dessous le rend no-op
// sur toute autre cible que Windows plutôt que de le restreindre via `[target.'cfg(windows)'
// .build-dependencies]`, qui ne s'appliquerait pas correctement à un script de build.
//
// 17/08/2026 — vérifié par compilation réelle (toolchain assemblée manuellement, cf.
// STATUS.md) : `winres` cherche `windres`/`ar` **nus** par défaut (corrects seulement sur
// un hôte Windows natif) — en cross-compilation depuis Linux (seul chemin documenté,
// agent/README.md § Build), il faut explicitement pointer vers les binaires préfixés
// `x86_64-w64-mingw32-*` fournis par mingw-w64, sans quoi `res.compile()` échoue avec
// "No such file or directory" (repéré et corrigé avant tout build réel, pas laissé à
// découvrir par l'utilisateur).
//
// 18/08/2026 — ajout de la dépendance `Microsoft.Windows.Common-Controls` (rendu constaté
// en conditions réelles sur un poste, capture à l'appui : boutons/contrôles non thémés,
// rendu "Windows 98" malgré `nwg::init()` qui tente pourtant d'activer les styles visuels
// tout seul à l'exécution via un contexte d'activation `CreateActCtxW` — cf. code source de
// `native-windows-gui`, `win32/mod.rs::enable_visual_styles`). Cette astuce runtime cohabite
// mal avec un manifeste déjà embarqué par l'exe lui-même (celui-ci devient le manifeste de
// processus par défaut, prioritaire) : le fait de déclarer nous-mêmes la dépendance dans CE
// manifeste, plutôt que de compter sur le contournement de `nwg`, est l'approche standard et
// évite l'ambiguïté. `dpiAware` ajouté au passage (même bloc, coût nul) — évite un rendu flou
// par mise à l'échelle bitmap sur les écrans HiDPI, autre symptôme classique de "vieille appli
// Win32". ⚠️ Non re-vérifié visuellement (pas de poste Windows disponible pour capturer un
// nouveau rendu depuis ici) — hypothèse solide (mécanisme Win32 documenté), pas confirmée.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winres::WindowsResource::new();
        res.set_windres_path("x86_64-w64-mingw32-windres");
        res.set_ar_path("x86_64-w64-mingw32-ar");
        res.set_manifest(
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
        match res.compile() {
            Err(e) => println!("cargo:warning=échec de l'embarquement du manifeste UAC (windres manquant ?) : {e}"),
            Ok(()) => {
                // 17/08/2026 — vérifié par compilation réelle : `winres` emballe la ressource
                // compilée dans une archive statique (`cargo:rustc-link-lib=static=resource`),
                // mais l'objet ne contient aucun symbole de code référencé ailleurs — l'éditeur
                // de liens GNU (`ld`, cible `x86_64-pc-windows-gnu`) n'extrait un membre
                // d'archive que s'il résout un symbole non défini, donc il **élague silencieusement
                // ce membre et le manifeste n'atterrit jamais dans l'exécutable final** (`.rsrc`
                // absent, confirmé via `objdump -h`) — contrairement à `link.exe` (MSVC) qui
                // traite les `.res` à part. `rustc-link-arg` pointant directement sur l'objet
                // (hors archive) force son inclusion inconditionnelle. Sans cette ligne, la
                // fenêtre UAC ne se déclencherait jamais et l'échec resterait invisible (aucune
                // erreur de build) jusqu'à un test manuel sur un vrai poste.
                if let Ok(out_dir) = std::env::var("OUT_DIR") {
                    println!("cargo:rustc-link-arg={out_dir}/resource.o");
                }
            }
        }
    }
}
