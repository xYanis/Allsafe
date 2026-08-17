// Manifeste Windows `requireAdministrator` (17/08/2026) — embarqué dans l'exécutable pour
// que Windows déclenche l'UAC automatiquement au lancement (double-clic ou ligne de
// commande), sans dépendre de l'utilisateur pour ouvrir un PowerShell "en administrateur"
// (cause de l'échec silencieux constaté sur le poste aos12, cf. STATUS.md/docs/AGENTS.md).
// Cohérent avec le service Windows (`service-run`, toujours lancé par le SCM en
// LocalSystem, jamais soumis à l'UAC) et avec Linux où `enroll`/les checks de durcissement
// exigent déjà `root` (cf. agent/README.md).
//
// `build.rs` compile toujours pour l'hôte qui build (même en cross-compilation vers
// Windows depuis Linux, cf. agent/README.md § Build) — le `if` ci-dessous le rend no-op
// sur toute autre cible que Windows plutôt que de le restreindre via `[target.'cfg(windows)'
// .build-dependencies]`, qui ne s'appliquerait pas correctement à un script de build.
//
// ⚠️ NON VÉRIFIÉ EN COMPILATION (pas de toolchain Rust/mingw-w64 disponible dans
// l'environnement où ce fichier a été écrit, 17/08/2026) — nécessite `windres` sur le PATH
// (fourni par mingw-w64, déjà requis pour la compilation croisée de l'exécutable
// Windows) ; à vérifier au premier build réel.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winres::WindowsResource::new();
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
</assembly>
"#,
        );
        if let Err(e) = res.compile() {
            println!("cargo:warning=échec de l'embarquement du manifeste UAC (windres manquant ?) : {e}");
        }
    }
}
