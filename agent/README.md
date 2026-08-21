# allsafe-agent

Agent Allsafe (lecture seule) pour postes Windows/Linux — complète le scan centralisé
SSH/WinRM (`backend/services/asset_scanner.py`) sur les postes qu'il atteint mal (éteints,
hors réseau, VPN). Ne modifie et n'exécute jamais rien sur le poste au-delà de commandes de
lecture locales (cf. `CLAUDE.md` § non-intervention).

## Usage

```bash
# 1. Générer un jeton d'enrôlement depuis Allsafe > Sécurité > Agents (admin)
# 2. Sur le poste :
allsafe-agent enroll --token <JETON> --server https://allsafe.exemple.local
allsafe-agent run       # mode recommandé (13/08/2026) — boucle persistante, ne se termine jamais
allsafe-agent checkin   # ou : une seule collecte, à planifier soi-même (cron/tâche planifiée)
```

`enroll` persiste l'identité du poste (serveur + credential) dans un fichier local à
permissions restreintes (`/etc/allsafe-agent/agent.json` sur Linux, `%ProgramData%\allsafe-
agent\agent.json` sur Windows). `run`/`checkin` collectent l'inventaire + les checks de
durcissement et les poussent au serveur. Les paquets `.deb`/`.msi` (§ Installation) installent
et démarrent automatiquement un service systemd/Windows qui lance `run` — `checkin` reste utile
pour un poste ponctuel ou tester une collecte sans installer le service.

⚠️ **`--server`** : l'URL de base d'Allsafe telle que joignable **depuis le poste**, sans
`/api` à la fin (ajouté par l'agent). Si le backend n'est exposé qu'en local sur la machine
Docker (ex. `127.0.0.1:8000` dans `docker-compose.yml`), c'est le port du **frontend**
(`3000`, qui proxy `/api` vers le backend) qu'il faut viser, pas celui du backend —
schéma `http://` ou `https://` obligatoire (`hhtp://` ou toute coquille dans le schéma fait
échouer l'appel avec `URL scheme is not allowed`, avant même la moindre tentative réseau).

## Installation directe (17/08/2026 — sans .msi ni script ; GUI Tauri le 18/08/2026)

> ✅ **Vérifié par compilation + link croisés réels** (`src/install.rs`/`src/gui.rs`/
> `build.rs`, `x86_64-pc-windows-gnu`, conteneur `rust:1-trixie`) — script CI complet
> (`.gitlab-ci.yml::build-agent`) rejoué avec succès de bout en bout : build, `.msi`, `.deb`,
> vérifications `msiinfo`. **Reste non vérifié** : le comportement runtime sur un vrai poste
> Windows (chargement WebView2, rendu, `invoke` JS → Rust).

Pensé pour les **actifs critiques** (jeton unique par actif, cf. § Installation rapide
ci-dessous pour le cas parc/non-critique) : deux fichiers à copier sur le poste
(`agent/dist/` ou compilés soi-même) — `allsafe-agent.exe` **et** `WebView2Loader.dll`, dans
le même dossier. Pas de `.msi`, pas de script, mais pas non plus un seul fichier isolé (cf.
encadré ci-dessous). Depuis l'appli (18/08/2026) : bouton "Télécharger l'agent" sur la page
Agents sert les deux fichiers déjà zippés ensemble (`GET /api/agents/latest/windows-exe`) —
plus besoin d'aller chercher `WebView2Loader.dll` séparément.

- **Double-clic sur `allsafe-agent.exe`, sans argument** → ouvre une fenêtre (menu
  Installation/Réparation/Mise à jour/Désinstallation, rendue en HTML/CSS via WebView2 —
  cf. `ui/`), demande l'élévation UAC automatiquement (manifeste `requireAdministrator`,
  `build.rs`). Écran Installation : serveur + jeton, service Windows + PATH + enrôlement en
  un clic.
- **Ligne de commande équivalente** (même effet, pratique pour scripter) :
  ```powershell
  .\allsafe-agent.exe install --token <JETON> --server http://<hôte-allsafe>:3000
  ```
- **Désinstallation** : `allsafe-agent.exe uninstall` (admin), ou depuis l'écran
  "Désinstallation" de la fenêtre — arrête/désenregistre le service et retire le `PATH`. Ne
  supprime pas les fichiers (un exe ne peut pas se supprimer lui-même en cours d'exécution)
  — à faire à la main si besoin (`Program Files\Allsafe Agent`, `%ProgramData%\allsafe-agent`).

L'exécutable se copie lui-même vers `Program Files\Allsafe Agent\allsafe-agent.exe` au
premier lancement (même emplacement que le `.msi`) — inutile de le placer soi-même à cet
endroit avant.

> ⚠️ **Pourquoi deux fichiers, pas un seul** — décision actée le 18/08/2026 : sur la cible
> `x86_64-pc-windows-gnu` (notre seul pipeline de build, cross-compilé depuis Linux/CI),
> `WebView2Loader.dll` (~200 Ko, redistribuable Microsoft, généré automatiquement par
> `tauri-build` à côté de l'exe compilé) est un import **statique**, résolu par Windows
> avant même le lancement du programme — impossible à extraire "à la volée" au démarrage.
> Basculer en MSVC lierait le loader statiquement (vrai "un seul .exe"), mais changerait tout
> le pipeline de cross-compilation déjà en place (jamais testé, risque disproportionné pour
> ce gain). Le `.msi` embarque déjà les deux fichiers ensemble (cf. `wix/main.wxs`) — un seul
> artefact à double-cliquer pour qui préfère cette voie.

## Build "bulk" — jeton réutilisable pré-rempli dans le .msi

Pensé pour les **actifs non-critiques** (un seul jeton réutilisable pour tout le lot,
déployé silencieusement par GPO "Installation de logiciels", cf. échange du 17/08/2026) :

1. Générer un jeton réutilisable ("Réutilisable (parc)") depuis Inventaire > Agents,
   `max_uses` = taille réelle du lot, expiration courte = fenêtre de déploiement réelle
   (cf. docs/AGENTS.md § Sécurité — ne pas laisser un `.msi` valable indéfiniment).
2. Créer `enroll-defaults.json` à côté de `wix/main.wxs` :
   ```json
   { "server": "http://<hôte-allsafe>:3000", "token": "<JETON_REUTILISABLE>" }
   ```
3. Ajouter ce fichier au `<Component>` de `wix/main.wxs` (même dossier `INSTALLFOLDER` que
   l'exécutable), puis rebuilder le `.msi` normalement (`wixl -a x64 ...`).
4. Au premier démarrage du service sur chaque poste, `daemon.rs::bootstrap_from_defaults`
   détecte l'absence de configuration existante + la présence de ce fichier, et s'auto-
   enrôle avec — aucune interaction, aucun jeton à saisir sur chaque poste.

⚠️ Un `.msi` "bulk" contient le jeton en clair (extractible du fichier) — traiter ce build
comme un artefact jetable (révoquer le jeton une fois le parc déployé), pas un fichier à
garder indéfiniment sur un partage. Le `.msi`/l'`.exe` "normaux" (sans `enroll-defaults.json`)
n'embarquent jamais rien — ce fichier n'existe que dans ce build dédié.

## Installation rapide (recommandée — script)

**17/08/2026** : plutôt que les commandes manuelles ci-dessous, `agent/deploy/update-agent.ps1`/
`.sh` téléchargent le paquet depuis Allsafe, l'installent et enrôlent le poste en une seule
commande — vérifient l'élévation (Windows)/root (Linux) et affichent les erreurs à l'écran au
lieu de les faire disparaître dans un log (cause d'une install `.msi` `/qn` silencieusement
échouée en conditions réelles, poste `aos12`, 17/08/2026). Seul le script (petit fichier texte)
doit être transféré sur le poste, pas le `.msi`/`.deb` :

```powershell
# Windows, PowerShell en admin
.\update-agent.ps1 -Server http://<hôte-allsafe>:3000 -EnrollToken <JETON>
```
```bash
# Linux, root
sudo ./update-agent.sh http://<hôte-allsafe>:3000 <JETON>
```

La modale « Jeton d'enrôlement » (page Agents) génère ces deux commandes prêtes à copier, jeton
et URL déjà substitués. Les instructions manuelles ci-dessous restent valables pour un poste
isolé sans accès au script, ou pour comprendre ce que le script fait sous le capot.

### Linux (.deb)

```bash
# Transférer agent/dist/allsafe-agent_<version>_amd64.deb sur le poste, puis :
sudo dpkg -i allsafe-agent_<version>_amd64.deb
# → binaire installé dans /usr/bin/allsafe-agent, service systemd "allsafe-agent" démarré

sudo allsafe-agent enroll --token <JETON> --server http://<hôte-allsafe>:3000
sudo systemctl restart allsafe-agent   # prend le relais tout seul ensuite (check-in horaire)
```

`enroll` s'exécute en `root` : les checks de durcissement lisent des ressources protégées
(membres des groupes `sudo`/`wheel`, config SSH, LUKS...). Le service (13/08/2026,
`agent/deploy/allsafe-agent.service`) est enregistré et démarré automatiquement par le paquet
(`debian/postinst`) — rien à faire de plus, `systemctl status allsafe-agent` pour vérifier.

**Alternative sans service (cron)** — pour qui préfère ne pas laisser tourner un process
résident :

```bash
sudo systemctl disable --now allsafe-agent
echo "0 * * * * root /usr/bin/allsafe-agent checkin" | sudo tee /etc/cron.d/allsafe-agent
```

Exécute `checkin` toutes les heures pile, en root (champ utilisateur propre à
`/etc/cron.d/`, absent d'un `crontab -e` classique). Ajuster `0 * * * *` selon la fréquence
de rafraîchissement voulue (ex. `0 */6 * * *` = toutes les 6h) — rien d'imposé côté Allsafe.
⚠️ Sans le service, pas de scan à la demande réactif (latence bornée par cette fréquence) ni
de rapport de coupure (cf. `docs/AGENTS.md`).

### Windows (.msi)

```powershell
# Transférer agent/dist/allsafe-agent.msi sur le poste, puis double-clic ou :
msiexec /i allsafe-agent.msi /qn
# → exécutable installé dans "Program Files\Allsafe Agent", service Windows "AllsafeAgent" démarré

allsafe-agent enroll --token <JETON> --server http://<hôte-allsafe>:3000
Restart-Service AllsafeAgent   # prend le relais tout seul ensuite (check-in horaire)
```

À lancer depuis un PowerShell/invite de commandes **admin** (fenêtre ouverte via "Exécuter en
tant qu'administrateur" — être membre du groupe Administrateurs ne suffit pas, l'UAC filtre le
jeton par défaut) — mêmes accès protégés que côté Linux (`net localgroup administrators`,
`manage-bde`, clés de registre HKLM). Sans élévation, `msiexec /qn` échoue **sans le moindre
message** (constaté en conditions réelles, poste `aos12`, 17/08/2026) ; pour diagnostiquer un
échec, relancer avec un journal : `msiexec /i allsafe-agent.msi /l*v install.log`. Le service
(13/08/2026, `wix/main.wxs::ServiceInstall`) est enregistré et démarré automatiquement par le
`.msi` — rien à faire de plus, `Get-Service AllsafeAgent` pour vérifier.

⚠️ **`allsafe-agent` hors `PATH`** : avant le correctif du 17/08/2026 (`wix/main.wxs::Environment`,
à vérifier après rebuild — `msiinfo export allsafe-agent.msi Environment`), le `.msi` n'ajoutait
pas `Program Files\Allsafe Agent` au `PATH` système. Sur un `.msi` construit avant ce correctif
(ou si la vérification échoue), utiliser le chemin complet :
`& "C:\Program Files\Allsafe Agent\allsafe-agent.exe" enroll ...`. Même après le correctif, une
fenêtre PowerShell **déjà ouverte** ne relit pas le `PATH` — en ouvrir une nouvelle après l'install.

**Alternative sans service (Planificateur de tâches)** — pour qui préfère ne pas laisser
tourner un process résident :

```powershell
Stop-Service AllsafeAgent; Set-Service AllsafeAgent -StartupType Disabled
schtasks /create /tn "Allsafe Agent Checkin" /tr "'C:\Program Files\Allsafe Agent\allsafe-agent.exe' checkin" /sc hourly /ru SYSTEM
```

Exécute `checkin` toutes les heures sous le compte `SYSTEM` (accès registre HKLM sans
session interactive, cf. § Checks collectés dans `docs/AGENTS.md`). ⚠️ Sans le service, pas de
scan à la demande réactif (latence bornée par cette fréquence) ni de rapport de coupure.

## Mise à jour

Pas d'auto-update poussé par Allsafe (le backend ne se connecte jamais aux postes, `CLAUDE.md`
§1) : une nouvelle version se déploie en **rebuild + redistribution**. Réinstaller ne touche que
le binaire, jamais `agent.json` (le poste reste enrôlé, pas besoin de relancer `enroll`).

⚠️ **Versionnement séparé par plateforme** (19/08/2026, demande explicite) — `.exe`/`.msi`
(même binaire Windows compilé une fois, `.msi` l'embarque tel quel : ne peuvent jamais diverger
l'un de l'autre) et `.deb` sont des artefacts souvent modifiés indépendamment (un correctif MSI
ne touche jamais au binaire Linux, et réciproquement). Avant, une seule version crate
(`Cargo.toml`) forçait à bumper les deux à chaque release, même sans rien changer pour l'autre
OS — l'agent Linux s'affichait "en retard" dans Allsafe après un correctif Windows pur (incident
réel, cf. STATUS.md). Deux pistes indépendantes désormais, **ne jamais bumper l'une pour un
changement qui ne concerne que l'autre** :

| | Windows (.exe/.msi) | Linux (.deb) |
|---|---|---|
| Source de vérité | `src/main.rs::RELEASE_VERSION` (`#[cfg(target_os = "windows")]`) | `src/main.rs::RELEASE_VERSION` (`#[cfg(target_os = "linux")]`) **et** `Cargo.toml::version` (doivent rester identiques — `cargo-deb` n'a pas d'override indépendant, `unknown field version`, testé en conditions réelles) |
| Fichier MSI | `wix/main.wxs::Version` (4 segments, ex. `0.1.12.0`) — **oublié une fois le 13/08/2026** : sans ce bump, `ProductVersion` reste figé côté MSI même si le binaire à l'intérieur est à jour | — |
| Backend | `CURRENT_AGENT_VERSION_WINDOWS` (`backend/routers/agents.py`) | `CURRENT_AGENT_VERSION_LINUX` (`backend/routers/agents.py`) |

À chaque release, sur la ou les plateformes réellement concernées :
1. Bumper `RELEASE_VERSION` (Rust) + `wix/main.wxs::Version` (Windows) et/ou `Cargo.toml::version`
   (Linux) — cf. tableau ci-dessus, **avec la même valeur** de part et d'autre pour la plateforme
   concernée.
2. Rebuild + repackage (§ Build ci-dessous) — même si une seule plateforme a changé, la
   compilation croisée reconstruit forcément les deux binaires dans le même job CI (`rust:1-trixie`
   compile les deux cibles) ; seul ce qui a un `RELEASE_VERSION` bumpé change de contenu
   significatif, l'autre reste identique bit à bit hors métadonnées.
3. Copier les nouveaux paquets dans `dist/` — remplacer uniquement ceux qui ont changé (ne pas
   supprimer/retélécharger l'autre plateforme si elle n'a pas bougé).
4. Bumper `CURRENT_AGENT_VERSION_WINDOWS`/`_LINUX` (`backend/routers/agents.py`) **avec la même
   valeur** — sinon Allsafe compare à une version périmée et les postes à jour s'affichent à tort
   comme en retard (ou l'inverse). Rien n'automatise ce lien, les deux projets sont compilés
   séparément.
5. Redistribuer :
   - **Poste isolé/test** : `dpkg -i`/`msiexec` manuel (§ Installation ci-dessus). Sur un poste déjà
     enrôlé (`agent.json` déjà présent), le plus simple est de retélécharger directement le paquet
     publié par Allsafe plutôt que de transférer un fichier à la main — testé en conditions réelles
     le 19/08/2026 (`gitlab.aer.loc`, mise à jour 0.1.5 → 0.1.8 pour le socle diff de détection
     d'évènements) :
     ```bash
     wget -O /tmp/allsafe-agent.deb http://<serveur-allsafe>:<port>/api/agents/latest/linux
     sudo apt install /tmp/allsafe-agent.deb
     ```
     `apt install ./fichier.deb` fonctionne aussi bien que `dpkg -i` (résout les dépendances au
     passage si besoin) — `postinst` (`debian/postinst`) réenregistre et **redémarre** le service
     automatiquement (`systemctl restart`, cf. § Mise à jour du 19/08/2026 plus haut dans
     l'historique — `enable --now` seul ne suffisait pas sur un service déjà actif), rien d'autre à
     faire côté poste.
   - **Parc géré (13/08/2026)** : `deploy/update-agent.sh`/`.ps1`, planifiés par votre propre infra
     (cron/GPO), viennent chercher `GET /api/agents/latest/*` tout seuls et se réinstallent si
     besoin — cf. `deploy/README.md`. Toujours "pull", jamais Allsafe qui pousse.

Chaque `checkin` déclare sa version (`agent_version`, `RELEASE_VERSION`) — comparée côté serveur
à `CURRENT_AGENT_VERSION_WINDOWS`/`_LINUX` (selon l'OS de l'agent), elle fait apparaître un badge
« Mise à jour dispo » sur la page Agents pour les postes en retard (cf. `docs/AGENTS.md` § Mise à
jour).

## Build

Binaire natif (plateforme courante) :

```bash
cargo build --release
```

### Paquet Linux (.deb)

Via [`cargo-deb`](https://github.com/kornelski/cargo-deb) — génère un paquet installant le
binaire dans `/usr/bin/allsafe-agent` (métadonnées dans `Cargo.toml` §
`[package.metadata.deb]`) :

```bash
sudo apt-get install musl-tools
rustup target add x86_64-unknown-linux-musl
cargo install cargo-deb
cargo deb --target x86_64-unknown-linux-musl
# → target/debian/allsafe-agent_<version>_amd64.deb
```

⚠️ **`--target x86_64-unknown-linux-musl` obligatoire** (19/08/2026) — sans lui, `cargo deb`
build/package pour la cible **native** du conteneur de build, glibc comprise. Incident réel :
un `.deb` construit nativement dans `rust:1-trixie` (Debian 13, glibc 2.41 — cette image est
nécessaire pour `wixl` côté build Windows, cf. § ci-dessous) refusait de s'installer sur le
parc cible (Debian 12/bookworm, glibc 2.36) :
`Dépend: libc6 (>= 2.39) mais 2.36-9+deb12u14 devra être installé`. musl (lien 100% statique,
aucune dépendance dynamique, `ldd` renvoie `statically linked`) élimine le problème pour de
bon plutôt que de juste viser une distro de build plus ancienne (qui aurait fini par
reproduire le même écart glibc un jour, cf. Debian 11→12→13). Aucune dépendance C dans
l'arbre Linux du crate (les seules deps qui en auraient — `tauri`/`winapi`/`windows-service`
— sont `[target.'cfg(windows)'.dependencies]`, jamais compilées côté Linux ; `reqwest` en
`rustls-tls`, pas OpenSSL, le piège musl le plus classique) : compile sans adaptation.
Vérifié en conditions réelles : `dpkg-deb --info` sur le `.deb` généré affiche `Depends:`
**vide**.

Vérification : `dpkg-deb --info`/`--contents target/debian/*.deb`.

### Exécutable + installeur Windows (.exe / .msi)

Compilation croisée depuis Linux (mingw-w64, pas besoin d'une machine Windows pour ça) :

```bash
sudo apt-get install mingw-w64
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# → target/x86_64-pc-windows-gnu/release/allsafe-agent.exe
```

✅ **Vérifié par compilation + link croisés réels** (18/08/2026, conteneur, cf.
`install.rs`/`gui.rs`) : `build.rs` embarque un manifeste `requireAdministrator` via
`tauri_build::WindowsAttributes::app_manifest` (remplace un appel `winres` manuel antérieur).
⚠️ **Historique, gardé pour mémoire** : la version manuelle avait un piège GNU/`ld`
spécifique — sans forcer `cargo:rustc-link-arg=<OUT_DIR>/resource.o`, l'éditeur de liens GNU
élague silencieusement l'objet ressource (aucun symbole de code à résoudre dedans → jamais
extrait de l'archive statique), le manifeste ne finissant **jamais** dans l'exécutable sans
la moindre erreur de build pour le signaler. `tauri_build` (via `embed-resource`, successeur
de `winres`) n'a pas ce problème — vérifié empiriquement (`requireAdministrator` bien présent
dans le binaire compilé, pas seulement supposé), pas besoin de reproduire le contournement.
La fenêtre graphique (`tauri`, rendu WebView2) compile et **link** aussi correctement
(exécutable PE valide, `WebView2Loader.dll` généré à côté) — reste non vérifié : le
rendu/comportement réel sur un poste Windows.

⚠️ **`build.rs` fait maintenant échouer le build si `tauri_build` échoue** (18/08/2026 —
avant : simple `cargo:warning` avalé, un exe sans manifeste embarqué est passé un vrai test
utilisateur, crash immédiat `TaskDialogIndirect introuvable` au lancement). Si ça arrive en
dev local avec le message `failed to read plugin permissions` : purger le cache de build
périmé plutôt que chercher un bug dans le code —
```bash
rm -rf agent/gen agent/target/x86_64-pc-windows-gnu/release/build
```
Cause déjà rencontrée : `target/` garde des chemins absolus des builds précédents ; changer de
point de montage Docker d'une session à l'autre (`-v $(pwd):/work` puis `-v $(pwd)/agent:/agent`
par exemple) laisse un `OUT_DIR` obsolète dans le cache que `tauri_build` ne sait plus relire. Un
`cargo build` en CI n'y est jamais exposé (job sans `cache:` GitLab, `target/` toujours vide au
départ) — vérification en plus (grep sur le manifeste embarqué) ajoutée au job `build-agent` par
sécurité, cf. `.gitlab-ci.yml`.

Le `.msi` est généré avec [`wixl`](https://gitlab.gnome.org/GNOME/msitools) (paquet Debian/
Ubuntu `wixl`, alternative libre au WiX Toolset officiel qui est Windows-only/.NET) à partir
de `wix/main.wxs` — installe l'exécutable dans `Program Files\Allsafe Agent` :

```bash
sudo apt-get install wixl
wixl -a x64 -v wix/main.wxs -o allsafe-agent.msi
```

⚠️ **`-a x64` obligatoire** — sans ce flag, `wixl` (msitools 0.101) construit un paquet marqué
32-bit (`Template: Intel;1033` dans `msiinfo suminfo`) qui peut faire installer le binaire dans
`Program Files (x86)` au lieu de `Program Files` selon le contexte d'exécution du moment (constaté
en conditions réelles sur `DEPLOYAPP`, aucune erreur ni avertissement — juste au mauvais endroit).
Un attribut XML `Platform="x64"` sur `<Package>` serait le réflexe WiX officiel, mais cette version
de `wixl` ne le supporte pas (ignoré silencieusement). Vérifier après build :
`msiinfo suminfo allsafe-agent.msi` doit afficher `Template: x64;1033`, jamais `Intel;1033`.

`wix/main.wxs` ne comprend qu'un sous-ensemble de la syntaxe WiX (celui supporté par
`wixl`) — volontairement minimal (un seul composant, pas d'UI custom). L'`UpgradeCode` dans
ce fichier est figé une fois pour toutes : ne jamais le régénérer, c'est lui qui permet à
Windows Installer de reconnaître une mise à jour plutôt que d'installer une deuxième copie.

Vérification : `msiinfo suminfo`/`msiinfo export <fichier> File` (paquet `msitools`).

## Portée de ce MVP (limites assumées)

- Service systemd/Windows (13/08/2026) : géré côté binaire (`daemon.rs`/`service.rs`) et
  packaging (`.service` embarqué au `.deb`, `ServiceInstall` dans le `.msi`) — mais pas de mise
  à jour du binaire par le service lui-même (pas d'auto-remplacement d'un exécutable qui tourne),
  toujours `agent/deploy/update-agent.*` planifié à part pour ça (cf. `docs/AGENTS.md`).
- Pas de Credential Manager (Windows) ni de coffre équivalent (Linux) : le credential
  d'enrôlement est stocké en clair dans un fichier à permissions restreintes (`chmod 600`
  sur Linux ; restriction ACL non posée sur Windows) — à revoir avant un déploiement à
  grande échelle.
- Lecture seule strictement : aucun test actif/offensif (cf. `docs/vulnerabilites_securite.md`
  §3.7, entrées 🔍 uniquement) — un futur module Sécurité séparé couvrira le reste, avec ses
  propres garde-fous d'autorisation (comme Audits).
