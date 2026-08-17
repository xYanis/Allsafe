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

À chaque release :
1. Bumper `version` dans `Cargo.toml` **et** `Version="..."` dans `wix/main.wxs` (§ Product, ex.
   `0.1.1.0` — 4 segments, valeur séparée de `Cargo.toml`, oubliée une fois le 13/08/2026 : sans ce
   bump, `ProductVersion` reste figé côté MSI même si le binaire à l'intérieur est à jour)
2. Rebuild + repackage (§ Build ci-dessous), copier les nouveaux paquets dans `dist/`
3. Bumper `CURRENT_AGENT_VERSION` dans `backend/routers/agents.py` **avec la même valeur** — sinon
   Allsafe compare à une version périmée et les postes à jour s'affichent à tort comme en retard
   (ou l'inverse). Rien n'automatise ce lien, les deux projets sont compilés séparément.
4. Redistribuer :
   - **Poste isolé/test** : `dpkg -i`/`msiexec` manuel (§ Installation ci-dessus)
   - **Parc géré (13/08/2026)** : `deploy/update-agent.sh`/`.ps1`, planifiés par votre propre infra
     (cron/GPO), viennent chercher `GET /api/agents/latest/*` tout seuls et se réinstallent si
     besoin — cf. `deploy/README.md`. Toujours "pull", jamais Allsafe qui pousse.

Chaque `checkin` déclare sa version (`agent_version`, `CARGO_PKG_VERSION`) — comparée côté serveur
à `CURRENT_AGENT_VERSION`, elle fait apparaître un badge « Mise à jour dispo » sur la page Agents
pour les postes en retard (cf. `docs/AGENTS.md` § Mise à jour).

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
cargo install cargo-deb
cargo deb
# → target/debian/allsafe-agent_<version>_amd64.deb
```

Vérification : `dpkg-deb --info`/`--contents target/debian/*.deb`.

### Exécutable + installeur Windows (.exe / .msi)

Compilation croisée depuis Linux (mingw-w64, pas besoin d'une machine Windows pour ça) :

```bash
sudo apt-get install mingw-w64
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# → target/x86_64-pc-windows-gnu/release/allsafe-agent.exe
```

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
