# Module Sécurité > Agents — agent Rust pour postes Windows/Linux

> ✅ **IMPLÉMENTÉ (12/08/2026).** Backend (`backend/routers/agents.py`, `backend/models.py::Agent`/
> `AgentEnrollmentToken`, `backend/auth_deps.py::require_agent`), frontend (`frontend/src/pages/
> Agents.jsx`, colonne « Méthode » sur `Assets.jsx`), agent Rust (`agent/`, binaire `allsafe-agent`).
> Vérifié de bout en bout en conditions réelles, **Linux et Windows** — enrôlement + check-in réels
> contre le backend, Windows sur `DEPLOYAPP` (serveur de production existant) — cf. § Vérification.
> Détail de session : `STATUS.md` (12/08/2026).
>
> **13/08/2026 — mode persistant** : service systemd (Linux)/Windows Service (`agent run`/
> `service-run`), scan à la demande, rapport de coupure, distribution des paquets via l'API
> (`GET /latest/*`) + scripts `agent/deploy/update-agent.*`. Build/packaging vérifiés en réel
> (compilation croisée, `.deb`/`.msi` inspectés, `wixl` confirmé honorer `ServiceInstall`) — **le
> comportement du service lui-même sur un vrai poste reste à valider** (installation, démarrage,
> arrêt propre au reboot/désinstall) avant de considérer ce mode pleinement acquis.
>
> **17/08/2026 — friction d'installation manuelle corrigée**, suite à un enrôlement réel (poste
> `aos12`) où `msiexec /qn` non-élevé a échoué en silence puis `allsafe-agent` s'est révélé hors
> `PATH` : `wix/main.wxs` ajoute désormais `INSTALLFOLDER` au `PATH` système (**.msi existant dans
> `agent/dist/` pas encore rebuild avec ce correctif — à faire, `wixl -a x64`, puis vérifier
> `msiinfo export allsafe-agent.msi Environment`**) ; `agent/deploy/update-agent.ps1`/`.sh`
> vérifient désormais l'élévation/root en tout premier et affichent leurs erreurs à l'écran (avant :
> uniquement loggées en fichier, invisibles en usage manuel) — devenus la méthode d'installation
> **recommandée**, y compris pour un premier poste isolé, pas seulement les mises à jour planifiées
> (§ Installation rapide, `agent/README.md`). La modale « Jeton d'enrôlement » (page Agents) génère
> désormais la commande one-liner correspondante (token + URL serveur déjà substitués).
>
> **17/08/2026 — auto-installation Windows + fenêtre graphique** (`agent/src/install.rs`/
> `gui.rs`/`build.rs`) : `allsafe-agent.exe install --token ... --server ...` (ou
> l'exécutable lancé sans argument, qui ouvre une fenêtre demandant serveur + jeton)
> installe le service Windows + le `PATH` + enrôle depuis un seul fichier `.exe`, sans
> `.msi` ni script — pensé pour les **actifs critiques** (jeton unique par actif). Un build
> "bulk" du `.msi` (jeton réutilisable pré-rempli, `enroll-defaults.json`, cf.
> `agent/README.md` § Build bulk) couvre le cas **actifs non-critiques** (déploiement GPO
> silencieux, un seul jeton pour tout le lot — à traiter comme jetable : expiration courte,
> `max_uses` borné, révocation post-rollout). Le `.msi`/`wixl`/GPO "Installation de
> logiciels" restent le chemin recommandé pour un vrai déploiement de parc — cette nouvelle
> voie comble le cas poste isolé sans script à portée de main.
>
> **Vérifié par compilation + link croisés réels** le même jour (toolchain mingw-w64/wixl
> assemblée à la main dans l'environnement de build, sans accès root — `apt-get download` +
> extraction locale + correctifs de scripts linker glibc, sans droits root) :
> `install.rs`/`gui.rs`/`build.rs` compilent et **linkent** sans erreur contre les vraies
> crates `windows-service`/`winreg`/`native-windows-gui` pour `x86_64-pc-windows-gnu`,
> testés isolément (dépendances du binaire complet — `reqwest`/`rustls`/`ring` — bloquées
> par un problème d'environnement sans rapport avec ce code, cf. § Vérification). **Un vrai
> bug a été trouvé et corrigé à cette occasion** : `winres` embarque la ressource manifeste
> dans une archive statique que l'éditeur de liens GNU élague silencieusement faute de
> symbole référencé (`.rsrc` absent du binaire final, testé via `objdump`) — `build.rs`
> force désormais son inclusion via `cargo:rustc-link-arg` direct sur l'objet. Sans ce
> correctif, la fenêtre UAC ne se serait **jamais** déclenchée, sans la moindre erreur de
> build pour le signaler. **Reste non vérifié** : comportement runtime sur un vrai poste
> Windows (élévation, écriture registre, SCM, rendu de la fenêtre) — cf. § Vérification.

## Contexte

Allsafe collecte les données des serveurs via un compte de service centralisé (SSH pour Linux,
WinRM pour Windows — `services/asset_scanner.py`). Ce modèle « pull » avec identifiants partagés
fonctionne bien pour des serveurs toujours allumés et joints au domaine, mais atteint mal les postes
de travail (éteints, en veille, hors réseau d'entreprise, VPN).

**L'agent complète ce modèle, il ne le remplace pas.** Par actif, l'utilisateur choisit la méthode
de collecte (`Asset.collection_method`, `service_account` par défaut ou `agent`) — un champ, pas une
bascule globale. Décision actée avec l'utilisateur (cf. `STATUS.md`) :

- **Portée** : Windows + Linux, postes de travail en priorité (les serveurs restent scannés par le
  compte de service, sauf exception).
- **Capacités** : lecture seule strictement, même règle de non-intervention que le reste d'Allsafe
  (`CLAUDE.md` §1). L'agent est un **strict sur-ensemble** du compte de service : tout ce que fait
  `asset_scanner.py` aujourd'hui, **plus** des checks supplémentaires accessibles uniquement en
  local (chiffrement disque, comptes admin locaux, verrouillage d'écran, restriction USB,
  journalisation PowerShell — cf. `docs/vulnerabilites_securite.md` §3.7).
- **Hors scope explicite** : tests actifs/offensifs (WSTG/OWASP, scénarios BAS/Red Team). Un futur
  module Sécurité séparé couvrira ce terrain, avec ses propres garde-fous d'autorisation (comme
  Audits — autorisation écrite bloquante avant tout finding saisissable).

## Modèle de données

`Asset.collection_method` — `String`, défaut `"service_account"`, valeurs `service_account` |
`agent`. Distinct de `Asset.source` (*comment l'actif a été découvert* : `active_directory`/`ssh`/
`manual`/`meraki`/`prtg`/`agent`) — ce champ décrit *comment il est activement scanné aujourd'hui*.

```python
class Agent(Base):
    __tablename__ = "agents"
    id                        = Column(UUID, primary_key=True)
    asset_id                  = Column(UUID, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    hostname                  = Column(String, nullable=False)
    os                        = Column(String, nullable=False)   # "windows" | "linux"
    credential_hash           = Column(String, nullable=False, unique=True)  # sha256, jamais le secret en clair
    status                    = Column(String, nullable=False, default="enrolled")  # enrolled | revoked
    enrolled_at               = Column(DateTime(timezone=True))
    last_seen_at              = Column(DateTime(timezone=True))
    agent_version             = Column(String)              # déclarée à chaque check-in
    pending_scan_requested_at = Column(DateTime(timezone=True))  # scan à la demande
    last_gap_started_at       = Column(DateTime(timezone=True))  # rapport de coupure
    last_gap_failed_attempts  = Column(Integer)
    enrollment_token_id       = Column(UUID, ForeignKey("agent_enrollment_tokens.id", ondelete="SET NULL"))
    revoked_at                = Column(DateTime(timezone=True))
    revoked_by                = Column(String)

class AgentEnrollmentToken(Base):
    __tablename__ = "agent_enrollment_tokens"
    id                = Column(UUID, primary_key=True)
    token_hash        = Column(String, nullable=False, unique=True)
    asset_id          = Column(UUID, ForeignKey("assets.id", ondelete="CASCADE"), nullable=True)
    label             = Column(String)
    created_by        = Column(String, nullable=False)
    expires_at        = Column(DateTime(timezone=True), nullable=False)  # configurable (13/08/2026)
    max_uses          = Column(Integer, nullable=False, default=1)       # 13/08/2026, enrôlement à l'échelle
    use_count         = Column(Integer, nullable=False, default=0)
```

`AgentEnrollmentToken.asset_id` optionnel : un admin génère un jeton lié à un actif déjà existant
(bascule sa méthode de collecte au premier check-in, **sans** créer de doublon — cas typique d'un
serveur/poste déjà suivi par compte de service qu'on migre vers l'agent), ou un jeton « libre » pour
un poste encore inconnu d'Allsafe (le premier check-in crée l'actif — `asset_type="workstation"`,
`source="agent"`). N'a de sens que pour `max_uses=1` — un jeton réutilisable (`max_uses>1`, § Enrôlement
à l'échelle ci-dessous) refuse un `asset_id` (chaque enrôlement crée forcément son propre actif).

Agent : révocation par flag (`status`/`revoked_at`) — un agent est une identité d'appareil digne
d'un audit trail, pas une session éphémère. Suppression définitive possible (`DELETE /agents/{id}`,
admin) mais **seulement une fois déjà révoqué** — la révocation reste le geste d'audit trail
obligatoire, la suppression ne sert qu'à nettoyer une entrée déjà terminée.

## Enrôlement à l'échelle (13/08/2026)

Un jeton `max_uses>1` reste valable pour plusieurs postes jusqu'à épuisement du quota
(`use_count >= max_uses` refusé, `POST /enroll`) — utile pour un déploiement de parc (embarqué dans
un script de démarrage GPO/config management, cf. `agent/deploy/README.md` § Déploiement de parc)
plutôt que de générer un jeton par machine à la main. `expires_at` configurable à la création
(`expires_in_hours`, plus la contrainte fixe de 48h d'origine) — un déploiement de parc peut prendre
plus longtemps qu'un enrôlement isolé.

Traçabilité : `Agent.enrollment_token_id` (dérivable en sens inverse pour lister tous les postes
enrôlés via un même jeton) remplace l'ancien `AgentEnrollmentToken.used_by_agent_id` scalaire —
celui-ci ne pouvait référencer qu'un seul agent, inadapté à un jeton multi-usages. Révocation d'un
jeton (`DELETE /enrollment-tokens/{id}`) possible à tout moment quel que soit `use_count` : stoppe
les enrôlements futurs, n'affecte jamais les postes déjà enrôlés (`enrollment_token_id` passe à
`NULL`, l'agent lui-même reste intact).

## Authentification agent

`auth_deps.py::require_agent` — même idiome que `require_auth`, mais résout l'en-tête
`X-Agent-Token` plutôt qu'un cookie de session. Le credential est généré côté serveur
(`secrets.token_urlsafe(32)`), seul son hash SHA-256 est persisté — jamais de Fernet réversible
(`services/crypto.py`), le backend n'a jamais besoin de rejouer ce secret ailleurs.

Le jeton d'enrôlement suit le même principe TOFU (trust-on-first-use) que `services/ssh_trust.py` :
usage unique, jamais rejoué, une identité changée nécessite un ré-enrôlement explicite via un
nouveau jeton généré par un admin.

## Endpoints (`routers/agents.py`)

| Route | Auth | Description |
|---|---|---|
| `POST /api/agents/enrollment-tokens` | admin | Génère un jeton (48h), retourne le secret en clair une seule fois |
| `GET /api/agents/enrollment-tokens` | admin | Liste (audit : utilisé/expiré/en attente) |
| `DELETE /api/agents/enrollment-tokens/{id}` | admin | Révoque un jeton non utilisé |
| `POST /api/agents/enroll` | public (protégé par le jeton dans le corps) | Échange le jeton contre une identité `Agent`, retourne le credential une seule fois |
| `GET /api/agents/latest/version`/`/windows`/`/linux` | public | Distribution des paquets déjà construits (`agent/dist/`, cf. § Mise à jour) |
| `GET /api/agents/pending` | `require_agent` | Scan à la demande — sondé à intervalle court par la boucle persistante (`daemon.rs`), lecture seule |
| `POST /api/agents/{id}/request-scan` | admin | Pose le flag de scan à la demande — ne se connecte jamais au poste (CLAUDE.md §1), l'agent vient le chercher lui-même |
| `POST /api/agents/checkin` | `require_agent` | Pousse le résultat de collecte (même shape que `asset_scanner.py::_build_result()`), efface le flag de scan à la demande, enregistre un éventuel rapport de coupure |
| `GET /api/agents` | `require_page("/agents")` | Liste des agents enrôlés |
| `POST /api/agents/{id}/revoke` | admin | Révoque un agent |
| `DELETE /api/agents/{id}` | admin | Supprime définitivement un agent déjà révoqué |

`services/asset_scanner.py::apply_scan_result(asset, result, session)` — logique de persistance
(correction hostname/OS, reconstruction CPE, déclenchement matching CPE + cycle patch check)
**partagée** entre le scan pull (SSH/WinRM, `routers/assets.py::scan_asset_endpoint`) et le check-in
agent (`routers/agents.py::checkin`) : les deux producteurs du même shape de résultat aboutissent
exactement au même traitement côté données, sans logique dupliquée.

⚠️ **Aucun garde-fou spécifique requis pour la protection des décisions humaines** : le check-in
agent passe par le même pipeline que le scan pull, donc par le même garde-fou déjà en place
(`CLAUDE.md` §1 — états terminaux `false_positive`/`patched`/`accepted_risk` jamais écrasés
automatiquement). Basculer un actif de `service_account` vers `agent` ne remet jamais à zéro le
travail de qualification déjà fait sur ses CVE.

## Checks collectés

Même shape que les checks existants côté scan pull : `{"id", "label", "status": "ok"|"warn"|
"unknown", "detail"}` dans `compliance.checks` — affiché sans aucune adaptation frontend.

**Linux** (`agent/src/collect/linux.rs`) — parité avec `asset_scanner.py::_build_compliance_linux`
(âge/longueur mot de passe, connexion SSH root, authentification SSH par mot de passe, algorithmes
SSH faibles, services exposés à risque) **plus** :
- `disk_encryption` — LUKS (`/etc/crypttab`, `lsblk TYPE=crypt`)
- `privileged_accounts` — membres des groupes `sudo`/`wheel`
- `screen_lock` — best-effort (GNOME `gsettings` uniquement dans ce MVP, `unknown` sinon)
- `usb_policy` — règles udev de restriction USB
- `sudo_nopasswd` (13/08/2026) — directive `NOPASSWD` dans `/etc/sudoers`/`sudoers.d`
- `ssh_authorized_keys_perms` (13/08/2026) — permissions de `/root/.ssh/authorized_keys` (attendu 600)
- `world_writable_files` (13/08/2026) — fichiers world-writable dans `/etc`, `/usr/local`, `/opt`
  (périmètre borné, pas tout le système de fichiers)
- `shell_history_secrets` (13/08/2026) — motifs de secrets dans `/root/.bash_history` ; ne recopie
  jamais le contenu trouvé dans `detail` (juste un décompte), à vérifier manuellement

**Windows** (`agent/src/collect/windows.rs`) — parité registre avec `asset_scanner.py::
_build_compliance_windows` (RDP-NLA, SMBv1, signature/chiffrement SMB, sessions anonymes, invité
non sécurisé, LLMNR, WDigest, niveau NTLM, pare-feu, services exposés) **plus** :
- `bitlocker` — `manage-bde -status`
- `privileged_accounts` — `net localgroup administrators`
- `screen_lock` — stratégie `InactivityTimeoutSecs` (HKLM, pas HKCU — l'agent tourne généralement en
  tâche planifiée sous SYSTEM, sans session interactive HKCU fiable)
- `usb_policy` — clé `USBSTOR\Start`
- `powershell_logging` — `ScriptBlockLogging`
- `uac_enabled` (13/08/2026) — `EnableLUA` (registre)
- `powershell_transcription` (13/08/2026) — complément à `powershell_logging` (texte intégral de
  session, pas seulement les blocs de script)
- `defender_realtime` (13/08/2026) — protection temps réel Windows Defender ; proxy EDR
  volontairement honnête, ne prétend jamais détecter un antivirus tiers (WithSecure et consorts
  n'exposent pas cette clé) — `ok` par défaut si la clé de désactivation est absente
- `admin_account_renamed` (13/08/2026) — via `Get-LocalUser` filtré sur le SID `-500`
- `network_shares_everyone` (13/08/2026) — partages SMB non-administratifs accordant Modifier/
  Contrôle total à "Tout le monde" (`Get-SmbShare`/`Get-SmbShareAccess`)

⚠️ Les 9 checks du 13/08/2026 (backlog `docs/vulnerabilites_securite.md` §3.7) restent
**strictement agent-only**, jamais rétroportés vers le compte de service SSH/WinRM — même principe
que les checks agent-only déjà en place (BitLocker/LUKS, comptes privilégiés, écran, USB,
journalisation). Compilés et vérifiés (build croisé Linux/Windows OK, logique shell des 4 checks
Linux testée en conteneur réel cas positif/négatif) — **les checks Windows basés sur PowerShell
(`admin_account_renamed`, `network_shares_everyone`) restent à valider sur une vraie machine**,
aucun moyen de tester le comportement exact de ces commandes sans accès Windows direct.

L'agent tourne localement avec les droits nécessaires (généralement admin/SYSTEM via planification) :
contrairement au compte de service WinRM distant (pas de droits WMI/DCOM, cf. commentaires
`asset_scanner.py::_scan_windows`), il accède au registre HKLM directement — inventaire applicatif
(clés `Uninstall`) et durcissement en une seule collecte, sans contrainte de taille de commande
encodée WinRM.

**Regroupement par catégorie (13/08/2026)** : `frontend/src/utils/hardeningRemediation.js::
categoryFor()` associe chaque `id` à une catégorie d'affichage (Mots de passe/SSH/Réseau/SMB/
Authentification/Comptes/Chiffrement/Journalisation/Web/Système), lue par
`components/ComplianceChecklist.jsx` pour regrouper les checks en sections repliables (ouvertes par
défaut seulement si elles contiennent un avertissement) — la liste plate d'origine ne passait plus
à l'échelle une fois le catalogue étendu (10→14 Linux, 19→23 Windows). Catégorie **calculée côté
frontend uniquement** — pas de champ `category` dans le payload `Check` (Rust)/`_check()` (Python) :
c'est une métadonnée d'affichage, pas une donnée de collecte, plus simple à faire évoluer sans
recompiler/redéployer l'agent.

**Fin de support d'OS (17/08/2026, `services/os_eol.py`)** — équivalent du défaut "OS obsolète"
de Cyberwatch (référence utilisateur). Calculé **dynamiquement** depuis `Asset.os`/`os_version`
déjà connus (`routers/assets.py::_asset_dict` → champ `os_eol_check`), jamais stocké ni lié à un
scan précis : recalculé à chaque lecture, un OS peut devenir obsolète simplement parce que le
calendrier avance. `_EOL_TABLE` est une liste curatée à la main (Windows Server 2012→2022,
Windows 10, Ubuntu 18.04→24.04 LTS, Debian 9→12, CentOS/RHEL 7-8) — `None` si l'OS ne correspond
à aucune entrée, jamais une affirmation hasardeuse. **Piège vérifié en conditions réelles** :
`Asset.os` est souvent générique côté Windows ("Windows Server", sans l'année — cf.
`asset_scanner.py::_extract_windows_version`), l'année ne vit que dans `os_version` ; matcher sur
`os` seul (1er jet) ne trouvait aucun résultat sur le vrai parc — corrigé en croisant les deux
champs. Vérifié : 40/442 actifs matchés dont 21 Windows Server 2012 réellement en fin de support
(dépassé depuis le 2023-10-10).

**Durcissement web passif (17/08/2026, `services/web_hardening.py`, nouveau type d'actif
`asset_type="website"`)** — en-têtes de sécurité HTTP manquants (HSTS/CSP/X-Content-Type-Options/
X-Frame-Options/Referrer-Policy), cookies sans `Secure`/`HttpOnly`, protocole TLS négocié déprécié
(SSLv3/TLS1.0/1.1). **Volontairement limité au passif** : une requête GET HTTP normale + une
négociation TLS standard, aucun payload d'exploitation — détecter la *possibilité* réelle d'une
injection SQL/XSS nécessiterait d'envoyer des charges de test, un scan actif hors du principe de
non-intervention (CLAUDE.md §1, `docs/AUDITS.md` exclut explicitement sqlmap pour la même
raison) ; laissé de côté pour une réflexion future côté module Audits, pas construit ici. Colonne
dédiée `Asset.web_compliance` (même principe que `network_compliance` pour `asset_type="network"`
— ces actifs n'ont ni OS ni scan SSH/WinRM). `POST /api/assets/web-hardening/run` : déclenchement
manuel, pas planifié (même précédent que `network-protocol-check`/`switch-hardening`, aucun bouton
frontend dédié non plus). Vérifié en conditions réelles contre example.com/github.com — en-têtes
et cookies détectés correctement (dont un vrai cookie GitHub sans HttpOnly).

## Agent Rust (`agent/`)

Binaire unique `allsafe-agent`, cross-plateforme (`#[cfg(target_os)]`, pas deux codebases).
Sous-commandes :

```bash
allsafe-agent enroll --token <JETON> --server <URL>
allsafe-agent checkin   # une fois
allsafe-agent run       # boucle persistante (13/08/2026, mode recommandé) — ne se termine jamais
```

`service-run` (Windows uniquement, `#[cfg(target_os = "windows")]`) est une quatrième sous-commande
**cachée** (`#[command(hide = true)]`, absente de `--help`) : point d'entrée dédié au Service
Control Manager, jamais un usage manuel — posé par `wix/main.wxs::ServiceInstall` en `binPath`
(`Arguments="service-run"`), cf. § Mode persistant ci-dessous.

Identité locale persistée dans un fichier à permissions restreintes (`/etc/allsafe-agent/agent.json`
sur Linux — `chmod 600` ; `%ProgramData%\allsafe-agent\agent.json` sur Windows — restriction ACL
**non posée** dans ce MVP, limite assumée à revoir avant un déploiement à grande échelle).

Empaquetage documenté dans `agent/README.md` :
- `.deb` — `cargo-deb`, installe `/usr/bin/allsafe-agent` **et** le service systemd (§ ci-dessous).
- `.msi` — `wixl -a x64` (`agent/wix/main.wxs`), alternative libre au WiX Toolset officiel
  (Windows-only/.NET) qui permet de construire un `.msi` valide depuis Linux ; installe dans
  `Program Files\Allsafe Agent` **et** enregistre le service Windows (§ ci-dessous). ⚠️ `-a x64`
  obligatoire (13/08/2026) — omis, `wixl` construit un paquet marqué 32-bit qui peut se faire
  installer dans `Program Files (x86)` par Windows Installer sans erreur ni avertissement, constaté
  en réel sur `DEPLOYAPP` (cf. `agent/README.md` § Build).

## Mode persistant — service/daemon (13/08/2026)

Remplace la planification externe (cron/tâche planifiée) comme mode **recommandé par défaut** :
`allsafe-agent run` tourne en continu, sonde `GET /api/agents/pending` toutes les 60s (léger, ne
modifie rien côté serveur) et pousse un check-in complet toutes les heures — ou immédiatement si un
scan a été demandé (§ Scan à la demande). Le serveur n'initie jamais le contact (`CLAUDE.md` §1) :
c'est toujours l'agent qui vient chercher, même sondage court plutôt qu'une vraie connexion poussée.

- **Linux** : unité systemd `agent/deploy/allsafe-agent.service` (`ExecStart=/usr/bin/allsafe-agent
  run`, `Restart=on-failure`), embarquée dans le `.deb` (`[package.metadata.deb] maintainer-scripts
  = "debian"`) — `debian/postinst` fait `systemctl daemon-reload && systemctl enable --now`,
  `debian/prerm` fait `systemctl disable --now`. Automatique à l'installation, rien à faire.
- **Windows** : service natif `AllsafeAgent` (`ServiceType=ownProcess`, `StartType=auto`,
  `Account=LocalSystem`) déclaré via `wix/main.wxs::ServiceInstall`/`ServiceControl`
  (`Start="install"`, `Stop="both"`, `Remove="uninstall"`) — géré par `msiexec` lui-même à
  l'installation/désinstallation, aucun script séparé requis. Point d'entrée dédié `agent/src/
  service.rs` : `windows_service::service_dispatcher::start()` est bloquant et doit s'exécuter
  **avant** toute création de runtime tokio (sinon panique "Cannot start a runtime from within a
  runtime") — `main.rs` intercepte `service-run` avant de construire son propre runtime, seul le
  process SCM construit le sien à l'intérieur de `run_service()`.
  ⚠️ **Vérifié que `wixl` (msitools 0.101) honore bien `ServiceInstall`/`ServiceControl`**
  (`msiinfo export allsafe-agent.msi ServiceInstall` non vide, `ServiceType=16`/`StartType=2`
  corrects) — contrairement à `Platform="x64"` sur `<Package>`, silencieusement ignoré par cette
  même version de `wixl` (cf. § ci-dessus). Deux comportements différents pour deux éléments WiX
  différents dans le même outil — à revérifier après toute mise à jour de `wixl`/`msitools`.

`agent/deploy/update-agent.sh`/`.ps1` restent nécessaires **en plus** du service — celui-ci gère le
check-in, pas la mise à jour du binaire lui-même (pas d'auto-remplacement d'un exécutable qui
tourne). Toujours planifiés en externe (cron/tâche planifiée, cadence plus lâche que le check-in,
ex. quotidienne), ils redémarrent le service après un remplacement de binaire réussi
(`systemctl restart`/le `ServiceControl` de la nouvelle transaction msiexec) — sinon l'ancien code
resterait en mémoire jusqu'au prochain redémarrage machine.

## Scan à la demande (13/08/2026)

`Agent.pending_scan_requested_at` — posé par `POST /api/agents/{id}/request-scan` (admin, bouton
« Scanner maintenant » sur `pages/Agents.jsx`), jamais par une connexion au poste. Ramassé par la
boucle persistante à son prochain sondage `GET /api/agents/pending` (jusqu'à 60s de latence), qui
déclenche un check-in immédiat au lieu d'attendre le prochain tick horaire. Effacé
inconditionnellement par tout check-in réussi (`POST /checkin`), qu'il ait ou non été déclenché par
la demande — un cycle normal arrivé entre-temps la satisfait tout autant.

## Rapport de coupure (13/08/2026)

Pas une file d'attente qui rejoue des snapshots complets (le backend n'a pas de table d'historique
de conformité pour exploiter un rejeu) — juste un signal léger : `agent/src/config.rs::DaemonState`
mémorise localement (`daemon-state.json`, même dossier que `agent.json`) `offline_since` (secondes
Unix UTC, posé à la **première** tentative échouée seulement) et `failed_attempts`, à chaque échec
de check-in dans la boucle persistante. Inclus dans le check-in suivant qui réussit, stocké sur
`Agent.last_gap_started_at`/`last_gap_failed_attempts` — jamais effacé silencieusement, reste
affiché (icône ⚠, `pages/Agents.jsx::GapBadge`) tant qu'un nouveau rapport ne le remplace pas ou
que la coupure dépasse 7 jours (au-delà, plus vraiment exploitable, discrètement masqué côté UI —
la donnée elle-même reste en base).

## Mise à jour (13/08/2026)

**Pas d'auto-update dans le sens "poussé par Allsafe"** — le backend ne se connecte jamais aux
postes (`CLAUDE.md` §1). Faire évoluer l'agent nécessite toujours de reconstruire le binaire
(`cargo build --release`, `cargo deb`/`wixl -a x64` pour les paquets, cf. `agent/README.md` §
Build) puis de le redistribuer — mais depuis le 13/08/2026, le modèle est **pull** plutôt que
"réinstallation manuelle poste par poste" : `GET /api/agents/latest/version`/`/windows`/`/linux`
(`routers/agents.py`) servent le dernier paquet construit (`agent/dist/`, monté en lecture seule
dans le conteneur backend, `AGENT_DIST_DIR`), et `agent/deploy/update-agent.sh`/`.ps1` — planifiés
par **votre** infra (cron/GPO, jamais Allsafe, cf. `agent/deploy/README.md`) — comparent la version
installée à celle publiée, se réinstallent seuls si besoin, puis checkin. `dpkg -i`/`msiexec`
manuels (§ Installation) restent utilisables pour un poste isolé ou un premier test.

Réinstaller ne casse rien côté enrôlement : `dpkg -i`/`msiexec` ne touchent que le binaire
(`/usr/bin/allsafe-agent` / `Program Files\Allsafe Agent`), jamais le fichier d'identité local
(`agent.json`, cf. § ci-dessus) qui porte déjà le credential — pas de ré-enrôlement nécessaire après
une mise à jour. Côté `.msi`, ça suppose de ne jamais régénérer l'`UpgradeCode` figé dans
`wix/main.wxs` (cf. `agent/README.md`) — c'est lui qui permet à Windows Installer de reconnaître une
mise à jour en place plutôt que d'installer une deuxième copie.

**Visibilité côté Allsafe (repérer les postes en retard)** : chaque `checkin` déclare la version du
binaire (`agent_version`, `env!("CARGO_PKG_VERSION")` — cf. `agent/src/model.rs::CheckinPayload`),
stockée sur `Agent.agent_version` (`routers/agents.py::checkin`). Comparée côté serveur à
`routers/agents.py::CURRENT_AGENT_VERSION` (constante **à bumper manuellement** à chaque release, en
même temps que `agent/Cargo.toml::version`) → `GET /api/agents` expose un flag `outdated` par agent,
affiché en badge « Mise à jour dispo » sur `pages/Agents.jsx` (colonne « Version »). `agent_version`
reste `NULL` (jamais `outdated`) pour un agent enrôlé avant l'ajout de ce champ tant qu'il n'a pas
encore fait de check-in avec un binaire qui le déclare — pas de faux positif sur l'historique.

⚠️ **Limite assumée** : rien n'empêche d'oublier de bumper `CURRENT_AGENT_VERSION` après une release
— dans ce cas tous les agents à jour s'afficheraient comme périmés (ou l'inverse si on oublie de
mettre à jour `Cargo.toml`). Les deux valeurs doivent être changées ensemble à chaque release, aucun
lien automatique entre elles dans ce MVP (le backend et le binaire agent sont deux projets distincts,
compilés séparément — rien ne garantit qu'ils partagent le même dépôt/pipeline de build).

## Signature (18/08/2026)

Sans signature, Windows affiche "Éditeur : Inconnu" sur la fenêtre UAC déclenchée au lancement de
`allsafe-agent.exe` (manifeste `requireAdministrator`, cf. § Vérification) — normal, pas un bug.

Étape du **build CI** (`.gitlab-ci.yml::build-agent`), jamais un script séparé à lancer à la main :
`osslsigncode` (tourne nativement sous Linux, pas besoin de `signtool`/Windows SDK) signe le `.exe`
et le `.msi` juste après leur construction, **seulement si** deux variables CI/CD sont configurées
(Settings > CI/CD > Variables) :
- `AGENT_SIGNING_PFX` — variable de type **File**, le certificat de signature de code (`.pfx`,
  clé privée + certificat).
- `AGENT_SIGNING_PASSWORD` — variable **masquée**, mot de passe du `.pfx`.

Sans elles, le job continue normalement et publie des artefacts non signés (message explicite dans
les logs) — jamais un échec bloquant tant que le certificat n'existe pas.

Deux étapes **humaines, hors CI**, à faire une fois avant que ça serve à quelque chose :
1. **Générer le certificat** (poste admin, PowerShell) — auto-signé, suffisant pour un outil
   100% interne (jamais distribué hors du parc) :
   ```powershell
   New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Allsafe" `
     -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature
   ```
   Exporter en `.pfx` (clé privée, à mettre dans `AGENT_SIGNING_PFX`) et en `.cer` (public).
2. **Distribuer le `.cer` public à tout le parc par GPO** (Configuration ordinateur > Paramètres
   Windows > Paramètres de sécurité > Stratégies de clé publique > **Éditeurs de confiance** ET
   **Autorités de certification racines de confiance**, puisqu'auto-signé) — sans cette étape, la
   fenêtre UAC reste jaune/non vérifiée même signée (elle affiche juste "Allsafe" au lieu
   d'"Inconnu" comme Subject, la confiance elle-même se construit sur le parc, pas dans le binaire).

Mécanisme vérifié en conditions réelles (conteneur, certificat de test jetable, horodatage DigiCert
réel, 18/08/2026) : signature réussie sur `.exe` et `.msi`, Subject du certificat bien lu dans le
binaire signé (`osslsigncode verify`). Pas de certificat réel généré ni distribué — ça reste à faire
côté infrastructure Allsafe.

## Frontend

`pages/Agents.jsx` — page standalone, pas un onglet Administration (les agents sont de l'exploitation
sécurité courante, pas de l'administration de comptes, un analyste doit pouvoir les gérer sans être
admin). **Rattachée au module Inventaire depuis le 12/08/2026** (déplacée de Sécurité le même jour,
demande utilisateur — plus cohérent : l'agent est une méthode de collecte du patrimoine, au même
titre que le compte de service, pas une fonction de sécurité offensive/opérationnelle comme Audits/
Bastion). Liste des agents enrôlés (logo OS réel, `OsLogo.jsx`), génération de jeton (modale, secret
affiché une seule fois avec avertissement « copiez-le maintenant »), révocation.

`pages/Durcissement.jsx` (nouveau, 12/08/2026, module Inventaire) — vue dédiée sur les checks de
durcissement/conformité de tout le parc, extraite de la modale « Résultat du scan » d'`Assets.jsx`
(demande utilisateur — noyée dans une modale par-actif, pas adaptée pour comparer l'état du parc).
Tableau d'actifs (nom, OS, catégorie, résumé ok/warn/indéterminé, dernier scan), clic sur une ligne →
modale avec le détail complet (`components/ComplianceChecklist.jsx`, extrait de la même modale
Assets.jsx). Filtre « avec avertissements uniquement ». Deep-link `?asset=<id>` depuis Assets.jsx
(« Voir le durcissement/conformité de cet actif → », même esprit que le bandeau de rattrapage CVE du
Dashboard) — ouvre directement la modale de l'actif visé. **Aucun nouvel endpoint** : `GET /assets`
portait déjà `last_scan_result.compliance.checks` (serveurs/postes) et `network_compliance.checks`
(équipements réseau Meraki/PRTG, même shape) en entier pour chaque actif — la page recalcule le
résumé côté client à partir des données déjà chargées.

**Remédiation par check** (12/08/2026, même jour, demande utilisateur — "quand je clique sur un cas
j'ai des solutions et les commandes pour le faire") : chaque ligne de `ComplianceChecklist.jsx` est
cliquable, déplie une solution + des commandes prêtes à copier (`utils/hardeningRemediation.js`,
`REMEDIATION.windows`/`REMEDIATION.linux`, clé = même `id` que produit `_check()`/l'agent Rust —
29 entrées, certains `id` partagés entre OS avec un mécanisme de remédiation entièrement différent
donc jamais fusionnés). Bouton copier, avertissement dédié quand la commande peut avoir un effet de
bord réel (ex. couper `PasswordAuthentication` SSH sans clé déjà en place = se verrouiller dehors).
**Même principe que `services/remediation.py` côté CVE** : Allsafe propose uniquement, ne modifie
jamais rien lui-même — aucune commande n'est jamais exécutée par l'agent ni le backend, l'analyste
copie/colle après relecture (cf. `CLAUDE.md` § non-intervention, "Générer une recommandation /
script" est explicitement une action autorisée). Chemins de registre Windows repris exactement des
mêmes clés que celles lues par `agent/src/collect/windows.rs`, pour rester cohérent avec ce qui est
vérifié.

`pages/Assets.jsx` — colonne « Méthode » (icône seule + tooltip, pas de badge texte — évite de
faire déborder le tableau déjà chargé de colonnes), sélecteur de méthode de collecte dans le
formulaire d'actif (avec lien vers Agents si « agent » choisi sans agent encore enrôlé sur cet
actif).

## Vérification

- Tests backend (`pytest`, `tests/test_auth_guardrails.py::TestRequireAgent` + garde-fous de routes)
  — 174 tests, tous verts.
- Bout en bout réel (12/08/2026) : jeton généré → enrôlement Rust compilé (Linux, conteneur Docker)
  → check-in réel → actif créé avec `collection_method="agent"`, 300 paquets détectés, matching CPE
  déclenché (1257 vulnérabilités générées sur l'actif de test), affiché correctement dans
  Actifs/Inventaire sans aucune adaptation frontend. Données de test nettoyées après vérification.
- **Windows, testé en conditions réelles sur `DEPLOYAPP`** (12/08/2026, Windows Server 2019 Datacenter
  build 17763, actif de production existant) — installé via le `.msi` (`msiexec /i ... /l*v` pour un
  retour exploitable, le double-clic direct ne montre presque rien faute d'UI définie dans le `.wxs`),
  enrôlé et check-in réels depuis une invite de commandes sur la machine elle-même (pas de connexion
  distante initiée par Allsafe — cohérent avec la règle de non-intervention, cf. `CLAUDE.md` §1). Le
  stack de dev a suffi (backend joignable depuis `DEPLOYAPP` via le proxy Vite du frontend, port
  3000, les deux étant sur le même réseau d'entreprise) — pas besoin d'attendre la VM de production
  pour ce premier test.
  - `collection_method` basculé `service_account` → `agent` sans recréer l'actif, comme prévu.
  - **88 paquets** détectés (énumération registre `Uninstall`), **19 checks de durcissement**
    remontés avec des résultats réels et exploitables, pas des placeholders — 3 findings concrets sur
    ce serveur de production : pare-feu Windows désactivé (`firewall`, warn), sessions SMB anonymes
    non restreintes (`smb_restrict_anonymous`, warn), stockage de masse USB autorisé (`usb_policy`,
    warn, `USBSTOR Start=3`).
  - `bitlocker`/`privileged_accounts` remontés `unknown` sur cette machine (`manage-bde`/
    `net localgroup administrators` ont échoué — fonctionnalité BitLocker probablement non installée,
    cause de l'échec de `net localgroup` non encore investiguée) — comportement voulu : ni crash, ni
    donnée inventée, un droit/outil indisponible est un résultat légitime.
  - **Garde-fou vérifié en conditions réelles** : les 5011 `patched`/22 `false_positive`/2
    `awaiting_fix` déjà qualifiés sur cet actif sont restés **strictement inchangés** après le
    check-in agent — aucune reprise du travail de qualification déjà fait.
