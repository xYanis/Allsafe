# STATUS.md — État du projet Allsafe

## ⚠️ Échéance : passage en production ~24/08/2026

Annoncé par l'utilisateur le 10/08/2026 ("d'ici 2 semaines on passera en prod"). Avant cette
date : **refaire un tour de sécurité complet** (`audit/AUDIT_SECURITE.md`), pas juste relire l'existant
— redémarrer une revue depuis zéro sur tout le périmètre, comme celle du 10/08/2026. L'utilisateur
préfère être celui qui relance ce chantier plutôt qu'un rappel automatique programmé (demandé
explicitement) — ne pas le déclencher de soi-même, mais le proposer si la date approche sans
qu'il en ait reparlé. Peut aussi être l'occasion de statuer sur les points Docker encore ouverts
(mode "prod" sans `--reload`/`vite dev`, cf. § Points ouverts de `audit/AUDIT_SECURITE.md`) — un vrai
passage en prod est justement le moment où ces compromis "dev actif" cessent d'être valables.

## Lire au démarrage de chaque session, avec CLAUDE.md

Volontairement court : ce fichier est chargé à **chaque** session. Le déroulé chronologique des
sessions passées est dans `docs/HISTORIQUE.md`, à n'ouvrir que pour retrouver le contexte d'une
décision. Les détails techniques vivent dans `docs/` (cf. `CLAUDE.md` § Documentation détaillée).

**Dernière session : 21/08/2026 (suite)** — Ping agent + correctif mise à jour Windows MSI.

- **Ping agent** (pull model — Allsafe ne contacte jamais l'agent) : `ping_requested_at` posé
  sur l'agent, l'agent voit `ping_requested: true` dans `/pending` (POLL_INTERVAL réduit 60 s→5 s),
  répond via `POST /agents/pong` (latence enregistrée, entrée `AgentCheckinLog.is_ping=True`).
  Interface : bouton "Ping" individuel par ligne + "Ping tous" dans la PageHero (tous les deux avec
  confirmation modale), colonne "Ping" dédiée dans le tableau (centrée, séparée des actions),
  entrée bleue "↩ X ms" dans la frise historique. Cancel ping possible.
  Versions agent : Windows 0.1.21, Linux 0.1.10.

- **Correctif mise à jour Windows MSI** : l'exe 0.1.19 → 0.1.20 apparaissait réussi mais l'agent
  restait sur l'ancienne version. Cause : `FileVersion` encodée dans l'exe (`CARGO_PKG_VERSION`
  immuable entre builds Windows) → Windows Installer comparait des versions identiques → ne
  remplaçait pas le fichier. Fix : `REINSTALL=ALL REINSTALLMODE=amus` dans la table des propriétés
  MSI (`agent/wix/main.wxs`) — force le remplacement sans vérification de version.

- **Tests** : `test_agent_ping_guardrails.py` (9 tests — revoked → 409, pong sans ping en attente
  ignoré, latence, historique) ; `test_auth_guardrails.py` mis à jour (`/pong` dans
  `non_admin_agent_paths`). 30/30 passent.

- **`COMPOSE_PROJECT_NAME=cybervuln`** ajouté dans `.env` — sans ça, Docker dérivait le nom du
  projet depuis le chemin du répertoire (long hash WSL2), créant des volumes séparés des vrais
  `cybervuln_*` à chaque session depuis une autre racine.

---

**Dernière session : 21/08/2026** — Pages d'erreur personnalisées + audit Strix + 4 correctifs de
sécurité.

- **Pages d'erreur animées** (`frontend/src/pages/ErrorPage.jsx` nouveau,
  `components/ErrorBoundary.jsx` réécrit) : 404 gris, 403 or, 500 rouge — keyframes injectés via
  `<style>` (évite le conflit shorthand CSS/`animationDelay`), entrée séquencée code → titre →
  message → boutons. `App.jsx` route `*` → `<ErrorPage code={404}/>` ; `ProtectedRoute.jsx`
  redirige vers `<ErrorPage code={403}/>` au lieu de `<Navigate to="/">`.

- **Scan Strix v1.5.3** (white-box, DeepSeek, `backend/` uniquement) : 4 findings confirmés,
  résultats dans `strix_runs/backend_e1c4/`. Posture globale jugée bonne (0 CVE de dépendance,
  0 injection SQL/RCE/SSRF exploitable, uploads durcis, CSRF couvert).

- **#38 — BFLA backup** (Medium, corrigé) : `backup.router` passé de `_authed` à `_admin_only`
  dans `main.py` — tout compte authentifié pouvait déclencher un `pg_dump` superutilisateur.

- **#39 — BOLA notes** (Medium, corrigé) : `user_id` FK ajouté sur `NoteTheme`/`NoteSubject`/
  `NoteImage` ; contrainte `UNIQUE(name, user_id)` remplace `UNIQUE(name)` global ; backfill vers
  le 1er admin ; tous les handlers filtrés par `user.id` (404 en accès cross-user). Migration
  appliquée en conditions réelles.

- **#40 — Forgery `risk_score`** (Medium, corrigé) : `Field(ge=0, le=10)` sur `VulnUpdate.
  risk_score` (valeurs hors-bornes refusées par Pydantic à l'entrée).

- **#41 — CSV injection résiduelle** (Low, corrigé) : 4 colonnes manquées par le correctif #7
  du 27/07 (`themes`, actifs concernés dans `watch.py` ; `matched_identities`, `asset_name` dans
  `reports.py`) enveloppées dans `csv_safe()`.

- **`schema_patches.sql`** rejoué et 2 bugs d'idempotence préexistants corrigés : `UPDATE
  used_at` enveloppé en `DO $$` conditionnel (colonne déjà droppée) ; seed `note_themes` passé
  de `ON CONFLICT (name)` à `WHERE NOT EXISTS (name)` (ancienne contrainte supprimée).

- **Scan Strix `frontend/src/`** (même session, scan global impossible en WSL2 — TUI crash) :
  1 finding confirmé. Posture jugée bonne (0 vuln de dépendance, 0 injection DOM évidente hors ce cas).

- **#42 — XSS stocké export PDF** (Medium, corrigé) : `exportPdf()` dans `ReportMarkdown.jsx`
  convertissait le markdown en HTML sans échappement, puis l'écrivait via `document.write` dans un
  popup same-origin. Fix : `escapeHtml()` en amont de `colorizeHtml()` dans `inline()` +
  `DOMPurify.sanitize()` sur `bodyHtml`. DOMPurify était déjà installé (`^3.4.12`).

- **`audit/AUDIT_SECURITE.md`** : revue (6) ajoutée (#42), `schema_patches.sql` notes marqué appliqué.

---

**Dernière session : 19/08/2026 (suite 6)** — Incident réel grave sur `armadasenonches` : mise à jour
`.exe` (0.1.15 → 0.1.16) rendue "réussie" par la fenêtre graphique, mais `Program Files\Allsafe Agent`
entièrement vide après coup — plus d'exe, plus de DLL, service disparu. **Rien perdu côté Allsafe**
(l'identité `armadasenonches` reste `enrolled` en base, jamais touchée par ce flux) — uniquement local
au poste Windows.

**Cause** : la table `<Upgrade>` ajoutée plus tôt cette session (correctif d'un bug voisin, cf. entrée
précédente) programmait `RemoveExistingProducts` **tôt** (`After="InstallValidate"`), présenté à
tort comme "recommandé pour un composant partagé". C'est l'inverse : le composant `MainExecutable`
garde un GUID **fixe** entre versions (délibéré, remplacement de fichier par comptage de références
MSI) — un piège documenté Microsoft veut que retirer l'ancien produit AVANT que le nouveau ait posé
ses fichiers fasse tomber ce compteur à zéro pour un composant partagé, supprimant ses fichiers sans
que rien ne les remette. Reproduit exactement sur `armadasenonches`.

Corrigé : `RemoveExistingProducts After="InstallFinalize"` (le nouveau produit installe D'ABORD,
PUIS l'ancien se désinstalle — comportement historique par défaut de Windows Installer, l'early
scheduling n'a de sens que si les deux versions ne doivent jamais coexister, pas notre cas avec un
composant partagé). Vérifié via `msiinfo export ... InstallExecuteSequence` que `wixl` honore la
correction (`RemoveExistingProducts` bien positionné en séquence 6601, en fin de séquence).

⚠️ Point important clarifié avec l'utilisateur : même en n'utilisant jamais le `.msi` directement
("je ne travaille qu'avec le `.exe`"), le bouton **Mise à jour** de la fenêtre graphique télécharge
et exécute ce `.msi` en interne via `msiexec` — ce correctif concerne donc aussi l'usage 100% `.exe`.

Déployé en `0.1.17`. **Récupération** : `%ProgramData%\allsafe-agent\agent.json` n'est pas géré par
le `.msi` (créé au runtime par l'agent, jamais déclaré comme composant) — a survécu à l'incident,
donc une simple **Réparation** avec un `.exe` 0.1.17 frais suffit à tout récupérer sans réenrôler.

**Validation en conditions réelles** : `armadasenonches` réparé puis remonté en `0.1.17`, socle diff
Windows enfin vérifié avec de vraies données — comptes locaux réels (`Administrateur`, `Invité`
désactivé, `Restart`), ~130 tâches planifiées + services réels (dont `AllsafeAgent` lui-même,
`VeeamDeploySvc`, des instances SQL Server). Deux bugs supplémentaires repérés sur ces données réelles
et corrigés en `0.1.18` :
- **`admin_members` toujours vide** : `Get-LocalGroupMember -Group 'Administrators'` échoue
  silencieusement (`-ErrorAction SilentlyContinue` avale l'erreur) sur un Windows en français — le nom
  du groupe intégré est LOCALISÉ ("Administrateurs"). Corrigé avec le SID bien connu
  `S-1-5-32-544` (identique quelle que soit la langue d'installation), même principe déjà utilisé dans
  `config.rs::restrict_permissions`.
- **Caractères accentués corrompus** (`"Invité"` remonté `"Invit�"`) : PowerShell 5.1 encode sa sortie
  standard dans la page de code ANSI système par défaut dès qu'elle est redirigée (pas un vrai
  terminal) — cassait tout nom de compte/tâche en français. Corrigé en forçant
  `$OutputEncoding = [System.Text.Encoding]::UTF8` avant `ConvertTo-Json` dans `ps_json()`.

**Troisième bug distinct sur la même mise à jour** (0.1.17 → 0.1.18, testé à nouveau après les deux
correctifs précédents) : ni le fichier vidé (1er bug), ni resté figé sur une version instable — cette
fois l'ancienne version reste simplement en place, aucune erreur affichée, "succès" quand même annoncé.
Cause probable (non observable directement sans accès au poste, mais cohérente avec le symptôme et un
piège Windows connu) : les apps Tauri/WebView2 tournent souvent dans un **Job Object** qui tue tous les
processus enfants à la fermeture du parent — l'aide PowerShell détachée (`apply_update`/`uninstall`,
correctifs précédents) mourrait donc EN MÊME TEMPS que la fenêtre se ferme (`app.exit(0)`), avant même
d'avoir pu attendre la fin du process puis lancer `msiexec`/`Remove-Item`. Corrigé en faisant sortir
explicitement l'aide détachée du job object du parent (`CREATE_BREAKAWAY_FROM_JOB`, 0x01000000, flag
Win32 natif via `CommandExt::creation_flags`) + `DETACHED_PROCESS`. Si le job refuse le breakaway
(rare), l'échec de `spawn()` remonte maintenant une vraie erreur au lieu d'un faux "succès" silencieux
— strictement mieux dans les deux cas. Déployé en `0.1.19`, **pas encore revérifié en conditions
réelles** (3e tentative de mise à jour depuis un poste toujours bloqué en `0.1.17`).

---

**Dernière session : 19/08/2026 (suite 5)** — Versionnement de l'agent **séparé par plateforme**
(demande explicite utilisateur) : `.exe`/`.msi` (même binaire Windows, ne peuvent jamais diverger
l'un de l'autre) et `.deb` (compilation Linux distincte) sont désormais deux pistes indépendantes,
plus une seule version crate (`Cargo.toml`) partagée forçant à bumper les deux à chaque release —
un correctif Windows pur (le lot 0.1.9→0.1.11 juste avant, cf. entrée précédente) faisait
apparaître Linux "en retard" dans Allsafe sans qu'il ait réellement changé.

`agent/src/main.rs::RELEASE_VERSION` (nouvelle constante `#[cfg(target_os = ...)]`, remplace
`env!("CARGO_PKG_VERSION")` partout — `collect/linux.rs`/`collect/windows.rs`/
`install.rs::check_update`) : deux valeurs indépendantes, une par OS. Contrainte découverte en
implémentant : `cargo-deb` (cette version) n'a **aucun override de version indépendant** dans
`[package.metadata.deb]` (`unknown field version`, testé en conditions réelles — silencieusement
ignoré par un `2>&1 | tail -5` qui masquait l'échec derrière `set -e`, piège de pipeline classique
POSIX : seul le code de sortie de la DERNIÈRE commande du pipe compte). `Cargo.toml::version` reste
donc la seule source pour le nom du `.deb` généré — dédié au suivi **Linux** désormais (`0.1.9`),
plus touché pour un changement Windows seul. Windows vit entièrement dans `wix/main.wxs::Version`
(`0.1.12`) + le `RELEASE_VERSION` Windows.

Backend : `CURRENT_AGENT_VERSION` splitté en `CURRENT_AGENT_VERSION_WINDOWS`/`_LINUX`
(`routers/agents.py`), `_agent_dict::outdated` compare désormais contre la constante de l'OS de
l'agent (`_current_version_for(a.os)`) — avant, un seul seuil comparé aveuglément aux deux OS.
`GET /agents/latest/version` renvoie `version_windows`/`version_linux` (remplace l'ancien `version`
unique) — mis à jour dans `install.rs`, `update-agent.sh`/`.ps1` (`grep`/`ConvertFrom-Json`),
`Agents.jsx` (badge titre + détail par option de téléchargement, `versionKey` par plateforme comme
`dateKey` existant).

Vérifié : compile propre sur les deux cibles, `.deb` généré nommé `allsafe-agent_0.1.9-1_amd64.deb`
(confirmé, pas juste supposé — le premier essai avait laissé un `.deb` 0.1.11 périmé traîner suite
à l'échec silencieux `cargo-deb` ci-dessus), build frontend propre, backend importe sans erreur.
Déployé — `dist/` à jour, `CURRENT_AGENT_VERSION_WINDOWS/_LINUX` synchronisés.

⚠️ **Effet de bord attendu, pas un bug** : `gitlab.aer.loc` (Linux, dernier contact confirmé en
`0.1.8`) va réapparaître "en retard" dans Allsafe une fois — `0.1.9` est un bump de transition
(aucun changement fonctionnel Linux réel dans ce lot, juste le passage interne de
`CARGO_PKG_VERSION` à `RELEASE_VERSION`), pas un aller-retour à refaire à chaque session désormais.

---

**Dernière session : 19/08/2026 (suite 4)** — Corrections UI signalées par l'utilisateur + une
spécification figée. Aucune touche à l'agent Rust.

- **Détection d'évènements sensibles côté poste — conception figée** (`docs/AGENT_DETECTION.md`,
  nouveau) : extension à venir de l'agent (compte créé / privesc / process suspect type nmap /
  altération d'audit) par **lecture** des journaux natifs (Event Log Security, auditd) + diff d'état
  — lecture seule stricte, jamais d'exécution (même règle §1). Cible **Niveau 2 hybride** (diff =
  socle sans prérequis, journal = enrichissement quand l'audit OS est actif), N3 (corrélation/
  baseline/règles en base) documenté comme trajectoire hors MVP. Modèle `AgentSecurityEvent` +
  `AgentStateSnapshot` + `Agent.audit_coverage`, transport piggyback sur `checkin`, bannière séparée
  du honeypot DB, conservation totale sans purge auto. ⏳ **Spécifié, PAS implémenté** (rien en base/
  agent/front). Pointeurs ajoutés (CLAUDE.md § doc, `docs/AGENTS.md`).
- **Page Administration en orange** (`AdministrationSecurity.jsx`) : la nav des onglets était codée
  en `var(--accent-blue)` en dur alors que le reste de la page suivait le gris de Paramètres —
  incohérence. L'utilisateur a demandé l'orange plutôt que le gris : `MODULE_COLOR` passé à `#fb8f44`
  (orange déjà présent sur la page — boutons « + Ajouter »), pilote désormais hero + nav + carte +
  filtres d'un seul point. ⚠️ **Divergence assumée** : seul sous-module à ne pas reprendre la couleur
  de son parent (Paramètres, gris).
- **Page détail agent (`AgentHistory.jsx`) — 4 tuiles cassées corrigées** (signalées par l'utilisateur) :
  - *Mises à jour en attente* affichait toujours « — » : **vrai bug back**, `get_asset`
    (`routers/assets.py`) passait `pending_updates=None` (calculé seulement dans `list_assets`).
    Corrigé — même requête de ventilation système/application, scopée à l'actif.
  - *Connu depuis* affichait « 01/01/2020 » (sentinelle backfill `schema_patches.sql`) : front,
    helper `formatKnownSince` → « Avant le suivi » pour les actifs antérieurs à la colonne `created_at`.
  - *État réseau* (« Non supervisé », sans objet pour un poste agent) **remplacée** par **Durcissement**
    (résumé ✓/⚠/— via `complianceSummary` partagé, cliquable vers `/durcissement`).
  - *Mises à jour disponibles* (« 0 » structurel : agent Windows ne pose jamais `available_version`,
    impasse assumée) **remplacée** par **Fiabilité du dernier scan** (`last_scan_result.reachable`/
    `.error` → Complète/Partielle/Injoignable).
  - Front-only sauf le 1er point (back). Import `NetworkStatusBadge` retiré (plus utilisé).

---

**Dernière session : 19/08/2026 (suite 4)** — Démarrage de l'implémentation `docs/AGENT_DETECTION.md`
(détection d'évènements sensibles côté poste, jusque-là juste spécifié). Ordre validé avec
l'utilisateur : fondations backend d'abord, seule chose testable indépendamment des deux OS.

**Posé et vérifié en conditions réelles** (base réelle, pas juste relu) :
- `models.py::AgentSecurityEvent`/`AgentStateSnapshot` + `Agent.audit_coverage` ; `schema_patches.sql`
  rejoué contre la vraie base (idempotent, `GRANT` posés pour `cbr_app`).
- `services/agent_detection.py` (nouveau) : diff d'état (comptes/admins/persistance) contre le dernier
  snapshot connu, no-backfill au 1er check-in (aucun snapshot antérieur = pas de diff, juste stockage),
  journal natif dédoublonné sur `(agent_id, native_event_id)`, plafonds serveur sur
  `security_events`/`audit_coverage`/`state_snapshot` indépendants de ce que l'agent est censé
  respecter (cf. audit #35, même leçon appliquée ici).
- `POST /agents/checkin` étendu (`security_events`/`audit_coverage`/`state_snapshot`), branché via
  `apply_security_events()` — fonction dédiée, pas `apply_scan_result` (shape différent, comme prévu
  au doc).
- `GET /agents/security-events` (+`?unack_only`)/`POST .../{id}/ack`/`POST .../ack-all` réservés admin,
  `GET .../count` en exception (badge nav, tout connecté) — même schéma que `routers/security.py`.
- Script de test dédié rejoué dans le conteneur backend (agent jetable, nettoyé après) : 1er check-in
  → 0 évènement diff (juste le journal natif transmis), 2e check-in avec compte+admin+persistance
  neufs → exactement les 3 détections attendues + dédoublonnage confirmé sur l'évènement natif déjà
  vu. Ack/count testés via un compte admin jetable également.

**Piège de routing découvert en cours de route** : `GET /agents/{agent_id}` (catch-all existant)
enregistré AVANT mes nouvelles routes `/security-events*` aurait intercepté
`GET /agents/security-events` (`agent_id="security-events"`) — FastAPI/Starlette matche par ordre de
déclaration, pas par spécificité. Corrigé en les déplaçant avant le catch-all, comme `/history` le
fait déjà pour la même raison.

**Effet de bord positif** : en lançant la suite `pytest` complète, un test préexistant
(`test_agents_management_routes_require_admin_except_list`) a révélé que `GET /agents/history`
(ajouté par une session concurrente le même jour, cf. `AgentDeletionLog`) n'avait jamais été ajouté à
sa liste d'exceptions — sans rapport avec mon travail, corrigé au passage (255/255 tests verts).

**Reste à faire** (cf. doc, callout mis à jour) : toute la collecte côté agent Rust (Windows Event Log
Security + diff Linux/auditd, curseur persistant, buffer plafonné) et le frontend (page Durcissement,
badge nav, bandeau Dashboard séparé).

**Suite immédiate, même session** : socle diff **Linux** posé côté agent (`collect/linux.rs`) —
choix délibéré de commencer par Linux (pas de FFI Windows, testable tout de suite sur
`gitlab.aer.loc` déjà enrôlé) et par le socle diff avant le journal natif (4 des 6 catégories
`account_created`/`privilege_escalation`/`account_reactivated`/`persistence` n'ont besoin d'AUCUNE
lecture de journal — juste envoyer l'état brut, le serveur diffe). `local_users_snapshot()` filtre
aux comptes humains (UID ≥ 1000) + root explicitement — sans ce filtre, une simple installation de
paquet créant un compte système aurait déclenché un faux `account_created` (doc § "filtrage strict
dès le départ"). `admin_members_snapshot()` réutilise la source de `privileged_accounts_check()`
existant (sudo/wheel) en liste brute. `persistence_snapshot()` : fichiers cron système + crontab root
+ unités systemd **activées** (`enabled`, le signal qui survit à un reboot, pas juste en cours
d'exécution). `audit_coverage()` : constate `auditd` installé/actif, ne l'active jamais.

`model.rs` : nouveaux types `SecurityEvent`/`AuditCoverage`/`LocalUser`/`PersistenceEntry`/
`StateSnapshot`, miroir exact du payload backend. `collect/windows.rs` : champs ajoutés mais vides
pour l'instant (compile, socle Windows pas encore fait) — pas question de casser le build Windows en
ajoutant les champs seulement côté Linux.

Compilé et vérifié sur les deux cibles (`cargo check` x86_64-unknown-linux-musl +
x86_64-pc-windows-gnu, conteneur `rust:1-trixie`), rebuild complet + déployé en `0.1.8`
(`agent/dist/`, `CURRENT_AGENT_VERSION` bumpé).

**Testé en conditions réelles sur `gitlab.aer.loc`** (mise à jour manuelle `wget` + `apt install`
depuis `/api/agents/latest/linux`, cf. `agent/README.md` § Mise à jour — commandes exactes
documentées) : agent remonté en `0.1.8`, snapshot correctement collecté (4 comptes humains dont
`root`/`nobody` désactivé correctement filtrés/détectés, 2 membres sudo, cron/systemd réels
capturés dont un vrai cron utilisateur `sync-gitlab.sh`), **0 évènement généré** au 1er check-in
(no-backfill confirmé), `audit_coverage` honnête (`auditd` absent sur ce poste, remonté tel quel).

**Suite immédiate, même session** : socle diff **Windows** posé (`collect/windows.rs`) — même
principe que Linux, mais via PowerShell + `ConvertTo-Json` plutôt que du texte parsé (contrairement
à `local_admins_check()`/`net localgroup` existant, dont le filtrage par mots-clés dépend de la
langue d'installation Windows FR/EN codée en dur — un diff doit rester fiable, pas juste informatif
comme un check affiché). `local_users_snapshot()` : `Get-LocalUser`, filtre les comptes de bruit
présents par défaut sur toute installation (`Guest`/`DefaultAccount`/`WDAGUtilityAccount`/
`defaultuser0`). `admin_members_snapshot()` : `Get-LocalGroupMember -Group Administrators` (pas
`net localgroup`, locale-indépendant). `persistence_snapshot()` : tâches planifiées non désactivées
(`TaskPath+TaskName`, l'identité complète — deux tâches de dossiers différents peuvent porter le
même nom) + services en démarrage automatique (WMI `Win32_Service`). `audit_coverage()` :
`command_line_logging` via une clé de registre (DWORD, locale-indépendant) ; `process_auditing`
best-effort sur la sortie texte d'`auditpol` (anglais uniquement pour l'instant, comme
`screen_lock_check` côté Linux reste GNOME uniquement — honnête plutôt que de deviner sur un poste
en français).

`model.rs::AuditCoverage` **refactoré** en dict libre (`HashMap<String, bool>`) plutôt qu'une struct
à champs fixes — trouvé en implémentant Windows : Linux et Windows n'ont pas les mêmes signaux à
constater (`auditd_installed`/`auditd_running` vs `process_auditing`/`command_line_logging`), une
struct partagée aurait forcé des noms de clé qui n'ont de sens que pour l'une des deux plateformes.
Fidèle à ce que le backend attendait déjà (`audit_coverage: dict`, aucun schéma strict).

Compilé et vérifié sur les deux cibles, rebuild complet + déployé en `0.1.9` — **Windows pas encore
testé en conditions réelles** (prochaine étape : mise à jour d'`armadasenonches`, même vérification
que Linux : 0 évènement au 1er check-in, snapshot bien stocké).

**Reste pour Linux et Windows** (les deux socles diff sont posés) : enrichissement journal natif
(`suspicious_process` via `auditd`/`execve` côté Linux, Event Log Security `4688`/`4720`/`4732`/
`1102` côté Windows), curseur persistant, buffer plafonné pendant coupure.

**Incident réel découvert en testant le socle Windows** : mise à jour via la fenêtre graphique
(`armadasenonches`, 0.1.7 → 0.1.9) rendait "succès" mais la version restait inchangée en base.
Cause : `wix/main.wxs` n'avait **aucune table `Upgrade`** — `Product Id="*"` génère un nouveau
ProductCode à chaque build, donc `msiexec /i` sur le nouveau `.msi` s'exécutait sans que Windows
Installer sache qu'il devait remplacer l'ancienne installation (succès `msiexec` = exit 0, aucune
garantie que quoi que ce soit ait réellement changé). Ce bug existait depuis l'introduction du
`.msi` (13/08/2026) — jamais remarqué avant car aucune mise à jour Windows n'avait encore été
testée en conditions réelles sur un poste déjà installé.

Corrigé : ajout de `<Upgrade>`/`<UpgradeVersion>` (référence l'`UpgradeCode` fixe, plage
`0.0.0.0`–`99.0.0.0` — plafond haut fixe plutôt que la version courante, `wixl` ne supportant pas
le raccourci `<MajorUpgrade>` de WiX v3 qui l'aurait calculé dynamiquement ; un plafond à la
version courante aurait exigé de le rebumper à chaque release, un 5e endroit après Cargo.toml/
Cargo.lock/`Version` — piège déjà connu une fois) + `RemoveExistingProducts` dans
`InstallExecuteSequence`. **Vérifié explicitement via `msiinfo export ... Upgrade` que `wixl`
honore bien ces éléments** (déjà silencieusement ignoré des attributs par le passé sur ce
projet, cf. checkpoints `ServiceInstall`/`Environment` existants) — confirmé présent avec les
bonnes valeurs. Déployé en `0.1.10`.

**Deuxième bug, distinct, trouvé au test réel du premier correctif** : `0.1.10` toujours resté
sans effet sur `armadasenonches` (utilisateur : "je viens de lancer la MAJ via le .exe"). Cause :
`apply_update()` était lancé depuis l'exe **déjà installé** (`Program Files\Allsafe Agent\
allsafe-agent.exe`, pas un `.exe` fraîchement téléchargé) — le composant MSI cible exactement ce
même chemin, donc `msiexec` ne pouvait pas écraser un fichier que son propre lanceur avait encore
ouvert. Limite déjà **documentée dans le code** (docstring `apply_update`) mais jamais traitée
avant ce test réel. Windows Installer dévie alors sur un remplacement différé au reboot —
`msiexec` rend quand même succès, rien ne change avant un redémarrage (explique le "succès"
affiché côté agent sans changement en base).

Corrigé (`install.rs::apply_update`) : détection `current_exe() == install_exe_path()`, et si
auto-verrouillé, une aide PowerShell détachée est lancée EN PREMIER — elle attend explicitement
la fin du PID courant (`Wait-Process`, pas un `sleep` deviné) avant de lancer `msiexec` elle-même.
`apply_update` rend `Ok(())` immédiatement, la GUI affiche le succès puis se ferme d'elle-même
après quelques secondes (mécanisme déjà posé plus tôt cette session,
`autoQuitAfterSuccess`/`cmd_quit`/`app.exit`) — c'est cette fermeture propre qui libère
effectivement le verrou, l'aide déjà en attente prend alors le relais. Assumé différent de la
décision `uninstall()` ("pas d'astuce de suppression différée, trop fragile") : là-bas, laisser
l'utilisateur nettoyer un fichier à la main est une dégradation acceptable ; ici, sans ce détour,
la mise à jour depuis la GUI installée — le chemin **normal**, pas un cas limite — ne fonctionne
tout simplement jamais.

Déployé en `0.1.11`, test réel en cours sur `armadasenonches`.

---

**Dernière session : 19/08/2026 (suite 3)** — Incident réel signalé par l'utilisateur en testant
l'agent Linux sur un vrai poste (`gitlab.aer.loc`, Debian 12) : `apt install
allsafe-agent_0.1.4-1_amd64.deb` refusé, `Dépend: libc6 (>= 2.39) mais 2.36-9+deb12u14 devra être
installé`. Cause confirmée en conditions réelles (`docker run rust:1-trixie ldd --version` → glibc
2.41) : le conteneur CI (Debian 13/trixie, nécessaire pour `wixl` côté build Windows, cf.
`AUDIT_SECURITE_3` § build-agent historique) compile aussi le binaire **Linux** nativement — plus
récent que le parc cible (Debian 12/bookworm, glibc 2.36). Le `.deb` publié exigeait donc une glibc
que le parc n'a pas.

**Corrigé pour de bon, pas juste contourné** : `cargo deb --target x86_64-unknown-linux-musl`
(`.gitlab-ci.yml`, `agent/README.md`) — lien 100% statique (`ldd` → `statically linked`), aucune
dépendance glibc du tout. Viser une distro de build plus ancienne (bookworm) aurait juste repoussé
le même problème à la prochaine montée de version Debian ; musl l'élimine structurellement. Aucune
dépendance C dans l'arbre Linux du crate (`tauri`/`winapi`/`windows-service` sont
`[target.'cfg(windows)'.dependencies]`, jamais compilés côté Linux ; `reqwest` en `rustls-tls`, pas
OpenSSL) : compile sans adaptation, vérifié en conditions réelles dans `rust:1-trixie` (le
conteneur CI réel, pas une supposition) — `dpkg-deb --info` sur le `.deb` généré affiche
`Depends:` **vide**. `wix/main.wxs` (`Version="0.1.4.0"`, oublié lors du bump `Cargo.toml`
0.1.4→0.1.5 plus tôt dans la session — l'`agent/README.md` prévient explicitement ce piège)
corrigé au passage.

**Binaires reconstruits ET redistribués pour de vrai** (pas juste le code source cette fois,
contrairement au reste de la session) : build complet rejoué en local (même séquence que
`.gitlab-ci.yml::build-agent`, conteneur `rust:1-trixie`) — `.deb` musl 0.1.5 déposé dans
`agent/dist/` (bind-monté dans le conteneur backend, servi immédiatement par
`GET /api/agents/latest/linux`), `.exe`/`.msi`/`WebView2Loader.dll` Windows en cours de
reconstruction en parallèle (mêmes vérifications que la CI : `msiinfo`, manifeste
`requireAdministrator`). `CURRENT_AGENT_VERSION` (`backend/routers/agents.py`) à bumper vers
`0.1.5` une fois les artefacts Windows confirmés — pas fait avant, pour ne pas afficher "à jour"
sur un agent Windows qui recevrait encore l'ancien binaire non reconstruit.

---

**Dernière session : 19/08/2026 (suite 2)** — Deux bugs signalés sur le Dashboard.

- **Cloche de notifications invisible au clic** : `PageHero.jsx` posait `overflow-hidden`
  sur tout le conteneur (nécessaire pour clipper la lueur décorative + la trame de points
  aux coins arrondis), ce qui clippait aussi tout menu déroulant ouvert depuis ses
  `children` — un enfant en `position: absolute` reste borné par le premier ancêtre
  `overflow` non-`visible`, quel que soit son `z-index`. `NotificationHistory.jsx`
  (cloche) en faisait les frais, invisible bien que rendu (caché dans les bornes de la
  tuile). Corrigé en isolant lueur+trame dans leur propre wrapper `absolute inset-0
  overflow-hidden` — le conteneur principal n'a plus besoin de le porter lui-même
  (`border-radius` seul suffit à arrondir son propre fond). Concerne potentiellement
  d'autres consommateurs de `PageHero` avec un dropdown dans `children`, pas testé
  au-delà du cas signalé (bell du Dashboard).
- **Justification réutilisée garde le nom de l'actif source** : `bulk-false-positive`/
  `bulk-validate` (`routers/vulnerabilities.py`) génèrent une justification préfixée par
  `[NOM_ACTIF]` (utile là-bas pour distinguer plusieurs lignes d'un même lot). Copiée telle
  quelle par "↩ Réutiliser cette justification" (`OtherInstancesModal.jsx`, partagé
  Dashboard/Vulnerabilities) sur un AUTRE actif, le préfixe restait celui de la source —
  confirmé en conditions réelles (compte de test temporaire créé/supprimé, API interrogée
  directement : `[WBRO] ✅ Build installé...` reste `[WBRO]` même réutilisé sur un actif
  différent). Corrigé par substitution ciblée du préfixe `[sourceAssetName]` →
  `[targetAssetName]` dans `OtherInstancesModal.jsx` (nouveau prop `targetAssetName`) —
  no-op si le texte ne commence pas exactement par ce motif (notes manuscrites sans
  préfixe, laissées intactes). **Navigateur headless indisponible dans ce sandbox**
  (libs système manquantes, `libglib-2.0.so.0`, pas de root pour les installer) — diagnostic
  fait par requêtes API directes contre la vraie base plutôt que par capture d'écran ;
  correctif non revérifié visuellement, à confirmer au prochain accès UI réel.

- **Filtre par actif lent à s'afficher** : `Vulnerabilities.jsx`/`Watch.jsx` appelaient
  `GET /assets` (calcule 3 requêtes groupées sur toute la table `vulnerabilities` + un join
  `NetworkStatus` pour les 440 actifs du parc) juste pour peupler un menu id/nom
  (`AssetDropdown.jsx` n'utilise que `a.id`/`a.name`, vérifié). Nouveau `GET /assets/names`
  (une requête `SELECT id, name`). **Mesuré en conditions réelles** (440 actifs) :
  848ms → 107ms. `Reports.jsx` gardé sur l'endpoint lourd — il a réellement besoin de
  `hostname`/`ip_address` pour `redactText` (mode Présentation).
- **Page globalement lente** : trois causes mesurées en conditions réelles, pas supposées —
  1. Tri par défaut (`status='open'`, score desc) sans index composite : `EXPLAIN ANALYZE`
     confirmait un tri en mémoire sur ~119k lignes. Index `idx_vulnerabilities_status_risk_score`
     ajouté — la requête de liste passe de "tri après scan" à "déjà trié par l'index"
     (0,8-1,1ms mesuré après coup).
  2. `awaiting-fix-candidates` (appelé au montage de la page, jamais mis en cache) :
     **3,4s mesurés**. Cause : le pré-filtre SQL ne gardait que "patch check déjà passé"
     (`patch_check_result IS NOT NULL`), la vérification finale (`no_fix_available`) restant
     en Python après matérialisation ORM complète — correct quand ce filtre ne laissait
     passer que 1 244 lignes (28/07/2026), plus du tout maintenant que le cycle de patch
     check a tourné sur l'essentiel du parc élargi (77 075 lignes matérialisées pour ne
     retenir, au final, que 0-2 candidats). Poussé entièrement en SQL (opérateur JSON
     Postgres `->>'no_fix_available' = 'true'`) — même résultat exact vérifié par
     comparaison directe, **3,4s → ~0,4-0,6s** mesuré après coup (5-8×).
  3. `false-positive-candidates` (même appel au montage) : **~7,5s à froid** confirmé encore
     valable aujourd'hui (mémoïsation 5 min déjà en place depuis le 08/08, mais chaque
     premier appel après expiration reste plein tarif). Profilé en détail : la phase de
     matching CPE elle-même est rapide (~530ms sur 15 320 évaluations CVE×profil) — le vrai
     coût est la phase 2, qui matérialise ~17-27k lignes ORM en Python. Tentative de
     réplication de l'optimisation ci-dessus **infirmée par la mesure** : sur un parc
     hétérogène Windows/Linux à 8 profils distincts, la quasi-totalité des CVE candidates
     (1915/1915 mesurées) sont "invalides pour au moins un profil" par construction (une CVE
     Windows ne matche jamais un profil Debian) — le filtre `cve_id IN invalid_cve_ids`
     n'exclut donc presque rien, contrairement à l'intuition. **Laissé tel quel** : corriger
     nécessiterait vraiment de revoir la logique même de pré-filtrage (par profil de l'actif
     réel de la ligne, pas "invalide pour N'IMPORTE LEQUEL des profils du parc"), un
     changement plus risqué sur une fonction qui alimente une qualification NIS 2 — pas
     tenté sans pouvoir le valider plus à fond.
- **Validation Docker réelle** (accès retrouvé en cours de session) : `docker compose build
  backend` (Dockerfile multi-stage, cf. #32) — `gcc` bien absent de l'image finale
  (`which gcc` → introuvable), `ldap3`/tout le reste importent sans erreur avec les vraies
  variables d'environnement. `schema_patches.sql` rejoué contre la vraie base (idempotent,
  aucune erreur) — les deux nouveaux index (#19, perf ci-dessus) créés avec succès,
  confirmés par `\d`. Suite de tests passée via le chemin CI exact
  (`docker run ... pytest`) : 255/255. `backend`/`worker`/`beat` reconstruits et recréés
  (leçon déjà connue du projet : les trois partagent la même image, `docker compose build
  backend` seul ne suffit pas) — les 6 services confirmés `healthy`.
- **Notes de version alimentées** (`release_notes`, table réelle, pas juste ce fichier) :
  scope `allsafe` 1.2.0 (4 entrées : perf page Vulnérabilités, RBAC actifs admin-only,
  suppression d'image de note, mot de passe oublié durci) et scope `agent` 0.1.5 (3
  entrées : vérification avant mise à jour, identité vérifiée à l'enrôlement, ACL Windows).
  `agent/Cargo.toml`/`Cargo.lock` bumpés à `0.1.5` en conséquence (source seulement — les
  binaires distribués dans `agent/dist/` restent ceux d'avant cette session, pas
  reconstruits/redistribués, cf. point ouvert plus bas).

**Dernière session : 19/08/2026** — Correctifs des 3 nouveaux audits de sécurité du 18/08/2026
(`audit/AUDIT_SECURITE.md`/`_3.md`/`_4.md`, #13 à #37) : les 26 findings numérotés traités
(23 corrigés en code, #28 tranché "laisser ouvert" sans changement, #29/pytest bumpé en gardant
le risque théorique documenté). `AUDIT_SECURITE.md` était déjà clos avant cette session.

- **#13 CRITIQUE** (RCE, `.msi` de mise à jour agent non vérifié) : SHA-256 attendu publié par
  `GET /latest/version` (`sha256_windows`/`sha256_linux`), vérifié avant `msiexec`/`dpkg -i` dans
  `install.rs::apply_update` **et** les deux scripts de déploiement (`update-agent.ps1`/`.sh`,
  toujours vivants et recommandés — pas supprimés comme un instant cru en session). `require_https`
  volontairement laissé en **avertissement non bloquant** (`warn_if_not_https`) : le serveur de
  prod tourne encore en HTTP aujourd'hui, bloquer aurait cassé la mise à jour réelle — décision
  explicite, à repasser en blocage strict au déploiement du reverse-proxy TLS (cf. docs/AGENTS.md).
- **#14 ÉLEVÉ** (`assets.py` sans RBAC) : `require_admin` sur create/update/delete/scan d'actif +
  les 3 endpoints de durcissement réseau/switch/web (`delete_asset` aligné aussi, pas dans la
  liste de l'audit mais même trou) ; SSRF corrigée (`validate_public_url` sur actif website +
  revalidation par hop de redirection dans `web_hardening.py`) ; UI (Assets.jsx/Durcissement.jsx)
  masque les actions désormais admin-only pour un compte analyst ; test anti-régression ajouté.
- **#15/#16 ÉLEVÉ** (race jetons agent + hostname non vérifié) : `enroll_agent` en `UPDATE...
  RETURNING` atomique ; mismatch hostname/actif rejeté **avant** de consommer le jeton (bug UX
  attrapé avant livraison : rejeter après aurait grillé un jeton sur un simple typo).
- **#18/#34/#35** (Lot 2, agent/check-in) : ACL Windows (`icacls`) sur `%ProgramData%\allsafe-
  agent` ; bascule auto **gardée identique** agent/compte de service (décision explicite), mais
  `validated_by="Auto (patch check, agent-reported)"` pour une piste NIS 2 honnête — bug connexe
  trouvé et corrigé au passage : le filtre du bandeau "depuis votre dernière visite"
  (`vulnerabilities.py::auto_bascule_summary`) ne cherchait que l'ancien libellé exact, les
  bascules agent auraient disparu du rattrapage ; throttle 1 check-in/min + troncature `[:300]`.
- **#19-#24** (Lot 3, mot de passe oublié) : index unique partiel `ux_password_reset_pending`
  (`schema_patches.sql`, à rejouer côté DB) + `IntegrityError` catché ; verrou anti-spam par IP
  + journalisation `PASSWORD_RESET_REQUESTED` (même tentatives sur email inconnu, comme /login) ;
  sessions révoquées après remise à zéro d'un mot de passe ; nombre d'opérations DB égalisé entre
  les deux branches (email inconnu vs compte existant) ; `with_for_update()` sur resolve/dismiss ;
  `max_length=2000` sur le champ `message`.
- **#25-#27** (Lot 4, CI) : `if: $CI_COMMIT_REF_PROTECTED` sur `build-agent` (+ rappel à vérifier
  côté Settings GitLab : variables "Protected", restriction des déclenchements manuels) ; `set -e`
  + vérification explicite du code de sortie sur les deux appels `osslsigncode sign`.
- **#29/#32/#33** (Lot 5, Docker/deps) : `backend/Dockerfile` en multi-stage (`gcc`/`*-dev`
  absents de l'image finale — `ldap3` est pur Python, aucun `.so` runtime à recopier) ; en-têtes
  `X-Content-Type-Options`/`X-Frame-Options` sur `location /` de `frontend/nginx.conf` (scopés,
  pas au niveau `server`, pour ne pas dupliquer les en-têtes déjà posés par le backend sur `/api/`) ;
  `pytest` 8.3.3→9.0.3 + `pytest-asyncio` 0.24.0→1.4.0 (changement de version majeure des deux
  côtés, `asyncio_mode = auto` déjà explicite dans `pytest.ini` donc pas affecté par le retrait du
  mode "legacy" — **vérifié en conditions réelles dans la foulée, cf. § ci-dessous : 255/255 tests
  verts avec ces deux versions**).
- **#36/#37** (Lot 6, Notes) : `DELETE /notes/images/{id}` ajouté (n'existait pas, contrairement
  aux 3 modules frères) + nettoyage disque dans `delete_subject` (le cascade DB n'efface jamais
  les fichiers) ; signature WebP vérifiée à l'offset 8 (`WEBP`, pas juste le préfixe `RIFF`
  générique partagé avec WAV/AVI).
- **#28** — décision prise avec l'utilisateur : `GET /assets/lifecycle-since` reste ouvert à tout
  compte connecté, cohérent avec la limite déjà assumée sur `/api/assets`/`/api/vulnerabilities`.
- **Non traité, à vérifier séparément** : la note annexe d'`AUDIT_SECURITE.md` sur
  `severity IS NULL` contournant la garde CRITICAL par égalité stricte — nécessite une requête SQL
  sur la base réelle (`SELECT COUNT(*) FROM cves WHERE severity IS NULL`) pour savoir si des CVE
  non notées participent réellement au cycle de patch check ; pas fait faute d'accès DB dans
  l'environnement de cette session.

## `cargo check` + `pytest` réellement exécutés après coup (19/08/2026)

Le sandbox de la session de correctifs n'avait ni Docker ni `pip`/`cc` préinstallés — statut
initial "rien n'a tourné, tout relu à la main". Sur demande explicite de l'utilisateur
("lance cargo check et pytest de ton côté"), débloqué sans root :
- **pip** amorcé via `get-pip.py --user --break-system-packages` (environnement Debian
  "externally-managed", PEP 668 — override sûr : n'écrit que dans `~/.local`, jamais dans les
  paquets système). `pip install --user` de `requirements.txt` : tout passe en wheel précompilé
  sauf `asyncpg==0.29.0` (pas de wheel `cp313`, tentative de build depuis les sources faute de
  `cc` — écarté, `asyncpg>=0.30` a un wheel `cp313` et suffit pour faire tourner les tests, qui
  ne touchent jamais une vraie base). **`pytest` exécuté pour de vrai : 255/255 verts**
  (`pytest==9.0.3`/`pytest-asyncio==1.4.0`, le bump du Lot 5 #29 — aucune régression).
- **`cargo check --target x86_64-pc-windows-gnu` (agent/) — vert, 0 warning**, ~1m36. Bloqué
  au premier essai par l'absence de `cc` natif (mingw-w64 système ne fournit qu'un compilateur
  croisé, pas d'hôte) ; débloqué avec **Zig 0.16.0** (binaire portable téléchargé, `zig cc` en
  wrapper `CC` pour les build scripts qui compilent pour l'hôte) + **`x86_64-w64-mingw32-gcc`**
  (déjà présent, réglé en `CC_x86_64_pc_windows_gnu` pour le code natif réellement compilé pour
  la cible Windows, ex. `ring`'s `curve25519.c`) — aucune modification du dépôt, juste de
  l'outillage local à cette machine.

**Un vrai bug trouvé en faisant tourner la suite pour de vrai, pas en la relisant** : FastAPI
0.140.0 (bumpé le 27/07/2026, cf. `AUDIT_SECURITE.md`) a changé la structure interne de
`app.routes` — les routes des routers inclus (`app.include_router(...)`) ne sont plus aplaties,
elles vivent derrière des objets `_IncludedRouter`. `TestAllApiRoutesAreProtected`
(`test_auth_guardrails.py`), le filet de sécurité anti-régression sur le RBAC de **toute** l'API,
marchait sur `app.routes` à l'ancienne — résultat : **0 route trouvée depuis le bump FastAPI,
donc chaque assertion passait par vacuité**, y compris en CI (`test-backend`), sans jamais rien
vérifier. Invisible sans un test qui compare un ensemble *trouvé* à un ensemble *attendu*
(`test_assets_write_and_scan_routes_require_admin_read_stays_open`, ajouté cette session pour
#14, a été le premier à le faire échouer au lieu de passer dans le vide). Corrigé : les helpers
marchent maintenant sur `_IncludedRouter.original_router.routes` + `include_context` (prefix et
dependencies de routeur), avec `fastapi.dependencies.utils.get_dependant` pour résoudre
correctement les fabriques de dépendance (`require_page(...)`/`require_page_or_internal(...)`,
qui renvoient une nouvelle closure à chaque appel). Au passage, plusieurs vraies lacunes de
couverture révélées et corrigées dans le test lui-même (pas dans l'app — comportement déjà
correct, juste jamais vérifié) : `GET /api/agents/latest/*` (public, oublié de la liste),
`POST /api/auth/forgot-password` (public, nouveau ce jour), `require_admin_or_internal`/
`require_page_or_internal` pas reconnus comme formes valides de protection.

**Reste non vérifié** (pas de Docker/DB dans ce sandbox même après déblocage pip/cc) :
`docker compose up --build` (le Dockerfile backend multi-stage n'a jamais buildé — `ldap3` étant
pur Python le risque théorique de `.so` runtime manquant est jugé nul, mais pas confirmé en
conditions réelles) ; `backend/db/schema_patches.sql` (nouvel index `ux_password_reset_pending`,
pas rejoué contre une vraie base) ; `frontend` (Assets.jsx/Durcissement.jsx, boutons masqués pour
un compte non-admin — pas testé au navigateur) ; le point `severity IS NULL` d'`AUDIT_SECURITE.md`
ci-dessus (nécessite une requête SQL réelle).

---

## 📊 État du parc

| | |
|---|---|
| Actifs supervisés | **142** — 72 serveurs (70 Windows importés le 28/07 depuis `OU=Serveur,DC=AER,DC=LOC` + `DEPLOYAPP` — Windows Server 2019 ; `gitlab.aer.loc` — Debian 12) + **70 équipements réseau Meraki** importés le 03/08 (`asset_type="network"`, `source="meraki"` — 48 bornes Wi-Fi + 22 pare-feux MX67C, cf. § invariants). Ces 70 n'ont ni OS ni paquets installés — jamais de CVE matchée dessus, `exposed_assets` inchangé |
| CVE en base | ~181 000 (grossi le 28/07 via des `run_nvd_sync_by_id` unitaires déclenchés par l'ingestion WithSecure) |
| Corrigées / Faux positifs / En attente / **En attente (partiel)** / Risque accepté / **Ouvertes** | ~5463 / ~226 / ~52 / **3** / **2** / **~264 900** |
| Taux de correction global | Non représentatif tant que le cycle de patch check n'a pas tourné sur le parc élargi (cf. session 28/07 ci-dessous) |

*Instantané de fin de session (28/07/2026). Le bond du volume ouvert (`0` → `~264 900`) reflète
l'élargissement de `AD_OU` à tout le parc réel le même jour, pas une régression — voir le récit de
session ci-dessous avant de s'inquiéter d'un chiffre qui semble énorme. Les `2` "risque accepté"
(`Test bulk`, `Test bulk historique`) restent des artefacts de test du 27/07 sur `gitlab.aer.loc`, à
ignorer ou réouvrir sans chercher de contexte métier derrière.*

```bash
curl -s http://localhost:8000/api/stats | python3 -m json.tool
docker compose exec db psql -U cybervuln -d cybervuln -c \
  "SELECT status, count(*) FROM vulnerabilities GROUP BY 1 ORDER BY 2 DESC;"
```

**Le dernier reliquat du lot IEEE P1735 est résolu** : `CVE-2017-13091` sur DEPLOYAPP (CPE dégénéré,
artefact de matching déjà corrigé) est passée en `false_positive`, auto-basculée avec justification —
cf. invariant "Rattachement invalide" ci-dessous. Ses 10 sœurs réouvertes le 22/07 avaient déjà été
re-tranchées par le cycle. **Aucune vuln ouverte sur le parc** *(vrai jusqu'au 03/08, cf. ci-dessous)*.

⚠️ **Mise à jour 03/08/2026 (suite, l'après-midi)** : ce n'est plus le cas — un second exemple de
Correspondance Windows a été ajouté pour rendre la table démonstrative (l'unique entrée `putty→putty`
ne prouvait rien, pattern et produit identiques). `Wireshark 4.6.6 x64` (réellement installé sur
DEPLOYAPP, `installed_packages`) → produit CPE `wireshark`, vendeur `wireshark`. Le matching CPE
ciblé sur cet actif (`run_cpe_matching_for_asset`, purement base de données — aucune connexion
SSH/WinRM) a fait remonter **242 vulnérabilités réelles jusque-là invisibles** faute de correspondance
(240 HIGH, 1 CRITICAL, 1 MEDIUM). Total ouvertes : **264 847 → 265 089**. Comportement voulu, même
mécanique que `putty` (31/07, 24 CVE) — mais la CRITICAL nécessite une revue manuelle (jamais
d'auto-bascule, cf. règle de sévérité).

⚠️ **Suite immédiate, même jour** : l'utilisateur travaillait sur `CVE-2016-2563` (PuTTY, CRITICAL)
et a demandé pourquoi le patch check ne l'avait pas vue — PuTTY 0.81.0.0 est installé sur DEPLOYAPP,
largement au-dessus du seuil corrigé (`versionEndIncluding: 0.66`). Diagnostic : `check_patch_windows`
ne sait vérifier que l'**OS** (KB/build) — aucune branche ne comparait jamais la version d'une
application tierce (PuTTY, Wireshark...) matchée via `WindowsAppMapping` aux plages de version NVD,
alors que cette machinerie existe déjà côté Linux (`_extract_version_constraints`/`_version_patched`,
utilisées par `check_patch_linux`) et que `installed_packages[].version` est une donnée déjà en base
(ex. `"0.81.0.0"`, propre, séparée du nom affiché). Corrigé : `_check_windows_app_patch` (nouvelle
fonction, `services/patch_checker.py`), branchée en amont de `check_patch_windows` dans `check_patch`
— retourne `None` (repli sur le chemin OS/KB inchangé) si la CVE ne cible aucune application Windows
installée correspondue. 8 tests ajoutés à `test_patch_checker_guardrails.py` (142 au total, tous
verts), dont un qui reproduit exactement ce cas. Vérifié en conditions réelles via l'API (session
admin temporaire, supprimée après usage) : `CVE-2016-2563` → `patch_detected: true`, signalée sans
bascule (CRITICAL) ; rattrapage lancé sur les 241 autres CVE PuTTY/Wireshark HIGH/MEDIUM du même
actif → toutes basculées en `patched`. **Il ne reste que les 2 CRITICAL** (`CVE-2016-2563` PuTTY,
`CVE-2018-6836` Wireshark) en `open`, à valider manuellement. Total ouvertes retombé à **264 848**.

⚠️ **Précision demandée dans la foulée** : le premier jet ne disait que "patché"/"vulnérable" sans
préciser contre quelle plage NVD la version installée avait été comparée — insuffisant pour
qu'un analyste comprenne le verdict sans rouvrir NVD lui-même. Ajouté : `_format_version_range`
(rend une contrainte `versionStart/EndIncluding/Excluding` lisible, ex. `≤ 0.66`), champ structuré
`app_version_check` dans le résultat, et un bloc dédié dans la modale Patch Check
(`Vulnerabilities.jsx`, même gabarit visuel que le bloc `msft_build` existant) affichant
explicitement "Version installée X — plage vulnérable NVD pour `produit` : Y". 7 tests de plus
(149 au total). Vérifié en conditions réelles (Playwright) sur `CVE-2016-2563` : le bloc affiche
bien "Version installée 0.81.0.0 — plage vulnérable NVD pour `putty` : ≤ 0.66". Même bloc ajouté
dans la modale Patch Check du **Dashboard** (`Dashboard.jsx`, copie miroir de celle de
`Vulnerabilities.jsx`) — vérifié en conditions réelles, mêmes gabarit/texte.

✅ **Les CRITICAL restantes validées manuellement par l'utilisateur** (`CVE-2016-2563` PuTTY,
`CVE-2018-6836` Wireshark, DEPLOYAPP) — en parallèle de cette session, via l'info désormais précise
du patch check. **4 autres CRITICAL PuTTY découvertes par l'utilisateur** en repérant leur badge
"patch détecté" sur le Dashboard (`CVE-2017-6542`, `CVE-2019-9895`, `CVE-2019-9898`,
`CVE-2019-17067`) — mon rattrapage initial ne filtrait que sur `wireshark` dans le CPE, celles-ci
avaient été recontrôlées entre-temps par le cycle planifié sans être signalées. Toutes `patched`,
`validated_by = "Yanis Hortholary"`. **Plus aucune vuln ouverte sur ce lot PuTTY/Wireshark.**

**Recherche texte dans le filtre d'actifs** (`AssetDropdown.jsx`, partagé Dashboard/Rapports) : champ
de recherche en haut du menu déroulant, filtre la liste par nom en direct — plus la peine de
parcourir les 72 actifs un par un pour en cocher un. Réinitialisée à chaque réouverture.

**"Autres actifs concernés par cette CVE"** (demande explicite : retrouver ce qu'on a déjà fait sur
un autre serveur pour la même CVE, sans redemander les mêmes infos) :
- Backend : `GET /api/vulnerabilities/{id}/other-instances` — toutes les instances de la même CVE
  sur les autres actifs (statut, validateur, justification), résolues en premier. `GET
  /api/vulnerabilities` gagne `resolved_elsewhere_count` (une seule requête `GROUP BY` pour toute
  la page affichée, jamais une par ligne — même principe de performance que les endpoints
  "candidats") **et** `patched_elsewhere_count` (même requête, groupée en plus par statut) — permet
  au frontend de distinguer "corrigé ailleurs" du reste sans requête supplémentaire.
- Frontend : pastille en pointillés — même famille visuelle que "Correctif détecté ?"/"Faux positif
  ?" du Dashboard, **à côté de l'identifiant CVE** (pas un bouton séparé, renommage demandé
  explicitement après un premier jet "🔁 N ailleurs" jugé pas assez clair) : "✅ Correctif déjà
  appliqué sur N autre(s) actif(s)" quand au moins une instance est réellement `patched`, repli "🔁
  Déjà qualifié sur N autre(s) actif(s)" sinon (faux positif/risque accepté ailleurs, sans détail
  du compte exact par statut). Visible seulement si `resolved_elsewhere_count > 0`, détail chargé
  seulement au clic (`OtherInstancesModal.jsx`, réutilisé Vulnerabilities.jsx + Dashboard). Bouton
  "↩ Réutiliser cette justification" pré-remplit l'annotation de la ligne courante
  (`ValidateDropdown`/`AnnotationModal`, `key` dynamique pour forcer le remount avec le nouveau
  texte). Vérifié en conditions réelles sur `CVE-2020-1467` (DEPLOYAPP déjà patché → pastille "✅
  Correctif déjà appliqué sur 1 autre actif" sur les deux pages, justification reprise
  correctement).
- **Filtre dédié sur le Dashboard** (demande explicite, même jour) : case "✅ Correctif déjà
  appliqué ailleurs" à côté de "Patch détecté uniquement"/"Faux positifs proposés"
  (`dashFilter.onlyResolvedElsewhere`). Contrairement au filtre faux positif, pas de bug de plafond
  possible ici : `resolved_elsewhere_count` est déjà porté par chaque ligne de la liste "à traiter"
  déjà chargée (même réponse `fetchVulns`), pas une liste candidate séparée — filtre directement
  `assetScopedOpen`. Vérifié en conditions réelles : 55 correspondances sur le parc actuel.

**Criticité métier visible + filtrable sur le Dashboard, comme sur Actifs** (demande explicite,
même jour) :
- Backend : `_vuln_dict` (donc `GET /api/vulnerabilities` et les 3 endpoints "candidats") ajoute
  `asset.criticite` (`asset.tags.criticite`, même donnée que la page Actifs, jamais éditée ici).
  ⚠️ **Régression introduite puis corrigée dans la foulée** : les 3 endpoints "candidats"
  (`awaiting-fix`/`false-positive`/`critical-review`) chargent l'Asset avec `load_only(...,
  raiseload=True)` pour la performance (cf. `_CANDIDATE_LOAD_OPTIONS`) — `tags` n'y était pas inclus,
  d'où un 500 (`InvalidRequestError: 'Asset.tags' is not available due to raiseload=True`) détecté
  immédiatement au test navigateur. Corrigé en ajoutant `Asset.tags` à ce `load_only` (colonne JSON
  légère, coût négligeable).
- Frontend : badge `CriticiteBadge` (Haute/Moyenne/Faible, déjà utilisé sur Actifs) affiché à côté
  du nom de l'actif dans les 3 tableaux du Dashboard (à traiter/en attente/traitées). Nouveau
  sélecteur "Toutes criticités" dans la barre de filtres (Dashboard **et** Actifs, demande
  explicite des deux), filtre purement client comme la sévérité. Mapping des libellés extrait en
  constante partagée (`constants/criticite.js`) plutôt que dupliqué une deuxième fois — Assets.jsx
  avait déjà `CRITICITE_LABELS` en local, migré vers le fichier partagé. Vérifié en conditions
  réelles sur les deux pages (filtre "Haute" → badges rouges cohérents sur les lignes affichées).

⚠️ **Bug réel trouvé par l'utilisateur en cours de route, corrigé** : la case "🚫 Faux positifs
proposés" du Dashboard vidait entièrement le tableau "à traiter" au lieu d'afficher les 75
candidats. Cause : le filtre recoupait la liste **déjà tronquée** à 200 lignes (les mieux scorées)
avec l'ensemble des candidats faux positif — ces derniers étant souvent d'anciennes CVE mal
classées par score, l'intersection était vide (**0 sur 75**, vérifié en conditions réelles).
Corrigé : la case cochée bascule la source sur `fpCandidates` (déjà chargée en entier,
indépendamment du plafond) au lieu de filtrer la liste tronquée. Justification affichée en clair
sous chaque CVE (pas seulement au survol du badge, demande explicite pour trier plus vite) —
`fpReasonById`, déjà calculé, simplement rendu visible. ⚠️ **Endpoint lent constaté en direct**
(`GET /false-positive-candidates`, ~18s sur ce parc) — non traité ici, à garder en tête si le
Dashboard semble figé après avoir coché cette case.

Les anciennes catégories "16 SSU/DBX", "9 Windows sans KB", "5 Debian mixtes", `CVE-2013-3900` (session
du 21/07) restent traitées comme documenté dans `docs/HISTORIQUE.md` — non revues aujourd'hui, pas de
raison de penser qu'elles ont changé.

**Registre de veille (27/07/2026)** : 2179 éléments, la quasi-totalité non traités — le stock
s'accumule, c'est le principal chantier fonctionnel restant côté veille.
Le **profil de veille n'est plus vide** — correction d'une affirmation périmée (24/07) : il compte en
réalité **198 termes**, tous cochés (2 OS, 176 logiciels depuis l'inventaire dont VMware/Veeam/Zerto
ajoutés le 27/07, 4 firewall, 3 SaaS, 7 applications — Matériel/Constructeurs reste vide, aucun
constructeur physique connu). 55 éléments actuellement marqués ★ « concerne mon parc » sur 2179. Choix
délibéré de laisser les paquets Linux génériques (bash, curl, openssl...) cochés plutôt que les
décocher — une CVE sur un composant réellement installé reste pertinente même si l'article est
générique ; le ratio observé (55/2179, ~2,5%) montre que ça ne noie pas le signal en pratique.
8 rapports hebdomadaires archivés (S29/S30 × cve/veille/surveillance, dont le rapport CVE décliné par
actif).

## ⚙️ Invariants, pièges et impasses vérifiées

À lire avant de toucher au patch check, au matching ou aux statuts de vulnérabilité.

**Sommaire** (section longue, journal append-only dans l'ordre chronologique d'écriture — se
repérer avant de tout relire) :
- *Dashboard — bandeau "Analyse en cours"* (11/08/2026) : `pending` (backlog) ≠ `running` (cycle
  réellement actif) — ne pas réintroduire `data.pending > 0` comme signal d'activité côté frontend
- *Identité visuelle + delight Login/Bienvenue Boss* (11/08/2026) : tokens de marque centralisés
  (`--brand-grad`, `--font-mono`), `components/CbrMark.jsx`, animations scopées aux écrans rares
  (skill emil-design-eng § fréquence) — détail dans `docs/FRONTEND.md`
- *Tour complet fonctionnel/logique* (11/08/2026) : 9 points (colonne vulns ouvertes fausse sur
  Assets.jsx, injection CSV nom d'actif, erreurs avalées Administration, ack_by générique, badge MAJ
  figé, filtre Actifs Dashboard précoché par défaut, `/rescore` non paginé, relance de cycle patch
  check qui perdait son périmètre) — ne pas réintroduire `effectiveAssetIds` comme prop `selected` de
  `AssetDropdown` sur Dashboard.jsx (précoche tout par défaut, cf. détail plus haut)
- *Patch check & statuts* : ordre des signaux Windows, impasses SSU/DBX, garde-fous
  `apply_patch_result`, invariant SQL direct, pièges de matching, signal Debian, performance
  WinRM/SSH, audit de cohérence (22/07), rattachement invalide, quatre issues automatiques
  (patched/false_positive/awaiting_fix/awaiting_fix_partial), risque accepté, incident de
  migration du 27/07
- *Frontend/Dashboard* : convention des badges, trois flux de qualification groupée, bascules
  auto vues depuis le Dashboard
- *Rapports hebdomadaires* : règles de figeage, fenêtres reçus/traités
- *Veille* : regroupement à l'affichage
- *Sécurité* : déception DB, rôle applicatif `cbr_app`, TOFU SSH
- *Scan d'actifs* : criticité métier, durcissement CIS-like, limite commande WinRM, `net accounts`
- *Infra/Docker* : redémarrage sans effet de bord, Vite/WSL, images par service, limites mémoire
- *Schéma* : `ALTER TABLE` manuels appliqués
- *Sauvegarde* : pg_dump quotidien, rétention, procédure de restauration
- *Tests* : premiers tests automatisés, portée et limites
- *WithSecure* (28/07/2026) : intégration EDR/EPP en complément (pas en remplacement), API VM
  non souscrite, correctifs manquants CVE/CVSS Windows uniquement
- *Passage à l'échelle* (28/07/2026) : incident mémoire `patch_checker.py` sur ~265 000 vulns,
  correctif par pagination, droits WinRM non provisionnés sur tout le parc
- *Correspondance Windows* (31/07/2026) : `WindowsAppMapping`, cinq points de branchement dans
  `cpe_matcher.py`/`patch_checker.py`, DDL bloqué côté `cbr_app` sur une table neuve
- *Gestion de crise* (31/07/2026) : `Crisis`/`CrisisTimelineEntry`, escalade multi-incidents,
  cellule de crise, journal décisions/communications — module Incidents
- *Icônes Service + mini organigramme* (31/07/2026, même jour) : `Service.icon`, palette SVG
  curatée, `OrganizationRole.reports_to_id`, garde-fou anti-cycle, `ServiceOrgChartModal.jsx`
- *Rapport d'incident enrichi + stepper* (31/07/2026, même jour) : section « Escalade en crise » +
  « Plan d'action » dans `incident_report.py`, frise horizontale `Stepper.jsx` sur les fiches
  Incident/Crise
- *Droits d'accès par module (RBAC analyst)* (31/07/2026, même jour) : `User.allowed_pages`,
  `require_page` côté serveur, auto-liaison Utilisateur → Analystes, limite assumée sur
  assets/vulnerabilities (cross-référencés par trop de pages pour être gatés sans casser)
- *Module Audits* (03/08/2026) : construction complète (backend + frontend + intégrations),
  garde-fou d'autorisation bloquante, bug réel `useState` détecté par le test E2E, premier audit
  réel saisi (6 findings d'`audit/AUDIT_SECURITE.md`)
- *Tour applicatif complet + série de correctifs* (03/08/2026, même jour, l'après-midi) : port 8000,
  bugs Dashboard réels, injection CSV + suppressions admin-only, N+1, code mort, doublon
  `ConnectionLog`, retry `AnalystContext`, erreurs réseau silencieuses câblées, contraste mode clair,
  matching/rescore ciblés enfin branchés, **images `worker`/`beat` désynchronisées** (rapports
  hebdo `cve`/`surveillance` cassés en silence depuis le 28/07), plafond anti-OOM sur l'activité des
  rapports CVE
- *Reliquats traités + patch check applications Windows* (03/08/2026, même jour, encore plus tard) :
  tests crisis/audit_attachments/document_storage, déduplication timeline + CRUD Administration,
  "Scanner tout" Inventaire, vue carte mobile Vulnérabilités, second exemple Correspondance Windows
  (Wireshark) ; **puis** `_check_windows_app_patch` — comparaison de version pour les applications
  Windows tierces (PuTTY/Wireshark), absente jusqu'ici du patch checker (OS seulement), découverte
  via une question utilisateur sur CVE-2016-2563

**Détection de correctif — ordre des signaux Windows** (détail dans `docs/MATCHING.md`) :
KB installé → build vs plages NVD → build vs article KB Microsoft (`services/kb_build.py`) → repli par
date (indicatif seul). Le titre de l'article support.microsoft.com est la **seule** source trouvée
donnant un build pour les CVE anciennes : NVD, MSRC sug v2 (`affectedBinaries`), MSRC CVRF v3
(`AffectedFiles`) et le registre CBS ont tous été testés et sont vides ou purgés.

**Impasses vérifiées — ne pas réexplorer** :
- *SSU / Secure Boot DBX* : le registre CBS nomme les SSU par composant (`ServicingStack-Base~10.0.17763.1`),
  jamais par numéro de KB ; `Get-SecureBootUEFI -Name dbx` renvoie « Accès refusé » (privilèges élevés,
  contraires au compte lecture seule). Sans issue à droits constants — 16 vulns concernées.
- *Élever les droits du compte de service* : écarté, contraire au principe de non-intervention.
- *Windows Update disponibles côté WinRM (10/08/2026)* : `New-Object -ComObject Microsoft.Update.Session`
  (seule API lecture-seule d'énumération des mises à jour non installées, y compris via le module
  `PSWindowsUpdate` qui n'est qu'un wrapper dessus) échoue avec `UnauthorizedAccessException, 0x80070005`
  sous le compte de service WinRM read-only — testé en conditions réelles contre `deployapp.aer.loc`.
  Même famille de restriction que `Get-WmiObject`/`Get-SecureBootUEFI` ci-dessus (accès COM/WMI refusé
  à ce compte). Aucune alternative registre trouvée (contrairement à CPU/RAM/disques ailleurs dans ce
  fichier) : la seule autre source, `SoftwareDistribution\DataStore\DataStore.edb`, est une base ESE
  binaire propriétaire, pas un fichier exploitable en lecture simple. Élever les droits du compte
  écarté pour la même raison que ci-dessus. Conséquence : `available_updates_count` (cf. § Actifs —
  mises à jour disponibles indépendamment d'une CVE, 10/08/2026) reste structurellement à 0 sur tout
  actif Windows du parc — Linux uniquement (`apt list --upgradable`, déjà collecté depuis le 07/08).

**Invariants à ne pas casser** :
- `apply_patch_result` ne doit **jamais** écraser une décision humaine — mais sans bloquer non plus la
  progression légitime. Deux niveaux : états terminaux (`false_positive`/`patched`/`accepted_risk`)
  jamais touchés ; décision humaine sur `awaiting_fix` → seule la détection d'un correctif peut la
  faire évoluer vers `patched` (raison d'être du statut). Le cycle ne traite que
  open/in_progress/awaiting_fix, mais le bouton unitaire est cliquable partout — incident réel :
  statut *et* annotation d'analyste détruits ; puis, en corrigeant trop large, `awaiting_fix` figé
  pour toujours.
- **Ne pas modifier un statut de vuln en SQL direct** : `update_vulnerability` efface `last_patch_check`
  ET `patch_check_result` à la réouverture. Sans ça, `backfill_auto_patch` réapplique le verdict périmé
  au cycle suivant et re-bascule la ligne (28 lignes concernées lors de l'incident).
- `pending: 0` ne signifie pas « à jour avec la logique actuelle », seulement « contrôlé il y a moins de
  24h ». Après amélioration d'un signal, croiser `last_patch_check` avec l'heure du déploiement, ou
  utiliser le bouton ⟳ (`?force=true`).
- Trois issues automatiques, même règle de sévérité (CRITICAL toujours manuel) : `patched`
  (correctif détecté), `false_positive` (produit absent — *rien n'a été corrigé*), `awaiting_fix`
  (aucun correctif publié par la distro). Cf. `CLAUDE.md`.

**Correspondance nom d'application Windows → produit CPE — `WindowsAppMapping`** (31/07/2026) :
un nom d'application Windows est du texte libre de registre ("PuTTY release 0.81 (64-bit)",
"F-Secure Policy Manager 15.30 build 96312...") sans convention exploitable par regex, contrairement
aux paquets Debian/RPM (`_package_candidates`). Table réglable en base plutôt qu'un heuristique deviné
("premier mot" aurait donné "microsoft" pour "Microsoft Edge") : `pattern` (sous-chaîne, insensible à
la casse, survit aux changements de version/architecture) → `cpe_product`. CRUD réservé admin
(lecture ouverte), Administration > onglet « Correspondances Windows ». Vérifié en conditions
réelles : `PuTTY release 0.81 (64-bit)` sur `deployapp.aer.loc` résout bien vers le produit `putty`,
qui indexe 24 CVE en base (`CVE-2017-6542`, `CVE-2019-9894`...) — invisibles avant ce correctif.
⚠️ **Cinq points de branchement, pas un seul** — `_installed_package_products` (nouveau paramètre
`windows_mappings`, chargé une fois par cycle via `_load_windows_mappings(db)`, jamais par actif/par
ligne, mêmes raisons de performance que `product_index`) : `run_cpe_matching`, `run_cpe_matching_for_asset`,
`run_cpe_matching_for_cve`, `get_installed_package_vulnerabilities`, `asset_match_context`/`still_matches`/
`still_matches_ctx` (routers/vulnerabilities.py : `false-positive-candidates`, `bulk-false-positive`) et
`patch_checker.py::check_patch` (garde-fou « rattachement invalide » — sans lui, un vuln Windows créée
par ce nouveau mécanisme aurait été signalée à tort comme rattachement invalide au premier patch check).
⚠️ **Nouvelle table = DDL bloqué côté `cbr_app`** (reconfirmé en le vivant) : `create_all` au démarrage
tente `CREATE TABLE windows_app_mappings`, bloqué par `ddl_guard.sql` (`cbr_app` n'a pas de DDL) —
backend resté `unhealthy` jusqu'à la création manuelle de la table par le superuser `cybervuln`
(`docker compose exec db psql -U cybervuln ...`). `ALTER DEFAULT PRIVILEGES` (`app_role.sql`) accorde
alors automatiquement `cbr_app` en DML, sans `GRANT` manuel. Toute nouvelle table de modèle devra
repasser par cette étape avant déploiement (cf. invariant "Rôle applicatif" plus bas).

**Gestion de crise — `Crisis`/`CrisisTimelineEntry`** (31/07/2026, module Incidents, page
`/crises`) : comble le vide identifié par `ROADMAP_RNCP42335.md` (Bloc 1.5 « Gestion de crise
cyber ») — la Roadmap par catégorie (`IncidentRoadmap.jsx`) hébergeait déjà un plan d'action, mais
aucune structure d'escalade. Décisions déjà tranchées avec l'utilisateur avant de coder (cf.
plan approuvé) : cellule de crise + escalade (pas une simulation d'exercice pour l'instant), et une
crise peut regrouper **plusieurs** incidents (`Incident.crisis_id`, nullable, `ON DELETE SET NULL`
— supprimer la crise ne supprime jamais les incidents qu'elle regroupait). Activation = création
(toujours un acte humain, `activated_by` obligatoire) ; désactivation avec justification
obligatoire. `crisis_roles` en JSON sur `Crisis` (même pattern qu'`affected_asset_ids`, pas de
table de liaison pour un volume aussi faible). Aucun envoi réel de communication — même garde-fou
que le reste du module (tracé, jamais envoyé).

**v2, même session** — jugée trop légère par l'utilisateur (v1 : cellule de crise + journal
seulement), complétée par : **plan d'action** (`CRISIS_STEPS`, checklist générique sans
branchement catégorie, `Crisis.completed_crisis_steps`) ; **intervenants à prévenir**
(`CrisisContact`, natif `NATIVE_CRISIS_CONTACTS` + personnalisé en base — Direction, RSSI, DPO,
Communication/RP, Juridique, Assureur cyber, RH — distinct des contacts réglementaires
d'`Incident`) ; **lien bidirectionnel** — bouton « Escalader en crise » sur `IncidentDetailModal.jsx`
(nouvelle crise ou crise active existante), **sans nouvel endpoint backend** (composition de
`createCrisis`/`linkCrisisIncident`/`getIncident` déjà existants). Composants `ContactRow`/
`ScopeTag` exportés d'`IncidentRoadmap.jsx` et réutilisés tels quels par `CrisisRoadmap.jsx` — pas
de duplication.
⚠️ **Ordre de déclaration des routes** : `GET/POST /crises/contacts` et
`PATCH/DELETE /crises/contacts/{id}` déclarées **avant** `/{crisis_id}` dans `routers/crises.py`
(même piège qu'`incidents.py`/`notification-contacts` — sinon FastAPI matcherait "contacts" comme
un `crisis_id`).

Testé en conditions réelles via **l'API HTTP avec un compte de test temporaire + cookie de
session** (méthode plus fiable qu'un script Python direct qui contourne l'auth, cf. leçon tirée
juste avant dans cette même session — un script `docker exec` ne suit pas le même chemin qu'un
navigateur) : v1 — crise créée, incident réel rattaché (`crisis_id` posé), rôle assigné, décision
+ communication consignées, désactivation, suppression avec `crisis_id` revenu à `NULL` confirmé
(`ON DELETE SET NULL` vérifié en conditions réelles). v2 — intervenant custom ajouté, étape de
plan d'action cochée et persistée, **scénario d'escalade complet** : un incident réel escaladé vers
une nouvelle crise, un second incident (créé pour le test) escaladé vers cette **même crise
existante** — `crisis_title` confirmé identique sur les deux incidents. Toutes les données de test
nettoyées après coup (crises, contact, incident temporaire, comptes). `GET /api/crises(/contacts)`
sans cookie → 401 confirmé. Cf. `docs/INCIDENTS.md` § 5ter.

**Registre « Rôles » (organigramme) + correctifs mode Présentation** (31/07/2026, même session) :
`OrganizationRole` (poste → personne → email, ex. RSSI → Michel Lacroix), Administration > onglet
Rôles (juste après Analystes, même convention lecture ouverte/écriture admin), consommé par
`CrisisRoadmap.jsx` (remplace les placeholders génériques `NATIVE_CRISIS_CONTACTS` de la v1,
retirés) et une nouvelle sous-section « Postes internes à contacter » sur
`IncidentRoadmap.jsx`. Audit fait avant de coder : la déception (`deception_setup.sql`) n'avait
besoin d'aucune mise à jour pour les tables ajoutées cette session (couche fixe et générique,
`ddl_guard.sql` couvre déjà toute nouvelle table sans configuration) ; en revanche un vrai trou
existait côté mode Présentation — aucun composant Crise ni `IncidentFormModal.jsx`/
`IncidentRoadmap.jsx` (préexistant) ne consultait `usePresentation()`. Corrigé **une seule fois,
centralisé dans `AnalystContext.jsx`** (`names = isAnonymous ? FAKE_VALIDATORS : ...`) plutôt que
patché dropdown par dropdown : couvre d'un coup tous les dropdowns d'analyste, actuels et
futurs. Les 3 endroits qui le faisaient déjà en local (`Vulnerabilities.jsx`,
`ValidateDropdown.jsx`, `AnnotationModal.jsx`) simplifiés (ternaire devenu redondant).
`utils/fakeData.js::anonymizeRoleHolder` pour le nouveau registre (noms réels → pool dédié de
noms complets, distinct de `FAKE_VALIDATORS` qui sont des initiales abrégées ; poste jamais
modifié, pas sensible). Testé via l'API HTTP réelle (compte analyst + compte admin) : lecture 200
en tant qu'analyst, écriture 403 en tant qu'analyst, écriture 201 en tant qu'admin — conforme.
⚠️ **Limite assumée** : la bascule `isAnonymous` elle-même n'a pas pu être vérifiée en conditions
réelles (pas de navigateur disponible dans cette session) — relecture de code + bundle-check
uniquement, même limite que l'Error Boundary React (27/07/2026).

**Registre « Rôles » v2 — Services** (31/07/2026, même session) : nouveau modèle `Service`
(RH/DSI/Juridique/Direction en seed, liste ouverte, code couleur — Administration > onglet
Services, juste avant Rôles) ; `OrganizationRole.service_id` (nullable, `ON DELETE SET NULL` —
supprimer un service détache ses postes sans les supprimer) rattache un poste à un service.
`routers/organization_roles.py` résout `service_name`/`service_color` à la lecture (même pattern
que `crisis_title` sur les incidents). Grille de cartes (Administration > Rôles) colorée par
service si renseigné, sinon repli sur un hash du poste (comportement v1 inchangé pour les postes
non rattachés). Postes suggérés complétés : DG, DAF, DRH, DSI, RSSI, REI, DPO, Communication/RP,
Juridique, RH, Assureur cyber — toujours du texte libre, rien n'est bloqué. Testé via l'API HTTP
réelle (compte admin) : les 4 services seedés confirmés présents, poste créé rattaché à un
service (résolution service_name/service_color vérifiée), détachement (`clear_service`)
vérifié — tout nettoyé après coup.

**Nouveau module Documentation** (31/07/2026, même session) — gouvernance NIS 2 : `DocumentType`
(registre ouvert, seed PSSI/Charte Administrateur/Charte Utilisateur/Organigramme, spécifique à ce
module, pas géré dans Administration contrairement à Rôles/Services qui sont consommés par
plusieurs modules) + `Document` (fichier uploadé, `services/document_storage.py` — validation
signature de fichier par format : PDF `%PDF-`, docx/xlsx `PK\x03\x04` (ZIP OOXML), doc/xls
`\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1` (OLE2 legacy) — 10 Mo max, même esprit qu'`incident_attachments.py`
étendu à plusieurs formats). **Pas de table de versions séparée** : chaque upload crée une nouvelle
ligne du même `document_type_id`, triée par `uploaded_at desc` à la lecture — la liste EST
l'historique, la plus récente est la version courante. `Document.document_type_id` sans `ondelete`
(défaut Postgres `NO ACTION`) : supprimer un type encore utilisé est bloqué au niveau DB,
intercepté en 409 côté API plutôt que de laisser remonter une erreur SQL brute. Nouveau volume
Docker `documents`, monté `rw` sur `backend` uniquement (comme `incident_attachments`).
Testé via l'API HTTP réelle (compte admin + compte analyst) : upload refusé pour un non-admin
(403), fichier falsifié rejeté (signature invalide, 400), PDF réel accepté (201), 2e version
uploadée et confirmée en tête de l'historique, téléchargement vérifié (contenu identique),
suppression d'un type encore utilisé refusée (409) — tout nettoyé après coup.
⚠️ **Correction en passant** : `CLAUDE.md` inversait les couleurs Incidents/Inventaire par
rapport au code réel (`constants/modules.js` : `inventaire` = `#39c5cf` cyan, `incidents` =
`#b5793a` marron) — repéré en construisant ce module (choix d'une couleur encore inutilisée
pour Documentation), corrigé dans la même passe.

**Documentation v2 — formats image + prévisualisation + glisser-déposer** (31/07/2026, même
session) : `document_storage.py` accepte désormais aussi PNG/JPEG (signature `\x89PNG\r\n\x1a\n`
et `\xff\xd8\xff` — un organigramme est souvent une image). **Prévisualisation navigateur** :
`Content-Disposition` choisi par format (`inline` pour PDF/PNG/JPEG que le navigateur affiche
nativement, `attachment` pour Word/Excel) — vérifié en conditions réelles (en-têtes HTTP
inspectés directement, pas seulement en théorie) : PNG et PDF renvoient bien `inline` +
`Content-Type` correct. ⚠️ **Limite technique assumée, communiquée à l'utilisateur avant de
coder** : aucune API web ne peut faire ouvrir un fichier par l'application native (Word/Excel)
depuis une page — ça demanderait une intégration WOPI/Office Online, hors de portée. Word/Excel
restent en téléchargement forcé, ouverts ensuite par l'OS via l'appli associée. `DocumentPreviewModal.jsx`
distingue les deux cas (iframe/img vs message + bouton télécharger). **Glisser-déposer** : dans
la modale d'upload (`UploadDocumentModal.jsx`) et directement sur la carte d'un type
(`Documentation.jsx`, admin) — dans ce dernier cas, ouvre la modale déjà pré-remplie avec le
fichier déposé (`initialFile`), l'analyste et les notes restent à confirmer explicitement (pas
d'upload silencieux sans attribution). Testé via l'API HTTP réelle (compte admin) : PNG falsifié
rejeté (400), PNG réel accepté (201), PDF réel accepté avec `inline` confirmé — tout nettoyé
après coup (⚠️ 3 documents réels restaient en base au moment du nettoyage — uploadés par
l'utilisateur en parallèle pendant la session, non touchés, cf. méthode déjà établie : ne jamais
confondre données réelles et artefacts de test sur un simple écart de nombre).

**Polish visuel Home/Login** (31/07/2026, même session, purement frontend — aucun modèle/endpoint
touché) :
- **`Home.jsx`** : en-tête remonté en haut de page (`justify-start pt-14/20` au lieu de
  `justify-center`) avec plus d'espace avant la grille de tuiles (`mb-10/14`, `gap-4`) — halo
  décoratif suivant via une classe dédiée `.home-glow--high` (ne pas réutiliser `.home-glow` seul
  pour Home : Login/WelcomeOverlay restent centrés verticalement, un changement du `top` de base
  les aurait désalignés — piège déjà rencontré et corrigé en cours de session).
- **`WelcomeOverlay.jsx`** (nouveau composant) : écran de bienvenue affiché une fois après
  connexion, **réservé au compte admin** (`Home.jsx` : `location.state?.justLoggedIn` posé par
  `Login.jsx` à la navigation + `user?.role === 'admin'`, jamais rejoué au rechargement — le state
  de navigation est effacé juste après lecture). Contient un **récap réel** (pas décoratif) :
  bascules automatiques depuis la dernière visite (réutilise `last_seen_auto_bascule` du
  `localStorage`, lu **jamais réécrit** — `Dashboard.jsx` reste seul propriétaire du repère),
  alertes de sécurité non acquittées, échéances NIS 2 — mêmes sources que la cloche 🔔/les badges
  sidebar, pas un nouveau système. Se dissipe au clic (bouton ou fond), filet de sécurité 9s.
  **Chorégraphie de transition** : l'en-tête/les tuiles de `Home.jsx` ne se montent qu'au moment où
  l'écran de bienvenue COMMENCE à se retirer (`onExitStart`, avant `onDone`) — sans ça, la Home
  était déjà figée/statique sous l'écran de bienvenue et sa disparition ne faisait que révéler une
  page immobile plutôt qu'une vraie animation d'arrivée.
- **`Login.jsx`** : essai d'anneaux de pulsation autour du logo **rejeté par l'utilisateur**
  ("Bof") — retiré, ne pas réintroduire. Version retenue : cadre gris (fond/bordure) retiré
  entièrement autour des champs (posés directement sur le fond de page) ; séquence volontairement
  lente (~1,85s, durations/delays inline sur les classes déjà existantes `home-enter`/`home-logo`
  plutôt que de nouvelles animations) — logo → "CBR" (sous-titre "Connexion" retiré sur demande
  explicite), pause marquée, puis Email → Mot de passe → bouton un par un. Occasion rare (une fois
  par session) : se permet d'être plus lente que les animations "fréquentes" de Home/tuiles
  (cf. emil-design-eng § fréquence) — ne pas copier cette lenteur ailleurs dans l'app sans la même
  justification de rareté.
- **Limite non contournable, à ne pas retenter** : aucune API web ne peut faire ouvrir un fichier
  par son application native (Word/Excel) depuis une page — nécessiterait une intégration
  WOPI/Office Online, hors de portée. Concerne le module Documentation (§ ci-dessus) mais vaut pour
  toute future demande similaire.
- ⚠️ **Bug repéré après coup** : `MODULES.incidents.paths` (`constants/modules.js`) ne listait
  que `/incidents`, oubliant `/crises` ajouté plus tôt dans la session — `PageLoader.jsx`
  (`moduleColorForPath`) retombait donc sur la couleur par défaut (bleu CyberVeille) au lieu du
  marron Incidents sur la page Gestion de crise. Corrigé (`paths: ['/incidents', '/crises']`).
  **Leçon** : toute nouvelle route ajoutée à un module existant doit être ajoutée à son
  `paths` dans `constants/modules.js`, pas seulement à `NAV_GROUPS`/`HOME_MODULES` — sinon
  seule la couleur de nav reste correcte (posée explicitement par groupe), mais tout ce qui
  dérive la couleur depuis l'URL (`PageLoader`) se trompe silencieusement.

**Icônes Service + mini organigramme par service** (31/07/2026, même jour, suite de la session
ci-dessus — demandes utilisateur successives) : `Service.icon` (clé d'une palette fixe de 10 SVG
curatés — `briefcase`/`users`/`building`/`scale`/`server`/`shield`/`euro`/`headset`/`globe`/
`wrench`, `components/ServiceIcon.jsx::SERVICE_ICON_KEYS`) plutôt qu'un champ libre ou de l'emoji
(rejeté par l'utilisateur pour rester cohérent avec le style SVG épuré déjà utilisé partout) —
affichée sur les pastilles Services et sur l'avatar des cartes Rôles (remplace les initiales quand
un service est rattaché). `OrganizationRole.reports_to_id` (auto-référence, `ON DELETE SET NULL`,
même logique que `service_id`) : chaque poste peut désigner son supérieur direct, garde-fou
anti-cycle côté API (`_validate_reports_to`, remonte la chaîne des supérieurs proposés, profondeur
bornée à 200 par sécurité). `ServiceOrgChartModal.jsx` : mini organigramme (boîtes + traits CSS,
pas de librairie) ouvert depuis une carte Service — un poste dont le supérieur est dans un AUTRE
service (ou n'en a pas) devient racine dans cette vue-là, elle ne montre que la hiérarchie interne
au service. Onglet Services transformé de pastilles en cartes listant directement les postes
rattachés (+ bouton « Voir l'organigramme »).
⚠️ **Incident de migration en cours de session** : colonne `icon` ajoutée au modèle `Service` sans
rejouer `schema_patches.sql` contre la base réelle avant redémarrage — le backend plantait en
silence sur toute requête touchant `services`/`organization_roles` (colonne inexistante), le
frontend avalait l'erreur (`.catch(() => setSvcs([]))`) et affichait une liste vide : l'utilisateur
a cru avoir perdu les services/postes qu'il venait de saisir (RSSI, REI, service « Achat »...).
Rien n'était perdu — juste inaccessible tant que la colonne n'existait pas côté DB. Vérifié après
coup par `SELECT` direct : toutes les données réelles intactes. **Leçon reconfirmée** (déjà notée
pour `WindowsAppMapping` le même jour, § ci-dessus, mais retombée dedans quand même dans la même
session) : toute nouvelle colonne/table de modèle doit être suivie **immédiatement** par
`docker compose exec -T db psql -U cybervuln -d cybervuln < backend/db/schema_patches.sql`, pas
juste ajoutée au fichier.

**Scénario de test incident → crise complet, créé via l'API réelle** (31/07/2026, même jour,
demande explicite de l'utilisateur pour valider le flux de bout en bout) — session admin créée
directement en base (token + hash SHA-256 insérés dans `sessions`, pas besoin du mot de passe de
l'utilisateur), supprimée après usage. Incident *« Ransomware — chiffrement partiel sur
gitlab.aer.loc »* (critique, actif réel touché) qualifié NIS 2 avec justification, alerte précoce
marquée envoyée, 2 étapes du plan d'action cochées, statut passé « En cours » ; escaladé vers une
nouvelle crise *« Crise ransomware — gitlab.aer.loc »* avec cellule de crise assignée aux **vrais
noms** du registre Rôles créé la même session (RSSI = Nicolas Szebesta, Direction = Eric Hentges,
Communication = Véronique Porcher), 2 décisions + 2 communications tracées, 4 étapes du plan
d'action de crise cochées. ⚠️ **Contrairement aux scénarios de test des sessions précédentes, ces
données N'ONT PAS été nettoyées après coup** — l'incident et la crise sont **toujours réels en
base** au moment d'écrire ceci (l'utilisateur a enchaîné sur d'autres demandes sans redemander leur
suppression). **Ne pas les confondre avec un vrai incident/crise en cours** — à supprimer via
l'app (Incidents > cet incident > Supprimer, cascade la timeline ; `/crises` > cette crise >
Supprimer, détache l'incident sans le supprimer) si un usage réel du parc en a besoin.

**Rapport d'incident enrichi — deux sections manquantes repérées par l'utilisateur** (31/07/2026,
même jour, en relisant le rapport généré pour le scénario de test ci-dessus) :
`services/incident_report.py::build_incident_report` ignorait totalement l'escalade en crise et le
plan d'action coché. Ajouté : **« Escalade en crise »** (titre/statut/activation/désactivation/
cellule/journal de la crise liée, requiert `incident.crisis_id`) et **« Plan d'action »**
(`RESPONSE_STEPS`, dupliqué en Python depuis `frontend/src/constants/incidentPlaybooks.js` — même
limite de synchronisation manuelle que les `*_LABELS` déjà dupliqués dans ce fichier — avec qui/
quand par étape cochée). Vérifié en conditions réelles sur l'incident de test ci-dessus : les deux
sections apparaissent correctement dans le markdown généré.

**Frise horizontale sur les fiches Incident/Crise — `Stepper.jsx`** (31/07/2026, même jour,
demande explicite après discussion sur l'opportunité d'un nouvel onglet « timeline » — jugé
redondant avec le journal détaillé déjà présent, une frise compacte en haut de fiche retenue à la
place) : composant générique réutilisable (`done`/`current`/`overdue`/`pending`/`skipped`), un seul
jalon NIS 2 non envoyé marqué actif/en retard à la fois (les suivants restent neutres même si leur
propre échéance est dépassée — l'attention doit porter sur le plus urgent). Incident : Déclaré →
Qualifié NIS 2 (ou « Non requise », branche sautée si non qualifié) → Alerte précoce → Notification
→ Rapport final → Clôturé. Crise : Activée → Cellule constituée → Incident(s) rattaché(s) →
Désactivée (reste `pending` tant que la crise est active — étape terminale, pas « en cours »).

**Droits d'accès par module pour les comptes `analyst`** (31/07/2026, même jour, demande
utilisateur : auto-liaison Utilisateur ↔ Analystes + restriction de modules/pages par compte) —
chantier le plus lourd de la journée :
- **Auto-liaison** : créer un compte (Administration > Utilisateurs) crée automatiquement une
  entrée du même nom dans le registre Analystes si elle n'existe pas déjà (`_ensure_analyst`,
  best-effort, silencieux si le nom existe). Les deux registres restent des tables séparées (pas de
  fusion, décision déjà actée le 30/07) — juste un raccourci de saisie à la création. Pas de
  synchronisation au renommage/à la suppression (scope volontairement limité à la création).
- **`User.allowed_pages`** (JSON nullable) : `NULL` = accès total (défaut à la création, choisi
  explicitement par l'utilisateur) ; une liste de clés de page = restriction. `role == "admin"`
  ignore toujours ce champ.
- **Contrôle réel côté serveur, pas cosmétique** : `auth_deps.py::require_page(*page_keys)` posé
  sur les routers dans `main.py`, sur le même principe que `require_admin` déjà en place. Choix
  explicite de l'utilisateur en amont (deux questions posées avant de coder) : granularité
  module+sous-module (pas juste module entier) et accès total par défaut. ⚠️ **Limite assumée et
  documentée dans le code** (commentaire dans `main.py`) : `assets.router`/`vulnerabilities.router`
  restent en accès libre à tout compte connecté — lus en cross-référence par de nombreuses autres
  pages (Dashboard, Incidents, Reports, Watch appellent tous `GET /api/assets` pour des noms
  d'actifs), les gater casserait ces pages pour un analyste sans accès à Inventaire/CyberVuln. Un
  découpage lecture-référence vs page-propriétaire endpoint par endpoint resterait à faire pour ce
  niveau de granularité. `watch.router` (partagé /veille + /fuite-de-données) et `incidents.router`/
  `crises.router` (partagés entre plusieurs pages) gatés en OR (accès si au moins une des pages du
  groupe est autorisée).
- **Frontend** : nav (sidebar) et tuiles d'accueil filtrées (`utils/pageAccess.js::canAccessPage`,
  partagé), navigation directe vers une page interdite bloquée et redirigée (`ProtectedRoute
  page="..."`). `/settings` volontairement **jamais restreignable** (thème, déconnexion,
  changement de mot de passe forcé) — sinon un analyste restreint pourrait se retrouver bloqué
  hors de l'app.
- **`UserFormModal.jsx`** : case « Accès à tout » + arborescence Module > pages à cocher
  (`constants/modulePages.js::MODULE_PAGE_TREE`, dupliqué depuis `Layout.jsx::NAV_GROUPS`) quand le
  rôle est Analyste.
- **Trou fermé en cours de route, sans rapport direct avec cette demande** : la ligne
  « Administration » (section Sécurité de `Settings.jsx`) s'affichait à **tout** compte connecté,
  même un simple analyste — la description « Connexions IP, base de données, comptes et
  analystes » restait visible même si cliquer dessus renvoyait déjà à l'accueil (`ProtectedRoute
  role="admin"` sur la route). Masquée pour tout compte non-admin.
- **Testé en conditions réelles** (même méthode que la Gestion de crise le matin même — API HTTP
  avec un compte de test temporaire, pas un script qui contourne l'auth) : compte analyste restreint
  à Incidents+Crises créé, auto-liaison Analystes confirmée en base, login réel, `GET /incidents`
  et `/crises` → 200, `GET /documents` et `/cves` → 403 (« Accès à ce module non autorisé pour
  votre compte »), `GET /assets` → 200 (limite assumée ci-dessus confirmée en pratique), `GET
  /users` → 403 (admin only, inchangé). Compte de test supprimé après coup, entrée Analystes
  associée aussi.

**Module Audits — construction complète** (03/08/2026, cf. `docs/AUDITS.md`, chantier prioritaire
`ROADMAP_RNCP42335.md` Bloc 3) : backend + frontend + intégrations en une session, sur le modèle des
grosses sessions précédentes (Incidents, 31/07). Suit fidèlement la spec déjà écrite le 30/07/2026 —
aucun écart de conception.
- **Backend** : 5 tables (`audits`, `audit_assets`, `audit_findings`, `audit_finding_history`,
  `audit_attachments`), `routers/audits.py` (CRUD, `POST /authorize` avec garde-fou d'immuabilité,
  liaison actifs, findings avec garde-fou « aucun finding avant autorisation », retest, historique,
  pièces jointes mandat/preuves, rapport, compteur Dashboard), `services/audit_attachments.py`
  (PDF/PNG/JPEG, calqué sur `document_storage.py`), `services/audit_finding_history.py` (même
  pattern que `vuln_history.py`, pas `incident_timeline.py` — décision déjà actée dans la spec de ne
  pas fusionner les 3 formes de journal), `services/audit_report.py` (markdown à la demande, calqué
  sur `incident_report.py`). `Incident.audit_finding_id` ajouté (FK optionnelle `SET NULL`, même
  pattern que `vulnerability_id`/`watch_item_id`) + branche `source_type="audit_finding"` dans
  `prefill_incident` (mapping sévérité CRITICAL/HIGH→critical, MEDIUM→major, LOW/INFO→minor).
  Nouveau volume Docker `audit_attachments` (rw, backend uniquement).
- **Frontend** : `Audits.jsx` (liste, remplace le placeholder) + `AuditFormModal.jsx` ; nouvelle page
  `AuditDetail.jsx` (route `/audits/:id`) avec bloc cadrage/autorisation verrouillable, actifs
  ciblés, tableau findings, synthèse exécutive, rapport (`ReportMarkdown.jsx` réutilisé tel quel) ;
  `AuditFindingModal.jsx` (tous les champs, pièces jointes preuve, retest inline). `SeverityBadge.jsx`
  étendu avec `INFO` (bleu). Intégrations : compteur « findings ouverts non retestés » sur Dashboard
  (`AuditFindingsCard`, isolé du reste du composant — trop couplé pour y toucher, cf. invariant
  KpiCard), section « Findings d'audit » dans `ScanResultModal` (Assets.jsx, fiche actif), bouton
  `DeclareIncidentButton` sur chaque finding.
- ⚠️ **Bug réel détecté par le test navigateur, pas juste au code review** : `AuditDetail.jsx`
  initialisait `useState(null)` pour `findingModal` au lieu de `useState(false)` — la modale
  « Nouveau finding » s'ouvrait donc **au chargement de la page**, avant même toute autorisation
  (le commentaire à côté disait pourtant `false=fermé, null=création`). Invisible en relecture de
  code seule, sauté aux yeux dès la première capture d'écran du parcours E2E. Corrigé, revérifié.
- **Méthode de test navigateur** : `chromium-cli` non disponible dans cet environnement ;
  contournement via un conteneur `mcr.microsoft.com/playwright:v1.62.0-jammy` (déjà en cache local)
  monté sur `--network host`, driver Playwright Node écrit à la volée. Parcours complet vérifié par
  captures d'écran : liste → création → garde-fou d'autorisation (bouton « Ajouter un finding »
  désactivé, confirmé programmatiquement) → autorisation → déblocage → création de finding → rapport
  → suppression. Un run a laissé un audit de test orphelin (script interrompu avant le nettoyage
  scripté) faute d'avoir géré l'échec du premier essai — repéré et supprimé à la main après coup.
- **Premier jeu de données — audit réel, pas un scénario de test nettoyé** (§9 de la spec) : « Audit
  de code — Application CBR », autorisé par Nicolas Szebesta (RSSI, registre Rôles) via un **mandat
  PDF de régularisation rétroactive** généré et soumis à relecture avant d'être joint (l'audit
  `audit/AUDIT_SECURITE.md` avait été conduit le 24/07/2026, avant que le garde-fou d'autorisation
  n'existe). Les 6 findings originaux saisis avec leur statut réel : 5 corrigés et retestés
  (27/07/2026) — SSRF veille (HIGH), SSH TOFU (MEDIUM), LDAP clair (MEDIUM), XML non durci (MEDIUM),
  secrets `changeme` (LOW) — et 1 resté `ouvert` (absence de `.gitignore`, toujours vrai). Audit
  passé en statut `termine` ; le compteur Dashboard confirme 1 finding ouvert non retesté. Ces
  données restent en base, contrairement aux scénarios de test.
- **Tests** : `backend/tests/test_audits_guardrails.py` — refus de finding sur audit `cadrage`,
  immuabilité de l'autorisation (2e appel → 409), rejet d'un scope vide, mapping de sévérité du
  prefill incident. Suite complète du projet toujours verte après ajout (78 tests).

⚠️ **Effet de bord observé pendant les tests, sans rapport avec le code de la crise** :
`AnalystContext.jsx` charge la liste des analystes **une seule fois** au montage de l'app, sans
retry. Un redémarrage backend (`--force-recreate`, nécessaire à chaque nouveau modèle/table)
pendant qu'un onglet est ouvert casse cet unique fetch (`ECONNREFUSED`, IP interne du conteneur
recréée) et **aucun dropdown d'analyste ne se repeuple** avant un rechargement complet de page.
Constaté deux fois cette session (logs Vite `http proxy error: /api/analysts` synchrones avec mes
`docker compose up -d --force-recreate backend`). **Corrigé le 03/08/2026 l'après-midi** (retry au
focus fenêtre, cf. paragraphe dédié ci-dessous) — pour tout redémarrage backend antérieur à cette
date, un rechargement de page complet restait le seul recours.

**Pièges de matching corrigés** : CPE dégénéré `-:-:-` (sans vendeur ni produit) matchait tout le parc ;
`target_sw` applicatif (jenkins, kubernetes…) désigne un plugin, pas un paquet système — mais
`windows`/`macos`/`unix` sont des OS et ne doivent pas déclencher l'exclusion. Détail dans
`docs/MATCHING.md` § Bugs de matching corrigés.

**Signal Debian** : le Security Tracker référence toute CVE touchant un paquet Debian, y compris
« non affecté ». Absence complète = aucun paquet concerné. Garde-fous : ne rien conclure si le tracker
est injoignable, et exclure les CVE de moins de 30 jours (`TRACKER_LAG_DAYS`).

**Performance** : le relevé WinRM/SSH est identique pour toutes les CVE d'un même actif — un seul par
actif et par cycle (`_fetch_windows_patch_snapshot` / `_fetch_linux_package_snapshot`). Le rejouer par
CVE bloquait complètement le cycle. Cache KB→build permanent en base contre le rate-limiting Microsoft
(réponse « Service unavailable » ; un échec réseau ne doit jamais être mis en cache).

**Redémarrer le backend sans toucher aux données** : `STARTUP_MATCHING=false` et
`STARTUP_PATCH_CHECK=false` dans `.env`. ⚠️ **`docker compose restart` ne recharge pas `env_file`** —
il faut `docker compose up -d --force-recreate backend` pour qu'une variable modifiée soit prise en
compte (vérifiable par `docker compose exec backend printenv | grep STARTUP`). Par défaut à `true`, un `docker compose restart backend`
lance une corrélation CVE **et** un cycle de patch check — ce qui crée des vulnérabilités et bascule
des statuts. Constaté le 21/07/2026 : un redémarrage technique a créé 72 lignes et basculé 41 en
`patched`, rendant les écarts de chiffres illisibles pour l'utilisateur. Les deux tâches restent
déclenchables à la main (`POST /api/sync/match`, `POST /api/patch-check/run`).

**Environnement** : le rechargement à chaud Vite est **peu fiable sur ce montage WSL** — après
modification du frontend, `docker compose restart frontend`. Côté backend, si le conteneur se bloque sur
« Waiting for application startup » après plusieurs redémarrages rapprochés, `docker compose up -d
--force-recreate backend` (un `restart` ne suffit pas).

**Convention visuelle des badges** (tableaux du Dashboard) : **contour pointillé + « ? »** = une
proposition du système sur une ligne encore ouverte, en attente de validation ("Correctif détecté ?",
"Faux positif ?") ; **badge plein** = décision actée ("Patched", "Faux positif" dans "traitées"). La
distinction a dû être introduite deux fois le 21/07/2026, après que l'utilisateur ait chaque fois cru
à tort que des lignes étaient déjà clôturées. Ne pas réintroduire de badge plein sur une ligne `open`.

**Méthode** : la base bouge pendant les sessions (l'utilisateur travaille dans l'app en parallèle) — ne
pas conclure à une régression sur un simple écart d'état, vérifier `validated_by` et l'horodatage.
Et vérifier *comment* une vuln a matché avant de la qualifier de faux positif : un comptage par motif
textuel a produit des catégories fausses (les messages KB Windows contiennent « non trouvé » comme les
messages de paquet Linux).

**Audit de cohérence (22/07/2026)** — une annotation d'analyste peut être factuellement fausse sans
que rien ne le signale techniquement (statut cohérent, note non vide, analyste renseigné). Repéré en
croisant le texte des notes `false_positive` ("produit absent") avec `asset.installed_packages` : 7
CVE sur `gitlab.aer.loc` fermées "produit absent" alors que le paquet visé (gzip/libexpat1/libssh2-1/
openssl) était bien installé — probablement une note générique copiée-collée sur le mauvais lot
pendant un traitement rapide. **Ne jamais faire confiance à une justification texte sans la
recouper avec les données structurées déjà en base** quand on audite une session. Les 11 lignes
suspectes (celles-ci + 3 IEEE P1735 mal qualifiées) ont été réouvertes via l'API (jamais en SQL direct,
cf. invariant `update_vulnerability` ci-dessus) pour laisser le cycle autonome re-trancher — une
d'entre elles a d'ailleurs été re-résolue automatiquement en `false_positive` (avec la bonne
justification, tracker Debian) dans l'heure suivant la réouverture, preuve que le mécanisme
fonctionne correctement une fois la donnée corrigée.

**Rattachement invalide, désormais vérifié dans `check_patch()` lui-même** (22/07/2026) —
`still_matches(asset, cve)` (déjà utilisée par `false-positive-candidates`) est appelée en tête de
`check_patch()`, avant tout signal Windows/Linux. Avant ce correctif, un rattachement déjà identifié
comme artefact de matching retombait dans les branches normales, qui répondaient un générique
« Vérification manuelle requise » sans jamais dire que le rattachement lui-même était en cause —
signalé par l'utilisateur sur `CVE-2017-13091`/DEPLOYAPP (« je n'ai pas d'infos sur pourquoi ce
serait un faux positif »). Deux bouts de code calculaient chacun une partie de la vérité sans se
croiser. `not_applicable: true` alimente maintenant `apply_patch_result` comme "produit absent" —
même règle de sévérité. Détail : `docs/MATCHING.md` § Validité du rattachement.


**Trois flux de qualification groupée**, tous sur `BulkQualifyModal.jsx` (généralisé le 21/07/2026) :
correctif détecté (CRITICAL), faux positif, en attente de correctif. Même principe : le système
propose des candidats sur critères objectifs, l'analyste confirme avec analyste **et** annotation
obligatoires. Ajouter un 4e flux = un endpoint `*-candidates` + un `bulk-*` + des props, pas un
nouveau composant.

**Rapports hebdomadaires figés** (22/07/2026, détail dans `docs/ARCHITECTURE.md`) — quatre règles à ne
pas casser :
- Un rapport porte sur une **semaine ISO close** (`datetime.fromisocalendar`, `iso_year` stocké : le
  2029-12-31 appartient à la semaine 1 de 2030). La fenêtre d'activité est bornée **des deux côtés** —
  sans borne droite, un rapport S30 régénéré en S32 inclurait tout ce qui s'est passé depuis.
- **Le gel a une exception** : un rapport dont `generated_at < period_end` a été produit en cours de
  semaine, donc tronqué — il est régénéré automatiquement jusqu'à ce que la semaine soit close, puis
  devient définitif (seul `force=true` réécrit). Sans cette règle, un rapport généré manuellement un
  mercredi resterait partiel pour toujours, la tâche du lundi le sautant.
- **Générer à temps, pas à la demande** : rouvrir une vuln efface sa date de clôture, elle
  disparaîtrait d'un rapport reconstruit après coup. D'où un rapport par actif généré chaque semaine
  (0,25 s/rapport) plutôt qu'au clic.
- **Tous les rapports ne se déclinent pas par actif** (`ASSET_SCOPED_KINDS = ("cve",)`) : veille et
  surveillance ne sont pas rattachées au parc.

**Deux fenêtres à ne jamais confondre dans le rapport de veille** : « reçus » (`received_at`) = volume
à traiter, « traités » (`reviewed_at`) = travail fait, qui porte souvent sur des semaines antérieures.
Les confondre fausse le taux de traitement. Et dans le rapport de surveillance, **le volet IP n'est pas
rétroactif** : les listes de blocage publiques ne donnent que leur état courant.

**`ALTER TABLE` manuels appliqués le 22/07/2026** (pas de système de migration — `create_all` ne
modifie jamais une table existante). À rejouer sur toute base antérieure, SQL exact dans
`docs/ARCHITECTURE.md` :
- `reports` : colonnes `asset_id`/`asset_label` + index unique avec `COALESCE` (deux `NULL` étant
  distincts en SQL, un UNIQUE simple n'empêcherait pas d'empiler des rapports globaux) ;
- `watch_items` : colonne `asset_ids`.

**Regroupement veille — affichage seulement, jamais en base** (24/07/2026) : la même actu republiée
par plusieurs sources (avis CERT-FR repris par Global Security Mag) ou à deux URLs sur une même source
a des titres identiques mais des URLs différentes → le dédoublonnage à l'insertion (URL exacte) ne la
voit pas. `routers/watch.py` regroupe **à l'affichage** par titre normalisé (`_group_rows_by_title`/
`_group_dict`, param `group_duplicates` défaut `true`, pagination Python). Rien n'est supprimé — le
registre NIS 2 reste complet. Traiter une ligne groupée = **cascade** sur tous ses membres
(`group_item_ids`), sinon le groupe réapparaît en « à traiter ». Critère = titre strictement identique
(pas de « sujet proche », trop risqué pour un registre auditable). Toggle UI retiré : toujours actif.

**Consultation d'une bascule auto depuis le Dashboard — deux surfaces à garder synchronisées**
(24/07/2026) : cliquer une CVE ouvre son justificatif de clôture **en modale, sur place** (helper
partagé `openCveJustification`, recherche serveur `search=` sur `/api/vulnerabilities`) — jamais de
renvoi vers la page Vulnérabilités (qui filtre « ouvertes » par défaut, paraît vide, parc à 0 ouverte).
Les **deux** surfaces doivent rester câblées : la cloche 🔔 `NotificationHistory` **et** le bandeau vert
« Depuis votre dernière visite ». Piège vécu : seul le bandeau avait été câblé, l'utilisateur cliquait
la cloche. Le param `search` (`CVE.cve_id ILIKE`) sert aussi à la recherche **serveur** de la section
« Vulnérabilités traitées » du Dashboard — sinon plafonnée à 200 lignes par score, une CVE LOW
auto-patchée y était introuvable (cas réel CVE-2020-19909/curl).

**Déception DB — ne jamais référencer un objet leurre dans le code** (24/07/2026) : des honeypots
sont plantés en base (`backend/db/deception_setup.sql`) — vues leurres `api_keys`/`app_users`/
`ssh_credentials_backup`/`admin_tokens` (lecture journalisée via fonction `SECURITY DEFINER`, renvoient
des honeytokens), rôles leurres `admin`/`root`/`dba`/`backup`/`postgres_admin`. Tout accès alimente
`security_events` (modèle `SecurityEvent`) → **badge rouge (nombre) sur l'item Paramètres** de la
sidebar (poll du compteur, sans détail) ; détail derrière mot de passe (Paramètres > Sécurité >
Administration). API `/api/security/events*`. **Aucun code Allsafe ne doit toucher ces objets** : leur seule légitimité d'accès
est un attaquant (référence = faux positif). Script SQL idempotent, à **rejouer sur toute base** (comme
les `ALTER` manuels — `create_all` ne crée que `security_events`). `log_connections=on` activé
(`ALTER SYSTEM`). Le `RAISE WARNING` en doublon (log serveur) reste un second canal hors table.

**Rôle applicatif à privilèges réduits — l'app tourne en `cbr_app`, pas en superuser** (24/07/2026) :
`backend/db/app_role.sql` crée `cbr_app` (DML only, NOSUPERUSER, aucun DDL) ; `config.py` l'utilise via
`APP_DB_USER`/`APP_DB_PASSWORD` (repli sur `DB_USER`/`DB_PASSWORD` si vides → rollback facile). Sur
`security_events` : SELECT + UPDATE(acknowledged,…) seulement, **pas de DELETE** → traces de déception
inviolables même avec les creds app volées. ⚠️ **Une nouvelle table de modèle doit être créée par
l'owner `cybervuln` AVANT le déploiement** (create_all sous cbr_app n'émet pas de DDL sur base existante,
mais échoue s'il doit créer une table manquante). Le service Docker `db` garde `DB_USER`=cybervuln
(init + healthcheck) ; seuls backend/worker/beat consomment `APP_DB_*`.

**Risque accepté — quatrième statut terminal avec une nuance** (27/07/2026) : `accepted_risk` exige
désormais justification + validateur + `accepted_risk_until` (date de revue), comme `false_positive`/
`awaiting_fix` exigent déjà justification + validateur. **La date de revue n'est jamais appliquée
automatiquement** — passé cette date, `review_overdue` (calculé à la volée dans `_vuln_dict`, jamais
stocké) affiche juste un badge ⚠, exactement comme `sla_exceeded` sur la Veille. Ne jamais faire
rouvrir une vuln automatiquement sur cette base : `accepted_risk` reste listé parmi les états
terminaux jamais modifiés automatiquement (règle absolue, `CLAUDE.md`).

**Criticité métier — le calcul existait, seul le branchement manquait** (27/07/2026) : `scoring.py`
pondère déjà le score via `asset.tags["criticite"]` (haute ×1.5 / moyenne ×1.0 / faible ×0.7) depuis
longtemps, mais rien ne permettait de le régler. `PUT /api/assets/{id}` avec un `tags.criticite`
appelle maintenant `recalculate_scores_for_asset()` — **sans quoi changer la criticité n'a aucun effet
visible tant qu'un scan/sync ne redéclenche pas un recalcul**. Le payload frontend doit merger
`tags` (`{...asset.tags, criticite: ...}`), pas l'écraser : `PUT` remplace tout le dict.

**Durcissement CIS-like — dégradation "indéterminé", jamais d'échec de scan** (27/07/2026) :
`asset_scanner.py` ajoute un bloc `compliance` (politique de mot de passe, SSH root/mdp, RDP-NLA,
SMBv1, pare-feu, ports à risque) dans `last_scan_result` — pas de nouvelle colonne, JSON générique
déjà exposé par les routes existantes. Un droit insuffisant (ex: `sudo -n sshd -T` sans NOPASSWD)
renvoie `"unknown"`, jamais une exception qui ferait échouer tout le scan.

⚠️ **Limite de longueur de commande WinRM, déjà documentée mais reconfirmée en la dépassant**
(27/07/2026, cf. `docs/ARCHITECTURE.md` § scan d'actif) : ajouter les 4 nouveaux contrôles Windows a
fait dépasser la limite ~8191 caractères (`La ligne de commande est trop longue`), script raccourci
(`gp`/`-ea 0`, variables PS mono-lettres, préfixe de registre factorisé). **Ne jamais laisser de
commentaire explicatif dans la chaîne `ps_script`** — un bloc de 6 lignes de commentaire y avait été
ajouté par erreur et comptait dans le quota transmis (aucun bénéfice, juste du gaspillage). Marge
actuelle : voir le chiffre exact dans `docs/ARCHITECTURE.md`, à revérifier avant tout nouvel ajout.

**`net accounts` (Windows, stratégie de mot de passe) — texte localisé, pas les libellés qu'on croit**
(27/07/2026) : sur le parc réel (Windows en français), les accents sont mal encodés (`é`→`�`) et le
libellé exact est *« Durée de vie maximale du mot de passe »*, pas *« Ancienneté maximale »* comme
supposé au premier jet. Regex tolérantes : `.` à la place de chaque lettre accentuée, `[^:]*:` plutôt
que `\s*:` entre le libellé et le deux-points (absorbe le caractère mal encodé). Vérifié en direct
contre `DEPLOYAPP`, pas juste en théorie — un jeu d'essai français réel a suffi à révéler les deux bugs.

**SSH — vérification de clé d'hôte (TOFU), plus de `known_hosts=None`** (27/07/2026) :
`services/ssh_trust.py` (`connect_trusted`) remplace l'appel direct à `asyncssh.connect` dans
`asset_scanner.py`/`patch_checker.py`. Premier contact → clé apprise et pinnée dans
`keys/known_hosts` (volume désormais **en écriture**, plus `:ro`, sur `backend`+`worker`) ; contact
suivant avec une clé différente → connexion **rejetée**, jamais de réapprentissage silencieux (sinon
ça annulerait la protection — exactement le scénario MITM qu'on veut détecter). Testé en direct contre
`gitlab.aer.loc` : apprentissage, acceptation, puis rejet d'une fausse clé sans écraser le pin.

**Docker — une image par service, même avec le même `Dockerfile`** (27/07/2026) : `backend`, `worker`
et `beat` pointent tous sur `build: ./backend` mais Compose construit trois images séparées
(`cybervuln-backend`/`cybervuln-worker`/`cybervuln-beat`). Reconstruire `backend` seul après un
changement de `requirements.txt` laisse `worker`/`beat` sur l'ancienne image → `ModuleNotFoundError`
au démarrage (constaté deux fois ce jour-là). **Toujours `docker compose build backend worker beat`
ensemble** après un changement de dépendances.

**Limites mémoire Docker — `STARTUP_MATCHING` pique à ~4.6GiB** (27/07/2026) : en ajoutant
`mem_limit`/`cap_drop`/`security_opt` au `docker-compose.yml` (durcissement runtime), une première
limite à 1g puis 3g sur `backend` a laissé le conteneur bloqué indéfiniment sur "Waiting for
application startup" (ni crash ni `OOMKilled` — juste plafonné en silence). Mesuré sans limite : pic
réel ~4.6GiB pendant le matching CVE synchrone au démarrage, retombée à ~300MiB une fois terminé.
Réglé à `6g` (`backend`) / `4g` (`worker`, mêmes syncs NVD/patch-check volumineuses). À revoir à la
hausse si le référentiel CVE grossit significativement.

**Statut « correctif partiel » — `awaiting_fix_partial`** (27/07/2026) : quatrième issue automatique,
cf. `CLAUDE.md` § anonymisation/non-intervention pour la règle de sévérité (identique aux trois autres
— CRITICAL toujours manuel). Détection dans `_check_debian_tracker` (`services/patch_checker.py`) :
`partial_fix = true` quand au moins un paquet visé par la CVE est absent (hors sujet) **et** au moins un
autre est installé sans correctif Debian publié, sans qu'aucun paquet ne soit réellement vulnérable
avec un correctif disponible non appliqué (ce dernier cas doit rester une vraie vuln ouverte). Même
comportement qu'`awaiting_fix` : reste dans le cycle de recheck, bascule seule en `patched`, protégée
par le même garde-fou (décision humaine non écrasée). Avant ce statut, ce cas ne correspondait à aucune
branche d'`apply_patch_result` et restait ouvert sans signal exploitable — `awaiting-fix-candidates`
anticipait déjà littéralement ce trou dans sa docstring (« les cas mixtes sont exclus par
construction »). Choix délibérément proportionnés (3 cas connus, tous HIGH) : pas de couple
candidates+bulk dédié (le PATCH unitaire suffit, comme pour les 3 CRITICAL "produit absent"
ci-dessus) ; côté Dashboard, fusionné dans la même section "en attente" qu'`awaiting_fix` (badge
« partiel » en plus) plutôt qu'une section séparée ; côté rapports/stats, plié dans le compteur
`awaiting_fix` existant plutôt qu'une colonne dédiée.

⚠️ **Incident de migration le jour même** : le PATCH unitaire (`update_vulnerability`) n'avait pas de
branche dédiée pour ce nouveau statut — il retombait dans le `else` prévu pour open/in_progress, qui
efface `validated_by`/`last_patch_check`/`patch_check_result` (et aurait effacé une éventuelle date
`accepted_risk_until`). Repéré immédiatement en vérifiant l'état après migration des 3 Debian mixtes :
`validated_by` vide alors qu'il aurait dû rester "Yanis Hortholary". Branche `elif` dédiée ajoutée
(même traitement qu'`awaiting_fix`, conserve `last_patch_check`/`patch_check_result`) ; les 3 lignes
réparées via l'API (`validated_by` restauré, `patch_check_result` régénéré par un vrai contrôle SSH).
Les notes d'analyste (texte libre, non touchées par cette branche du code) n'ont jamais été perdues.
**Leçon** : tout nouveau statut doit être ajouté à *chaque* switch/if-chain sur `Vulnerability.status`
avant d'être utilisé en écriture — le `else` fourre-tout de `update_vulnerability` est un piège
silencieux (pas d'erreur levée, juste des champs effacés).

**Sauvegarde PostgreSQL** (27/07/2026, détail complet dans `docs/ARCHITECTURE.md` § Sauvegarde) :
`pg_dump` quotidien à 4h sur un volume dédié `backups`, format `-Fc` (restauration sélective via
`pg_restore --table=`), rétention 14 jours (`BACKUP_RETENTION_DAYS`, purge uniquement après un dump
réussi). Déclenchement manuel `POST /api/backup/run`, toujours exécuté côté worker (jamais dans le
process API) via Celery. **Client `postgresql-client-16` du dépôt PGDG**, pas le paquet Debian
générique (v15, plus ancien que le serveur `postgres:16-alpine` — non supporté par pg_dump). Vérifié
en conditions réelles : dump de 124 Mo sur la base de production, structure validée (`pg_restore -l`),
purge testée avec un faux fichier antidaté. La restauration elle-même reste une procédure **manuelle**,
jamais automatisée — un restore écrase des données réelles, ça doit rester un choix humain explicite.

**Premiers tests automatisés** (27/07/2026, détail complet dans `docs/ARCHITECTURE.md` § Tests) :
`backend/tests/`, lancés via `docker compose exec backend pytest -v`. Portée délibérément ciblée sur
`apply_patch_result` (garde-fous de sévérité/état terminal/décision humaine) et une régression directe
de l'incident `awaiting_fix_partial` ci-dessus — pas une couverture large. **Aucune base de données
requise** : `session` mockée, `Vulnerability`/`CVE` instanciés en mémoire, `update_vulnerability`
appelée directement comme une fonction Python (pas de serveur HTTP). 31 tests, tous verts. Ne couvre
pas (encore) le matching CPE, le patch check Windows/Linux réel, ni rien touchant PostgreSQL.

**Healthchecks sur les 6 services** (27/07/2026, détail complet dans `docs/ARCHITECTURE.md` §
Healthchecks) : seuls `db`/`redis` en avaient. `backend` (`curl /api/health`), `worker` (`celery
inspect ping` — via le broker, pas juste "le process existe"), `beat` (`pgrep`, pas d'endpoint HTTP),
`frontend` (`wget --spider`). ⚠️ **Piège réel** : `http://localhost:...` échoue par intermittence
(`Connection refused`) — `/etc/hosts` résout `localhost` en `::1` (IPv6) avant `127.0.0.1`, alors
qu'uvicorn/Vite n'écoutent qu'en IPv4 (`0.0.0.0`). Fix : `127.0.0.1` explicite, jamais `localhost`,
dans un healthcheck Docker. Les 6 services confirmés `healthy` après reconstruction.

**Error Boundary React** (27/07/2026, détail complet dans `docs/FRONTEND.md`) : `components/
ErrorBoundary.jsx`, autour de `<Outlet/>` dans `Layout.jsx` (pas au sommet de l'app) — une page qui
plante n'emporte plus la sidebar/nav, l'utilisateur peut naviguer ailleurs. Réutilise le `<div
key={location.pathname}>` déjà présent (transition de page) pour se réinitialiser tout seul au
changement de route, sans logique de reset dédiée. ⚠️ **Limite de vérification** : testé par lecture
de code et compilation Vite propre (aucune erreur de build, contenu servi confirmé à jour) — pas de
vérification visuelle en navigateur, aucun outil de ce type disponible dans cette session.

**Rotation des logs Docker** (27/07/2026, détail dans `docs/ARCHITECTURE.md` § Services Docker) :
`json-file` sans limite grossit indéfiniment par défaut — vérifié sur cet hôte (`docker inspect`
montrait un `LogConfig` vide, pas de `daemon.json`). `max-size: 10m` / `max-file: 5` (50 Mo max) sur
les 6 services. Confirmé via `docker inspect` après recréation complète — données/compteurs de vulns
inchangés.

**Build de production du frontend** (27/07/2026, détail complet dans `docs/ARCHITECTURE.md` §
Services Docker) : jusque-là uniquement le mode Vite dev (`npm run dev`), y compris dans ce qui sert de
déploiement principal. `frontend/Dockerfile` multi-stage (`dev`/`build`/`prod`), nouveau service
`frontend-prod` (nginx + build minifié) derrière un profil Compose (`docker compose up -d
frontend-prod`) plutôt qu'un `docker-compose.prod.yml` séparé — évite l'ambiguïté de fusion YAML entre
fichiers (`volumes`/`healthcheck` se concatènent entre fichiers Compose, ne se remplacent pas). Mode
`dev` inchangé par défaut : `target: dev` fixé explicitement sur le service `frontend`, sinon Docker
construirait le dernier stage du Dockerfile (`prod`) par défaut au prochain rebuild. **Vérifié en
conditions réelles** : build + conteneur nginx isolé (port de test, réseau du projet) — SPA servie,
routes inconnues retombent sur `index.html` (pas de 404 au rechargement), proxy `/api` fonctionnel,
`X-Forwarded-For` transmis et retrouvé dans `connection_logs` (testé avec une IP factice, nettoyée
après coup — pas de code direct, `DELETE` SQL sur une simple ligne de log, sans rapport avec l'invariant
« ne jamais modifier un statut de vuln en SQL direct »).

## 🔭 Points ouverts

✅ **`GET /false-positive-candidates` lent (~18s constaté en direct, 03/08/2026) — RÉSOLU**,
correction de doc le 17/08/2026 : jamais remis à jour après les deux correctifs qui l'ont réglé
(two-phase du 28/07, cache process du 08/08, cf. entrées correspondantes plus bas). Remesuré le
17/08 : 5,45s à froid / 66ms à chaud (TTL 5 min). Rien à faire de plus, le Dashboard sonde toutes
les 30s donc quasi toujours en cache chaud. Note d'origine conservée ci-dessous pour l'historique :
pas de régression connue (le calcul revérifie `still_matches` par profil d'actif, cf. sa docstring)
mais jamais mesuré à ce point avant — désormais visible côté Dashboard puisque la case "Faux positifs
proposés" en dépend directement (cf. § invariants, correctif du filtre vidé à tort). À profiler si
ça devient gênant en usage réel ; candidat naturel : mémoïser par cycle plutôt que par requête HTTP.

✅ **Données de test nettoyées** (03/08/2026, suite) : l'incident *« Ransomware — chiffrement
partiel sur gitlab.aer.loc »* et sa crise liée *« Crise ransomware — gitlab.aer.loc »* (créés le
31/07/2026 pour valider le flux d'escalade, jamais nettoyés depuis) supprimés via l'API avec une
session admin temporaire — `DELETE /crises/{id}` puis `/incidents/{id}`, tous deux 204, confirmé
en base (0 ligne restante sur les deux tables).

✅ **PRTG construit** (04/08/2026, suite) : intégration lecture seule de l'API cœur PRTG Network
Monitor (pas Multiboard, produit à part qui agrège des widgets visuels entre instances — écarté
après clarification avec l'utilisateur, qui avait deux tokens et hésitait entre les deux).
`services/prtg_client.py` (auth `apitoken` en paramètre de requête, `content=devices`) +
`services/prtg_matcher.py` (rapprochement host PRTG → `Asset.ip_address`/`hostname` normalisé, puis
repli sur le nom d'affichage → `hostname`/`name`) + `routers/prtg.py` (`POST /api/prtg/run`,
`GET /api/prtg/status`), monté dans `main.py`. Alimente la même table `network_status` que Meraki
(`source="prtg"`), avec le statut texte PRTG ("Up"/"Down"/"Warning"/"Paused"...) normalisé vers le
même vocabulaire partagé (online/offline/alerting/dormant) — cf. `docs/ARCHITECTURE.md`.

Différence initiale avec Meraki, tranchée avec l'utilisateur avant de coder : **PRTG ne crée jamais
d'actif** (pas d'équivalent `import_new_assets`) — il surveille des machines déjà connues de CBR,
pas des équipements réseau bruts sans existence côté parc.

**Décision revue dans la foulée** : après le premier sync réel (67 actifs déjà connus rapprochés
sur 410 devices PRTG), l'utilisateur voulait en fait **voir les devices PRTG comme actifs dans
CBR** — les 343 restants (routeurs de site, bornes Wi-Fi...) invisibles ne répondaient pas au
besoin. `import_new_assets` ajouté à `prtg_matcher.py`/`routers/prtg.py`, même mécanique que
Meraki, avec une exclusion propre à PRTG : `_is_prtg_internal` écarte structurellement (host vide
ou loopback `127.0.0.1`, pas une liste de noms codée en dur) les objets internes à la plateforme
elle-même (sonde, serveur central) — 4 objets exclus sur les 410.

⚠️ Utilisateur alerté sur le risque de doublon avant l'exécution (« Attention au doublon ») —
vérifié avant d'activer : sur les 343 devices non rapprochés, **aucun** ne partage un nom
normalisé ou une IP exacte avec un `Asset` déjà en base (Meraki ou AD/SSH), le rapprochement exact
existant suffit. Des noms proches repérés par recoupement flou (`difflib`) se sont révélés être des
boîtiers réellement distincts au même site (ex. "Routeur Bellevigny" 192.168.30.254 vs
"AP_Bellevigny" 192.168.30.69 — routeur et borne Wi-Fi, pas le même équipement).

**Résultat réel** (`POST /api/prtg/run?import_new_assets=true`, session admin temporaire) : **339
`Asset` créés** (`asset_type="network"`, `source="prtg"`), parc CBR passé de **142 à 481 actifs**.
Recontrôlé après coup : 0 doublon par nom normalisé toutes sources confondues.

⚠️ **Effet de bord découvert juste après** : `services/stats.py::compute_stats` comptait tous les
`Asset` sans filtrer par type — le KPI "actifs" du Dashboard reflétait donc 481 au lieu de 142,
alors que 409 (Meraki + PRTG) ne matcheront jamais aucune CVE (ni OS ni CPE, confirmé en
inspectant les capteurs PRTG disponibles côté API — rien d'exploitable pour construire un CPE).
Corrigé : `total_assets` (quand aucun `asset_ids` explicite n'est fourni) exclut désormais
`asset_type == "network"` — revenu à 72 actifs, vérifié via `GET /api/stats`. Les actifs réseau
restent visibles normalement sur Actifs/Inventaire avec leur badge, seuls les compteurs CVE du
Dashboard les excluent.

**Puis, même jour, question de l'utilisateur : lier ces actifs réseau à la Veille technologique
plutôt qu'aux CVE.** Vérifié avant de coder : la table `devices` PRTG ne porte aucune colonne
vendor/modèle, mais certains **capteurs** en révèlent un (`content=sensors`, colonne `type_raw`,
stable — pas `type`, localisée comme `status`, même piège) — seul cas observé : les capteurs
`snmpsynology*` (Synology). Rendement réel mesuré avant d'implémenter : **14 devices sur 410**
concernés. Décidé avec l'utilisateur : ça vaut le coup malgré le faible volume (des CVE Synology
DSM existent réellement).

Construit : `prtg_client.py::get_sensor_vendor_hints()` ({device objid: vendor}, table tenue à la
main sur les cas observés, même esprit que `_AMBIGUOUS_WORDS` dans `watch_profile.py`) ;
`prtg_matcher.py` écrit `Asset.hardware.vendor_hint` uniquement pour les actifs **qu'il a
créés lui-même** (`asset.source == "prtg"`) — jamais sur un actif AD/SSH matché par hostname, dont
`hardware` porte le vrai cpu/ram/disks du scan ; rafraîchi à chaque cycle (un capteur peut
apparaître après coup). `watch_profile.py::suggestions_from_inventory()` lit ce champ et l'ajoute
à la catégorie **"Matériel / Constructeurs"**, basculée `from_inventory: True` (elle existait déjà,
pensée dès le 22/07 pour ce que CBR ne scanne pas — juste jamais peuplée automatiquement avant).
Toujours une **suggestion**, jamais un ajout automatique au profil — même garde-fou que
OS/Logiciels (« le profil marque, il ne filtre jamais »).

Vérifié en conditions réelles : re-sync PRTG (`POST /api/prtg/run`) → 12 des 14 devices Synology
récupèrent `vendor_hint="Synology"` sur leur `Asset.hardware` (les 2 restants, "Datacore1/2", ont
en fait matché des serveurs Windows déjà connus par hostname — `hardware` non touché, comportement
voulu). `GET /api/watch/profile` confirme la suggestion "Synology" avec les 12 actifs concernés,
catégorie Matériel.

**Puis, même jour, demande de l'utilisateur sur la page Actifs** : différencier les modèles Meraki
(MR = bornes Wi-Fi, MX = routeurs/pare-feu — actuellement affichés comme code brut dans la colonne
OS) et ajouter un pendant "réseau" aux filtres OS/criticité déjà existants. Frontend uniquement,
rien côté backend :
- `MERAKI_MODEL_LABELS` (`Assets.jsx`) — nomenclature officielle Cisco Meraki (MR/MX/MS/MG/MT/MV/Z),
  dérivée du préfixe de `Asset.os` (seul champ qui la porte, cf. meraki_matcher.py). Colonne OS
  affiche désormais "Borne Wi-Fi (MR36)" au lieu de "MR36" seul pour les actifs Meraki catégorisables.
- Deux nouveaux filtres, même esprit data-driven que le filtre OS existant (`osOptions` dérivé du
  parc, pas de liste codée en dur) : **Catégorie** (`assetCategory()` — Serveur/Poste pour le parc
  scanné, catégorie de modèle ou "Équipement réseau" générique pour PRTG sans donnée exploitable) et
  **Statut réseau** (online/offline/alerting/dormant, libellés désormais exportés depuis
  `NetworkStatusBadge.jsx::NETWORK_STATUS_LABELS` plutôt que dupliqués).
- Effet de bord traité au passage : `SOURCE_LABELS`/`SOURCE_STYLES` (`Assets.jsx`) n'avaient jamais
  reçu d'entrée `prtg` (repli sur le texte brut "prtg" + style par défaut CSV) — ajoutée.

Vérifié : répartition réelle du parc par catégorie recalculée côté API — 72 Serveur, 48 Borne
Wi-Fi, 22 Pare-feu / Routeur, 339 Équipement réseau (PRTG). Vite recompile sans erreur (HMR,
`NETWORK_STATUS_LABELS` provoque une invalidation complète du module au lieu d'un fast refresh —
normal pour un nouvel export nommé, pas un bug).

Effet de bord traité au passage : `routers/assets.py::list_assets` filtrait en dur
`NetworkStatus.source == "meraki"`, ce qui aurait silencieusement ignoré toute ligne PRTG une fois
écrite. Corrigé pour retenir, par actif, la ligne `NetworkStatus` la plus récemment mise à jour
toutes sources confondues — et `NetworkStatusBadge.jsx` affichait "Meraki" en dur dans la tooltip,
rendu dynamique (`SOURCE_LABELS`) pour les deux sources.

`.env` complété avec `PRTG_URL=https://trinity.eurofeu.fr:40888` et le token API fourni par
l'utilisateur. Le domaine résout vers une IP privée (`192.168.100.58`, réseau interne Eurofeu),
hors de portée du bac à sable utilisé pour écrire le code (accès internet public uniquement) —
testé à la place directement depuis le conteneur `cybervuln-backend-1` (même hôte Docker que la
production, route réelle vers ce LAN confirmée).

⚠️ **Deux détails réels découverts en testant avec la vraie clé, corrigés avant de considérer
l'intégration terminée** :
- **TLS** : certificat serveur signé par une CA interne (`AER-ALADDIN-CA`, AD CS), absente du
  magasin de confiance du conteneur → `CERTIFICATE_VERIFY_FAILED`. Ajouté `PRTG_VERIFY_TLS` (défaut
  `true`, explicite plutôt que désactivé en dur) à `config.py`/`prtg_client.py`, mis à `false` dans
  `.env` pour ce déploiement précis, avec le nom de la CA en commentaire.
- **Libellé de statut localisé** : la colonne `status` de l'API PRTG renvoie du texte traduit selon
  la langue de l'interface PRTG — `"OK"` (pas `"Up"`), `"En pause (...)"` (pas `"Paused"`) sur ce
  serveur configuré en français (410 devices interrogés, confirmé par `status_raw` correspondant :
  3 pour les 390 `"OK"`, 7 pour les 20 `"En pause..."`). Un mapping sur le texte anglais aurait
  silencieusement classé tous les devices "up" comme `dormant`. Corrigé : `prtg_matcher.py`
  normalise sur `status_raw` (code numérique stable, doc API PRTG), le texte reste seulement dans
  `metrics.raw_status` à titre informatif.

**Vérifié en conditions réelles, bout en bout** (`POST /api/prtg/run`, session admin temporaire
créée puis supprimée en base après usage, même procédure que les nettoyages précédents) : 410
devices PRTG interrogés, **67 rapprochés** par hostname aux `Asset` existants (serveurs
Windows/Debian du parc, ex. `diarus.aer.loc`, `aos12.aer.loc`), 67 `NetworkStatus` créés
(`source="prtg"`, `status="online"`, `metrics.raw_status="OK"`) — 343 devices PRTG non rapprochés
restent dans `unmatched_devices` (routeurs de sites, bornes Wi-Fi, sonde PRTG elle-même : aucun
`Asset` correspondant, cohérent avec la décision de ne jamais en créer). `GET /api/assets`
recontrôlé après coup : les deux sources coexistent correctement (ex. certains actifs Meraki
affichent encore `source="meraki"` faute de ligne PRTG plus récente, d'autres basculent sur
`source="prtg"`) — confirme que le choix de la ligne la plus récente par actif (routers/assets.py)
fonctionne comme prévu, pas de source figée en dur qui aurait masqué l'une ou l'autre.

**Modale patch check — bouton "Détail" (commandes SSH/WinRM + retour brut) (07/08/2026)** : demande
explicite, "si c'est pas trop long". Nouveau `debug_commands` dans le résultat de
`services/patch_checker.py::check_patch` — `_fetch_windows_patch_snapshot`/`_fetch_linux_package_snapshot`
retiennent désormais la commande exécutée et son retour brut (`_raw`, liste de `{command, output}` —
un seul appel WinRM combiné pour Windows, trois commandes SSH pour Linux : `dpkg-query`, repli `rpm
-qa`, `uname -r`). `_cap_lines` (500 lignes) protège contre un `dpkg-query` démesuré sur un actif à
plusieurs milliers de paquets.

⚠️ **Jamais persisté en base** — `apply_patch_result` filtre explicitement `debug_commands` avant
d'écrire `vuln.patch_check_result` : un relevé WinRM/SSH est strictement identique pour toutes les
CVE d'un même actif dans un même cycle (déjà mis en cache par l'appelant, cf. commentaires existants
sur `_fetch_*_snapshot`), le dupliquer sur chaque ligne de `vulnerabilities` aurait gonflé la base
pour rien. Conséquence assumée : le bouton "Détail" n'apparaît que sur un résultat **fraîchement
recontrôlé**, jamais sur un résultat en cache (`vuln.patch_check_result` lu depuis la base n'a jamais
ce champ). Vérifié en conditions réelles : `debug_commands` présent dans la réponse HTTP d'un contrôle
frais, absent en base (`patch_check_result::jsonb ? 'debug_commands'` → `false`).

Bouton "🔍 Détail" ajouté aux **deux** modales dupliquées de patch check (Dashboard.jsx ET
Vulnerabilities.jsx, pas de composant partagé entre les deux — cf. limite déjà connue) à côté du
bouton de qualification ("✓ Corrigé"/"✓ Marquer comme corrigé"), état replié par défaut, remis à
`false` à chaque nouveau contrôle (`handlePatchCheck`).

⚠️ **Premier rendu cassé, corrigé dans la foulée** : la commande (script PowerShell multi-lignes
~50 lignes, ou requête SSH) était affichée dans un `<div>` sans `whitespace-pre-wrap` — les retours à
la ligne collapsés par défaut en HTML transformaient tout le script en un seul paragraphe géant,
débordant du cadre de la modale (`max-w-lg`, sans `overflow-y-auto` sur le corps). Corrigé : commande
et retour dans des `<pre>` séparés (`whitespace-pre-wrap break-words`, hauteur plafonnée 140px/220px
avec défilement propre), modale élargie à `max-w-2xl` + `max-h-[85vh] overflow-y-auto` sur les deux
fichiers.

**Actifs — mises à jour système vs applicatives (07/08/2026, partie A d'une demande utilisateur en
deux temps, B — mises à jour disponibles indépendamment d'une CVE connue, type `apt list
--upgradable`/Windows Update — faite le 10/08/2026, cf. entrée dédiée plus bas)** : nouveau champ `Vulnerability.component_type`
(`"system"` | `"application"` | `NULL`), posé à la création par les 3 sites de `services/cpe_matcher.py`
qui créent des `Vulnerability` — priorité "application" quand un paquet installé matche (plus
actionnable), sinon "system" (CPE OS ou fallback mots-clés, toujours OS). Nouveau helper partagé
`match_component_type_ctx` (mêmes primitives que `still_matches_ctx`, qui s'appuie maintenant dessus
plutôt que de dupliquer la logique). `services/withsecure_matcher.py` laissé volontairement à `NULL` :
pas de signal fiable côté API pour distinguer OS/application dans les correctifs "Software Updater"
remontés (le champ `item` de `get_missing_updates` n'a pas été inspecté en détail pour ça — à vérifier
si besoin plus tard).

Backfill des ~86k `Vulnerability` déjà en base (créées avant ce champ) : `POST
/api/sync/backfill-component-types`, `services/cpe_matcher.py::backfill_component_types` — même
optimisation contexte-par-actif que `still_matches_ctx` (cf. incident de perf du 28/07), pas
recalculé ligne par ligne. Laisse `NULL` les rattachements dont la règle de matching a changé depuis
(candidats faux positifs) plutôt que de deviner. ⚠️ **Pas encore exécuté en conditions réelles** — à
lancer après déploiement, puis vérifier un échantillon (`SELECT component_type, count(*) FROM
vulnerabilities GROUP BY component_type`).

`routers/assets.py` : agrégat `pending_updates: {system, application}` par actif (une requête groupée
pour toute la liste, même principe que `vuln_count`/`network_status`), filtré aux statuts encore "à
traiter" (`PENDING_UPDATE_STATUSES = open/in_progress/awaiting_fix/awaiting_fix_partial` — même liste
que `arCandidates` côté frontend). Frontend : nouvelle colonne "Mises à jour" sur **Actifs uniquement**
(pas Inventaire — la distinction sécurité/patrimoine du module l'exclut délibérément, cf. CLAUDE.md),
`PendingUpdatesBadge.jsx` (deux pastilles 🖥/📦 distinctes, pas un total fusionné).

Migration : `ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS component_type VARCHAR` ajoutée à
`schema_patches.sql` — **à exécuter avec le rôle superuser `cybervuln`** avant de redémarrer le
backend (`cbr_app` n'a pas de droit DDL, cf. `db/ddl_guard.sql`), sans quoi les 3 sites de création
de `cpe_matcher.py` échoueraient sur la colonne manquante.

**Dashboard — périmètre par défaut restreint aux actifs "configurés" (07/08/2026)** : demande
explicite, chiffres cibles donnés par l'utilisateur et vérifiés exacts avant de coder (3 actifs
configurés sur 72 serveurs/postes — `gitlab.aer.loc`, `DEPLOYAPP`, `CRAFTER` — 69 jamais scannés
avec succès). "Configuré" = `installed_packages` non vide (`json_array_length > 0`), c'est-à-dire
au moins un scan SSH/WinRM réussi avec de vraies données — pas juste un CPE dérivé de l'OS à
l'import, qui existe même sans scan et gonflait les compteurs de CVE non vérifiées pour les 69
autres. `services/stats.py::compute_stats` gagne un paramètre `default_configured_only` (défaut
`False`) plutôt qu'un changement de comportement global : seul `routers/stats.py` (dashboard) le
passe à `True`. ⚠️ Point de vigilance identifié avant de livrer : `compute_stats` est **partagé**
avec `routers/reports.py::build_summary_payload` (rapports hebdomadaires/exécutifs, traçabilité
NIS 2) — un rétrécissement silencieux du périmètre là-bas aurait été un vrai problème de conformité
(rapport qui semble "propre" juste parce que 69 actifs sur 72 sont invisibles). Vérifié après coup :
`POST /api/reports/executive-summary` affiche toujours 72 actifs au total, `GET /api/stats`
(dashboard) affiche 3 — comportements bien découplés. Nouveau champ `assets_to_configure` dans la
réponse (`None` si un filtre "Actifs" explicite est actif), affiché sur la tuile "Actifs exposés"
(`Dashboard.jsx`) : "sur 3 actifs (69 à configurer)".

**Dashboard borné à 2 ans + cycle patch check corrélé (07/08/2026)** : suite immédiate. D'abord
`Dashboard.jsx` (`loadLists`, recherche "vulns traitées") passe `max_age_years: 2` à
`GET /api/vulnerabilities` (paramètre déjà existant, aucun changement backend nécessaire) — "trop
chargé" sinon, la page Vulnérabilités reste l'outil pour un historique complet. Vérifié : 2994 → 1615
vulns ouvertes avec la limite. `false-positive-candidates` avait déjà cette borne par défaut
(`CANDIDATE_MAX_AGE_YEARS = 2`, préexistant) — cohérent sans rien y changer.

Puis demande explicite de mettre le **cycle réel** en corrélation avec cet affichage, pas seulement
l'écran : nouveau `PATCH_CHECK_MAX_AGE_YEARS = 2` (`services/patch_checker.py`), appliqué
inconditionnellement dans `run_startup_patch_checks` (join CVE + `CVE.published >= cutoff` sur les
deux requêtes de la fonction) — jamais sur `backfill_auto_patch` (pure reconciliation d'un résultat
déjà en base, aucun nouveau contrôle SSH/WinRM, pas de charge à réduire là). Toutes les invocations
réelles du cycle partent du dashboard (bouton, démarrage, cycle périodique, déclenchement post-scan),
aucune ne justifiait de garder les CVE anciennes dans le périmètre automatique.

`GET /patch-check/status?configured_only=true` reçoit le même filtre (join CVE, même cutoff) — sans
ça, `pending` serait resté artificiellement élevé pour des CVE que le cycle ne vérifiera plus jamais,
donnant l'impression d'un blocage plutôt que d'un périmètre assumé. **Vérifié en conditions réelles** :
`pending` 2717 → 1477 après le filtre (même actifs, mêmes statuts) ; cycle relancé, progression
confirmée sur ce nouveau périmètre réduit (128→129 vérifiées, `current` avançant sur ARMADASENONCHES).

**Cycle patch check — automatique, auto-relance, et un vrai bug d'auth découvert (07/08/2026)** :
suite immédiate du chantier précédent. L'utilisateur a configuré ARMADASENONCHES pendant qu'un
cycle tournait déjà sur les 3 premiers actifs — il a fini, puis un nouvel actif configuré n'a
**jamais été couvert automatiquement**, restant inactif jusqu'à relance manuelle. Demande explicite :
automatiser complètement, "pas un truc qui tourne mais qui fait rien".

**Auto-relance** (`services/patch_checker.py::run_full_patch_check_cycle`) : nouveau paramètre
`refresh_configured` (recalcule le périmètre "configurés" à **chaque passage** plutôt qu'une fois,
au lieu d'un `asset_ids` figé) + `_rerun_requested` (une demande arrivant pendant qu'un cycle tourne
n'est plus perdue — `already_running` mémorise plutôt que d'ignorer, une passe supplémentaire
s'enchaîne dès la fin de la passe en cours). Le garde `is_patch_check_cycle_running()` qui bloquait
`POST /run` a été retiré : chaque appel déclenche désormais la logique d'auto-relance plutôt qu'un
simple rejet silencieux.

**Déclenchement automatique** : `tasks/scheduled_tasks.py::run_cpe_matching_for_asset_task` (déjà
appelée après chaque scan réussi) POST maintenant `/api/patch-check/run` une fois le matching CPE
terminé — un actif tout juste configuré est vérifié sans attendre le cycle périodique (jusqu'à 6h).

⚠️ **Bug réel trouvé en implémentant ça, sans rapport avec la demande initiale mais bloquant pour
elle** : `patch_check_periodic` (cycle Celery toutes les 6h) POST cet endpoint sans aucune
authentification depuis toujours — l'endpoint exige une session utilisateur depuis l'introduction du
login (30/07/2026). Vérifié en conditions réelles : `curl -X POST /api/patch-check/run` sans cookie
→ 401. **Le cycle périodique échouait donc silencieusement (401, retry Celery) à chaque exécution
depuis le 30/07/2026, jamais remarqué** (aucune alerte sur un échec de tâche Celery). Corrigé :
nouveau `INTERNAL_API_TOKEN` (`.env`, partagé backend/worker, jamais exposé au navigateur) +
`auth_deps.py::require_page_or_internal` (accepte soit une session valide, soit l'en-tête
`X-Internal-Token` — le corps duplique volontairement `require_auth`/`require_page` plutôt que de
les composer, `Depends` en paramètre par défaut s'exécute avant qu'un `try/except` puisse intercepter
son échec). `main.py` : dependency globale du router `patch_check` retirée, chaque route porte
désormais la sienne (`require_page` normal pour `/status`/`/{vuln_id}`, `require_page_or_internal`
pour `/run` seul). **Vérifié en conditions réelles, les trois cas** : sans rien → 401 ; jeton correct
→ 200 ; mauvais jeton → 401. Cycle relancé avec le jeton, `checked` a continué de progresser
normalement (199→213 en quelques minutes, `current` avançant réellement sur ARMADASENONCHES).

**Faux positifs proposés + cycle patch check réel — même périmètre "configurés" (07/08/2026)** :
retours utilisateur successifs le même soir. D'abord `false-positive-candidates` (151 affichés sur
le dashboard alors que les 3 tableaux principaux étaient déjà corrigés) : nouveau `configured_only`
sur cet endpoint (`_candidate_conditions` accepte `configured_asset_ids`), câblé depuis
`loadFpCandidates` (Dashboard.jsx) — vérifié : `configured_only=true` → 0 résultat (les 151 étaient
100% sur des actifs non configurés), sans filtre (Vulnerabilities.jsx, inchangé) → 151 toujours.

Puis constat que le **cycle de patch check réel** (pas juste son affichage) tournait toujours sur
tout le parc — l'utilisateur a repéré que le compteur restait bloqué ("173 ça bouge pas") après un
premier correctif purement cosmétique sur `GET /patch-check/status`. Décision explicite : restreindre
le cycle réel, pas juste l'affichage — sans ça il passe l'essentiel de son temps à tenter (et échouer)
des connexions SSH/WinRM sur des actifs jamais scannés avec succès, sans espoir d'y arriver tant
qu'ils ne sont pas configurés. Trois points de déclenchement corrigés pour défaut = actifs configurés
uniquement (`asset_id` explicite reste prioritaire, comportement inchangé) :
- `routers/patch_check.py::trigger_patch_check_run` (déclenchement manuel + `patch_check_periodic`
  Celery, qui POST cet endpoint sans `asset_id`).
- `main.py::_startup_patch_check` (cycle de démarrage, `STARTUP_PATCH_CHECK` — trouvé désactivé
  dans `.env` en vérifiant, sans rapport avec les nombreux redémarrages backend de la soirée : les
  compteurs `checked`/`pending` viennent de la base, pas de mémoire, donc pas remis à zéro par un
  redémarrage — seuls `current`/`last_completed`, en mémoire, le sont).
- Garde-fou ajouté aux deux : `asset_ids=[]` (aucun actif configuré) serait lu comme "aucun filtre"
  par `backfill_auto_patch`/`run_startup_patch_checks` (`if asset_ids:`) — skip explicite au lieu de
  relâcher le cycle sur tout le parc par accident.

**Vérifié en conditions réelles, bout en bout** : `POST /api/patch-check/run` sans `asset_id` →
`asset_ids` limité aux 3 UUID configurés (au lieu de tout le parc) ; suivi via `/status` : passé de
36/173 restants à 97/112 en ~40s, `current` progressant réellement (gitlab.aer.loc puis CRAFTER,
WinRM plus lent que SSH) — le cycle qui aurait mis des jours sur 261 344 vulns se termine maintenant
en quelques minutes sur les 173 réellement vérifiables.

**Dashboard — les 3 tableaux de vulns suivent enfin le périmètre "configurés" (07/08/2026)** :
retour utilisateur immédiat après le changement précédent — les KPI affichaient "3 actifs" mais
les tableaux Ouvertes/Corrigées/En attente montraient encore les vulns des 69 non configurés,
`GET /api/vulnerabilities` n'ayant aucune notion de périmètre par défaut. Nouveau paramètre
`configured_only` sur cet endpoint (réutilise `services/stats.py::get_configured_asset_ids`,
extrait en fonction partagée pour ne jamais faire diverger la définition), appliqué uniquement en
l'absence de `asset_id` explicite — jamais sur `Vulnerabilities.jsx` (catalogue complet, comportement
inchangé, vérifié : `GET /api/vulnerabilities?status=open` sans paramètre reste à 261325). Dashboard
(`loadLists`, recherche "vulns traitées") passe `configured_only=true` par défaut, vérifié :
`configured_only=true` → 154 vulns ouvertes sur CRAFTER/DEPLOYAPP uniquement (== `open_vulnerabilities`
de `/api/stats`).

⚠️ **Bug réel trouvé en câblant `configured_only`, corrigé au passage** : `asset_id` sur
`GET /api/vulnerabilities` ne gérait qu'un UUID unique (`==`), jamais une liste séparée par
virgules — une sélection multiple dans le filtre "Actifs" du dashboard (`AssetDropdown`, pourtant
prévu pour) renvoyait silencieusement 0 résultat dans les 3 tableaux. Corrigé (`.in_()` dès que
plusieurs ids), vérifié : sélection CRAFTER+DEPLOYAPP → 154 (au lieu de 0 avant). Les 3 endpoints
"candidats" (`_candidate_conditions`, awaiting-fix/false-positive/critical-review) ont la même
limitation structurelle, non corrigée ici (`fpCandidates` du dashboard reste donc un point aveugle
résiduel : la section "Faux positifs proposés" n'est pas encore filtrée par le périmètre
"configurés" ni par une sélection multiple — connu, pas encore traité).

Filtre "Actifs" du dashboard (`AssetDropdown`) : affichait "Tous les actifs" sans coche visible
tant qu'aucune sélection explicite n'existait, alors que le périmètre réel effectif était déjà
restreint aux 3 configurés — invisible pour l'utilisateur (demande explicite de corriger). Nouveau
`effectiveAssetIds` (Dashboard.jsx) = sélection explicite, ou repli sur les 3 configurés (jamais en
mode Présentation, où les actifs fictifs n'existent pas dans cette liste réelle) — passé à
`AssetDropdown` pour l'affichage (cases cochées, libellé "3 actifs") ; `onChange` continue d'écrire
dans `selectedAssetIds`, donc décocher l'un des 3 pré-cochés crée une vraie sélection explicite.

**Test protocoles réseau — switches/pare-feux (07/08/2026)** : demande utilisateur (relayée d'un
collègue) de couvrir aussi les ~409 actifs réseau importés via PRTG/Meraki, qui n'ont jamais eu de
vulnérabilité trackée (pas de CPE exploitable). Cadré avec l'utilisateur avant de coder : uniquement
un test TCP passif (Telnet=23, HTTP=80 — `connect()` qui se referme aussitôt, rien envoyé/négocié
ensuite), jamais de test SNMP actif (community string) — écarté explicitement comme action offensive,
contraire au principe déjà posé pour le module Audits ("CBR héberge et trace, n'exécute jamais rien
d'offensif"). Nouveau `services/network_protocol_check.py`, nouvelle colonne `Asset.network_compliance`
(même forme `{"checks": [...]}` que la compliance serveur, mais dédiée : ces actifs ne passent jamais
par un scan SSH/WinRM). `POST /api/assets/network-protocol-check/run` — pas encore de bouton
frontend, déclenchement manuel via l'API pour l'instant (même état que les premiers runs PRTG/Meraki).
Badge `NetworkComplianceBadge.jsx` à côté du badge réseau existant sur Actifs, seulement si `warn`.

⚠️ **Bug de perf réel, corrigé avant de considérer la fonctionnalité terminée** : première version
séquentielle (un actif après l'autre) — avec ~400 actifs réseau et des pare-feux qui laissent
souvent tomber une connexion silencieusement (pas de TCP RESET) plutôt que la refuser, chaque port
fermé pouvait coûter le timeout complet (3s). Un run a dépassé largement 2 minutes en conditions
réelles avant d'être interrompu (requête toujours en cours au moment du redémarrage backend qui l'a
coupée). Corrigé : tous les actifs testés en parallèle, borné par un sémaphore
(`MAX_CONCURRENT_ASSETS = 50`) plutôt que sans limite. **Revérifié en conditions réelles après
correctif** : 409 actifs vérifiés en 24,7s (`{"checked":409,"warnings":125,"skipped_no_ip":23}`).

⚠️ **Limite connue, assumée** : un simple test TCP ne distingue pas un vrai panneau d'admin HTTP en
clair d'un serveur qui répond sur le port 80 juste pour rediriger vers HTTPS (portail captif Wi-Fi,
etc.) — une partie des 125 avertissements est probablement de ce type. Rester strictement passif
(pas de requête HTTP pour vérifier une redirection) était une condition explicite de l'utilisateur,
pas encore affiné.

**Patch check unitaire — fenêtre de cache trop courte (07/08/2026)** : retour utilisateur réel, le
bouton "Patch check" d'une ligne relance un vrai contrôle SSH/WinRM même en recliquant sur une vuln
déjà contrôlée, dès qu'on a entre-temps contrôlé 2-3 autres vulns du même actif. Cause :
`MIN_RECHECK_GAP` (`services/patch_checker.py`) à 30s, conçu à l'origine seulement contre le
double-clic/la modale rouverte juste après — trop court pour l'usage réel (contrôler plusieurs vulns
d'un même actif à la suite, puis revenir sur l'une d'elles). Porté à 5 minutes. `force=true` (bouton
"🔄 Relancer un scan") reste disponible pour forcer un vrai contrôle malgré le cache. `RECHECK_INTERVAL`
(24h, cycle automatique) non touché — sans rapport, gouverne quand une vuln déjà contrôlée redevient
éligible au cycle planifié, pas le cache anti-spam du bouton unitaire.

**PRTG — "depuis quand en ligne/hors ligne" ajouté (07/08/2026)** : `NetworkStatus.metrics.status_since`,
demandé par l'utilisateur en creusant "quoi d'autre exploiter avec la clé PRTG déjà en place ?".
⚠️ Hypothèse initiale fausse, corrigée avant de livrer : `content=devices` ne porte **pas**
`lastup_raw`/`lastdown_raw` (colonnes toujours vides, vérifié en conditions réelles) — ces dates
n'existent qu'au niveau capteur (`content=sensors`). `prtg_client.py::connectivity_timestamps_from_sensors`
sélectionne, par device, le capteur de joignabilité le plus fiable disponible
(`CONNECTIVITY_SENSOR_TYPE_PRIORITY = ("ping", "snmpuptime", "wmiuptime")` — pas n'importe quel
capteur : un capteur d'espace disque ou de trafic aurait donné un "depuis quand" trompeur, sans
rapport avec la joignabilité réelle du device). Date brute PRTG (`_raw`, jours depuis le 30/12/1899,
format Automation/OLE — même piège de localisation que `status`/`type` déjà rencontré sur PRTG)
convertie par `prtg_client.py::parse_prtg_date`, confirmée exacte en conditions réelles
(`46241.2753588542` ↔ `07/08/2026 08:36:31` CEST = `06:36:31 UTC`). `status_since` : `lastup_raw` si
`online`, `lastdown_raw` si `offline`/`alerting`, `None` si `dormant` ou si le device n'a aucun
capteur de joignabilité reconnu (ex. `TRINITY`, le serveur PRTG lui-même). Exposé dans
`GET /api/assets` (`network_status.status_since`) et affiché dans la tooltip de
`NetworkStatusBadge.jsx`. **Vérifié en conditions réelles** (`POST /api/prtg/run`, 406 `NetworkStatus`
mis à jour) : `status_since` correctement rempli pour la quasi-totalité des devices matchés — dates
cohérentes avec l'heure du sync pour les devices stables depuis peu, mais aussi une date ancienne
correcte pour un device qui n'a pas flappé depuis longtemps (`RENAULT`, `03/02/2026`), preuve que ce
n'est pas juste l'heure du sync recopiée partout.

✅ **Module Audits construit** (03/08/2026, cf. § invariants ci-dessus et `docs/AUDITS.md`, désormais
marqué implémenté) — n'est plus un point ouvert. Reste ouvert dans son périmètre : pas d'import
automatique Nmap/Burp/Nessus (délibérément écarté, cf. spec §7), preuves/mandats non testés en
navigateur au-delà du parcours E2E principal (upload de captures d'écran sur un finding vérifié
côté API seulement).

✅ **Reliquats du tour applicatif du 03/08/2026 traités** (même jour, un peu plus tard) — tous
sauf le refactor Dashboard (délibérément laissé de côté, risque de régression trop élevé pour un
passage non dédié) :
- **Tests ajoutés** : `backend/tests/test_crisis_guardrails.py` (20 tests — désactivation,
  assignation/retrait de rôle, rattachement/détachement d'incident, décision/communication) ;
  `test_audit_attachments.py` + `test_document_storage.py` (36 tests — un cas par format de
  signature, taille, extension inconnue, contenu ne correspondant pas à l'extension déclarée).
  Suite complète du projet : 134 tests, tous verts.
- **Déduplication** : `crisis_timeline.py`/`incident_timeline.py` délèguent désormais à une
  fabrique commune (`services/timeline.py::record_entry`, paramétrée par modèle ORM + nom de
  colonne) — signature publique de `record()` inchangée dans les deux fichiers, aucun appelant
  (`services/crisis.py`, `services/nis2_deadlines.py`, `routers/crises.py`, `routers/incidents.py`)
  à toucher. `AdministrationSecurity.jsx` : `ServicesTab`/`OrganizationRolesTab`/
  `WindowsAppMappingsTab` partagent désormais `useLoadList`/`useCrudModals` (chargement de liste +
  modales formulaire/suppression) au lieu de dupliquer la charpente trois fois — testé en
  conditions réelles (création/suppression Service, création correspondance Windows).
- **UX** : bouton "Scanner tout" sur Inventaire (`handleScanAll`, concurrence limitée à 3,
  compteur "X/72" dans le header, bannière si des actifs sont injoignables sans bloquer les
  autres) — testé en navigateur, arrêté après quelques actifs pour ne pas scanner tout le parc
  réel sans nécessité. Vue carte mobile sur Vulnérabilités (`renderActions()` extrait et partagé
  entre la table desktop et les cartes, `hidden sm:block`/`sm:hidden`) — testée en viewport 390px,
  table desktop inchangée en 1280px, aucune erreur console.
- **Second exemple de Correspondance Windows** : `Wireshark 4.6.6 x64` (réellement installé sur
  DEPLOYAPP) → `wireshark`, cf. § État du parc ci-dessus pour l'effet de bord (242 vulns réelles
  surfacées, dont 1 CRITICAL à trier manuellement).

📋 **Pilotage RNCP42335** : `ROADMAP_RNCP42335.md` (racine) aligne le projet sur le titre visé par
l'utilisateur, échéance **juillet 2028**. Contient la matrice de traçabilité compétence → artefact et
le séquencement jusqu'au gel des fonctionnalités (S1 2028). **À consulter avant de proposer un nouveau
chantier.** Distinction clé qui y est posée : certaines compétences se prouvent par un *acte réalisé*
(conduire un audit, mener une enquête OSINT), jamais par une fonctionnalité construite — l'outil
héberge la preuve, il ne l'est pas.

**Rien d'actionnable immédiatement** côté vulnérabilités : 0 vuln `open` sur le parc (cf. § État du parc).

**Rien en suspens sur ce front** : le statut « correctif partiel » (`awaiting_fix_partial`) est livré le
27/07/2026 — cf. § invariants « Statut correctif partiel ». Les 3 Debian mixtes (CVE-2023-31486,
CVE-2024-28757, CVE-2025-59375, `gitlab.aer.loc`) y sont migrées.

⚠️ **« 25 Windows sans issue (16 SSU/DBX + 9 sans KB) », affirmation du bilan du 21/07, retirée le
22/07/2026 : constatée fausse.** DEPLOYAPP n'a aujourd'hui que 12 lignes non `patched` (10
`false_positive` avec justification réelle, 2 `awaiting_fix`) — aucune ne correspond à ce blocage
« sans issue à droits constants ». Ces CVE ont dû être requalifiées entre-temps (session 21/07 elle-
même ou qualifications manuelles ultérieures) sans que `STATUS.md` soit corrigé. **Leçon retenue** :
une affirmation de blocage structurel doit être revérifiée contre la base avant d'être recopiée d'une
session à l'autre — cf. principe déjà énoncé pour l'audit de cohérence, § Invariants.

**Pistes non engagées** :
- **Envoi des rapports par email** : nécessiterait un SMTP, absent de `.env`. Écarté pour l'instant.
- **4e rapport** : la mécanique est générique — un `build_*_payload()` + une branche dans
  `generate_report`. Ni table, ni endpoint, ni tâche, ni écran à ajouter.

**Dette identifiée** :
- ~~**Correctifs de sécurité — 5 des 6 faits, le dernier volontairement différé**~~ **les 6 faits** :
  audit défensif du 24/07 dans `audit/AUDIT_SECURITE.md` (racine). #1 SSRF, #2 clé d'hôte SSH, #3 TLS LDAP,
  #4 `defusedxml`, #6 secrets par défaut → corrigés et testés en conditions réelles le 27/07/2026.
  #5 (`.gitignore` avant tout `git init`) différé tant qu'il n'y avait pas de repo git — **fait**
  depuis (`git init` posé le 14/08/2026, `.gitignore` en place). `pip-audit`/`npm audit` passés le
  27/07 : CVE restantes sur starlette/python-multipart **corrigées** (bump `fastapi` 0.115.0→0.140.0).
  CVE `react-router-dom`/`esbuild`-dev, laissées ouvertes le 27/07 faute de valider une montée
  majeure potentiellement cassante — **corrigées le 17/08/2026** (`react-router-dom` 7.18.2, `vite`
  7.3.6, `npm audit` à 0 vulnérabilité, cf. entrée de session ci-dessus). Durcissement runtime Docker
  (`cap_drop`, `no-new-privileges`, limites mémoire/CPU) fait le même jour (27/07) — cf. invariants
  ci-dessus pour les deux pièges rencontrés en le faisant.
- ~~**Table d'historique des statuts**~~ **fait le 27/07/2026** — `vulnerability_status_history`,
  cf. § Historique des changements de statut ci-dessus. A immédiatement servi à diagnostiquer
  CVE-2026-55199 (bascule automatique artificielle d'un test, repérée en un coup d'œil).
- ~~**Correspondance nom d'appli Windows → CVE**~~ **fait le 31/07/2026** — nouvelle table
  `WindowsAppMapping` (`models.py`), CRUD réservé admin (`routers/windows_app_mappings.py`,
  Administration > onglet « Correspondances Windows »), branchée dans `services/cpe_matcher.py`
  (`_installed_package_products`, `get_installed_package_vulnerabilities`, `run_cpe_matching*`,
  `asset_match_context`/`still_matches*`) et dans `patch_checker.py::check_patch` (garde-fou
  « rattachement invalide »). Cf. § invariant dédié ci-dessous.
- ~~**Aucune authentification**~~ **fait le 30/07/2026** — le module « Bastion » (sélecteur « Je
  suis… », `visible_modules`, filtrage de nav sans mot de passe ni session) a été retiré, remplacé
  par une vraie authentification : compte email/mot de passe (`bcrypt`), session par cookie HttpOnly,
  RBAC binaire admin/analyst, verrou anti-bruteforce (email + IP), toutes les routes `/api/*`
  protégées sauf `/api/health` et `POST /api/auth/login` (garde-fou testé,
  `tests/test_auth_guardrails.py`). Ferme au passage un vrai trou hérité de l'ancien verrou côté
  client d'`AdministrationSecurity.jsx` (mot de passe en clair dans le bundle JS, `/api/connections`
  et `/api/security/*` totalement ouverts jusque-là) — cf. docs/ARCHITECTURE.md § Authentification.
  Le registre de noms d'analystes (CRUD) reste séparé des comptes de connexion — décision
  reconfirmée après usage réel (l'utilisateur a expérimenté la confusion Utilisateur/Analyste puis
  choisi de garder les deux). Sa gestion a déménagé une seconde fois le même jour, de Paramètres vers
  **Administration** (onglet Analystes) : lecture ouverte à tout connecté, écriture réservée admin
  (avant, n'importe quel compte pouvait l'éditer depuis Paramètres).
  Mot de passe : **16 caractères minimum** (relevé le même jour depuis 12), champ avec bascule
  afficher/masquer (`PasswordInput.jsx`). Email d'un compte modifiable en édition (`UserFormModal.jsx`,
  contrôle d'unicité serveur). Plus de badge utilisateur/déconnexion dans la sidebar — déplacé dans
  Paramètres > section « Compte », en bas de page. Un second module « Bastion » (placeholder, sans
  rapport avec celui retiré ci-dessus) a été ajouté sous le groupe nav Sécurité, à côté d'Audits :
  futur accès bastion/jump host vers les serveurs critiques, portée pas encore définie — attention à
  la tension avec la règle de non-intervention (CLAUDE.md § 1) le jour où ce sera implémenté pour de
  vrai. **Reste ouvert** : Phase 2 (SSO Microsoft Entra ID / OIDC), pas engagée — le schéma n'anticipe
  pas encore de table `user_identities` dédiée, ajoutable via `schema_patches.sql` le moment venu sans
  réécriture.
- **Pas de vrai outil de migration de schéma** : `create_all` au démarrage ne modifie jamais une table
  existante. Convention établie le 27/07/2026 pour les `ALTER TABLE` : `backend/db/schema_patches.sql`,
  fichier idempotent unique à faire grossir au fil des sessions (plutôt que des `ALTER` ad hoc non
  tracés) — toujours à exécuter avec le rôle superuser `cybervuln`, jamais `cbr_app` (bloqué par
  `ddl_guard.sql`).
- **Modale de patch check dupliquée** entre `Dashboard.jsx` et `Vulnerabilities.jsx` — toute
  évolution doit être appliquée aux deux. Seule duplication restante : les modales de qualification
  (`BulkQualifyModal`), le rendu de rapport (`ReportMarkdown`) et les archives (`WeeklyArchives`) sont
  désormais factorisés.
- ~~**Aucune sauvegarde PostgreSQL**~~ **fait le 27/07/2026** — `pg_dump` quotidien + rétention 14j,
  cf. § invariant « Sauvegarde PostgreSQL » ci-dessus.
- ~~**Aucun test automatisé**~~ **fait le 27/07/2026** — 31 tests sur les garde-fous de patch check,
  cf. § invariant « Premiers tests automatisés » ci-dessus. Portée volontairement partielle (pas de
  DB, pas encore de test sur le matching/patch check réel).
- ~~**Pas de healthcheck backend/worker/beat/frontend**~~ **fait le 27/07/2026** — cf. § invariant
  « Healthchecks sur les 6 services » ci-dessus.
- ~~**Pas d'Error Boundary React**~~ **fait le 27/07/2026** — cf. § invariant « Error Boundary React »
  ci-dessus.
- ~~**Pas de rotation des logs Docker**~~ **fait le 27/07/2026** — cf. § invariant « Rotation des logs
  Docker » ci-dessus.
- ~~**Frontend en mode dev même en "production"**~~ **fait le 27/07/2026** — cf. § invariant « Build de
  production du frontend » ci-dessus. Mode dev reste le défaut (`docker compose up`), le build prod est
  disponible en opt-in (`docker compose up -d frontend-prod`).

