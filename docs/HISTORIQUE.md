# HISTORIQUE.md — Journal des sessions antérieures

## Charger uniquement pour retrouver le contexte d'une décision passée

Ce fichier n'est **pas** lu au démarrage : il sort du chemin de lecture systématique
(`CLAUDE.md` + `STATUS.md`) pour ne pas coûter de tokens à chaque session. `STATUS.md` ne conserve
que l'état courant, les invariants et les points ouverts ; tout le déroulé chronologique est ici.

Utile quand une question porte sur **pourquoi** une décision a été prise, ou sur un incident déjà
rencontré. Contenu déplacé tel quel le 21/07/2026, sans réécriture.

---

### Sessions précédentes (résumé cumulé)
- Fix crash app, modal Analyser enrichie, export PDF
- WinRM DEPLOYAPP débloqué (SDDL)
- Fix bug Celery queue + asyncpg rollback
- Sync NVD 30 jours (7 845 CVEs), CPE matching (85 CVEs parc)
- Patch check : 3 sources KB (WinRM Event Log + WMI + PSWindowsUpdate)
- Compte cybervuln ajouté au groupe "Lecteurs des journaux d'événements" (SID S-1-5-32-573)
- KB5094123 (Cumulative Update juin 2026 WS2019) détecté sur DEPLOYAPP
- Traçabilité des corrections : `validated_by` (dropdown analyste), filtre par analyste
- Fix bug RSS fetcher asyncpg : séparation phase HTTP/DB, `SessionLocal()` direct
- Page Synchronisation, Bouton Matching CVE, Suivi connexions IP, Dark/Light mode, Batch Patch Check
- Matching CVE automatique au démarrage, tri serveur Vulnérabilités, KPIs Dashboard restructurés, fix light mode
- **Module veille cyber NIS 2 complet** : 16 sources, 11 thèmes, registre auditable, export CSV, SLA 48h

### Session courante (25/06/2026)
- **Fix unicode filtre thèmes** : PostgreSQL stocke les accents en `\uXXXX` dans JSON. `_apply_themes()` dans `routers/watch.py` doublement des backslashes (`replace("\\", "\\\\")`) pour matcher littéralement — filtres `Données`, `Vulnérabilité`, `Réseau`, `Réglementation` fonctionnels
- **Dropdown sources horizontal** : panneau 3 colonnes côte à côte (OFFICIELLES / MÉDIAS & TRACKERS / ÉDITEURS SÉCU) — fini le déroulement vertical vers le bas
- **KPI "Critiques non traités"** : remplace "Non traités" générique — compte uniquement `severity=critical` ET `status IN (new, in_review)` ; champ `critical_untreated` ajouté dans `/api/watch/stats`
- **Thème "Fuite de données"** (11e thème) : ajouté backend (THEME_KEYWORDS + SOURCE_DEFAULT_THEMES) et frontend ; backfill 10 items existants (ZATAZ, fuitesinfos, bonjourlafuite)
- **`docs/VEILLE.md` créé** : Étape 3 complète — 10 sections (sources, thèmes, workflow, SLA, procédure auditeur NIS 2 avec 5 Q&R types, modèle SQL, maintenance)

### Session courante (01/07/2026) — Patch check automatique + fiabilisation dashboard

**Bug critique corrigé — sync NVD cassée**
- `database.py` : `poolclass=NullPool` — les tâches Celery ouvrent chacune une boucle asyncio différente ;
  un pool persistant survivait à la fermeture de la boucle qui l'a créé → `cannot perform operation:
  another operation is in progress` en cascade dès qu'un incident réseau NVD déclenchait un retry.
  Sync passée de 0 créée/2300 erreurs à 0 erreur après fix. Testé sous charge concurrente (3 syncs simultanées).

**Patch check automatique au démarrage**
- `models.py` : colonnes `last_patch_check`, `patch_check_result` sur `Vulnerability`
- `services/patch_checker.py` : `run_startup_patch_checks()` (vérifie les vulns jamais contrôlées, séquentiel),
  `apply_patch_result()` (règle CRITICAL=manuel / HIGH-MEDIUM-LOW=auto-patched), `backfill_auto_patch()`
  (réconcilie les résultats déjà collectés avec la règle actuelle), `run_full_patch_check_cycle()` (rattrapage
  + check, réutilisable, verrou anti-concurrence), `fetch_msrc_kb_products()` + `_kb_matches_asset_os()`
  (info : le KB installé cible-t-il bien l'OS déclaré de l'actif ? — jamais bloquant)
- `main.py` : cycle lancé en tâche de fond au démarrage (non bloquant pour l'API)
- `routers/patch_check.py` : `GET /status` (polling dashboard), `POST /run` (déclenchement manuel)
- `routers/vulnerabilities.py` : `patch_detected` exposé dans `_vuln_dict` ; **fix important** — repasser
  une vuln à `open`/`in_progress`/`accepted_risk` vide maintenant `last_patch_check`/`patch_check_result`
  (sinon le rattrapage suivant la re-bascule instantanément en `patched` sur un résultat périmé)
- **`backend/routers.py` supprimé** : code mort jamais importé (le package `routers/` prenait le dessus)

**Dashboard — patch check UI**
- Bandeau "Analyse en cours" avec barre de progression (X/Y), poll `GET /api/patch-check/status` toutes les 3s
- Bouton "Patch check global" (à côté de "Matching CVE") → `POST /api/patch-check/run`
- Badge "Patched" (petit tag vert à côté du CVE ID) dans "à traiter" ET "traitées"
- Bouton "🔍 Patch check" ajouté aussi dans "Vulnérabilités traitées" (spot-check une vuln déjà corrigée)
- KPI "Taux de correction global" : couleurs alignées sur "Taux de correction par sévérité" (vert ≥80%, orange ≥50%, rouge sinon)
- **2 bugs React corrigés** (StrictMode double-invoke d'un setState imbriqué + closure périmée dans le
  polling `useEffect(...,[])` qui figeait `openVulns` à `[]` pour toujours) — `openVulnsRef` ajouté

**Méthodologie de test** : vérification systématique en navigateur réel (Playwright headless via conteneur
Docker, réseau `--network host` — le nom d'hôte `frontend` est bloqué par `allowedHosts` de Vite) plutôt
que sur la seule lecture du code. A permis de détecter les 2 bugs React ci-dessus, invisibles en review.

**Onglet Actifs — CRUD complet + scan read-only**
- Ajouter un actif : bouton haut-droit, modale (nom, hostname, IP, OS, version, type) — pas de mot de
  passe par actif, un seul compte de service sert pour tout le parc (`POST /api/assets`, `source="manual"`)
- Modifier un actif : même modale en mode édition (`PUT /api/assets/{id}`)
- Supprimer un actif : modale d'avertissement, exige de retaper le nom exact pour activer le bouton ;
  suppression en cascade des vulnérabilités liées (pas de `ON DELETE CASCADE` en DB, géré explicitement
  dans `routers/assets.py`)
- Scanner (fiabilité + applications) : `services/asset_scanner.py` (nouveau) — vérifie hostname/OS/version
  déclarés vs détectés, collecte les applications installées. **Le compte de service n'a pas les droits
  WMI/CIM** (`Get-WmiObject`/`Get-CimInstance` → accès refusé, contrairement à `Win32_QuickFixEngineering`
  utilisé par `patch_checker.py` qui lui est autorisé) — bascule sur lecture registre
  (`HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion`) + `$env:COMPUTERNAME` pour hostname/OS
- Colonnes `installed_packages`, `last_scan_result` ajoutées sur `Asset`

### Session courante (01/07/2026) — Refonte architecture : rebranding CBR + module Inventaire

**Rebranding** : le produit s'appelle désormais **CBR**, "CyberVuln" devient le nom du module de
gestion de vulnérabilités (un sous-ensemble, pas tout l'outil). Renommé dans `Layout.jsx` (logo
sidebar) et `index.html` (`<title>`) uniquement — le code interne (dossier `backend/`, noms de
variables) garde "CyberVuln" par simplicité, pas de renommage en profondeur.

**Nav à deux niveaux** (`Layout.jsx`, restructuré en `NAV_GROUPS`) :
```
CBR
├── CyberVuln : Dashboard / Vulnérabilités / Actifs / CVE / Rapports
├── Veille        (transverse, existant)
├── Inventaire    (transverse, nouveau)
├── Pentest       (transverse, nouveau — placeholder vide)
└── Paramètres    (transverse, existant)
```

**Module Inventaire** (`pages/Inventaire.jsx`, route `/inventaire`, nouveau) — vue *patrimoine IT*,
distincte d'Actifs (vue *sécurité*). Mêmes actifs en base (table `assets`), présentation différente :
specs matérielles (CPU, cœurs, RAM, disques) + applications installées, avec bouton "Scanner" par ligne.

**Specs matérielles collectées** (`services/asset_scanner.py` étendu, colonne `hardware` JSONB sur
`Asset`) — même connexion WinRM/SSH que le scan de fiabilité existant, aucun appel réseau
supplémentaire :
- Windows : CPU via registre (déjà fait pour l'OS), RAM totale via **appel natif `GlobalMemoryStatusEx`**
  (P/Invoke direct sur `kernel32.dll`, contourne WMI), disques via `[System.IO.DriveInfo]` (.NET,
  contourne WMI aussi) — testé : `systeminfo` (qui utilise WMI en interne) échoue aussi avec ce compte
- Linux : `lscpu`, `nproc`, `free -g`, `df -BG` (SSH, aucun droit spécial requis)

**Module Pentest** (`pages/Pentest.jsx`, route `/pentest`, nouveau) : placeholder "Rien pour l'instant"
sans aucune logique — portée à définir plus tard. Point de vigilance noté dans CLAUDE.md : si ce module
finit par déclencher des actions offensives, ça entrera en tension directe avec la règle de
non-intervention — à trancher explicitement avant d'implémenter quoi que ce soit dedans.

**Page d'accueil + module Administration** (même session) :
- `pages/Home.jsx` (nouveau, route `/`) — sélecteur de module en tuiles (CyberVuln, Veille, Inventaire,
  Pentest, Administration, Paramètres), affiché **sans sidebar** (en dehors de `<Layout>`)
- Dashboard déplacé de `/` vers `/dashboard` pour libérer la route racine
- `App.jsx` : deux `<Route path="/">` sœurs (Home sans enfants + Layout avec ses routes filles) — motif
  volontaire, documenté dans `docs/FRONTEND.md`, pas un bug
- `pages/Administration.jsx` (nouveau, route `/administration`) : placeholder "Rien pour l'instant",
  comme Pentest — même point de vigilance à garder en tête si un périmètre concret lui est donné plus tard
- `Layout.jsx` : logo/titre "CBR" devient un lien vers `/`, entrée "Administration" ajoutée à la nav
- Logo CBR (sidebar + Home) : bouclier + épées croisées (remplace bouclier+check) ; icône Veille :
  œil au lieu d'un logo wifi jugé incohérent

**Page CVE — colonne date, fenêtre 15j, sync incrémentale** (même session) :
- Colonne "Publiée" déplacée entre CVE ID et Description (le CVE ID est aussi devenu un vrai lien
  externe vers la fiche NVD, `target="_blank"`, sur Dashboard/Vulnérabilités/CVE — avant c'était du
  texte stylé sans lien réel)
- Page CVE affiche désormais **toutes** les CVE (`matched_only=false`) des 15 derniers jours, pas
  seulement celles touchant le parc — 30j testé en réel (~6 min, API NVD elle-même limitante), 15j
  retenu comme dans la fourchette proposée
- Bouton "Actualiser" → dropdown 2 choix (7 / 15 jours), déclenche `POST /api/sync/nvd`, suit la
  progression par polling (`GET /api/sync/status/{id}`)
- **Sync NVD rendue incrémentale** (`nvd_fetcher.py`, `incremental=True` par défaut) : si des CVE
  existent déjà en base, interroge NVD par date de modification (`lastModStartDate`) depuis
  `MAX(CVE.modified)` plutôt que de retélécharger toute la fenêtre `days` à chaque clic. Gain mesuré :
  73s/2271 CVE → 1.5s/2 CVE sur un appel répété. **Piège rencontré** : le premier test montrait encore
  l'ancien comportement lent — le code était bien modifié mais seul `backend` avait été redémarré,
  pas `worker` (le process Celery qui exécute réellement la tâche, sans hot-reload)

### Session courante (03/07/2026) — Mode Présentation (Anonyme)

**Objectif** : pouvoir présenter/démo CyberVuln (ex : à un prospect) sans jamais afficher de vraie
donnée du parc — noms d'actifs, IP, noms d'analystes. 100% frontend, aucune donnée fictive écrite en
base, aucune vraie donnée envoyée nulle part.

- `frontend/src/contexts/PresentationContext.jsx` (nouveau) — `isAnonymous` + `toggle()`, persisté en
  `localStorage` (`presentation_mode`), même pattern que `ThemeContext`
- `frontend/src/utils/fakeData.js` (nouveau) — cœur du mode :
  - `FAKE_ASSETS` (24 actifs 100% inventés, id `demo-asset-N`) + `FAKE_VULNERABILITIES` (2-6 par
    actif, statuts variés) + `FAKE_CVE_POOL` (CVE fictives, IDs `CVE-2026-710xx` inventés — jamais de
    vraie CVE réutilisée) + `FAKE_VALIDATORS` (6 faux noms d'analystes)
  - `isFakeId(id)` — convention `demo-*` pour distinguer une entité 100% fictive d'une entité réelle
    affichée sous nom anonymisé (id réel conservé dans ce 2e cas)
  - `anonymizeAsset`/`anonymizeVuln`/`anonymizeValidator`/`anonymizeConnection` — remplacent nom/
    hostname/IP/analyste réels par un équivalent fictif **déterministe** (hash du vrai id/nom → même
    faux nom à chaque fois, partout dans l'app), sans jamais toucher l'id réel
  - **Deux pools de noms distincts** (`FAKE_ASSET_NAMES` pour le padding, `ANON_REAL_NAMES` pour les
    actifs réels anonymisés) — un seul pool aurait fait certains vrais actifs porter par coïncidence
    le même nom qu'un actif de démo déjà affiché dans la même liste (bug constaté, corrigé)
  - `redactText(text, realAssets, realValidatorNames)` — reformate un texte libre (résumé exécutif,
    export CSV) en y remplaçant toute occurrence de nom/hostname/IP d'actif réel **et** de nom
    d'analyste réel par leur équivalent fictif
  - `computeDashboardStats(...)` — recalcule les KPI (taux de correction, actifs exposés,
    `severity_rates`) localement depuis les listes déjà fusionnées réel+fictif, sur le même modèle que
    `backend/services/stats.py` (le backend ignore tout des données de démo)
  - `fakePatchCheckResult`/`fakeAnalysis`/`fakeRecommendation`/`fakeScript` — simulent localement le
    résultat des actions (Analyser, Patch check, Recommandation, Script) sur les vulns fictives, sans
    aucun appel réseau
- `Settings.jsx` — nouvelle section "Présentation" au-dessus d'"Apparence", switch "Anonyme" (même
  style pill que le toggle de thème)
- Câblage par page :
  - `Dashboard.jsx` : au fetch initial, fusionne actifs/vulns réels (anonymisés) + fictifs dans le
    state React existant (pas de re-fetch au toggle, juste un re-merge) ; `displayKpis` bascule entre
    `kpis` (backend, mode normal) et `computeDashboardStats(...)` (local, mode Anonyme)
  - `Assets.jsx` / `Inventaire.jsx` : mêmes 24 actifs fictifs ajoutés à la liste ; scan/édition/
    suppression désactivés sur les lignes fictives (pas de ligne DB derrière) ou simulés localement
    (scan d'un actif fictif = relit directement ses données déjà en mémoire, pas d'appel réseau)
  - `Vulnerabilities.jsx` : liste paginée côté backend en mode normal ; en mode Anonyme, un seul fetch
    (`per_page=200` — **limite dure côté backend `le=200`**, un premier essai à `per_page=1000`
    renvoyait un 422) puis fusion/tri/pagination **côté client** avec le pool fictif filtré par les
    mêmes filtres actifs (statut/sévérité/analyste)
  - `Reports.jsx` : `realAssetList` (brut, sert de base à `redactText`) distinct de `displayAssetList`
    (anonymisé + complété par les 24 actifs fictifs, utilisé par le filtre `AssetDropdown`) — **bug
    trouvé en test** : le filtre "Tous les actifs" affichait les vrais hostnames en clair
    (`DEPLOYAPP`, `gitlab.aer.loc`) car seul le texte généré (résumé/CSV) était redacté, pas la liste
    elle-même. Résumé exécutif/export CSV : seuls les ids d'actifs **réels** de la sélection sont
    envoyés au backend (`onlyFakeAssetsSelected()` bloque l'appel si la sélection ne contient que des
    actifs de démo, message d'erreur plutôt qu'un résumé trompeur sur tout le parc). Connexions IP
    anonymisées (`anonymizeConnection`)
  - `ValidateDropdown.jsx` / `AnnotationModal.jsx` : listent `FAKE_VALIDATORS` au lieu des vrais
    `ANALYSTS` dès que `isAnonymous` est actif — **corollaire important** : comme le nom choisi est
    désormais toujours fictif, `handleMarkPatched`/`handleMarkAwaitingFix`/`handleMarkFalsePositive`
    (Dashboard) et `handleMarkPatched`/`handleStatus` (Vulnerabilities) n'écrivent **plus du tout**
    dans le vrai backend tant que le mode Anonyme est actif (avant : seul `demo-*` était bloqué) — pour
    ne jamais polluer l'historique de validation d'une vraie vulnérabilité avec une identité inventée
- **Bug trouvé en test** (Playwright, cf. méthodologie ci-dessous) : décalage de bits signé (`h >> 8`)
  appliqué à un hash déjà normalisé non-signé (`h >>> 0`) — pour `h >= 2^31`, `>>` traite la valeur
  comme négative et produit un octet d'IP négatif (`10.99.227.-201` observé sur les connexions
  anonymisées et les actifs réels anonymisés). Corrigé en `>>> 8` (décalage non-signé) dans
  `fakeIpForReal` et `anonymizeConnection`.
- **Méthodologie de test** : vérification systématique en navigateur réel (conteneur
  `mcr.microsoft.com/playwright`, `--network host`), pas seulement lecture de code — a permis de
  détecter les 3 bugs ci-dessus (limite `per_page`, collision de noms, décalage signé) invisibles en
  review.
- Favicon (`frontend/public/favicon.svg`, nouveau) — reprend le logo CBR (bouclier + épées croisées,
  fond `#1f6feb`) déjà utilisé dans `Layout.jsx`/`Home.jsx`, référencé dans `index.html` — le site
  n'avait aucun favicon jusque-là.

### Session courante (03/07/2026, suite) — Architecture CPU (32/64 bits) au scan d'actif

- `backend/services/asset_scanner.py` : `_format_arch()` (nouveau helper) normalise l'architecture
  brute en libellé lisible (`64 bits (x64)`, `64 bits (ARM64)`, `32 bits (x86)`...), valeur brute
  conservée telle quelle si non reconnue plutôt que masquée
  - Windows : `$env:PROCESSOR_ARCHITECTURE` (AMD64/x86/ARM64) — variable d'environnement, pas de WMI
    (même contrainte que le reste du scan, cf. `docs/ARCHITECTURE.md`)
  - Linux : `uname -m` (SSH, aucun droit spécial) — ajouté à la liste des commandes autorisées dans
    `docs/SECURITY.md`
  - Résultat exposé dans `hardware.arch` (JSONB `assets.hardware`), testé en réel sur les 2 actifs du
    parc (Windows → "64 bits (x64)", Debian → "64 bits (x64)")
- Frontend : ligne "Architecture" ajoutée dans les modales de detail specs matérielles (`Assets.jsx`
  `ScanResultModal`, `Inventaire.jsx` `PackagesModal`) + colonne "Arch." dans le tableau principal
  d'Inventaire ; actifs fictifs du mode Présentation portent aussi une architecture (`64 bits (x64)`)
  pour rester cohérents
- Les actifs déjà scannés avant ce changement affichent "—" jusqu'à leur prochain scan (l'info
  n'était pas collectée avant, pas de rétro-remplissage automatique)

### Session courante (03/07/2026, suite) — Module Pentest construit puis retiré

Décision produit explorée en session : Pentest comme hub de suivi d'engagements/findings (pas de
scan actif, cohérent avec la règle de non-intervention). Prototype complet implémenté et testé
(modèles `PentestEngagement`/`PentestFinding`, `routers/pentest.py`, réécriture de `Pentest.jsx`,
généralisation légère d'`AnnotationModal`/`AnnotationDetailModal`) — CRUD, transitions de statut et
cascade de suppression validés au `curl`, création d'engagement/finding vérifiée en navigateur réel.

**Revirement** : retiré intégralement à la demande de l'utilisateur avant merge — pas de besoin
confirmé pour l'instant. Tout a été effacé : `backend/routers/pentest.py` supprimé, les deux modèles
retirés de `models.py`, le montage retiré de `main.py`, tables `pentest_engagements`/`pentest_findings`
droppées en base (elles ne contenaient que des données de test créées pendant cette session),
`Pentest.jsx` restauré à son placeholder d'origine, les exports `pentest*` retirés de `client.js`, et
les props `title`/`target` ajoutées à `AnnotationModal`/`AnnotationDetailModal` retirées (elles
n'étaient utiles qu'au module supprimé). `CLAUDE.md` n'a jamais été modifié pour ce module — le
paragraphe Pentest y est resté "placeholder, portée à définir" tout du long, donc rien à revenir
dessus. Le module reste à l'état de placeholder ; le design (hub de suivi, pas de scan actif) reste
une piste valable si le besoin se confirme plus tard.

---

## ✅ Fichiers complétés

### Infrastructure
- `docker-compose.yml` — 6 services : db, redis, backend, worker, beat, frontend
- `.env` — NVD_API_KEY + AD (AER.LOC) + WinRM configurés

### Backend
- `backend/main.py` — FastAPI, 10 routers montés (dont connections) ; lifespan lance le cycle patch check
  en tâche de fond au démarrage (`run_full_patch_check_cycle`)
- `backend/config.py` — DATABASE_URL + WINRM_USER/PASSWORD/PORT/TRANSPORT
- `backend/database.py` — SQLAlchemy async, PostgreSQL, **`poolclass=NullPool`** (fix cascade d'erreurs Celery/asyncio)
- `backend/models.py` — CVE, Asset, Vulnerability, Feed, ConnectionLog — colonnes `validated_by`,
  `last_patch_check`, `patch_check_result` ajoutées sur Vulnerability
- `backend/routers/vulnerabilities.py` — PATCH accepte `validated_by`, GET filtre + tri (`sort_by`, `sort_dir`),
  `published` + `patch_detected` dans la réponse ; PATCH vide `last_patch_check`/`patch_check_result` quand
  le statut quitte `patched`
- `backend/routers/patch_check.py` — `POST /{vuln_id}` (check unique + auto-bascule), `GET /status`
  (polling), `POST /run` (cycle complet manuel, anti-concurrence)
- `backend/routers/connections.py` — POST log + GET liste (500 dernières)
- `backend/routers/stats.py` — KPIs + `severity_rates` (CRITICAL/HIGH/MEDIUM/LOW : total, patched, rate)
- `backend/services/nvd_fetcher.py` — `SessionLocal()` direct (fix Celery)
- `backend/services/rss_fetcher.py` — séparation HTTP/DB, `SessionLocal()` direct (fix asyncpg)
- `backend/services/cpe_matcher.py` — matching CPE préfixe + fallback mots-clés
- `backend/services/scoring.py` — `min(cvss × epss × criticité, 10.0)`
- `backend/services/patch_checker.py` — WinRM read-only, 3 sources KB, cycle auto/manuel, règle
  CRITICAL=manuel / HIGH-MEDIUM-LOW=auto-patched, `kb_os_hint` informatif
- `backend/services/asset_importer.py` — LDAP SIMPLE auth
- `backend/services/asset_scanner.py` (nouveau) — scan read-only fiabilité (hostname/OS/version) +
  applications installées + specs matérielles (CPU/**architecture 32/64 bits**/cœurs/RAM/disques),
  Windows (WinRM, sans WMI/CIM, `$env:PROCESSOR_ARCHITECTURE`) et Linux (SSH, `uname -m`)
- `backend/routers/assets.py` — CRUD complet (POST/PUT/DELETE), `POST /{id}/scan`, `GET /{id}/packages`,
  `vuln_count`/`package_count`/`hardware` exposés dans `_asset_dict`
- `backend/tasks/scheduled_tasks.py` — Celery beat : NVD toutes les 4h, RSS toutes les heures
- ~~`backend/routers.py`~~ — supprimé (code mort jamais importé)

### Frontend
- `frontend/src/index.css` — CSS variables dark/light
- `frontend/src/contexts/ThemeContext.jsx` — ThemeProvider + useTheme hook
- `frontend/src/contexts/PresentationContext.jsx` (nouveau) — `isAnonymous` + `toggle()`, mode
  Présentation, persisté en localStorage, même pattern que ThemeContext
- `frontend/src/utils/fakeData.js` (nouveau) — pools d'actifs/vulns/analystes 100% fictifs, helpers
  d'anonymisation (déterministes, id réel conservé), simulateurs d'actions locales — détail complet
  dans `docs/FRONTEND.md` § Mode Présentation
- `frontend/src/App.jsx` — ThemeProvider + **PresentationProvider**, ConnectionTracker (log au
  démarrage), route `/` = Home (sans Layout) + routes /dashboard, /sync, /veille, /inventaire,
  /pentest, /administration sous `<Layout>`
- `frontend/src/components/Layout.jsx` — nav à 2 niveaux (`NAV_GROUPS`) : groupe "CyberVuln" + items
  transverses (Veille/Inventaire/Pentest/Administration/Paramètres), logo/titre **CBR** cliquable → `/`
- `frontend/src/components/ValidateDropdown.jsx` — dropdown analyste, `position: fixed`, CSS vars ;
  liste `FAKE_VALIDATORS` au lieu des vrais `ANALYSTS` en mode Présentation
- `frontend/src/components/AnnotationModal.jsx` — même bascule `FAKE_VALIDATORS`/`ANALYSTS` selon le
  mode Présentation
- `frontend/src/pages/Dashboard.jsx` — KPIs (3 cartes + carte sévérité, couleurs alignées 80/50%), batch
  patch check, filtre sévérité, tri client, colonne Publié, Matching CVE + **Patch check global**, CSS
  vars, bandeau "Analyse en cours" + barre de progression, badges "Patched", `openVulnsRef` (fix closure
  périmée du polling) ; mode Présentation : fusion réel(anonymisé)+fictif au fetch, `displayKpis`
  local, actions simulées sur `demo-*`, aucune écriture backend tant que le mode est actif
- `frontend/src/pages/Vulnerabilities.jsx` — filtre analyste, tri serveur (sort_by/sort_dir), en-têtes
  cliquables, colonne Publié, score CVSS, CSS vars ; mode Présentation : fusion/tri/pagination côté
  client (`per_page=200`, limite backend), même règle "aucune écriture" que Dashboard
- `frontend/src/components/SeverityBadge.jsx` — inline styles rgba (compatible dark/light), suppression classes Tailwind dark-only
- `frontend/src/pages/Sync.jsx` — NVD 7j/30j, Import actifs, Recalcul scores
- `frontend/src/pages/Settings.jsx` — toggle dark/light mode + **switch "Anonyme"** (section
  "Présentation", au-dessus d'"Apparence"), "À propos"
- `frontend/src/pages/Reports.jsx` — résumé exécutif + section Connexions IP (mot de passe protégée),
  CSS vars ; mode Présentation : `realAssetList` vs `displayAssetList`, `redactText` sur résumé/CSV
  (actifs + analystes), Connexions IP anonymisées
- `frontend/src/pages/CVEs.jsx` — CSS vars
- `frontend/src/pages/Assets.jsx` — CRUD complet (ajouter/modifier/supprimer avec confirmation), scan
  read-only par ligne (`ScanResultModal`, colonne **Architecture**), badge apps installées ; mode
  Présentation : 24 actifs fictifs ajoutés, actions désactivées/simulées sur ces lignes
- `frontend/src/pages/Inventaire.jsx` (nouveau) — vue patrimoine IT (hardware + apps + **architecture**),
  route `/inventaire` ; mode Présentation : mêmes 24 actifs fictifs que Assets.jsx
- `frontend/src/pages/Pentest.jsx` (nouveau) — placeholder, route `/pentest`
- `frontend/src/pages/Administration.jsx` (nouveau) — placeholder, route `/administration`
- `frontend/src/pages/Home.jsx` (nouveau) — page d'accueil/sélecteur de module, route `/`, sans sidebar
- `frontend/index.html` — `<title>CBR</title>` (était `CyberVuln`), favicon SVG ajouté
- `frontend/public/favicon.svg` (nouveau) — logo CBR (bouclier + épées croisées), absent jusqu'ici
- `frontend/src/api/client.js` — logConnection, getConnections, syncMatch, patchCheckStatus, patchCheckRun,
  createAsset, updateAsset, deleteAsset, scanAsset, getAssetPackages ajoutés

---

## 📊 État de la base de données

| Donnée | Valeur |
|--------|--------|
| Actifs importés | 1 (DEPLOYAPP — OU Test / AER.LOC) |
| CVE totales NVD en base | ~9 459 (30 jours + delta quotidien) |
| **CVE concernant le parc** | **84** (matching CPE + mots-clés) |
| dont CRITICAL | 3 · HIGH | 63 · MEDIUM | 17 · LOW | 1 |
| Vulnérabilités | 84 sur DEPLOYAPP — 84 `patched` (dont 3 CRITICAL validées manuellement, le reste via patch check auto) |

---

## ✅ État actuel — 6/6 services UP

- Dashboard : http://localhost:3000
- API docs  : http://localhost:8000/api/docs
- `docker compose up -d --force-recreate backend worker` → recharge le .env
- `docker compose restart frontend` → rechargement obligatoire après modifs frontend (WSL2)

---

## ✅ WinRM DEPLOYAPP — Opérationnel

- Root WinRM SDDL débloqué
- `cybervuln` dans le groupe "Lecteurs des journaux d'événements" (SID S-1-5-32-573)
- Patch check fonctionnel : détecte KB via System Event Log (Event ID 19, ProviderName WindowsUpdateClient)
- Logique de détection : `patch_detected = len(installed) > 0` — un seul KB suffit (chaque KB cible une version Windows)

---

## ✅ Patch check DEPLOYAPP — Automatisé

KB5094123 (Cumulative Update juin 2026 WS2019) installé le 23/06/2026, couvre plusieurs CVE simultanément.

Le patch check tourne maintenant automatiquement (démarrage backend + bouton "Patch check global") :
CRITICAL signalé pour validation manuelle, HIGH/MEDIUM/LOW basculées automatiquement en `patched` si
détectées. Plus d'action manuelle à faire pour les non-CRITICAL — seules les 3 CRITICAL nécessitent
une validation humaine explicite (cf. `CLAUDE.md` § Non-intervention).

---

## ⚠️ RSS Feeds — État partiel

| Flux | Statut |
|------|--------|
| Exploit-DB | ✅ Fonctionnel |
| CERT-FR Avis | ⚠️ Retourne HTML (réseau on-premise — vérifier proxy/accès internet depuis Docker) |
| CERT-FR Alertes | ⚠️ Même raison |
| GitHub Advisories | ⚠️ 406 Not Acceptable — nécessite un token GitHub (`GITHUB_TOKEN=ghp_xxx` dans `.env`) |

Les flux RSS ne bloquent plus le worker (bug asyncpg corrigé) — les erreurs sont loggées et ignorées.

---

## ⏳ Prochaines étapes

1. ~~Appliquer fix SDDL DEPLOYAPP~~ ✅
2. ~~Sync NVD complète~~ ✅
3. ~~CPE matching~~ ✅
4. ~~Patch check fonctionnel~~ ✅
5. ~~Fix bug RSS asyncpg~~ ✅
6. **Étendre l'import AD** à l'OU de production : modifier `AD_OU` dans `.env`, puis `curl -X POST http://localhost:8000/api/sync/assets`
7. **Relancer le matching** après import AD : `curl -X POST http://localhost:8000/api/sync/match`
8. *Optionnel* — GitHub RSS : ajouter `GITHUB_TOKEN` dans `.env` + passer le header dans `rss_fetcher.py`

---

## 🔭 Chantier en cours — Outil de veille cyber (NIS 2)

**Objectif :** module de veille cyber auditable NIS 2, avec registre de traitement prouvable à un auditeur ANSSI.

### Ordre d'implémentation

#### Étape 1 — Backend ✅
- [x] Modèle `WatchItem` dans `models.py`
  - Champs : `id`, `source`, `source_label`, `title`, `url` (unique, clé de dédup), `published_at`, `received_at`, `severity` (critical/important/informational), `status` (new/in_review/treated/not_applicable), `reviewed_by`, `reviewed_at`, `decision`, `linked_cve_id`, `cve_ids_found`
- [x] `backend/services/watch_fetcher.py` — agrégateur RSS multi-sources
  - 10 sources : CERT-FR (avis + alertes + bulletins), ANSSI, Cybermalveillance, Sekoia, HarfangLab, Synacktiv, Intrinsec, No Limit Secu
  - Sévérité par source (cert-fr-alerte → critical, avis/anssi → important, blogs → informational)
  - Élévation par mots-clés titre (0day, ransomware, RCE…)
  - Déduplication par URL, pattern asyncpg respecté (phase HTTP séparée de phase DB)
- [x] `backend/routers/watch.py` — endpoints CRUD + export
  - `GET /api/watch` (filtres : source, status, severity, reviewed_by, date, sla_only)
  - `PATCH /api/watch/{id}` (status, reviewed_by, decision, linked_cve_id — reviewed_at auto)
  - `GET /api/watch/stats` → KPIs NIS 2 complets
  - `GET /api/watch/export` → CSV auditeur (`;` delimiter, UTF-8)
  - `POST /api/watch/sync` → déclenchement manuel
- [x] Celery beat : `sync_watch_feeds` toutes les heures à H+10
- [x] SLA 48h : `sla_exceeded` calculé à la volée, filtre `sla_only=true` disponible

#### Étape 2 — Frontend ✅
- [x] `frontend/src/pages/Watch.jsx` — page `/veille` complète
  - KPIs (4 cartes) : non traités, SLA dépassé, taux traitement 30j, délai moyen
  - **Filtres multi-sélection** :
    - Sources : dropdown avec cases à cocher, groupées (Officielles / Médias & trackers / Éditeurs sécu)
    - Sévérité : chips cliquables (Critique / Important / Informatif)
    - Thèmes : chips cliquables (Cyber, Admin, Réseau, Hardware, Software, Données, Réglementation, Ransomware, APT, Vulnérabilité)
    - Toggle SLA dépassé
  - Tableau avec colonne Thèmes (badges bleus), CVEs auto-détectées, lien source, délai de traitement
  - Lignes SLA dépassé surlignées en rouge
  - Modal de traitement : 3 boutons statut + analyste + CVE liée + décision, thèmes affichés dans le header
  - Export CSV auditeur avec colonne Thèmes
  - Bouton Sync manuel avec retour stats
- [x] `frontend/src/api/client.js` — 5 nouvelles fonctions
- [x] `frontend/src/App.jsx` — route `/veille` ajoutée
- [x] `frontend/src/components/Layout.jsx` — entrée "Veille" dans la nav (avant Rapports)

#### Sources veille — 16 flux configurés
| Groupe | Sources |
|--------|---------|
| Officielles françaises | CERT-FR Avis, CERT-FR Alertes, CERT-FR Bulletins, ANSSI, CNIL, Cybermalveillance |
| Médias & trackers | IT Connect, ZATAZ, Global Security Mag, fuitesinfos.fr, Bonjour la fuite |
| Éditeurs sécu | Sekoia, HarfangLab, Synacktiv, Intrinsec, No Limit Secu |

#### Thèmes auto-catégorisés (11)
`Cyber` `Admin` `Réseau` `Hardware` `Software` `Données` `Fuite de données` `Réglementation` `Ransomware` `APT` `Vulnérabilité`
- Attribution par source (ex: CNIL → Données + Réglementation)
- Enrichissement par mots-clés dans titre + résumé
- Filtres multi-sélection OR côté backend
- **Fix unicode** : PostgreSQL stocke le JSON avec des échappements unicode (`é` → `é`). Le LIKE doit doubler les backslashes pour les matcher littéralement. Résolu dans `_apply_themes()` via `json.dumps()[1:-1].replace('\\', '\\\\')` ✅

#### Modèle BDD mis à jour
- Colonne `themes` (JSON) ajoutée à `watch_items` — **recréer la table si elle existe déjà**

#### Étape 3 — Documentation ✅
- [x] `docs/VEILLE.md` — sources 16 flux, workflow traitement, SLA 48h, procédure auditeur NIS 2 complète (7 sections)

### Sources retenues (ordre de priorité)
| Source | URL RSS | Priorité |
|--------|---------|----------|
| CERT-FR Avis | https://www.cert.ssi.gouv.fr/avis/feed/ | Obligatoire |
| CERT-FR Alertes | https://www.cert.ssi.gouv.fr/alerte/feed/ | Obligatoire |
| CERT-FR Bulletins | https://www.cert.ssi.gouv.fr/actualite/feed/ | Haute |
| ANSSI | https://www.ssi.gouv.fr/feed/ | Haute |
| Cybermalveillance | https://www.cybermalveillance.gouv.fr/feed/ | Haute |
| Sekoia blog | https://blog.sekoia.io/feed/ | Moyenne |
| HarfangLab blog | https://harfanglab.io/feed/ | Moyenne |
| Synacktiv blog | https://www.synacktiv.com/feed.rss | Moyenne |
| Intrinsec blog | https://www.intrinsec.com/feed/ | Moyenne |
| No Limit Secu | https://www.nolimitsecu.fr/feed/ | Basse |

### Contraintes NIS 2 à respecter
- Chaque item doit avoir un `reviewed_by` (analyste identifié) avant de passer à `treated`
- Le délai de traitement (`reviewed_at - received_at`) est tracé et exportable
- Lien CVE obligatoire si CVE-ID détecté dans le contenu
- L'export auditeur doit couvrir une période configurable (ex : 12 derniers mois)

---

### Session courante (01/07/2026) — Suppression de l'onglet Synchronisation

L'onglet "Synchronisation" (Sync NVD 7j/30j, Recalcul des scores, Import actifs) est retiré de la
nav CyberVuln — jugé redondant avec le bouton "Actualiser" (7/15j, sync incrémentale) déjà présent
sur la page CVE.

- `frontend/src/pages/Sync.jsx` supprimé
- `App.jsx` : import + route `/sync` retirés
- `components/Layout.jsx` : item nav "Synchronisation" et icône `ICONS.sync` retirés de `NAV_GROUPS`
- `api/client.js` : `syncAssets`/`syncRescore` retirés (plus aucun appelant) — `syncNvd`/`syncTaskStatus`
  conservés (utilisés par le dropdown "Actualiser" de `CVEs.jsx`), `syncMatch` conservé (bouton
  "Matching CVE" du Dashboard)
- `pages/Home.jsx` : description de la tuile CyberVuln mise à jour (retrait de "synchronisation")
- **Endpoints backend non touchés** : `POST /api/sync/assets` et `POST /api/sync/rescore` restent
  disponibles côté API (utilisables via `/api/docs` ou script) — seule l'UI est retirée, à la demande
  explicite de l'utilisateur (portée limitée au tab, pas au backend)

### Session courante (01/07/2026) — Inventaire : adresse MAC au scan, IP intégrée à la fiabilité

- `services/asset_scanner.py` : collecte de l'adresse MAC ajoutée au scan read-only, stockée dans
  `hardware.mac` (JSONB, colonne existante) — affichée dans la modale specs d'Inventaire
  - Windows : `getmac.exe` **et** `Get-NetAdapter` testés en premier, tous deux "Accès refusé" pour ce
    compte de service (même limitation que WMI/CIM) — solution retenue :
    `[System.Net.NetworkInformation.NetworkInterface]` (API .NET pure, contourne WMI comme
    `GlobalMemoryStatusEx`/`DriveInfo`). Testé et validé sur DEPLOYAPP (`00-50-56-AC-B5-C0`).
  - Linux : lecture directe de `/sys/class/net/*/address` (SSH, aucun droit spécial requis)
- **IP essayée d'abord comme simple colonne Inventaire, puis déplacée sur demande** : l'IP est
  maintenant détectée pendant le scan (même API .NET que la MAC, `GetIPProperties().UnicastAddresses`
  côté Windows, `hostname -I` côté Linux) et exposée à deux endroits à partir du même relevé :
  - `hardware.ip` (JSONB) — modale specs matérielles d'**Inventaire**, positionnée entre "Disques" et
    "Adresse MAC" (demande explicite de positionnement)
  - `ip_match`/`detected.ip_address` — comparée à l'IP déclarée au même titre que hostname/OS/version,
    modale "Fiabilité des infos déclarées" d'**Actifs** (`ScanResultModal` dans `Assets.jsx`)
  `_build_result()` étendu avec `detected_ip`/`ip_match`.
  - **Bug rencontré** : ajouter MAC + IP a fait dépasser la limite de ~8191 caractères de la
    commande WinRM encodée (`La ligne de commande est trop longue`) — corrigé en réécrivant le
    P/Invoke `GlobalMemoryStatusEx` en version compacte (noms de champs/méthode raccourcis, structure
    C# sur une ligne) ; a nécessité d'ajouter explicitement `EntryPoint="GlobalMemoryStatusEx"` au
    `DllImport` (le nom de méthode raccourci `G` ne correspond plus au symbole exporté par la DLL).
- `worker`, `backend` et `frontend` redémarrés pour charger le nouveau script de scan

### Session courante (01/07/2026) — Ports TCP en écoute au scan

- `services/asset_scanner.py` : `hardware.open_ports` (liste d'int triée), affiché dans la modale
  specs d'Inventaire juste sous "Adresse MAC"
  - Windows : `[System.Net.NetworkInformation.IPGlobalProperties]::GetActiveTcpListeners()` (.NET,
    même famille que MAC/IP/RAM — évite WMI). Testé et validé sur DEPLOYAPP (26 ports détectés,
    dont 3389/RDP, 5985/WinRM, 445/SMB, 8080/8081/8085 applicatifs)
  - Linux : `ss -tuln` (SSH, pas besoin de root pour lister sans PID)
  - `_parse_ports()` (nouveau helper) normalise les deux formats (CSV Windows / liste Linux) en
    liste d'int dédupliquée triée
  - Marge de commande WinRM après ajout : ~7611/8191 caractères (cf. note taille de commande dans
    `docs/ARCHITECTURE.md`)
- `worker`, `backend` et `frontend` redémarrés

### Session courante (01/07/2026) — Veille : SLA restreint aux critiques + fix faux positifs sévérité

**Bug rapporté** : des articles purement informatifs classés `critical` à tort — exemple donné par
l'utilisateur : *"Docky : le Dock de macOS réinventé, gratuit et open source"*.

- `services/watch_fetcher.py` : root cause identifiée — les mots-clés courts `apt`/`rce` de
  `CRITICAL_KEYWORDS` étaient testés en simple sous-chaîne (`kw in title_lower`), et matchaient donc
  au milieu de mots courants sans rapport : "source"/"resource" contiennent "rce", "capteur"/"adaptation"
  contiennent "apt". Corrigé en isolant `apt`/`rce` dans `CRITICAL_KEYWORDS_STRICT`, vérifiés en tant
  que **mot entier** (regex `\bapt\b`/`\brce\b`) via le nouveau helper `_contains_keyword()`. Les
  autres mots-clés (plus longs/spécifiques : `critique`, `ransomware`, `vulnérabilité`...) restent en
  sous-chaîne pour continuer à matcher pluriels/conjugaisons ("vulnérabilités", "critiques").
  - Testé avant/après sur des cas réels : "Docky... open source" et "capteur IoT... open source"
    passent bien de `critical`→`informational` ; "Faille RCE critique" et "Campagne APT" restent
    `critical` ; "Vulnérabilités affectant..." reste `important`.
- **Backfill** des 108 items déjà en base (script one-off, recalcul `severity` via `_severity()`
  corrigée) : 7 items mal classés au départ, dont "Docky" (`critical`→`informational`), "Euro-Office"
  et "Check..." (idem), 1 item repassé de `critical` à `important` correctement ("GLPI... 2 critiques"
  reste `critical` car "critiques" matche bien la sous-chaîne "critique").
- **SLA restreint aux critiques** (`routers/watch.py`) : le flag `sla_exceeded` (ligne surlignée ⚠,
  KPI, filtre `sla_only`) ne concerne désormais que les items `severity=critical` — avant, un item
  `important`/`informational` non traité depuis >48h déclenchait la même alerte qu'un item critique,
  ce qui n'a pas de sens (la pression de délai ne se justifie que pour le vraiment critique). Les 3
  emplacements corrigés : `_item_dict()` (flag par item), `watch_stats()` (KPI), `list_watch_items()`
  (filtre `sla_only`).
  - `pages/Watch.jsx` : libellés mis à jour ("SLA dépassé" → "SLA critique dépassé") sur la KPI et le
    filtre, pour refléter la restriction
- Docs (`docs/VEILLE.md` § 2.4, § 4.1, § 8) et `worker`/`backend`/`frontend` mis à jour/redémarrés

### Session courante (01/07/2026) — Export CSV auditeur : lisibilité + statut "Non concerné"

**3 problèmes rapportés sur l'export CSV** ("n'est pas lisible") :

1. **Encodage cassé** : `routers/watch.py` `export_watch_items()` ne préfixait pas de BOM UTF-8
   malgré ce qu'affirmait (à tort) `docs/VEILLE.md` — Excel (surtout en locale FR) n'autodétecte pas
   l'UTF-8 sans BOM et affichait les accents en mojibake ("Ã©" au lieu de "é"). Fixé :
   `codecs.BOM_UTF8 + output.getvalue().encode("utf-8")`, `StreamingResponse` servi en bytes.
2. **Colonnes brutes non traduites** : `Statut` et `Sévérité` exportaient la valeur enum interne
   (`not_applicable`, `critical`...) au lieu du libellé FR affiché dans l'UI. `STATUS_LABELS_FR` ajouté
   pour traduire `Statut` ; `Sévérité` retirée de l'export (devenue redondante, voir point 3).
3. **Trop de bruit** (demande explicite utilisateur, confirmée via question de clarification —
   "les deux" : filtrer les lignes ET réduire les colonnes) : l'export est désormais **restreint aux
   items `severity=critical`** (ce sont les seuls soumis au SLA 48h, donc les seuls dont l'auditeur a
   besoin de la traçabilité complète — cf. § 4.1 `docs/VEILLE.md`). Colonnes `Sévérité` (redondante,
   toujours "critique") et `CVEs détectées auto` (bruit technique) retirées, gardant `CVE liée`
   (validée par l'analyste, plus fiable pour l'audit). 11 colonnes au lieu de 13.
   - Testé : export ne contient plus que 4 lignes (= le compte `by_severity.critical` en base),
     BOM présent (`data[:3] == b'\xef\xbb\xbf'`), `Statut` affiche "Traité"/"Non concerné" etc.

**Statut renommé "Non applicable" → "Non concerné"** (clarifié via question : renommage du libellé,
pas un 4e statut — la valeur enum stockée `not_applicable` ne change pas, seul l'affichage change) :
- `pages/Watch.jsx` : `STATUS_LABELS`, libellé du bouton workflow
- `routers/watch.py` : `STATUS_LABELS_FR` (traduction utilisée dans l'export CSV)
- `docs/VEILLE.md` : diagramme workflow § 4, tableau champs auditables § 4.2

Vérifié visuellement (Playwright) : le badge "Non concerné" s'affiche bien dans le tableau et la
modale de détail, à la place de "Non applicable".

### Session courante (01/07/2026) — Premier test Linux : clé SSH + identifiants ponctuels au scan

**Clé SSH générée** : `keys/` était vide (jamais testé côté Linux jusqu'ici, tout le travail précédent
portait sur DEPLOYAPP en WinRM). `ssh-keygen` indisponible dans l'environnement — générée via
`asyncssh.generate_private_key('ssh-ed25519')` dans le conteneur `backend`, copiée sur l'hôte
(`keys/id_ed25519` + `.pub`, `chmod 600`), lisible depuis le mount `:ro` des conteneurs.

**Identifiants ponctuels au scan (Linux)** — l'utilisateur n'avait qu'IP/user/mdp pour la machine de
test, pas encore la clé partagée dans son `authorized_keys`. Clarifié par question avant d'implémenter
(ça allait à l'encontre du choix explicite "pas de mot de passe par actif") : le mot de passe **n'est
pas persisté**, saisi à chaque scan.
- `routers/assets.py` : `ScanCredentials` (body Pydantic optionnel `{username, password}`) sur
  `POST /api/assets/{id}/scan`, jamais stocké
- `services/asset_scanner.py` : `_scan_linux()` accepte `username`/`password` — si fournis,
  `asyncssh.connect(..., password=...)` au lieu de `client_keys=[SSH_KEY_PATH]` ; `scan_asset()`
  route ces paramètres uniquement côté Linux (Windows reste sur le compte WinRM partagé)
- `pages/Assets.jsx` + `pages/Inventaire.jsx` : nouvelle `ScanCredentialsModal` (2 champs optionnels,
  rien de pré-rempli) — le bouton "Scanner" l'ouvre **uniquement pour les actifs non-Windows** ; les
  actifs Windows scannent directement comme avant (pas de friction ajoutée à un flux qui marchait déjà)
- Testé : `_scan_linux()` avec mauvais mot de passe contre un hôte injoignable → échec propre, message
  d'erreur vide (le mot de passe ne fuite jamais dans les logs) ; Playwright confirme le payload
  `{"username":"testuser","password":"testpass123"}` bien envoyé à `/scan`, et que la modale
  n'apparaît pas pour DEPLOYAPP (Windows)

**Fix formulaire "Ajouter un actif"** : `autoComplete="off"` ajouté sur le `<form>` et chaque `<input>`
— les "données préremplies" que voyait l'utilisateur venaient de l'autofill du navigateur (aucune
valeur par défaut n'existait réellement dans `EMPTY_FORM`).

### Session courante (01/07/2026) — Revirement : identifiants SSH stockés par machine (phase de test)

**Décision explicite de l'utilisateur** : au lieu des identifiants ponctuels saisis à chaque scan
(ci-dessus), l'utilisateur veut le nom d'utilisateur/mot de passe directement dans le formulaire
"Ajouter un actif" — *"on est en phase de test on ajustera après on mettra des clés ssh par machine"*.
Un vrai revirement par rapport au choix initial "pas de mot de passe par actif", assumé et temporaire.

- `models.py` : `Asset.scan_username` (clair), `Asset.scan_password_encrypted` (chiffré) — colonnes
  ajoutées à la table `assets` existante via `ALTER TABLE` manuel (`create_all` ne migre pas les
  tables déjà créées)
- `services/crypto.py` (nouveau) : `encrypt_password()`/`decrypt_password()`, Fernet dérivé de
  `SECRET_KEY` (`hashlib.sha256` → base64 urlsafe) — pas de secret supplémentaire à gérer, mais
  changer `SECRET_KEY` invalide tous les mots de passe déjà chiffrés
- `routers/assets.py` : `AssetCreate` gagne `scan_username`/`scan_password` (write-only — jamais
  renvoyés par `_asset_dict`, qui expose `scan_username` en clair mais seulement `has_scan_password: bool`
  pour le mot de passe). En édition, laisser le champ mot de passe vide = conserve l'existant (pas de
  moyen d'afficher/pré-remplir un secret déjà chiffré). Priorité au scan : `creds` de la requête >
  identifiants stockés sur l'actif > clé SSH partagée du parc
- **`ScanCredentialsModal` retirée** (`Assets.jsx`/`Inventaire.jsx`) : redondante maintenant que les
  identifiants sont sur l'actif — le bouton "Scanner" redevient un scan direct comme avant, le backend
  va chercher les identifiants stockés tout seul
- Vérifié : mot de passe stocké chiffré en base (`gAAAAA...`, format Fernet), déchiffrement correct
  (`decrypt_password()` → valeur d'origine), `GET /api/assets` ne renvoie ni le clair ni le chiffré
  (confirmé par `grep -i "scan_\|password"` sur la réponse JSON) ; formulaire testé via Playwright,
  payload `POST /api/assets` capturé avec `scan_username`/`scan_password` corrects

### Session courante (01/07/2026) — Bug : 0 CVE pour un actif ajouté manuellement

**Rapporté par l'utilisateur** après avoir ajouté sa première vraie machine Linux ("hortholary",
Debian, 192.168.100.72) : aucune CVE affichée.

**Root cause** : `POST /api/assets` (ajout manuel) ne renseignait jamais `cpe_list` — seul l'import
AD/SSH (`asset_importer.py`) dérivait un CPE via `_build_cpe(os_name, os_version)`. Sans `cpe_list`,
`cpe_matcher.py` ne peut matcher aucune CVE à l'actif (cf. `docs/MATCHING.md`), quel que soit le
nombre de CVE en base. L'actif de l'utilisateur avait de plus `os_version` vide (juste "Debian"
saisi), donc même une dérivation aurait produit un CPE incomplet.

**Fix** (`routers/assets.py`) :
- `POST /api/assets` / `PUT /api/assets/{id}` : dérivent `cpe_list` via `_build_cpe()` (réutilisé
  depuis `asset_importer.py`) si vide, puis appellent `run_cpe_matching_for_asset()` (déjà présent
  dans `cpe_matcher.py`, jusqu'ici seulement branché sur l'import AD/SSH et le bouton "Matching CVE"
  manuel — jamais sur l'ajout manuel d'actif)
- `POST /api/assets/{id}/scan` : reconstruit `cpe_list` depuis l'OS **détecté** par le scan (plus
  précis que déclaré — ex: "Debian" seul → "Debian GNU/Linux 12 (bookworm)" détecté via
  `/etc/os-release`), puis relance le matching. Corrige le cas d'un OS déclaré trop générique pour
  matcher (`_build_cpe` a besoin d'un nom de distro reconnu : ubuntu/debian/centos/rhel/rocky/alma)
- Testé : asset test Ubuntu 22.04 → 0 CVE (normal, aucune CVE 22.04 en base actuellement, vérifié) ;
  asset test Ubuntu 24.04 → 9 CVE matchées automatiquement à la création
- **Corrigé pour l'actif réel de l'utilisateur** : `POST /api/assets/{id}/scan` relancé sur
  "hortholary" → détecté `gitlab.aer.loc`, Debian 12 bookworm → `cpe_list` reconstruit
  (`debian_linux:12`) → 2 CVE matchées, confirmées visuellement sur `/vulnerabilities`
  (CVE-2026-11852, CVE-2026-11853)

### Session courante (02/07/2026) — Patch check Linux fonctionnel + 3 bugs de matching corrigés

**Rapporté par l'utilisateur** : après avoir mis à jour sa machine Linux de test ("hortholary"), le
"Patch check global" et le patch check individuel ne détectaient toujours rien.

**Root cause n°1 — `check_patch_linux()` était un stub** (déjà noté comme limite connue en fin de
session du 01/07, cf. `docs/SECURITY.md:58-60`) : relevait la version installée via SSH mais ne la
comparait jamais à la version corrigée → `patch_detected` restait toujours `None`, quel que soit
l'état réel de la machine. **Fix** : vraie comparaison de version contre les plages vulnérables NVD
(`versionStartIncluding/Excluding`/`versionEndIncluding/Excluding` extraites de
`cve.raw_data.configurations`), même règle d'auto-bascule que Windows. Détail complet dans
`docs/MATCHING.md` § Patch checker.

**Root cause n°2 — mauvais identifiants SSH** : `check_patch_linux()` utilisait toujours le compte de
service partagé (`SSH_USER`/`SSH_KEY_PATH`), en ignorant les identifiants stockés sur l'actif
(`scan_username`/`scan_password_encrypted`, cf. session "Revirement" du 01/07). Confirmé en base :
dernier résultat stocké = `"Permission denied for user svc-cybervuln"` sur l'IP de "hortholary", qui
utilise ses propres identifiants. **Fix** : priorité aux identifiants de l'actif, même ordre que
`asset_scanner.py`.

**Autonomie du cycle** : "Patch check global" ne revérifiait jamais une vuln déjà contrôlée une fois
(même en résultat `None`/erreur) → restait bloqué indéfiniment même après les deux fix ci-dessus.
- `RECHECK_INTERVAL = 24h` ajouté (`patch_checker.py`) : une vuln contrôlée il y a plus de 24h est
  revérifiée automatiquement (`run_startup_patch_checks`, `GET /api/patch-check/status`)
- Nouvelle tâche Celery `patch_check_periodic` (`tasks/scheduled_tasks.py`), beat toutes les 6h
  (H+20) — déclenche `POST /api/patch-check/run` **via HTTP vers le process `backend`**, pas en
  appelant le service directement depuis le `worker` : l'état d'avancement (`_cycle_running`,
  `_current_check`, suivi par le dashboard) vit en mémoire dans le process FastAPI unique, l'invoquer
  depuis un autre process casserait le suivi et le verrou anti-concurrence
- Testé en réel : déclenchement worker → HTTP → backend confirmé dans les logs des deux conteneurs

**3 bugs de matching creusés à la demande de l'utilisateur** (les 3 CVE ouvertes sur "hortholary"
avant fix, aucune n'était un vrai résultat exploitable) — détail complet dans `docs/MATCHING.md` §
Bugs de matching corrigés :
1. `CVE-2026-11852`/`CVE-2026-11853` ("Debusine") : faux positif du fallback mots-clés — "debian" en
   sous-chaîne dans "Debian-based distribution" (outil sans rapport). Fix : nom d'OS nu jamais gardé
   comme keyword seul + correspondance en mot entier (`\b`), même principe que le fix `apt`/`rce` de
   `watch_fetcher.py`. **Les 2 vulnérabilités déjà créées en base ont été supprimées** (confirmées
   faux positifs, ne seraient plus recréées par le matching corrigé).
2. `CVE-2026-31431` (CVE noyau Linux, "crypto: algif_aead") : `_cpe_matches()` comparait les CPE en
   préfixe de chaîne globale — `"...debian_linux:12".startswith(...)` sur `"...debian_linux:12.0"`
   ne marchait que par coïncidence de caractères, sans notion de composant. Fix : comparaison
   composant par composant (part/vendor/product/version), avec tolérance de padding zéro sur la
   version. Le match reste positif après fix (légitime — NVD liste bien Debian 12 comme affecté).
3. Conséquence du point 2 : `_extract_packages_from_cpe()` remontait des dizaines de produits
   commerciaux tiers sans rapport (Arista CloudVision, RedHat OpenShift, SUSE Manager, VMware
   VeloCloud...) pour cette CVE noyau. Fix : détection des CVE noyau via présence d'un CPE
   `cpe:2.3:o:linux:linux_kernel` → paquets ignorés, résultat `None` explicite plutôt que du bruit.

**État final "hortholary"** : 1 seule vulnérabilité ouverte, légitime (`CVE-2026-31431`, HIGH),
correctement signalée en indéterminé (pas de paquet dpkg exploitable pour un CVE noyau générique —
nécessiterait de comparer `uname -r`, non implémenté).

`backend`, `worker`, `beat` redémarrés et validés en conditions réelles (appels API directs contre
l'infra de test, pas seulement lecture de code).

### Session courante (02/07/2026, suite) — Détection des correctifs Debian via Security Tracker

**Rapporté par l'utilisateur** : après avoir réellement corrigé CVE-2026-31431 (mise à jour noyau),
le patch check ne détectait toujours rien — conséquence assumée du fix précédent (CVE noyau →
`_extract_packages_from_cpe` retourne `[]` → toujours indéterminé), mais l'utilisateur veut une
vraie détection automatisée sur Linux.

**Solution : Debian Security Tracker** (`services/debian_tracker.py`, nouveau). Le problème de fond
est que NVD publie les versions corrigées *amont* alors que Debian backporte sans changer le numéro
amont. Le tracker Debian (JSON public, 11,6 Mo gzip, téléchargé en ~2 s, parsé en ~1 s) donne la
version *Debian* du paquet qui corrige chaque CVE par release (ex : CVE-2026-31431 → `linux
6.1.170-1` pour bookworm) — comparable directement à `dpkg-query`. Détail dans `docs/MATCHING.md`
§ Patch checker.
- Cache disque 24h (`/tmp` conteneur) + index mémoire restreint aux CVE demandées (pas les ~150k)
- Comparaison de versions au format dpkg implémentée en local (`deb_version_compare`, epoch/`~`/
  révisions) — **validée contre le vrai dpkg : 361 comparaisons, 0 écart**
- `check_patch_linux()` : le tracker devient la voie prioritaire pour les actifs Debian (release
  déduite du CPE `debian_linux:12` → bookworm) ; les plages NVD restent le fallback pour les autres
  distros / CVE inconnues du tracker
- Cas noyau géré : note "redémarrage requis" si le paquet corrigé est installé mais que `uname -r`
  tourne encore sur une version antérieure

**Bug sérieux attrapé pendant le test réel** : sur Debian amd64, le noyau installé provient du
paquet source `linux-signed-amd64` (Secure Boot), pas de `linux` référencé par le tracker → le
premier essai a conclu "aucun paquet noyau installé → non affecté" (bon verdict, mauvaise raison —
une machine NON patchée aurait été auto-basculée pareil). Corrigé : normalisation des sources
`X-signed[-arch]` → `X` dans l'association source→binaires.

**Résultat final validé sur la machine réelle** : `linux-image-6.1.0-49-amd64 6.1.174-1 installé —
corrigé à partir de 6.1.170-1 (bookworm)` → `patch_detected: true` → vuln HIGH auto-basculée en
`patched` (`validated_by = "Auto (patch check)"`). Cas négatif vérifié au comparateur (6.1.162-1,
la version d'avant la mise à jour, donne bien "toujours vulnérable").

**Anonymisation** : le téléchargement du tracker n'envoie aucune donnée du parc (même profil que la
sync NVD). Commandes distantes ajoutées : `dpkg-query -W` (équivalent `dpkg -l` déjà autorisé) —
lecture seule, conforme.

**Extension possible plus tard** : Ubuntu a un équivalent (API JSON par CVE sur ubuntu.com/security) —
non implémenté, le parc Linux de test est Debian.

### Session courante (02/07/2026, suite) — Matching CVE contre les paquets installés (pas que l'OS)

**Rapporté par l'utilisateur** : CVE-2026-55200 (libssh2, réellement installé sur "hortholary" en
version vulnérable 1.10.0) invisible dans le dashboard.

**Root cause, plus large que ce seul CVE** : `cpe_matcher.py` ne comparait que `asset.cpe_list`
(OS uniquement, ex. `debian_linux:12`) aux CVE — jamais `asset.installed_packages` (300 paquets
collectés par le scan, stockés en base mais jusque-là seulement affichés dans Inventaire, jamais
exploités par le matching). Résultat : **toute CVE ne portant qu'un CPE applicatif sans CPE OS
associé — l'immense majorité des CVE de bibliothèques Linux (libssh2, libxml2, openssl, gnutls...)
— était invisible pour tout actif Linux**, même paquet vulnérable installé. Seule la CVE noyau
(matchée via le CPE OS) avait été détectée sur "hortholary" jusqu'ici — pas par chance, c'est la
seule catégorie que le matcher savait voir sur cet actif.

**Fix** (`cpe_matcher.py`) : nouveau chemin de matching paquet installé → CPE applicatif, en plus du
matching OS/mots-clés existant, sur les 3 points d'entrée (`run_cpe_matching`,
`run_cpe_matching_for_asset`, `run_cpe_matching_for_cve`) :
- `_package_candidates(pkg_name)` dérive les noms de produit CPE plausibles depuis un nom de paquet
  Debian/RPM (suffixe multi-arch `:amd64` retiré, suffixe soname `-N` retiré, préfixe `lib` retiré,
  préfixe `python3-` retiré) — best-effort et volontairement conservateur, ne devine pas les cas où
  le nom distro diverge totalement du nom amont (ex: `libssl3` → `openssl`, non couvert)
- `_cve_product_index()` indexe produit → CVE une fois par cycle (pas de boucle imbriquée
  paquets × CVE sur potentiellement des centaines de paquets par actif)
- **Bug attrapé au premier test réel** : le nom de paquet stocké en base porte le suffixe multi-arch
  Debian (`libssh2-1:amd64`, pas juste `libssh2-1`) — `_package_candidates` ne le gérait pas
  initialement (le strip du suffixe numérique de fin de chaîne ne matche pas quand la chaîne se
  termine par `:amd64`), donc aucun candidat utile n'était généré. Corrigé en retirant d'abord tout
  ce qui suit `:` avant les autres normalisations.

**Résultat validé sur "hortholary"** : 1 → **46 vulnérabilités** détectées (CVE-2026-55200 incluse,
statut `open`), dont **20 déjà auto-basculées en `patched`** par le cycle de patch check existant,
sans aucune action manuelle — confirme que le pipeline matching → patch check → auto-bascule
fonctionne bout en bout pour ces nouvelles CVE aussi. Échantillon vérifié à l'œil pour absence de
bruit (libssh2, libxml2/libexpat, nghttp2, gnutls, libcap, openssl, Perl — tous des paquets
plausibles sur un Debian, aucun faux positif visible).

### Session courante (02/07/2026, suite) — Statut "En attente d'un patch correctif" + annotation

**Demande utilisateur** (suite au cas CVE-2026-55200/libssh2, cf. session précédente — Debian n'a pas
encore publié de correctif pour bookworm) : pouvoir annoter une vulnérabilité pour justifier pourquoi
elle ne peut pas être traitée, et un 3e tableau dashboard entre "à traiter" et "traitées", même mise en
forme que "traitées".

**Backend** :
- `models.py` : nouveau statut `awaiting_fix` (+ `open`/`in_progress`/`patched`/`accepted_risk`
  existants), colonne `Vulnerability.awaiting_fix_at` (`ALTER TABLE` manuel, comme d'habitude —
  `create_all` ne migre pas). `notes` (déjà existant) réutilisé comme annotation/justification —
  pas de nouvelle colonne pour ça.
- `routers/vulnerabilities.py` : `PATCH` gère 3 branches désormais (`patched` / `awaiting_fix` /
  autre) — passer en `awaiting_fix` fixe `awaiting_fix_at`, vide `patched_at`/`validated_by`, mais
  **conserve** `last_patch_check`/`patch_check_result` (contexte technique utile en plus de
  l'annotation libre, et préserve le rythme de `RECHECK_INTERVAL` plutôt que de forcer un recheck
  immédiat) — contrairement à la sortie vers `open`/`in_progress`/`accepted_risk` qui les vide toujours
- `awaiting_fix` ajouté partout où `["open", "in_progress"]` filtrait les vulns "actives" :
  `patch_checker.py` (`run_startup_patch_checks`, `backfill_auto_patch` — le cycle autonome revérifie
  aussi les vulns en attente et les bascule en `patched` dès qu'un correctif sort, **sans repasser par
  "à traiter"**), `routers/patch_check.py` (`/status`), `scoring.py` (recalcul risk_score sur les 3
  fonctions) — **KPIs `stats.py` volontairement non touchés** (`open_vulns`/`exposed_assets` ne
  comptaient déjà que `status=="open"` strictement, ni `in_progress` ni `accepted_risk` n'y entraient —
  `awaiting_fix` suit la même convention préexistante, pas une régression)

**Frontend** (`Dashboard.jsx`) :
- Nouveau composant `AwaitingFixModal.jsx` — annotation obligatoire (textarea, bouton désactivé tant
  que vide), thème ambre `#d29922`
- Bouton "⏳ En attente" ajouté au tableau "à traiter" (à côté d'Analyser/Patch check/✓ Corrigé)
- Nouveau tableau "Vulnérabilités en attente d'un patch correctif" entre "à traiter" et "traitées" —
  même structure que "traitées" (colonnes, boutons Patch check/Réouvrir), thème ambre au lieu du vert
- `moveVulnToPatched` généralisé pour chercher dans `openVulnsRef` **et** `awaitingVulnsRef` (une vuln
  en attente peut être basculée en patched directement par le cycle autonome) ; `handleReopen`
  généralisé pour vider les deux tableaux `patchedVulns`/`awaitingVulns` (bouton "↩ Réouvrir" partagé)
- `Vulnerabilities.jsx` : `awaiting_fix` ajouté à `STATUS_STYLES`/`STATUS_LABELS`/`STATUSES` (filtre +
  affichage badge) pour rester cohérent — pas de bouton pour le déclencher depuis cette page (seulement
  depuis le Dashboard, comme demandé)

**Testé en réel** (Playwright headless, méthodologie du projet — cf. § Points d'attention) sur
CVE-2026-55200 : ordre des 3 tableaux correct, annotation affichée, patch check depuis le tableau
"en attente" fonctionne (résultat cohérent avec le Security Tracker : toujours non détecté, bookworm
sans correctif), "↩ Réouvrir" déplace bien vers "à traiter" en faisant apparaître le bouton "⏳ En
attente", modale d'annotation validée (bouton désactivé/activé correctement), ré-annotation confirmée
de retour dans le bon tableau. Aucune erreur console.

### Session courante (02/07/2026, suite) — Statut "Faux positif" + détail d'annotation cliquable

**Demande utilisateur** : pouvoir marquer une CVE comme faux positif (avec annotation de
justification) dans la partie "corrigé", et pouvoir voir le détail complet d'une annotation en
cliquant dessus dans le tableau "en attente d'un patch correctif".

**Backend** :
- `models.py` : nouveau statut `false_positive`, colonne `Vulnerability.false_positive_at`
  (`ALTER TABLE` manuel, comme d'habitude)
- `routers/vulnerabilities.py` : `PATCH` gère la branche `false_positive` (fixe `false_positive_at`,
  vide `patched_at`/`awaiting_fix_at`/`validated_by`) — **contrairement à `awaiting_fix`**, ne conserve
  pas spécialement `last_patch_check`/`patch_check_result` puisque ce statut n'entre volontairement pas
  dans le cycle de recheck (voir plus bas)
- **`false_positive` volontairement absent** des listes `["open", "in_progress", "awaiting_fix"]` dans
  `patch_checker.py`/`routers/patch_check.py`/`scoring.py` — état terminal comme `patched` : la CVE n'a
  jamais concerné l'actif, revérifier son patch n'a pas de sens

**Frontend** (`Dashboard.jsx`) :
- Ancien `AwaitingFixModal.jsx` **généralisé** en `AnnotationModal.jsx` (props `color`/`subtitle`/
  `helpText`/`placeholder`/`confirmLabel`) — réutilisé pour "En attente" ET "Faux positif", évite de
  dupliquer une modale à 90% identique
- Bouton "🚫 Faux positif" (gris `#8b949e`, même couleur que "Risque accepté" dans `Vulnerabilities.jsx`)
  ajouté au tableau "à traiter", à côté de "⏳ En attente"
- Tableau "Vulnérabilités traitées" fusionne désormais `patched` + `false_positive` (récupérés par un
  4e fetch `status=false_positive` au chargement, triés ensemble par date de clôture) — badge coloré
  différemment ("Patched" vert / "Faux positif" gris), colonne renommée "Clôturé le" (au lieu de
  "Corrigé le", pour rester juste dans les deux cas), colonne "Validé par" devenue "Validé par /
  Annotation" (affiche l'un ou l'autre selon le statut)
- Nouveau `AnnotationDetailModal.jsx` : l'annotation tronquée dans les tableaux ("en attente" ET
  "traitées") est désormais un bouton cliquable qui ouvre cette modale avec le texte complet — avant,
  seul un `title` HTML (tooltip navigateur, peu lisible pour du texte long) existait

**Testé en réel** (Playwright headless) : marquage faux positif sur CVE-2026-56411 (bouton → modale →
annotation → déplacement vers "traitées" avec badge gris), clic sur l'annotation → modale détail avec
texte complet correct, même vérification sur une entrée "en attente" existante (CVE-2026-55200).
Aucune erreur console. CVE-2026-56411 remise à `open` après test (donnée de test, pas une vraie
vulnérabilité à traiter) — les 2 vraies annotations "en attente" que l'utilisateur avait créées entre
temps (CVE-2026-11979, CVE-2026-41992, sur "hortholary") n'ont pas été touchées.

### Session courante (02/07/2026, suite) — Recherche CVE + correction auto du nom d'actif au scan

**Demande utilisateur** : 1) pouvoir rechercher une CVE dans les 3 tableaux du dashboard ("à traiter",
"en attente", "traitées") ; 2) quand le scan d'un actif détecte un hostname différent du nom déclaré
(ex: "hortholary" — nom de l'utilisateur qui a rempli le formulaire, pas le nom de la machine
"gitlab.aer.loc"), corriger automatiquement le nom affiché.

**Recherche CVE** (`Dashboard.jsx`) : input texte substring sur `cve.cve_id`, un état indépendant par
tableau — `dashFilter.search` (à traiter, intégré à la barre "Filtres" existante à côté du select
sévérité), `awaitingSearch`/`filteredAwaitingVulns`, `patchedSearch`/`filteredPatchedVulns`. Badges de
comptage volontairement non filtrés (cohérent avec le filtre sévérité déjà en place).

**Correction auto du nom** (`routers/assets.py`, `POST /{id}/scan`) : si le hostname détecté diffère
du hostname déclaré, `asset.hostname` **et** `asset.name` (affiché partout dans l'UI) sont alignés sur
la valeur détectée — même philosophie que la correction de CPE déjà en place pour l'OS déclaré après
scan. `IntegrityError` gérée (hostname déjà pris par un autre actif → correction abandonnée,
`name_correction_error` renvoyé, reste du scan conservé). `ScanResultModal` (Actifs) affiche un
bandeau "Nom corrigé automatiquement" ; `Inventaire.jsx` répercute le renommage dans sa liste sans
bandeau dédié.

**Testé en réel** (Playwright + scan SSH réel sur "hortholary") :
- Scan initial : `name_corrected: {from: "hortholary", to: "gitlab.aer.loc"}`, confirmé en base
  (`name`/`hostname` mis à jour), le nouveau nom apparaît immédiatement dans les 3 tableaux du
  dashboard sans reload. Un second scan (hostname déjà aligné) ne redéclenche pas la correction
  (idempotent).
- Recherche CVE : testée sur les 3 tableaux simultanément (2 inputs "Rechercher un CVE…" détectés
  pour en attente/traitées + 1 dans la barre Filtres pour à traiter), filtrage correct, aucune erreur
  console.

`hortholary` remis à son état (nom "hortholary", hostname vide) après capture d'écran de démonstration
de la bannière, puis re-scanné pour revalider `gitlab.aer.loc` — aucune perte des vulnérabilités liées
(même `asset_id`, seul le nom affiché change).

### Session courante (02/07/2026, suite) — Version Debian manquante, CPU vide, nom cliquable

**Rapporté par l'utilisateur** après le scan de "gitlab.aer.loc" (ex-"hortholary") : version Debian et
infos CPU absentes, et souhait de cliquer sur le nom d'un actif pour voir ses infos.

**Bug 1 — CPU toujours vide sur les Linux en locale non-anglaise** (`asset_scanner.py`) : `lscpu`
traduit ses libellés selon `$LANG`/`$LC_ALL` du serveur SSH — la machine de test tourne en
`fr_FR.UTF-8`, donc `lscpu` affiche "Nom de modèle :" au lieu de "Model name:", et le grep sur le
libellé anglais ne matchait jamais. **Bug général**, pas spécifique à cet actif — toute machine du
parc en locale FR (probable, entreprise française) aurait le même problème. Fix : `LC_ALL=C lscpu`
force la sortie en anglais indépendamment de la locale du serveur.

**Bug 2 — `os_version` jamais persistée après scan** (`routers/assets.py`) : le `VERSION_ID` détecté
(ex: "12") servait déjà à construire le CPE mais n'était jamais écrit sur `asset.os_version` — le
champ déclaré restait vide pour toujours, même après scan. Fix : même logique que la correction de
hostname/name de la session précédente — `os_version` alignée sur la valeur détectée à chaque scan ;
`os` (champ court "Debian") seulement rempli s'il était vide, pour ne pas écraser un libellé court par
le PRETTY_NAME complet. Le bloc de fallback `IntegrityError` (collision hostname) mis à jour en
cohérence, sinon la correction aurait été perdue silencieusement dans ce cas rare.

**Nom d'actif cliquable** (`Assets.jsx`) : la colonne "Nom" est devenue un bouton qui ouvre
`ScanResultModal` (même action que le badge "X apps") — modale enrichie d'une section "Specs
matérielles" (CPU/cœurs/RAM/disques/MAC/ports) qui n'existait que côté `Inventaire.jsx` jusqu'ici,
absente de `ScanResultModal` : c'était la deuxième cause du "il manque les infos CPU" (le scan
collectait bien le hardware, mais rien ne l'affichait sur la page Actifs).

**Testé en réel** : re-scan de "gitlab.aer.loc" → `detected.os_version: "12"`, `hardware.cpu:
"Intel(R) Xeon(R) Gold 5416S"`, confirmés persistés en base (`os_version='12'`,
`hardware->>'cpu'='Intel(R) Xeon(R) Gold 5416S'`). Colonne OS de la liste Actifs affiche "Debian 12".
Clic sur le nom → modale avec fiabilité + specs matérielles complètes. Aucune erreur console.

### Session courante (02/07/2026, suite) — Filtre "Actifs" sur le dashboard (un/plusieurs/tous)

**Demande utilisateur** : pouvoir choisir un, plusieurs, ou tous les actifs sur le dashboard, avec
recalcul des KPI (pas juste un filtre visuel sur les tableaux — confirmé explicitement via question de
clarification).

**Backend** (`routers/stats.py`) : `GET /api/stats?asset_id=uuid1,uuid2` (CSV, même convention que
`source`/`severity` dans `routers/watch.py`) — tous les compteurs (vulns ouvertes/corrigées/en attente,
taux, `severity_rates`, `exposed_assets`) recalculés sur le sous-ensemble via un helper `scoped(q)`.
`total_assets` devient la taille de la sélection quand elle est active, pour que "X exposés sur Y
actifs" reste juste. Sans le paramètre, comportement inchangé (parc entier) — retro-compatible.

**Pourquoi recalculer côté backend plutôt que filtrer les tableaux déjà chargés côté client** : le
Dashboard ne fetch que les statuts `open`/`patched`/`awaiting_fix`/`false_positive` — jamais
`in_progress`/`accepted_risk`. Calculer les taux depuis ces tableaux aurait donné des pourcentages
subtilement faux (dénominateur incomplet). Le nouvel appel `/api/stats?asset_id=...` reste la seule
source de vérité pour ces calculs, cohérent avec le comportement non filtré.

**Frontend** (`Dashboard.jsx`) : nouveau composant `AssetDropdown` (repris du pattern `SourceDropdown`
de `Watch.jsx`), ajouté dans la barre "Filtres" existante. `assetScopedOpen`/`assetScopedAwaiting`/
`assetScopedPatched` filtrent les 3 tableaux (+ badges de comptage, KPI "Vulns ouvertes"/"En attente
d'un patch", graphiques répartition/top actifs) ; les filtres sévérité/recherche s'appliquent ensuite
par-dessus, inchangés. `selectedAssetIdsRef` ajouté (même pattern que `openVulnsRef`) pour que le
polling du patch check autonome rafraîchisse les KPI avec la sélection courante, pas celle figée au
montage.

**Testé en réel** (Playwright) : sélection de "DEPLOYAPP" seul → KPI passe de "1 exposé sur 2 actifs"
à "0 exposé sur 1 actif" (cohérent, DEPLOYAPP est 100% corrigé), "Taux de correction par sévérité"
recalculé sur ses seules CVE (67/67 HIGH etc.), tableaux et graphiques vides comme attendu. Aucune
erreur console.

### Session courante (02/07/2026, suite) — Analyste requis pour "en attente"/"faux positif"

**Demande utilisateur** : savoir qui a validé un "faux positif" ou "en attente de patch", pas
seulement pourquoi — et corriger les 11 entrées déjà existantes en `Yanis Hortholary` (confirmé
explicitement par l'utilisateur comme étant lui sur toutes les entrées actuelles).

**Backend** (`routers/vulnerabilities.py`) : les branches `awaiting_fix`/`false_positive` du `PATCH`
ne vident plus `validated_by` (elles le faisaient jusque-là, symétriquement à `open`/`in_progress`/
`accepted_risk`) — l'affectation se fait désormais via `data.validated_by`, transmis obligatoirement
par la modale. Backfill one-off : `UPDATE vulnerabilities SET validated_by='Yanis Hortholary' WHERE
status IN ('awaiting_fix','false_positive') AND validated_by IS NULL` → 11 lignes.

**Frontend** (`AnnotationModal.jsx`) : ajout d'un `<select>` obligatoire (réutilise `ANALYSTS` exporté
par `ValidateDropdown.jsx`) à côté du textarea — bouton de confirmation désactivé tant que l'annotation
**et** l'analyste ne sont pas tous les deux renseignés. `onConfirm(note, validator)` — signature
étendue, propagée à `handleMarkAwaitingFix`/`handleMarkFalsePositive` (Dashboard.jsx).

**Affichage** : nouvelle colonne "Validé par" dans le tableau "en attente" (badge bleu, même style que
"traitées"). Dans "traitées", la colonne "Validé par / Annotation" affiche désormais **les deux**
empilés pour un faux positif (avant : l'annotation seule y masquait le validateur).

**Testé en réel** (Playwright) : bouton désactivé tant que note+analyste incomplets, activé une fois
les deux renseignés, ligne résultante affiche bien l'analyste choisi dans la nouvelle colonne. Aucune
erreur console. Ligne de test nettoyée après capture.

### Session courante (02/07/2026, suite) — Cohérence "en attente"/"traitées" + couleur badge faux positif

**Retour utilisateur** : la colonne "Validé par" venait d'être ajoutée séparément dans "en attente"
(2 colonnes : "Validé par" + "Annotation"), alors que "traitées" les affichait déjà fusionnées dans
une seule colonne "Validé par / Annotation" — incohérent entre les deux tableaux qui doivent suivre
la même mise en forme.

- `Dashboard.jsx` : tableau "en attente" repassé à une seule colonne "Validé par / Annotation" (badge
  analyste empilé au-dessus de l'annotation cliquable), identique à "traitées" — plus de colonne
  "Validé par" séparée.
- Badge "Faux positif" (à côté du CVE ID dans "traitées") : gris `#8b949e` → violet `#a371f7` (choisi
  par l'utilisateur parmi 3 options proposées) — il était identique au gris de "Risque accepté"
  (`Vulnerabilities.jsx`), peu distinctif dans le tableau. `badgeColor` n'est utilisé que pour ce
  badge précis, aucun autre impact.

Vérifié visuellement (Playwright) après chaque changement — aucune erreur console.

### Session courante (02/07/2026, suite) — Refonte Rapports : bug 500 + filtre actifs + période

**Rapporté par l'utilisateur** : erreurs en générant un résumé exécutif. Objectif plus large : pouvoir
choisir un/plusieurs/tous les actifs pour un rapport, et retravailler la partie Rapports pour être
cohérente — destinée à un envoi hebdomadaire à l'équipe sécurité pour expliquer ce qui a été fait.

**Bug 500 — root cause** : régression que j'avais moi-même introduite lors de la session "Filtre
Actifs sur le dashboard" — `routers/reports.py` appelait `get_stats(session)` en positionnel, un
handler de route FastAPI, pas une fonction normale. L'ajout du paramètre `asset_id` en tête de
signature de `get_stats` a décalé les positions : `session` (un `AsyncSession`) se retrouvait assigné
à `asset_id`, `AttributeError: 'AsyncSession' object has no attribute 'split'`. **Fix structurel, pas
juste un patch du call site** : logique de `routers/stats.py` extraite dans `services/stats.py`
(`compute_stats(session, asset_ids)`), appelable proprement par n'importe quel router — `Depends(...)`
n'a de sens que résolu par le pipeline HTTP, l'appeler comme fonction Python normale est fragile par
nature dès que la signature évolue.

**Filtre actifs** : `AssetDropdown` (jusque-là défini uniquement dans `Dashboard.jsx`) extrait en
composant partagé `components/AssetDropdown.jsx`, réutilisé par `Reports.jsx` — 2e site d'usage,
extraction justifiée (pas prématurée). S'applique à l'export CSV **et** au résumé exécutif.

**Filtre période** (nouveau) : select "7 derniers jours" (défaut) / "30 derniers jours" / "Vue
d'ensemble (tout l'historique)" — `POST /api/reports/executive-summary` accepte désormais
`{period_days, asset_id}` en body (au lieu d'aucun paramètre).

**Contenu du résumé restructuré** (`services/claude_analyzer.py generate_executive_summary`) :
nouvelle section "Ce qui a été fait — N derniers jours" en tête (visible seulement si une période est
choisie) — vulnérabilités **corrigées**/**mises en attente**/**faux positifs** durant la période
(CVE, actif, validé par, annotation tronquée), + nombre de nouvelles détections. Section existante
renommée "État actuel" (ex-"Exposition"), conservée telle quelle en dessous — c'est le "avant" que le
résumé "Ce qui a été fait" vient compléter, pas remplacer. `routers/reports.py::_activity_during_period`
interroge `patched_at`/`awaiting_fix_at`/`false_positive_at`/`detected_at` scopés sur la sélection
d'actifs et la fenêtre temporelle.

**Export CSV enfin branché** : `exportCsv`/`/api/reports/csv` existaient déjà côté API mais
**aucun bouton ne les appelait** sur la page Rapports (fonctionnalité orpheline découverte pendant la
refonte) — nouvelle carte "Export CSV — backlog courant", respecte le filtre actifs (pas la période,
c'est un instantané du backlog courant, pas un delta). CSV enrichi de 2 colonnes (`Validé par`,
`Annotation`) au passage, pour rester cohérent avec ce que montre déjà le dashboard.

**Testé en réel** (Playwright) : dashboard non cassé par l'extraction d'`AssetDropdown` (import
correct depuis le composant partagé), page Rapports — sélection d'un actif, téléchargement CSV
déclenché avec le bon nom de fichier, résumé généré contenant bien les 2 sections ("Ce qui a été
fait" + "État actuel"). Aucune erreur console.

### Session courante (02/07/2026, suite) — Résumé exécutif en tableaux plutôt qu'en puces imbriquées

**Demande utilisateur** : les listes de CVE ("Ce qui a été fait") en puces imbriquées se lisent mal —
plus lisible sous forme de tableau.

- `services/claude_analyzer.py` : `_activity_lines` → `_activity_table`, nouveau helper `_md_table()`
  (génère du markdown pipe-table standard, cellules échappées) — sections "corrigées"/"en attente"/
  "faux positifs" **et** "Top CVE critiques" passent en tableaux (colonnes CVE/Sévérité/Actif/Validé
  par/Annotation, ou CVE/CVSS/Description pour le top)
- Le renderer markdown maison du frontend (`Reports.jsx`) ne comprenait pas la syntaxe tableau — les
  lignes `| a | b |` seraient tombées dans le cas `<p>` générique et affiché du texte brut. Ajout
  d'un vrai parseur de tableau (détection ligne d'en-tête + séparateur `|---|---|`, consommation des
  lignes de données) dans `renderMd` (rendu écran) **et** `exportPdf` (rendu impression/PDF, jusque-là
  un convertisseur ligne à ligne séparé et non partagé) — les deux chemins de rendu devaient être
  traités, sinon le PDF aurait affiché la syntaxe pipe brute pendant que l'écran affichait déjà un
  vrai tableau
- `Bold` renommé `Inline` et étendu au passage : gérait seulement `**gras**`, gère maintenant aussi
  `*italique*` (nécessaire pour la note "*… et N de plus*" tronquée par `_activity_table`)

**Testé en réel** (Playwright) : 4 éléments `<table>` rendus sur la page, structure DOM vérifiée
(`<h1>`/`<h2>`/`<h3>`/`<strong>`/`<table><thead><tbody>` tous corrects). Aucune erreur console.

### Session courante (02/07/2026, suite) — Export CSV Rapports : encodage cassé (même bug que Veille)

**Rapporté par l'utilisateur** : caractères spéciaux mal encodés dans le CSV, et impression que "tout
ne remonte pas".

**Root cause confirmée** : `routers/reports.py::export_csv()` ne préfixait pas de BOM UTF-8 —
exactement le même bug déjà corrigé sur l'export veille (`routers/watch.py`) lors d'une session
précédente, jamais repris ici. Sans BOM, Excel (locale FR) n'autodétecte pas l'UTF-8 et affiche les
accents en mojibake ("SÃ©vÃ©ritÃ©" au lieu de "Sévérité") — probablement la cause de l'impression de
données manquantes : des colonnes mal décodées peuvent dérouter Excel sur le découpage des champs.
**Fix** : `codecs.BOM_UTF8 + output.getvalue().encode("utf-8")`, réponse servie en bytes avec
`charset=utf-8` — identique au fix déjà en place sur `routers/watch.py`.

**Vérification du volume de données** (l'autre partie du signalement) : compté précisément — 20
vulnérabilités non-`patched` en base, 20 lignes de données dans le CSV (21 avec l'en-tête). **Aucune
ligne manquante confirmée** ; le CSV se limite volontairement au statut `!= patched` (backlog courant
"à traiter", cf. session refonte Rapports) — si l'utilisateur veut aussi l'historique des vulns déjà
corrigées dans l'export, c'est un changement de périmètre différent à demander explicitement, pas ce
qui a été corrigé ici.

**Testé en réel** (Playwright, téléchargement déclenché depuis le vrai bouton "Exporter CSV") : BOM
présent, 21 lignes, accents corrects (`Sévérité`, `Détecté le` lisibles).

### Session courante (02/07/2026, suite) — "Top CVE critiques" du rapport hors-parc en "Tous les actifs"

**Rapporté par l'utilisateur** : 5 CVE (CVE-2026-48286, -48276, -48277, CVE-2025-71338,
CVE-2026-10134) remontaient en critique dans le résumé exécutif mais invisibles sur le dashboard.
Vérifié en base : `matched_count = 0` pour les 5 — aucune ne touche un actif réel du parc (juste
présentes dans la table `cves`, importées depuis NVD comme les ~9 000 autres jamais matchées).

**Root cause** : bug introduit lors de la refonte Rapports — `routers/reports.py::executive_summary()`
ne restreignait la requête "Top CVE critiques" aux CVE matchées à un actif (`Vulnerability.cve_id`)
que si un filtre d'actifs spécifique était choisi (`if asset_ids: ...`). En "Tous les actifs"
(`asset_ids` vide), aucune restriction n'était appliquée du tout → n'importe quelle CVE CRITICAL de la
table `cves` entière (tout NVD importé, sans rapport avec le parc) pouvait remonter. `compute_stats`
(KPI, `services/stats.py`) n'avait pas ce bug — toujours scopé aux CVE matchées, avec ou sans filtre
actif — c'est pour ça que les compteurs du dashboard restaient corrects pendant que "Top CVE" du
rapport dérapait.

**Fix** : la sous-requête `matched` (CVE liées à au moins une `Vulnerability`) est désormais construite
**avant** et toujours appliquée, filtrée par `asset_ids` seulement si fourni — même logique que
`compute_stats`, plus de branche "non scopée".

**Testé en réel** : les 5 CVE signalées confirmées absentes du résumé après fix (recherche directe
dans le texte généré), sur "Tous les actifs" comme sur une sélection d'actif.

**Généralité du fix confirmée** (l'utilisateur a demandé si d'autres CVE pourraient reproduire le
problème à l'avenir) : le correctif retire une branche conditionnelle, ce n'est pas une liste noire
des 5 CVE signalées — toute CVE CRITICAL non matchée au parc est exclue, peu importe laquelle. Preuve
en direct : une 6e CVE critique non matchée (`CVE-2026-20160`), jamais mentionnée par l'utilisateur et
repérée indépendamment en base pour le test, confirmée absente du résumé généré après fix. Audit
complet des `select(CVE)` dans `backend/` : aucune autre requête de listage (par opposition aux lookups
CVE par ID, ou au balayage volontairement exhaustif de `cpe_matcher.py` pour le matching lui-même)
n'a ce même défaut — `export_csv` et `_activity_during_period` partent tous les deux d'un `JOIN` sur
`Vulnerability`, donc structurellement incapables de remonter une CVE non matchée.

### Session courante (02/07/2026, suite) — "Top CVE" affichait des CVE déjà corrigées

**Rapporté par l'utilisateur** : les 5 CVE du "Top CVE critiques à traiter en priorité" (CVE-2026-44815,
-8376, -47291, -45602, -34182) étaient toutes déjà `patched` en base — confusion sur un rapport censé
dire ce qui reste à faire.

**Root cause, complémentaire du fix précédent** : la requête ne filtrait la CVE matchée au parc que
par sévérité (`CRITICAL`) et appartenance au parc — jamais par statut de la vulnérabilité elle-même.
Une CVE déjà corrigée sur tous les actifs où elle avait été détectée pouvait donc trôner en tête,
simplement parce qu'elle a le CVSS le plus élevé parmi *toutes* les CVE critiques jamais matchées,
corrigées ou non.

**Fix** (`routers/reports.py`) : la sous-requête `unresolved` (remplace `matched`) filtre désormais
aussi sur `Vulnerability.status IN (open, in_progress, accepted_risk, awaiting_fix)` — exclut
`patched` et `false_positive`. Une CVE matchée à plusieurs actifs avec des statuts différents reste
listée tant qu'au moins un actif ne l'a pas corrigée. `critical_unresolved`/`high_unresolved`
(comptage sur cette même sous-requête, sans la limite à 5) calculés en plus du total historique déjà
exposé par `compute_stats` — et propagés à `generate_executive_summary()` pour :
- Le **niveau de risque global**, qui se basait sur le total historique de CVE critiques (patchées ou
  non) plutôt que sur ce qui reste réellement une menace.
- La section **"CVE critiques et hautes"**, qui affiche maintenant les deux nombres ("X au total sur
  le parc, dont Y encore à traiter") plutôt qu'un total ambigu.
- Les **recommandations**, qui répétaient "N CVE critique(s) en attente" même à 0 CVE réellement en
  attente.
- Message explicite ("Aucune — toutes les CVE critiques... sont déjà corrigées ou écartées.") quand
  la liste est vide alors que des CVE critiques existent bien sur le parc, pour éviter qu'une section
  vide/absente ne soit interprétée comme un oubli.

**Testé en réel** : après fix, "CRITICAL : 5 au total, dont 0 encore à traiter", section "Top CVE"
avec message explicite, recommandation "en attente" disparue (remplacée par "✓ Bon taux de
correction"). Contre-vérifié sur HIGH : 3 CVE HIGH encore en `awaiting_fix` en base → "dont 3 encore
à traiter" correctement affiché, confirmant que le comptage n'est pas juste figé à 0.

### Session courante (02/07/2026, suite) — Couleurs dans le résumé exécutif

**Demande utilisateur** : coloriser le "Niveau de risque global" (FAIBLE en vert, etc.) et les
sévérités, dans le rapport.

Le rendu markdown maison (`Reports.jsx`) n'a pas de syntaxe native pour la couleur — plutôt que
d'inventer une extension markdown côté backend, la coloration se fait **côté rendu** : `Inline`
(écran) et `inline()` (`exportPdf`, impression) détectent désormais les mots CRITICAL/HIGH/MEDIUM/LOW
et CRITIQUE/ÉLEVÉ/MODÉRÉ/FAIBLE en mot entier n'importe où dans le texte (titres, tableaux, phrases)
et les colorent avec la même échelle que `SeverityBadge.jsx` (rouge/orange/ambre/vert) — y compris
à l'intérieur d'un passage déjà en gras (ex: "**Niveau de risque global : FAIBLE**").

**Piège rencontré** : `\b` (limite de mot) en JS se base sur `\w` (ASCII uniquement) — "É" n'est pas
reconnu comme caractère de mot, donc `\bÉLEVÉ\b`/`\bMODÉRÉ\b` ne matchaient jamais. Remplacé par
`(?<!\p{L})...(?!\p{L})` (lookaround Unicode, flag `u`) qui gère correctement les lettres accentuées.

**Testé en réel** (Playwright, valeurs CSS calculées) : "FAIBLE" → `rgb(63, 185, 80)` (`#3fb950`,
vert) dans le titre ; "CRITICAL"/"HIGH" correctement en rouge/orange dans les cellules des tableaux
d'activité. Confirmé visuellement par capture d'écran.

### Session courante (02/07/2026, suite) — Veille "Fuite de données" : 2 sources sur 3 ne remontaient rien

**Rapporté par l'utilisateur** : impression que les fuites de données réelles des sites suivis ne
remontent pas dans le module Veille.

**Vérifié en base** : sur les 3 sources taguées "Fuite de données" (ZATAZ, fuitesinfos.fr, Bonjour la
fuite), seule ZATAZ avait des items — `fuitesinfos`/`bonjourlafuite` : 0 ligne, jamais remonté depuis
la création du module.

**Root cause — 2 bugs distincts** (`services/watch_fetcher.py`) :
1. **fuitesinfos.fr** : l'URL configurée (`/feed/`) renvoie une 404 depuis une refonte du site — le
   vrai flux est en `/feed.xml` (retrouvé via la balise `<link rel="alternate"
   type="application/rss+xml">` de la page d'accueil).
2. **Bonjour la fuite** : URL correcte, mais déclarée `type: "atom"` alors que le flux est du RSS 2.0
   classique (`<item>`, pas `<entry>`) — `_parse_atom()` ne trouve donc jamais d'entrée et retourne
   silencieusement une liste vide, sans erreur ni log, malgré un flux réellement actif et à jour.

**Fix** : URL corrigée pour fuitesinfos, `type` corrigé en `"rss"` pour bonjourlafuite.

**Testé en réel** : sync manuelle déclenchée (`POST /api/watch/sync`) → 20 nouveaux items insérés,
dont 10 fuitesinfos + 10 bonjourlafuite (lycées, INSEE, Ministère des Sports, CapiFrance...), thème
"Fuite de données" correctement attribué. Vérifié visuellement sur `/veille` filtré par ce thème :
32 items au lieu d'une poignée ZATAZ seule.

**Audit complémentaire, hors périmètre de la demande** : en vérifiant les 16 sources une par une, 7
autres se sont révélées cassées côté source (pas un bug CyberVuln) — CERT-FR Avis/Alertes, ANSSI,
CNIL, Cybermalveillance, Global Security Mag (URLs mortes ou changées), Sekoia et HarfangLab
(bloqués par anti-bot/Cloudflare, 403). Non corrigé cette session — signalé à l'utilisateur, à traiter
en tâche dédiée si souhaité (retrouver les nouvelles URLs pour les unes, probablement pas contournable
proprement pour les blocages anti-bot).

---

### Session courante (02/07/2026, suite) — Correction des 8 autres sources Veille cassées

**Demandé par l'utilisateur** : corriger les sources signalées cassées dans l'audit précédent.
Recomptage en reprenant chaque source une par une (pas juste les 7 déjà nommées) : 9 sources en
échec au total, pas 7 — CERT-FR Avis, CERT-FR Alertes, ANSSI, CNIL, Cybermalveillance, Global
Security Mag, Sekoia, Synacktiv (non repéré dans l'audit précédent) et HarfangLab.

**Root cause par source** (`services/watch_fetcher.py`, toutes des URLs mortes/déplacées sauf
mention contraire) :
- **CERT-FR Avis/Alertes** : segments d'URL inversés (`/feed/avis/` au lieu de `/avis/feed/`) *et*
  déclarées `type: "atom"` alors que le flux réel est du RSS 2.0.
- **ANSSI** : `ssi.gouv.fr` a été rebrandé `cyber.gouv.fr`, `/feed/` n'existe plus — flux retrouvé
  sous `/actualites/rss/`.
- **CNIL** : `/fr/flux-rss-actualites` n'a jamais existé sur le site actuel — vrai flux
  `/fr/rss.xml`.
- **Cybermalveillance** : `/feed/` générique supprimé, remplacé par plusieurs flux Atom nommés —
  URL corrigée vers `/feed/atom-flux-actualites`, *et* type corrigé (`rss` → `atom`, le flux réel
  était bien de l'Atom). **Deuxième bug, plus profond, découvert après cette première correction** :
  malgré une URL et un type désormais corrects, tous les items remontaient avec un titre/résumé/lien
  vides. Cause — piège classique d'ElementTree dans `_parse_atom()` : le code faisait
  `entry.find("atom:title", NS) or entry.find("title")`. Un `Element` XML sans enfants (une feuille
  comme `<title>texte</title>`) a `__len__() == 0`, donc Python l'évalue comme *falsy* dans un `or`
  même s'il contient du texte — le fallback écrasait donc silencieusement l'élément pourtant valide.
  Corrigé avec un helper `_find()` qui teste `is not None` explicitement au lieu de s'appuyer sur la
  véracité de l'`Element`. Ce bug ne touchait jusqu'ici aucune source en prod car Cybermalveillance
  était la seule source `atom` du fichier — mais aurait cassé silencieusement toute future source
  Atom ajoutée.
- **Global Security Mag** : site SPIP, `/rss.xml` n'existe pas — vrai flux exposé via
  `/spip.php?page=backend`.
- **Synacktiv** : `/feed.rss` n'existe pas — vrai flux `/feed/lastblog.xml`.
- **Sekoia** : deux bugs empilés. (1) User-Agent générique `"CyberVuln-Veille/1.0"` bloqué en 403 —
  remplacé par un User-Agent Chrome réaliste au niveau du client HTTP (`_fetch_feed`), ce qui profite
  aux 16 sources, pas seulement Sekoia. (2) Après ce premier correctif, la vérification initiale
  (juste le code HTTP 200) s'est révélée insuffisante : `blog.sekoia.io/feed/` redirige désormais vers
  `www.sekoia.com/blog`, une page HTML Webflow (le site a migré de domaine/plateforme), pas du XML —
  `ET.fromstring()` échouait avec `not well-formed`. Vrai flux retrouvé à la main :
  `www.sekoia.com/blog/rss.xml`.
- **HarfangLab** : reste cassé, *volontairement non corrigé*. Confirmé qu'il ne s'agit pas d'un
  simple filtre User-Agent (le nouveau UA Chrome ne change rien) mais d'un vrai challenge JS
  Cloudflare ("Just a moment…") — infranchissable avec un client HTTP classique (`httpx`), il
  faudrait un navigateur headless rien que pour ce flux. Laissé en échec documenté (erreur loggée,
  ne bloque pas les 15 autres sources grâce à l'isolation par flux déjà en place dans `_fetch_feed`).

**Testé en réel** : sync manuelle (`POST /api/watch/sync`) → `{"feeds": 16, "fetched": 485,
"inserted": 21, "skipped": 464, "errors": 0}`. Vérifié en base
(`SELECT source, count(*) FROM watch_items GROUP BY source`) : 15 sources sur 16 ont maintenant des
items (contre 5 en tout début de session), avec des titres et dates de publication correctement
peuplés pour Cybermalveillance et Sekoia (ex. Sekoia : "Sold to the Highest Bidder: The Escalation
of ADINT…", publié 2026-06-30). Seule HarfangLab reste à 0, confirmé par les logs backend
(`403 Forbidden` sur `harfanglab.io/feed/`), conforme à la limitation documentée ci-dessus.

---

## 🐛 Points d'attention

- **Une base CVE "à jour en apparence" peut cacher un trou massif** (incident 20/07/2026) : la CVE la
  plus récente datait du jour même, et pourtant ~4750/4842 CVE manquaient pour un CPE Windows Server
  2019 (98%). Ne jamais conclure "la base est à jour" juste parce que `MAX(published)` est récent —
  ça ne dit rien sur la comprehensivité pour un produit donné. Pour vérifier vraiment : comparer le
  CPE exact d'un actif contre NVD directement (`GET /rest/json/cves/2.0?cpeName=...`), pas se fier à
  la fraîcheur apparente. Cause + fix détaillés dans `docs/ARCHITECTURE.md` § Incident sync NVD et
  `docs/MATCHING.md` (bugs de format CPE). Si un utilisateur signale "je ne vois pas telle CVE connue
  pour tel actif", tester `POST /api/sync/nvd/{cve_id}` puis `POST /api/sync/match` avant de supposer
  que l'absence est légitime.
- **WSL2 + Vite** : Vite dans Docker ne détecte pas les changements de fichiers Windows → `docker compose restart frontend` obligatoire après chaque modif frontend
- **WSL2 + `uvicorn --reload` côté backend** (rencontré pour la 1ère fois session 20/07/2026, même
  famille de bug que Vite ci-dessus) : sous forte itération sur un même fichier, `WatchFiles` peut
  boucler indéfiniment ("WatchFiles detected changes" en rafale, des dizaines de fois), le conteneur
  reste bloqué sur "Waiting for application startup" sans jamais finir — chaque rechargement
  interrompt `_startup_matching()` avant qu'il ne se termine, surtout depuis que la base CVE est plus
  grosse (rattrapage NVD de cette session). Un simple `docker compose restart backend` ne suffit
  pas à casser la boucle ; `docker compose up -d --force-recreate backend` oui.
- `docker compose restart` ne relit PAS le `.env` → toujours `up -d --force-recreate`
- **Les droits WMI/DCOM du compte de service WinRM sont plus restreints qu'il n'y paraît** : testé en
  conditions réelles (session 20/07/2026) sur l'environnement de ce parc — `Get-HotFix` ET
  `Get-WmiObject -Class Win32_QuickFixEngineering` renvoient "Accès refusé" ; seul `Get-WinEvent`
  (journal système) fonctionne. Ne jamais supposer qu'une cmdlet WMI "classique" marchera juste parce
  qu'elle ne demande pas de module tiers — tester en direct avant de bâtir une détection dessus (cf.
  `docs/MATCHING.md` § Détection Windows).
- Auth AD : `ldap3.SIMPLE` (DN complet), pas NTLM
- WinRM : deux couches — SDDL session PowerShell ET Root WinRM SDDL
- Win32_QuickFixEngineering ne liste plus les CUs sur WS2019 → utiliser System Event Log (Event ID 19)
- asyncpg dans Celery : utiliser `SessionLocal()` direct, jamais `get_session()`, toujours `flush()` avant SELECT après mutation
- **Connexions DB** : `poolclass=NullPool` obligatoire (cf. `docs/ARCHITECTURE.md`) — un pool persistant
  casse en cascade dès qu'une tâche Celery relance sa boucle asyncio
- `GET /api/cves` a `matched_only=true` par défaut — passer `?matched_only=false` pour voir toutes les CVEs NVD
- **Test navigateur headless (Playwright/Docker)** : le bind-mount Docker Desktop/WSL2 vers un dossier hôte
  peut perdre silencieusement des fichiers écrits juste avant la fin d'un conteneur `--rm` (bug de sync,
  pas lié à l'app) — contourner en écrivant dans le FS interne du conteneur (`/root/...`) puis `docker cp`
  après coup, sans `--rm` avant la copie. Accéder au dashboard via `--network host` + `localhost:3000`,
  pas via le nom de service `frontend` (bloqué par `server.allowedHosts` de Vite)
- **Vite ne recharge pas toujours un fichier édité** même après un simple changement `.js` (bind-mount
  WSL2, pas fiable à 100% pour le file-watch) — si un import fraîchement ajouté/retiré ne se reflète
  pas côté navigateur, `docker compose restart frontend` avant de chercher plus loin
- **Limite de commande WinRM** : le script PowerShell du scan Windows encodé en base64 a une limite
  dure d'environ 8191 caractères (`cmd.exe`) — déjà dépassée deux fois en ajoutant MAC/IP/ports
  (`La ligne de commande est trop longue`). Si un ajout futur au script Windows échoue pareil,
  compacter le P/Invoke `GlobalMemoryStatusEx` en exemple dans `services/asset_scanner.py`
- **`create_all` ne migre pas les tables existantes** — ajouter une colonne à `models.py` nécessite un
  `ALTER TABLE` manuel (`docker exec cybervuln-db-1 psql -U cybervuln -d cybervuln -c "ALTER TABLE ..."`),
  sinon `UndefinedColumnError` au premier `SELECT` touchant la nouvelle colonne
- **Un actif sans `cpe_list` ne matche jamais aucune CVE** (cf. `docs/MATCHING.md`) — `POST/PUT
  /api/assets` et `POST /api/assets/{id}/scan` le dérivent maintenant automatiquement depuis l'OS
  (déclaré ou détecté), mais un OS trop générique ("Linux" sans distro) ne matche toujours rien tant
  qu'un scan n'a pas détecté la distro exacte
- **`SECRET_KEY` chiffre les mots de passe SSH par machine** (`services/crypto.py`, phase de test,
  cf. session du 01/07) — la changer invalide tous les mots de passe déjà enregistrés en base
- **Playwright en npm package direct (pas en conteneur dédié) : inutilisable dans cet environnement**
  (session 20/07/2026) — `chromium`/`chrome-headless-shell` réclament des libs système absentes
  (`libglib-2.0.so.0`, `libnss3`...) et `playwright install --with-deps` exige `sudo` (pas de mot de
  passe disponible, non-interactif). Le contournement déjà documenté ci-dessus (conteneur
  `mcr.microsoft.com/playwright --network host`) reste la bonne piste — ne pas reperdre de temps à
  réinstaller Playwright en direct sur l'hôte WSL, ça ne marche pas ici. À défaut, vérifier via `curl`
  (API backend + `curl http://localhost:3000/src/....jsx` pour confirmer que Vite sert bien le code à
  jour, cf. point Vite ci-dessus) plutôt que de prétendre à un test visuel non fait.

---

## 📌 Prompt de reprise recommandé

```
Lis CLAUDE.md et STATUS.md uniquement.
Commence par : [décrire la tâche du jour]
```

### État en suspens au 02/07/2026 (fin de session)

- **Phase de test assumée à revoir** : mots de passe SSH par machine stockés chiffrés en base
  (`Asset.scan_password_encrypted`, `services/crypto.py`) — l'utilisateur a dit vouloir passer à des
  clés SSH par machine "après". Pas urgent, mais à ne pas oublier si le sujet ressort ; changer
  `SECRET_KEY` invalide tous les mots de passe déjà enregistrés.
- **Patch check Linux limité à Debian** : le Debian Security Tracker (fiable, backports inclus) ne
  couvre que les actifs Debian ; les autres distros retombent sur les plages de versions NVD (best
  effort, ne voit pas les backports). Ubuntu a un équivalent public (API JSON par CVE sur
  ubuntu.com/security), non implémenté — à faire si des actifs Ubuntu entrent réellement dans le parc
  (le parc Linux de test actuel est 100% Debian).
- **Veille — HarfangLab reste cassé** : seule source sur 16 encore en échec, bloquée par un vrai
  challenge JS Cloudflare (pas un simple filtre User-Agent) — infranchissable sans navigateur
  headless. Accepté comme limitation documentée, pas une tâche à reprendre sauf si l'utilisateur
  juge qu'un flux RSS unique justifie l'investissement Playwright/headless en prod.
- Rien d'autre en cours — la session du 02/07/2026 a couvert, dans l'ordre : patch check Linux
  (Debian Security Tracker), 3 bugs de matching CPE (dont matching par paquets installés), correction
  auto hostname/nom/version OS au scan + fix locale CPU, statuts `awaiting_fix`/`false_positive` avec
  annotation et analyste obligatoires (dashboard + tableaux fusionnés + couleurs), recherche CVE et
  filtre actifs (KPI recalculés) sur le dashboard, passe de mise à jour de toute la doc (`CLAUDE.md`
  compris — Tremor inutilisé, `claude_analyzer` sans appel API réel), refonte complète de la partie
  Rapports (bug 500 corrigé, filtre actifs + période, résumé en tableaux, export CSV enfin branché +
  encodage BOM corrigé), et pour finir la Veille cyber : 2 sources "Fuite de données" mortes
  (fuitesinfos.fr, Bonjour la fuite) puis, après audit complet des 16 sources, 8 autres sources
  cassées corrigées (CERT-FR Avis/Alertes, ANSSI, CNIL, Cybermalveillance — dont un vrai bug de
  parsing Atom lié à un piège `Element.__len__()`/`or` d'ElementTree —, Global Security Mag,
  Synacktiv, Sekoia), avec HarfangLab laissé en échec documenté (Cloudflare, non contournable
  proprement). Tout testé en conditions réelles (Playwright, souvent contre l'infra réelle via
  SSH/scan, et syncs Veille réelles vérifiées en base) et documenté au fil de l'eau dans `docs/`.

### Session courante (03/07/2026, suite) — Fix libellé connexion Linux + refonte identité visuelle CBR

**Fix libellé "Connexion WinRM" affiché pour des actifs Linux** (patch check) — le texte était codé en
dur, jamais conditionné à l'OS réel de l'actif :
- `Dashboard.jsx` / `Vulnerabilities.jsx` (modale patch check par vuln) : `/windows/i.test(asset?.os) ?
  'WinRM' : 'SSH'`
- Bandeau global "Analyse en cours" (cycle automatique) : nécessitait d'exposer `os` dans le dict
  `_current_check` de `patch_checker.py` (absent jusque-là) pour que le frontend puisse faire la même
  distinction sur ce second point d'affichage

**Logo/favicon CBR redessinés** ("plus qualitatif") — bouclier + épées croisées, fond violet
(`LOGO_PURPLE = '#5b21b6'`), agrandi et avec le même ratio badge/icône entre la sidebar, `Home.jsx` et
le favicon (`frontend/public/favicon.svg`) qui servait jusque-là de référence de qualité à atteindre.

**Sidebar réductible** (`Layout.jsx`) — bouton `<` en haut à droite de la sidebar (au lieu d'un bouton
pleine largeur en bas), bascule vers une "fine bande d'icônes" (largeur réduite, labels masqués, tooltip
au survol), état persisté (même pattern que `ThemeContext`).

**Couleurs par module dans la nav** — reprend la couleur de chaque tuile de `Home.jsx`, appliquée à la
fois à l'état actif (sélectionné) et à l'icône au repos (avant : bleu uniforme partout, y compris non
sélectionné) :
| Groupe nav | Couleur |
|---|---|
| CyberVuln | `#f85149` (rouge) |
| CyberVeille | `#58a6ff` (bleu — anciennement couleur d'Inventaire) |
| Inventaire | `#b5793a` (marron — anciennement couleur de Veille) |
| Pentest | `#3fb950` (vert) |
| Administration | `#fb8f44` (orange) |
| Rapports | `#a371f7` (violet) |
| Paramètres | `#8b949e` (gris) |

**Restructuration complète de la nav** (`Layout.jsx` `NAV_GROUPS`, `App.jsx` routes) — regroupement par
module produit plutôt que la liste plate précédente :
```
CyberVuln       : Dashboard / Vulnérabilités / Actifs / CVE
CyberVeille     : Veille technologique / Fuite de données / Surveillance Identités
Inventaire      : Inventaire Complet
Pentest         : (placeholder, inchangé)
Administration  : Bastion (renommé, ex-"Administration")
Rapports        : Rapport exécutif CVE / Rapport Veille / Rapport Surveillance
Paramètres      : (transverse, inchangé)
```
Nouvelles pages placeholder créées pour les entrées sans contenu réel pour l'instant :
`SurveillanceIdentites.jsx`, `RapportVeille.jsx`, `RapportSurveillance.jsx` (routes
`/surveillance-identites`, `/rapport-veille`, `/rapport-surveillance`).

### Session courante (03/07/2026, suite) — Nouvel onglet "Fuite de données" (CyberVeille)

**Séparation depuis Veille technologique** : les 3 sources dédiées fuite (ZATAZ, fuitesinfos.fr,
Bonjour la fuite) polluaient le registre NIS 2 général et le thème "Fuite de données" y remontait par
mots-clés des articles sans rapport (ex : un article HarfangLab mentionnant incidemment une fuite).
Nouvel onglet dédié (`FuiteDeDonnees.jsx`, route `/fuite-de-donnees`), 100% informatif — aucun statut/
analyste/décision/SLA, sans rapport avec le registre auditable NIS 2. Filtrage par **source** (pas par
thème) : `routers/watch.py` gagne `_apply_multi_exclude`/`exclude_source` (Veille technologique exclut
les sources dédiées) et `source=...` (Fuite de données les inclut par défaut) — les deux résolus
dynamiquement via un nouvel endpoint plutôt qu'une liste statique dupliquée des deux côtés (cf. plus
bas, "sources personnalisées").

**Refonte visuelle en plusieurs passes** (design épuré, prise d'information rapide, demandé
explicitement "pas une liste, des cards") :
- Grille de cards responsive (1/2/3 colonnes) au lieu d'une liste de lignes pleine largeur
- **Drapeaux pays en vraies images SVG**, pas en emoji unicode — `country-flag-icons` (npm) : les
  séquences d'indicateurs régionaux (🇫🇷 = "F"+"R") ne sont pas rendues comme un drapeau par tous les
  systèmes (Windows hors 11 récent, certains Chrome affichent le texte brut "FR"/"DE" au lieu d'une
  image) — bug remonté par l'utilisateur en test réel, corrigé en remplaçant l'emoji par
  `components/FlagIcon.jsx` (SVG local, pas de CDN)
- Filtre pays : France par défaut, "Monde entier", ou sélection multiple via `utils/countries.js`
  (~40 pays) — `WatchItem.country` (ISO alpha-2, nouvelle colonne) alimentée par l'API pour
  ransomware.live, défaut FR pour les trackers dédiés français, `None` sinon
- Une couleur distincte par source (chip + badge de carte), plus une teinte violette unique partagée
- Nom de l'entreprise affiché à côté du badge source (pas seulement dans le titre en dessous) — pour
  ransomware.live (seule source avec un champ "victime" structuré), le titre backend
  `"victime — groupe (activité)"` est éclaté côté frontend (`parseCompany()`) pour isoler le nom ; les
  autres sources utilisent le titre tel quel (déjà l'intitulé de l'entité pour ces flux dédiés)

**Nouvelles sources connectées** :
- **ransomware.live** (`/v2/recentvictims`, API publique sans clé) — endpoint `/v2/countryvictims/{code}`
  écarté volontairement : schéma de champs différent (`post_title`/`post_url`/`group_name` au lieu de
  `victim`/`url`/`group`) et son seul lien "public" est en réalité un lien `.onion`, jamais exposé.
  Champ `claim_url` (onion) jamais utilisé non plus, seul `url` (page ransomware.live publique) sert de
  lien sortant.
- **DataBreaches.net** (flux RSS standard, référence journalistique du secteur)
- **Have I Been Pwned** (`/v3/breaches`, API publique) — l'API renvoie tout l'historique (1000+
  brèches) sans filtre serveur par date ; filtré côté client à `AddedDate` < 120 jours pour éviter de
  noyer la première synchro sous des centaines d'entrées historiques
- **"Bonjour la fuite" retiré** (demande explicite) — flux RSS + toutes ses références nettoyées
  (sévérité/thèmes/pays par défaut, listes frontend)

**Sources RSS/Atom personnalisées** (`models.py` `WatchSource`, nouvelle table) — l'utilisateur peut
ajouter ses propres flux sans toucher au code, depuis **Fuite de données ET Veille technologique** :
- `category` (`general` | `leak`) distingue uniquement le routage d'affichage — une source "leak"
  (ajoutée depuis Fuite de données) apparaît dans cet onglet et est exclue de Veille technologique ;
  une source "general" (ajoutée depuis Veille technologique) fait l'inverse. La collecte elle-même
  (`run_watch_sync`) ne fait aucune distinction, les deux catégories sont fetchées identiquement
- `GET /api/watch/leak-sources` — unique source de vérité (BUILTIN_LEAK_SOURCES + sources `category=leak`
  actives) consommée par les deux pages, pour ne jamais dupliquer/désynchroniser la liste
- `POST/PATCH/DELETE /api/watch/sources` — slug généré depuis le nom (`_slugify`), garde-fou anti-
  collision avec une source codée en dur ou déjà existante (409). **Bug corrigé en test** : un nom
  accentué ("Test Veille Générale") produisait un slug fragmenté (`g-n-rale` au lieu de `generale`) car
  le regex `[^a-z0-9]+` traitait chaque caractère accentué comme un séparateur — fixé en passant par
  `unicodedata.normalize("NFKD", ...)` avant le regex pour retomber sur de l'ASCII pur
  ("Générale" → "Generale")
- Supprimer une source arrête sa collecte future mais **conserve les items déjà importés** (leur
  `source_label` est figé sur chaque `WatchItem`, pas de FK vers `WatchSource`)
- Frontend : `components/AddSourceModal.jsx` (modale partagée, `category` fixé par l'appelant, pas un
  choix dans le formulaire), `components/FlagIcon.jsx`, `utils/countries.js`, `utils/color.js`
  (`hexToRgba`) — extraits en composants/utils communs dès la 2e page consommatrice plutôt que dupliqués,
  cohérent avec le principe de scalabilité du projet (cf. `CLAUDE.md`)
- Ajout depuis Veille technologique : nouvelle colonne "Personnalisées" dans le dropdown sources
  (4e colonne, à côté d'Officielles/Médias & trackers/Éditeurs sécu), avec suppression (`×`) par source

**Scrollbar de la sidebar restylée** — le navigateur affichait par défaut une barre blanche/grise avec
son propre fond (détonnant surtout en dark mode) ; réduite et recolorée sur les variables CSS du thème
(`--border` au repos, `--text-faint` au survol), piste transparente — `.sidebar-scroll` dans
`index.css`, appliqué au conteneur nav de `Layout.jsx`, valable réduite ou non (même conteneur).

Tout vérifié en navigateur réel (Playwright, conteneur `mcr.microsoft.com/playwright --network host`) à
chaque étape : sync réelle des nouvelles sources, filtre pays, ajout/suppression de source personnalisée
sur les deux pages (Fuite de données et Veille technologique), zéro erreur console à chaque passe.

### Session courante (20/07/2026) — Date de dernière synchronisation (Veille, Fuite de données,
Matching CVE) + sévérité éditable manuellement

**Contexte** : premier lancement de la stack dans cette session — Docker n'était pas accessible au
départ (intégration WSL2 de Docker Desktop désactivée pour cette distro), résolu en démarrant Docker
Desktop côté Windows.

**Date de dernière synchronisation** — demandée d'abord pour Fuite de données, puis étendue à Veille
technologique et au bouton "Matching CVE" du Dashboard, une fois le même besoin identifié ailleurs :
- Nouvelle table générique `sync_state` (`models.py`) : une ligne par clé de tâche (`key`, ex. `watch`,
  `cpe_match`) plutôt qu'une table par tâche — la 2e tâche à en avoir besoin (matching CPE) a servi de
  signal pour généraliser au lieu de dupliquer un modèle `WatchSyncState` créé pour la 1ère
  implémentation (Fuite de données/Veille). Nécessaire car ces deux syncs tournent **aussi**
  automatiquement en arrière-plan (Celery beat horaire pour `run_watch_sync`, démarrage de l'app pour
  `run_cpe_matching`) — un simple state React local se serait remis à zéro à chaque rechargement de
  page et n'aurait jamais reflété les syncs automatiques.
- `GET /api/watch/sync-status` et `GET /api/sync/match-status` (nouveaux endpoints), `POST
  /api/watch/sync` et `POST /api/sync/match` renvoient aussi `synced_at` pour une mise à jour immédiate
  sans second aller-retour. L'horodatage est écrit même si la synchro ne trouve rien de neuf (une sync
  à 0 résultat reste une sync effectuée).
- Frontend : "Dernière sync : jj/mm/aaaa hh:mm" (ou "Jamais synchronisé") affiché sous le bouton
  correspondant sur `FuiteDeDonnees.jsx`, `Watch.jsx` et `MatchingCveButton` (`Dashboard.jsx`).
- **Bug rencontré** : la 1ère version de `WatchSyncState.id` avait été écrite en `Boolean` par erreur
  puis corrigée en `Integer` avant même le premier lancement — mais `create_all` avait déjà créé la
  table avec la colonne `boolean` en base (résidu d'un état antérieur, table vide) →
  `UndefinedFunctionError: operator does not exist: boolean = integer` au premier appel. Fixé en
  droppant la table vide et laissant `create_all` la recréer avec le bon type (cf. point `create_all` déjà
  documenté ci-dessus dans "Points d'attention").
- **Bug rencontré (confirmé, pas juste une hypothèse)** : après la 1ère implémentation (Fuite de
  données), tout fonctionnait ; après avoir ajouté le même code à `Watch.jsx`, l'utilisateur a rapporté
  "ça ne marche pas". Le module servi par Vite (`curl http://localhost:3000/src/pages/Watch.jsx`) ne
  contenait tout simplement pas le nouveau code, alors que le fichier sur disque était correct — cf.
  point Vite/bind-mount déjà documenté. `docker compose restart frontend` a suffi à corriger.

**Sévérité éditable manuellement** (Veille technologique uniquement, pas Fuite de données qui n'a
aucun workflow) — sélecteur Critique/Important/Informatif ajouté dans la modale de traitement, au-dessus
du workflow de statut existant, mêmes badges (`SEV_STYLES`/`SEV_LABELS`, déjà utilisés pour l'affichage).
`PATCH /api/watch/{id}` accepte désormais `severity` (validée serveur). Pas de trace de qui a changé
quoi pour ce champ (contrairement au statut) — changer la sévérité affecte rétroactivement le SLA 48h
et l'export CSV auditeur, tous deux restreints à `severity=critical` ; à surveiller si le sujet
d'auditabilité ressort plus tard.

Vérifié via `curl` (API directe + à travers le proxy Vite) plutôt qu'en navigateur réel : Playwright
inutilisable dans cet environnement précis (cf. "Points d'attention" ci-dessus, libs système absentes/
pas de `sudo`) — limitation propre à cette session/ce conteneur, pas à l'app.

### Session courante (20/07/2026, suite) — Statut "en attente" dans le Top CVE, Connexions IP déplacées,
thème IA

**Rapport exécutif — annotation "en attente de correctif" dans le Top CVE** : une CVE critique restait
listée en tête du Top 5 "à traiter en priorité" sans distinction, même quand elle était en réalité déjà
suivie via le statut `awaiting_fix` (correctif éditeur/distro pas encore sorti) — donnait l'impression
qu'elle était ignorée. Nouvelle colonne "Statut" dans la table markdown (`services/claude_analyzer.py`
`generate_executive_summary`) : "⏳ " + l'annotation complète (`Vulnerability.notes`) si au moins une
vuln de cette CVE (dans le périmètre actif filtré) est `awaiting_fix`, "—" sinon. `routers/reports.py`
récupère désormais ces annotations (`awaiting_fix_notes: dict[cve_id, notes]`, la plus récente si
plusieurs actifs). D'abord tronquée à 100 caractères comme les autres tableaux du rapport, puis affichée
en entier sur demande explicite — pas de troncature pour cette colonne spécifiquement (celle de la
CVE reste tronquée à 150, elle). Rendu (web + export PDF) 100% générique côté `Reports.jsx`
(`renderMd`/`exportPdf` parsent n'importe quelle table markdown par nombre de colonnes), aucune
modification frontend nécessaire.

**"Connexions IP" déplacée de Rapports vers Paramètres** — `ConnectionsSection` (mot de passe,
`GET /api/connections`, anonymisation) coupée-collée telle quelle de `Reports.jsx` vers `Settings.jsx`,
nouvelle section "Sécurité". Import `getConnections`/`anonymizeConnection` migrés avec. Zéro résidu
vérifié des deux côtés après coup (`curl` sur les modules Vite transformés).

**Section "À propos" retirée de Paramètres** (demande explicite, pas de raison donnée) — bloc identité
CyberVuln/stack/liens API docs supprimé de `Settings.jsx`. Il ne reste que Présentation / Apparence /
Sécurité.

**Nouveau thème "IA"** (`services/watch_fetcher.py` `THEME_KEYWORDS`) — mots-clés multi-mots
uniquement (intelligence artificielle, ia générative, chatgpt, genai, large language model, modèle de
langage, deepfake, machine learning, deep learning, prompt injection, ai act, règlement ia) : **pas** de
token court "ia"/" ia " seul, testé et rejeté mentalement avant même d'écrire le code — trop ambigu en
simple `in` substring (le mécanisme existant de `_themes_for_item` ne fait pas de word-boundary), aurait
matché "diagnostic", "sociale", "financiaire"...

- **Thèmes déjà en base jamais reclassés automatiquement** — bug d'usage détecté par l'utilisateur
  ("j'ai cliqué sur IA, rien ne s'affiche") : la classification ne tourne qu'à l'insertion
  (`run_watch_sync`), un item déjà importé ne se reclasse jamais tout seul quand un thème est ajouté
  après coup. Nouveau endpoint réutilisable `POST /api/watch/recompute-themes`
  (`recompute_all_themes()`) — recalcule `themes` pour tous les items déjà en base à partir des règles
  actuelles, fonction pure donc sans risque d'écraser une saisie d'analyste (les thèmes ne sont jamais
  édités manuellement). Lancé une fois : 1481 items, 19 mis à jour, dont 8 récupérant le thème IA. À
  relancer après tout futur ajout/affinement de thème — cf. `docs/VEILLE.md` § 3.
- **Chips de thème + `THEME_KEYWORDS` triés par ordre alphabétique** (demande explicite) — `Watch.jsx`,
  `RapportVeille.jsx` (const `THEMES`, dupliquée dans les deux, pas encore extraite en util partagé) et
  le dict backend par cohérence (son ordre n'a aucun effet fonctionnel, mais autant que les deux
  concordent pour qui lit le code).

Tout revérifié via `curl` (API + modules Vite transformés) après chaque redémarrage de conteneur,
Playwright toujours indisponible dans cet environnement (cf. note ajoutée aux "Points d'attention" plus
haut dans la session précédente).

### Session courante (20/07/2026, suite) — Module Surveillance Identités (fuites concernant l'entreprise)

**Besoin** : "voir les fuites de données concernant mon entreprise". Après discussion des options
gratuites (le vrai HIBP *Domain Search* est payant + vérif de domaine ; Intelligence X free tier trop
limité), retenu l'approche **la plus dans l'esprit du projet** : croiser des identités surveillées avec
les fuites **déjà collectées** par la Veille — aucune source externe propre, 100% gratuit.

- **`models.WatchedIdentity`** (nouvelle table `watched_identities`) : `value` + `kind` (name | domain)
  + `enabled` + `created_at`. Liste éditable dans l'interface (pilotée en base, principe scalable), pas
  de valeur codée en dur.
- **`routers/identities.py`** (nouveau, monté `/api/identities`) : CRUD + `GET /matches`. Le matching
  est calculé **à la volée** (pas de stockage) sur les `watch_items` des sources leak uniquement (mêmes
  clés que `/watch/leak-sources`). Nom matché en **mot entier** (regex `(?<!\w)…(?!\w)`, même précaution
  anti-sous-chaîne que le thème IA) — et pour ransomware.live aussi contre le champ victime isolé (titre
  avant " — ") ; domaine matché en sous-chaîne. Chaque item renvoyé porte `matched_identities`.
- **Frontend** : `SurveillanceIdentites.jsx` (était un placeholder) — gestion des identités (toggle
  Nom/Domaine, chips supprimables) + cards des fuites matchées (style repris de `FuiteDeDonnees.jsx`,
  badges rouges des identités ayant matché). États vides distincts (aucune identité vs aucun match =
  bonne nouvelle, message vert). `client.js` : `watchedIdentities`/`createIdentity`/`deleteIdentity`/
  `identityMatches`.
- **Validé bout en bout** : matching confirmé avec un vrai nom présent en base ("Deutsche Bank" →
  victime ransomware.live), puis identité de test supprimée. État laissé : AER + aer.loc enregistrés
  (0 match, normal — entreprise de test sans fuite réelle dans les données collectées).
- **Limite assumée documentée** (`docs/VEILLE.md` § 9bis) : ne voit que ce qui est publiquement
  rapporté ; pas de gestion du mode Anonyme pour l'instant (parité `FuiteDeDonnees.jsx`), à revoir si le
  sujet ressort vu que les identités contiennent le vrai nom d'entreprise.

Docs mises à jour : `CLAUDE.md` (module plus "placeholder", `WatchedIdentity`/`identities.py` dans
l'arbo), `docs/ARCHITECTURE.md` (table + endpoints), `docs/VEILLE.md` (§ 9bis complet), `docs/FRONTEND.md`
(description page + arbo). Vérifié via `curl` (API directe + proxy Vite), Playwright toujours indispo.

### Session courante (20/07/2026, suite) — Mode Anonyme + type IP/plage IP sur Surveillance Identités

**Mode Anonyme branché** — demande explicite : les identités surveillées contiennent littéralement le
nom/domaine réel, et les fuites matchées sont des articles publics qui les citent nommément dans le
texte (impossible à anonymiser par simple substitution de champ, contrairement à `anonymizeAsset`).
`anonymizeIdentity`/`anonymizeIdentityMatch` (`utils/fakeData.js`) redirigent chaque occurrence du
nom/domaine réel **dans le texte** (même technique que `redactText`), déterministe par hash. Complété
par `FAKE_IDENTITIES`/`FAKE_IDENTITY_MATCHES` (entreprise fictive "Norvenia Group") pour une démo
parlante même sans fuite réelle. Ajout/suppression désactivés en mode Anonyme.

**Recherche de sources supplémentaires** (demande explicite : "cherche des sources en lien avec des
fuites de données sur les IP") :
- **ransomwatch** (github.com/joshhighet/ransomwatch, agrégateur ransomware indépendant) — écarté après
  vérification de l'historique des commits : `posts.json` plus mis à jour depuis **juin 2025** (bot
  d'alimentation arrêté). Même type de vigilance déjà appliqué à chaque source RSS ajoutée par le passé
  (cf. sessions du 02/07 — plusieurs sources cassées corrigées à l'époque).
- **Leak-Lookup / Intelligence X / DeHashed** — nécessitent inscription/clé API, hors périmètre gratuit
  du projet.
- **IPsum, Blocklist.de, Feodo Tracker (abuse.ch)** — retenues (voir ci-dessous), fraîcheur vérifiée
  (mise à jour du jour même pour les deux premières).

**Type IP / plage IP ajouté** — vérifié avant d'implémenter : **0 des 1500+ items de veille déjà
collectés ne contient une seule adresse IP** dans son texte, donc le matching texte (§ 9bis) n'aurait
jamais fonctionné pour une IP. Mécanisme différent retenu :
- **`services/ip_watch.py`** (nouveau) — vérifie les IP/plages surveillées contre 3 listes de blocage
  tierces gratuites, sans clé API : IPsum (agrégat ~115k IP, `score` = nb de listes sources), Blocklist.de
  (~23k IP fail2ban), Feodo Tracker abuse.ch (C2 malware, liste volontairement petite). Cache process 30
  min (`CACHE_TTL_SECONDS`) pour ne pas marteler ces services à chaque appel — un échec réseau sur l'une
  des 3 ne fait pas échouer les autres (conserve son dernier cache).
- `routers/identities.py` : `kind` accepte désormais `ip`/`ip_range`, validés + normalisés via le module
  Python `ipaddress` (`ip_address`/`ip_network(strict=False)`, 400 si invalide — testé avec
  "999.999.999.999" et une plage sans `/`). `GET /matches` retourne en plus `ip_total`/`ip_matches`.
- Testé de bout en bout avec un vrai `/24` couvrant une IP présente sur IPsum : la plage a bien remonté
  **2 IP distinctes** de la liste (`.47` score 9 et `.17` score 2) + un hit Blocklist.de séparé — le
  matching CIDR fonctionne correctement, pas juste l'IP exacte ajoutée.
- Frontend : sélecteur à 4 types (Nom/Domaine/IP/Plage IP), nouvelle section tableau séparée des cards
  de fuites (donnée tabulaire, pas d'article) : Votre identité / IP détectée / Source / Détail. Compteur
  d'en-tête = somme des deux signaux. Anonymisation étendue (`FAKE_PUBLIC_IPS`/`FAKE_PUBLIC_IP_RANGES`
  en plages RFC 5737/TEST-NET, jamais routées — l'IP blocklistée elle-même n'est jamais anonymisée,
  c'est une IP attaquante tierce déjà publique, pas la vôtre).

Docs mises à jour : `docs/VEILLE.md` (§ 9bis étendu à 4 types, nouveau § 9ter détaillant les 3 sources
et le candidat écarté), `docs/ARCHITECTURE.md` (schéma + endpoints), `CLAUDE.md` (`ip_watch.py` dans
l'arbo), `docs/FRONTEND.md` (sélecteur 4 types, section IP, anonymisation étendue). Identités de test
nettoyées après vérification (AER/aer.loc + "Eurofeu" ajouté entre-temps par l'utilisateur laissés
intacts, seules mes IP/noms de test supprimés).

### Session courante (20/07/2026, suite) — Seuil minimum sur le score IPsum

L'utilisateur a demandé une explication du tableau IP (colonnes, sens de "score 1") puis, en voyant que
le score 1 est la confiance la plus faible possible, a demandé un seuil minimum pour filtrer le bruit.
Vérifié avant de choisir une valeur plutôt que de deviner : distribution réelle sur ~113k IP IPsum —
**score 1 = 78 355 IP (69% du total)**, score 2 = 16 396, score 3 = 11 049, score 4+ = ~7 300. Seuil
`IPSUM_MIN_SCORE = 2` retenu (`services/ip_watch.py`, filtré directement au parsing) : élimine le bruit
à source unique sans perdre les IP corroborées par au moins une 2e liste. Blocklist.de/Feodo Tracker
n'ont pas de score, rien à filtrer côté ces deux sources. Testé : la plage de l'utilisateur (3 résultats
score 1 dans son exemple) ne remonte plus rien après le filtre ; une IP score 2 de test passe toujours.
Doc mise à jour : `docs/VEILLE.md` (§ 9ter, tableau de distribution).

### Session courante (20/07/2026, suite) — Incident majeur : ~4750 CVE manquantes pour Windows Server
2019, sync NVD structurellement cassée

**Déclencheur** : l'utilisateur constate 0 CVE à traiter sur l'actif DEPLOYAPP (Windows Server 2019) et
demande si c'est normal. Vérification initiale : oui, en apparence — 88 CVE matchées, toutes
`patched`, base CVE fraîche (CVE la plus récente publiée le jour même). Puis l'utilisateur signale que
CVE-2022-30190 (Follina) n'est pas prise en compte. Investigation qui a révélé un problème bien plus
large que cette seule CVE.

**Chaîne de bugs découverts, dans l'ordre** :
1. CVE-2022-30190 absente de la base locale (0 ligne), alors que confirmée applicable à Windows
   Server 2019 par NVD (configuration `cpe:2.3:o:microsoft:windows_server_2019:*:...` avec
   `vulnerable: true`).
2. Cause : la sync incrémentale dérivait son curseur de `MAX(CVE.modified)` **recalculé à chaque
   appel** — un run interrompu en cours de pagination (timeout, 503) committait ce qu'il avait réussi,
   et ce résultat partiel devenait la nouvelle référence pour le run suivant. Ce qui restait à traiter
   dans la fenêtre interrompue était perdu **pour toujours**, sans erreur visible nulle part.
3. Mesure de l'ampleur (comparaison directe NVD ↔ base locale, sur les 2 seuls actifs actifs de ce
   parc de test) : **Windows Server 2019 (DEPLOYAPP) : 4756/4842 CVE manquantes (98%)** ; Debian 12
   (gitlab.aer.loc) : 28/28 (mais majoritairement de vieilles CVE Linux génériques peu spécifiques,
   moins alarmant que le cas Windows). Échantillon de sévérité (40 CVE Windows manquantes au hasard) :
   27 HIGH, 13 MEDIUM.
4. Découverte que **le filet de sécurité censé rattraper ça ne fonctionnait pas** : `sync_nvd_critical`
   (tâche quotidienne "CRITICAL+HIGH sur 30 jours") appelait `run_nvd_sync()` sans désactiver le mode
   incrémental — `days=30` était donc silencieusement ignoré, la rendant strictement identique à la
   sync des 4h. Un filet de sécurité qui n'a jamais rien rattrapé depuis sa création.
5. En tentant de mesurer/corriger via `fetch_by_cpe` (jusque-là jamais appelée dans le code), découverte
   de **CPE stockés malformés** (`services/asset_importer.py::_build_cpe`) : un composant `:*` en trop
   (12 au lieu de 11) rendait le CPE rejeté (404) par NVD en requête directe, bien que toléré par le
   matching interne (comparaison composant par composant, tronquée à la plus courte longueur — d'où
   l'invisibilité totale du bug jusqu'à cet incident). Puis un 2e défaut spécifique à Windows : le
   composant version répétait l'année déjà présente dans le nom du produit (`windows_server_2019:2019`)
   au lieu de `-` (convention NVD), restreignant fortement toute recherche NVD par CPE exact.

**Fixes appliqués** :
- `services/nvd_fetcher.py` : curseur persisté en base (`sync_state`, clé `"nvd"`), n'avance que si le
  run se termine sans exception, avec 3 jours de recouvrement (`INCREMENTAL_OVERLAP`) par précaution
  systématique. Nouveau paramètre `since_override` pour un balayage indépendant du curseur canonique
  (ne le lit ni ne l'avance) — utilisé par le filet de sécurité corrigé.
- `tasks/scheduled_tasks.py` : `sync_nvd_critical` rebalaie désormais réellement 45 jours par date de
  modification via `since_override`, indépendamment du curseur de la sync des 4h.
- `services/asset_importer.py::_build_cpe` : composant en trop retiré ; version Windows mise à `-`.
  CPE déjà stockés en base (DEPLOYAPP, gitlab.aer.loc) corrigés manuellement (le fix ne s'applique
  qu'aux futurs imports/scans).
- Nouveaux endpoints : `POST /api/sync/nvd/{cve_id}` (rattrapage ponctuel d'une CVE précise, utilisé
  pour importer CVE-2022-30190 dans l'instant) et `POST /api/sync/nvd-backfill` (rattrapage complet par
  CPE réellement présents sur le parc, ~260s pour les 2 CPE de ce parc de test avec clé API NVD).

**Résultat mesuré après rattrapage** : 0 CVE manquante pour les 2 CPE du parc (vérifié par nouvelle
comparaison directe avec NVD). Après ré-matching (`POST /api/sync/match`), DEPLOYAPP passe de 0 CVE à
traiter à **102 CRITICAL + 3103 HIGH + 1202 MEDIUM + 15 LOW ouvertes** — saut spectaculaire mais
attendu et légitime, pas une régression : c'est la vraie photo qui manquait depuis le début. Recommandé
à l'utilisateur de lancer un patch check global ensuite (beaucoup de ces CVE sont probablement déjà
corrigées en réalité via Windows Update cumulatif, jamais vérifiées puisqu'elles n'existaient pas en
base avant) — pas fait moi-même, ça touche une vraie connexion WinRM vers le serveur réel.

**Note pour la suite** : l'utilisateur signale que CVE-2022-30190 serait déjà patchée sur le serveur
réel — à vérifier via un vrai patch check read-only (`POST /api/patch-check/{vuln_id}`) plutôt que de
la marquer corrigée sur simple déclaration, cohérent avec la règle CLAUDE.md (aucune bascule sans
signal réel, même pour du non-CRITICAL où l'auto-bascule exige `patch_detected: true`).

Docs mises à jour : `docs/ARCHITECTURE.md` (nouvelle sous-section "Incident" complète + table
`sync_state` + endpoints), `docs/MATCHING.md` (bugs de format CPE), `STATUS.md` (Points d'attention +
cette entrée).

### Session courante (20/07/2026, suite) — Patch checker Windows aveugle aux correctifs anciens
absorbés par une CU récente

**Suite directe de l'incident ci-dessus.** L'utilisateur signale que CVE-2022-30190 serait déjà
patchée sur DEPLOYAPP. Premier contrôle read-only (`POST /api/patch-check/{vuln_id}`) : aucun des 12
KB de juin 2022 associés n'est trouvé, `patch_detected: false` — contredit l'utilisateur. Plutôt que
d'accepter sa déclaration ou de la rejeter, demande de preuve : l'utilisateur fournit `Get-HotFix`
(dernières mises à jour installées aujourd'hui même) et `reg query HKEY_CLASSES_ROOT\ms-msdt` (clé
toujours présente → pas de contournement registre appliqué).

**Diagnostic** : Windows Server fonctionne en mises à jour **cumulatives** — une CU de juillet 2026
inclut forcément le correctif de juin 2022, mais `Get-HotFix`/`Win32_QuickFixEngineering`/journal
Windows Update ne mentionnent plus jamais l'ancien KB une fois absorbé. Le patch checker cherchait
uniquement le KB exact → faux négatif garanti pour toute vieille CVE, potentiellement des milliers
étant donné le rattrapage NVD de la session précédente.

**Fix** (`services/patch_checker.py`) : 2e signal de détection, prioritaire quand disponible —
compare le build/révision Windows réellement installé (`CurrentBuildNumber.UBR`, lu par registre,
insensible à la supersession) à la plage de version vulnérable que NVD fournit par CPE **OS** pour
cette CVE. Généralisation de `_extract_version_constraints()`/`_version_patched()` — jusque-là
restreintes aux CPE type "application" (paquets Linux) — au type "o" (`part="o"`, nouveau paramètre).
Repli sur l'ancien check KB quand aucune plage de version n'est exploitable pour ce CPE.

**Validé en conditions réelles** : CVE-2022-30190 sur DEPLOYAPP → build installé `10.0.17763.9020`
contre seuil NVD `10.0.17763.3046` → `patch_detected: true`, auto-bascule `patched` (HIGH, non
critique) malgré les 12 KB toujours "non trouvés". Testé sur 12 vulnérabilités Windows au total (4
verdicts par build, 6 en repli KB sans erreur) + 2 vulnérabilités Linux (chemin Debian Security
Tracker, non touché, inchangé) — aucune régression.

Docs mises à jour : `docs/MATCHING.md` (nouvelle sous-section "Détection Windows", jusque-là jamais
détaillée alors que la voie Linux l'était déjà depuis la session du 02/07), `docs/ARCHITECTURE.md`
(renvoi depuis la section incident).

### Session courante (20/07/2026, suite) — 3e signal (repli par date) + découverte des droits WMI réels

**Déclencheur** : l'utilisateur pointe 9 autres CVE CRITICAL sur DEPLOYAPP (2019-2021, une de 2025),
constate qu'elles datent d'assez longtemps pour être sûrement déjà corrigées. Test du signal 2
(build/révision) : `build_verdict: None` pour 9/10 — NVD n'a simplement **pas** encodé de plage de
version exploitable pour ces CVE plus anciennes (vérifié sur `cve.raw_data` : juste
`{"vulnerable": true}` sans `versionEndExcluding`, contrairement à CVE-2022-30190). Pas un bug, une
vraie limite de données NVD pour ce millésime de CVE.

**Piste explorée et écartée** : l'API MSRC (déjà appelée pour les KB) ne fournit pas non plus de seuil
de build exploitable (`baseProductVersion` générique, `affectedBinaries` vide) — juste le nom du KB
d'origine et sa date de sortie (`releaseDate`), pas de numéro de build.

**3e signal ajouté** : repli par comparaison de dates — date de publication NVD de la CVE vs date de
l'événement Windows Update le plus récent (même Event ID 19 que le signal KB, aucun appel WinRM
supplémentaire). Purement informatif, n'alimente jamais `patch_detected`/l'auto-bascule.

**Découverte en débogant l'implémentation** : `Get-HotFix` **et** `Get-WmiObject -Class
Win32_QuickFixEngineering` renvoient tous deux "Accès refusé" pour le compte de service utilisé ici
(testé directement en WinRM depuis le conteneur backend) — seul `Get-WinEvent` (journal système)
fonctionne réellement. Ça n'a jamais empêché la détection KB de fonctionner (source 1, déjà celle qui
marchait), mais ça confirme que les sources 2/3 du check KB sont mortes dans cet environnement
précis — laissées en best-effort dans le code (n'affectent rien si elles échouent), pas retirées, au
cas où un futur déploiement ait un compte avec plus de droits.

**Incident opérationnel pendant le débogage** : après plusieurs redémarrages rapprochés du backend
(`docker compose restart`) pendant l'itération sur `patch_checker.py`, le conteneur est resté bloqué
indéfiniment sur "Waiting for application startup" — 58 cycles `WatchFiles detected changes`
enchaînés en boucle (même bug bind-mount WSL2/Docker déjà documenté pour le frontend Vite, jamais vu
côté backend jusqu'ici). Chaque rechargement interrompait le matching CPE au démarrage
(`_startup_matching`) avant qu'il ne finisse (base ~40% plus grosse depuis le rattrapage NVD de
cette session, donc plus long qu'avant). Résolu par `docker compose up -d --force-recreate backend`
(un simple `restart` ne suffit pas à casser la boucle) — ajouté aux "Points d'attention".

Testé après fix : les 9 CVE affichent maintenant `date_heuristic: true` (dernière mise à jour
2026-07-20, largement postérieure à leurs dates de publication 2019-2021) — reste à la charge de
l'utilisateur de valider manuellement (CRITICAL, jamais d'auto-bascule). Non-régression vérifiée :
CVE-2022-30190 utilise toujours le signal build (`date_heuristic: None`, pas invoqué), Linux inchangé.

Docs mises à jour : `docs/MATCHING.md` (signal 3 + droits WMI réels du compte de service), `STATUS.md`
(Points d'attention + cette entrée).

### Session courante (20/07/2026, suite) — Signal 3 affiné : date de sortie MSRC plutôt que
publication CVE

L'utilisateur demande si on peut être plus précis que "date de publication CVE" pour le repli par
date. Réponse : oui partiellement — l'API MSRC (déjà appelée pour le mapping KB→produit) fournit
`releaseDate`, la date de sortie **réelle** du correctif, jusque-là ignorée. `fetch_msrc_kb_products`
retourne désormais aussi cette date (la plus ancienne parmi les KB trouvés pour la CVE) ;
`check_patch_windows` l'utilise en priorité sur `cve.published`, avec repli sur ce dernier si MSRC
n'a rien retourné. Nouveaux champs `date_heuristic_reference`/`date_heuristic_source` dans la
réponse pour que l'analyste sache quelle date a servi. Reste purement indicatif, comme avant — pas de
numéro de build exact disponible pour ces vieilles CVE (vérifié : ni NVD ni MSRC ne l'exposent), donc
pas d'auto-bascule possible même avec cette précision supplémentaire.

Testé : CVE-2019-1365 utilise maintenant `date_heuristic_source: msrc_release` avec la date exacte du
KB (2019-10-08) au lieu de la publication CVE. Non-régression vérifiée (CVE-2022-30190 build_verdict
toujours prioritaire, Linux inchangé).

Docs mises à jour : `docs/MATCHING.md` (détail des 2 sources de date par ordre de préférence).

### Session courante (20/07/2026, suite) — Les signaux 2/3 étaient calculés mais jamais affichés

**Vrai bug, pas un malentendu** : l'utilisateur signale que CVE-2020-1350 "devrait apparaître comme
patched" après un patch check manuel. Vérification : le backend calcule bien tout (build_verdict,
date_heuristic...), mais la modale résultat (`patchModal`, Dashboard.jsx **et** Vulnerabilities.jsx,
dupliquée) n'affichait que le badge ✅/❌ `patch_detected` + la liste des KB — aucun des nouveaux
champs de la session (`build_installed`, `build_verdict`, `date_heuristic`,
`date_heuristic_reference`/`source`) n'était rendu nulle part dans l'UI. Un "❌ Patch non détecté"
sans plus de contexte est indiscernable d'un vrai échec de détection aux yeux de l'utilisateur, alors
qu'un signal indicatif "probablement déjà corrigé" existait juste à côté dans la réponse JSON.

**Fix** : deux blocs ajoutés dans les deux modales (identiques, pas de composant partagé entre les
deux pages) — un bandeau build/révision (gris, verdict coloré vert/rouge si concluant) et un bandeau
bleu "Signal indicatif" pour le repli par date (jamais vert/rouge, pour bien marquer que ce n'est
jamais un verdict définitif comme les deux autres signaux).

Docs mises à jour : `docs/FRONTEND.md` (nouveau paragraphe sur la modale patch check).

### Session courante (20/07/2026, suite) — Filtre d'affichage "masquer les CVE > 2 ans"

L'utilisateur propose de limiter les CVE à 2 ans max, vu le volume après le rattrapage NVD de ce soir.
Avis donné avant d'implémenter : une limite à la **collecte** aurait recréé exactement le trou qu'on
venait de combler (CVE-2022-30190 et consorts sont justement des CVE "anciennes" mais réellement
pertinentes) — l'âge d'une CVE ne dit rien sur son statut réel de correction. Proposé à la place un
**filtre d'affichage réversible**, accepté par l'utilisateur.

**Implémentation** : nouveau paramètre `max_age_years` sur `GET /api/vulnerabilities` (filtre
`CVE.published >= now - N ans`, jamais appliqué à la sync/au matching). Checkbox "Masquer les CVE > 2
ans" dans la barre de filtres de `Vulnerabilities.jsx` (mode réel + mode Présentation, filtré aussi
côté client sur `FAKE_VULNERABILITIES`). Testé : 4302 → 1180 vulnérabilités ouvertes sur le parc avec
le filtre actif, via proxy Vite. Scope volontairement limité à `Vulnerabilities.jsx` — le tableau
"Vulnérabilités à traiter" du Dashboard a son propre plafond `per_page=200` déjà pré-existant et non
lié à ce sujet, pas touché ici.

### Session du 21/07/2026 — bilan complet (déplacé de STATUS.md le 22/07/2026)

Session longue, centrée sur une question posée d'emblée par l'utilisateur : **« on doit trouver un
moyen de vérifier que les CVE sont patchées »**. Tout le reste en découle.

**Résultat chiffré**

| | Début de session | Fin |
|---|---|---|
| Vulnérabilités ouvertes (parc) | ~4 800 | 37 |
| Ouvertes sur DEPLOYAPP | 4 625 | 26 |
| Taux de correction global | 6,7 % | 94,9 % |
| CRITICAL | 9,6 % | 96,8 % |
| Corrigées / Faux positifs / En attente | 323 / 0 / 13 | ~5350 / ~210 / ~37 |

**Chaque fermeture repose sur une preuve vérifiable** — comparaison de build, comparaison de version
de paquet, ou absence constatée du produit — jamais sur une estimation.

**Les trois percées** :
1. **Build corrigé publié par Microsoft** (`services/kb_build.py`) — le titre de l'article
   support.microsoft.com porte le numéro de build (`"KB4489899 (OS Build 17763.379)"`). Les CU étant
   strictement cumulatives, un build supérieur **prouve** le correctif. C'est ce qui a débloqué les
   milliers de CVE Windows anciennes que NVD et les deux API MSRC laissaient sans verdict (toutes
   trois testées et écartées avant d'en arriver là).
2. **Absence du Debian Security Tracker** — le tracker référence toute CVE touchant un paquet Debian,
   y compris "non affecté". Une absence complète prouve qu'aucun paquet Debian n'est concerné.
3. **"Non applicable" ≠ "corrigé"** — un produit jamais installé n'a pas été corrigé. Statut
   `false_positive` distinct, avec justification, pour ne pas fausser la piste d'audit NIS 2.

**Workflow analyste** : trois flux de qualification groupée, tous sur `BulkQualifyModal.jsx` :
correctif détecté (CRITICAL), faux positif, en attente de correctif. Le système propose des candidats
sur critères objectifs, l'analyste confirme — analyste **et** annotation obligatoires. Convention
visuelle : badge en pointillé + « ? » pour une proposition sur ligne ouverte, badge plein pour une
décision actée ; cette distinction a dû être introduite deux fois après que l'utilisateur ait cru à
tort que des lignes étaient déjà clôturées.

`STARTUP_MATCHING` / `STARTUP_PATCH_CHECK` permettent désormais de redémarrer le backend sans effet
de bord sur les données — un redémarrage technique créait sinon des vulnérabilités et basculait des
statuts, rendant les écarts de chiffres illisibles.

**Performance** : le relevé WinRM/SSH était rejoué par CVE alors qu'il est identique pour toutes les
CVE d'un même actif. Mis en cache par actif → le cycle est passé d'une progression quasi nulle à
plusieurs centaines de vulns par minute. Cache KB→build permanent en base (142 entrées) contre le
rate-limiting de Microsoft.

**Ce qui restait ouvert à la fin de la session, et pourquoi** :
- 16 SSU / Secure Boot DBX : sans issue à droits constants (registre CBS nomme les SSU par composant,
  pas par KB ; `Get-SecureBootUEFI` exige des privilèges élevés, contraires au compte lecture seule).
- 9 Windows sans aucun KB rattachable (ni NVD ni MSRC).
- 5 Debian mixtes : un paquet absent + un paquet installé réellement vulnérable, sans correctif publié.
- 1 mitigation registre (`CVE-2013-3900`) non activée, remédiation exacte affichée.

**Deux erreurs commises, et ce qu'elles ont appris** :
1. **Écrasement d'une qualification d'analyste** — la bascule automatique ne vérifiait pas si une
   décision humaine existait déjà. Le bouton "Patch check" unitaire, cliquable sur n'importe quelle
   ligne, a détruit statut et annotation sur CVE-2026-41991. Réparé, garde-fou absolu ajouté dans
   `CLAUDE.md`. → *Raisonner sur "ce que fait le cycle" est insuffisant : les mêmes fonctions sont
   atteignables par des chemins manuels.*
2. **Modification de statut en SQL brut** — contournait les invariants de `update_vulnerability`, ce
   qui a fait re-basculer 28 lignes via `backfill_auto_patch` (résultat périmé non effacé).
   → *Passer par l'API, qui applique les invariants.*

**Hors sujet principal** : README.md créé (642 lignes, réécrit depuis le code vérifié — la doc
existante comportait des sections franchement fausses) ; 3 bugs de désynchronisation du Dashboard
corrigés (compteurs plafonnés, listes jamais rechargées, bascules perdues par le polling) ; code mort
supprimé (`services/`/`tasks/` à la racine) ; skills animation installés.

### Session du 22/07/2026 — bilan complet (déplacé de STATUS.md le 24/07/2026)

- **Annotations d'analyste** : « ✓ Corrigé » avec annotation facultative, bascule des 3 points d'entrée
  du Dashboard vers `AnnotationModal` généralisé (`title`/`detail`, `noteRequired`) pour un rendu
  uniforme. Rendu **Markdown** (`marked`+`dompurify`, `MarkdownNote.jsx`) partout, y compris aperçu
  clampé 2 lignes dans les tableaux. Bouton « ✏️ Modifier » sur « en attente » (ne touche que
  `notes`/`validated_by`).
- **Audit de cohérence** : croisement du **texte** des annotations `false_positive` avec les **données
  structurées** (`asset.installed_packages`) → 7 CVE gitlab fermées « produit absent » alors que le
  paquet était installé + 3 IEEE P1735 mal qualifiées. 11 lignes réouvertes via l'API. Le cycle
  autonome a confirmé (revenues en `awaiting_fix`, Debian sans correctif). Leçon : **ne jamais faire
  confiance à une justification texte sans la recouper avec la base**.
- **Rapports hebdomadaires figés** : les 3 types livrés (CVE + décliné par actif, Veille, Surveillance).
  Table `reports`, `weekly_report.py`, 4 endpoints, tâche Celery du lundi 7h, archives PDF/CSV.
  Extractions `ReportMarkdown.jsx`/`WeeklyArchives.jsx` faites *avant* d'en avoir besoin.
- **Profil de veille** (⚙️) : table `watch_profile` + `watch_profile.py`, OS/logiciels proposés depuis
  l'inventaire, cochés par l'analyste, marquage `★`/ligne teintée (jamais de filtrage). 6 catégories
  (OS, Logiciels, Firewall, SaaS, Matériel, Applications). Correspondance calculée à la volée. Stoplist
  `_AMBIGUOUS_WORDS` (discover/file/less). Confirmation en direct pendant la saisie (preview-term).
- **Veille — suivi** : filtre Traitement (Nouveau/En cours/Traité/Non concerné + « Reste à traiter »),
  `not_applicable` passé au violet, bouton « Consulter » vert une fois qualifié, décision en Markdown,
  champ « Actifs concernés » (`watch_items.asset_ids`).
- **Rattachement invalide au patch check** — vrai bug : `check_patch()` ne consultait jamais
  `still_matches()` → message générique au lieu de signaler l'artefact de matching. Fix : appel en tête,
  `not_applicable` alimente `apply_patch_result`. CVE-2017-13091/DEPLOYAPP auto-basculée avec
  justification → **parc à 0 vuln ouverte**.
- **Bandeau de rattrapage** : `GET /api/vulnerabilities/auto-bascule-summary?since=` + bandeau persistant
  Dashboard comparé à `localStorage`. Suivi par navigateur (pas de compte). Absent en Présentation.
- **Sources de veille** : 4 ajoutées après test réel (Hacker News, Krebs, Silicon.fr, Undernews) ;
  3 écartées avec raison (CISA 403 anti-bot, LeMondeInformatique en RDF non parsable, Vigilance/ENISA
  sans flux vérifiable).
- **2 erreurs de méthode** : `--force-recreate backend` sans couper `STARTUP_*` (a requalifié 9 lignes) ;
  test écrit sur une vraie alerte CERT-FR (état restauré, puis méthode = élément jetable).

### Session du 24/07/2026 — bilan complet (déplacé de STATUS.md le 27/07/2026)

#### Audit de sécurité défensif — `audit/AUDIT_SECURITE.md` (racine)

Revue complète du code en lecture seule (demandée par l'utilisateur). Livrable : `audit/AUDIT_SECURITE.md`
avec 6 correctifs priorisés, code prêt à coller, à implémenter **plus tard**. Priorité : #1 SSRF
(sources de veille `WatchSource.url`, seul exploitable à distance sans auth) → #2 clé d'hôte SSH
désactivée (`known_hosts=None`) → #5 `.gitignore` avant tout `git init` → #3 LDAP en clair → #4
`defusedxml` → #6 secrets par défaut « changeme ». Conforme vérifié : SSH/AD lecture seule stricte,
aucune commande utilisateur interpolée, pas d'appel API Claude, Fernet correct, pas d'injection
SQL/LDAP, XSS couvert (DOMPurify). *(Les 5 correctifs applicables ont été implémentés et testés en
conditions réelles le 27/07/2026 — cf. bilan de cette session.)*

#### Veille — regroupement automatique des doublons

Doublons signalés par l'utilisateur : 57 sur 1961 (même actu multi-sources / variantes d'URL). Cause :
dédoublonnage à l'insertion par URL exacte, aveugle aux titres identiques à URLs différentes. Décision :
**regroupement à l'affichage** (rien supprimé, registre NIS 2 intact), critère titre strictement
identique, traitement en **cascade** sur les membres du groupe. Toggle « Grouper les doublons » d'abord
ajouté puis **retiré sur demande** (regroupement désormais toujours actif). Détail : invariant
"Regroupement veille". Backend garde le param `group_duplicates` (défaut `true`).

#### Bandeau/cloche de rattrapage — consultation d'une CVE auto-basculée

Incident : CVE-2020-19909 (curl LOW, gitlab) annoncée « corrigée automatiquement » mais introuvable dans
les traitées. Diagnostic : correctement patchée (backport Debian), mais (a) la section « traitées » du
Dashboard ne charge que 200 lignes par score — une LOW y est hors fenêtre et sa recherche locale ne la
trouve pas ; (b) le filtre « CVE > 2 ans » l'exclut ailleurs. **Elle n'est apparue que parce qu'une
édition backend a déclenché le rechargement WatchFiles → cycle de démarrage** (effet de bord documenté ;
1 ligne, correcte). Corrigé :
- Param `search` (`CVE.cve_id ILIKE`) sur `GET /api/vulnerabilities` + champ recherche CVE sur la page
  Vulnérabilités + recherche **serveur** de la section « traitées » du Dashboard (plus de plafond à 200).
- Cliquer une CVE dans la **cloche 🔔** *et* le **bandeau vert** ouvre son justificatif de clôture en
  modale, **sur place** (helper partagé `openCveJustification`) — plus de renvoi vers la page
  Vulnérabilités (vide par défaut, parc à 0 ouverte). Piège : seul le bandeau avait été câblé au début,
  l'utilisateur cliquait la cloche → les deux surfaces corrigées.

#### Sécurisation de la base

État de départ déjà correct : DB **non exposée** au host (réseau Docker interne), auth externe en
`scram-sha-256`. Appliqué :
- **Rotation `DB_PASSWORD`** : `Cyb3rVuln_2026!` → 40 car. aléatoires alphanumériques (`ALTER ROLE` +
  `.env`, services recréés, ancien mdp vérifié rejeté). Alphanumérique car `config.py` build l'URL sans
  URL-encoding.
- **Fail-fast secrets par défaut** (`config.py`) : refuse de démarrer si `SECRET_KEY`/`DB_PASSWORD` =
  `changeme` (audit #6). Testé.
- **Déception (honeypots DB)** — les 4 couches (cf. invariant « Déception DB ») : table `security_events`
  + fonctions de journalisation, vues leurres (lecture/écriture journalisées + honeytokens), rôles
  leurres + `log_connections`, API `/api/security/events*` + **badge (nombre) sur l'item Paramètres**
  (sidebar poll le compteur, sans détail). Testé de bout en bout (lecture/écriture d'une vue → événement
  → API → badge → acquittement). Détail/console de consultation : **Paramètres > Sécurité >
  Administration** (page dédiée `/settings/administration`, verrou mdp, onglets Connexions IP / Base de
  données — cf. `docs/FRONTEND.md`). Bannière Dashboard retirée (elle exposait le détail sans mot de passe).
- **Rôle applicatif à privilèges réduits `cbr_app`** (cf. invariant dédié) : l'app ne tourne plus en
  superuser. Vérifié : DML complet OK, mais `CREATE TABLE`/`DROP`/`DELETE security_events`/superuser tous
  refusés. Lève la « limite assumée » de la déception (traces ineffaçables via les creds app).
- **Verrou DDL — event trigger** (`backend/db/ddl_guard.sql`) : toute DDL par un rôle non whitelisté (seul
  `cybervuln` autorisé) est **bloquée + journalisée** (`security_events` source `ddl_attempt`, log autonome
  via dblink car le RAISE EXCEPTION annule la transaction). Vérifié : cbr_app DROP/CREATE bloqués et loggés
  avec l'IP source ; cybervuln passe. Console : onglet Base de données (type « DDL bloquée »). Détail et
  nuance déploiement-à-neuf : `docs/ARCHITECTURE.md § Verrou DDL`.

Non retenus par l'utilisateur (restent dans `audit/AUDIT_SECURITE.md`) : durcir `pg_hba` (trust→scram local,
restreindre au sous-réseau), roter `SECRET_KEY` (casserait 1 mdp SSH chiffré).

#### Polish UI / motion (skill emil-design-eng)

Refonte page d'accueil (cascade, hover premium, halo, **spotlight à inertie**) + cohérence globale :
transition d'entrée à chaque changement de route, feedback au press sur boutons et items de nav,
survol de sidebar teinté à la couleur du module (mêmes tuiles que l'accueil), cascade douce
(`.stagger-rows`) sur les tableaux **Vulnérabilités / Veille / CVE** (pas ceux en polling),
uniformisation des animations de modale. Tout en CSS (hors main-thread), `prefers-reduced-motion`
respecté. Détail complet : `docs/FRONTEND.md` § Animations & polish. Aussi : nav « Sécurité › Pentest »
(comme Inventaire/Administration), page Administration déplacée en page dédiée `/settings/administration`.

#### Méthode

`STARTUP_MATCHING`/`STARTUP_PATCH_CHECK` passés à `false` pendant les éditions backend (pour éviter les
bascules parasites au rechargement WatchFiles), **remis à `true` en fin de session** (`up -d
--force-recreate backend`, vérifié).
