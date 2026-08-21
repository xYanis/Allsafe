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

### Session du 27/07/2026 — Bilan complet (déplacé de STATUS.md le 20/08/2026)

*(le déroulé de la session du 24/07/2026 est dans `docs/HISTORIQUE.md`.)*

#### Correction de précision — RAM Inventaire (Linux)

Signalé par l'utilisateur : `gitlab.aer.loc` affichait 3 Go de RAM au lieu de 3,8. Cause : le scan SSH
utilisait `free -g` (troncature en Go entiers) alors que la branche Windows était déjà précise à une
décimale. Remplacé par `free -b` + conversion Python arrondie (`services/asset_scanner.py`). Corrige
**toutes** les machines Linux au prochain scan, pas seulement celle signalée.

#### Audit de sécurité — 5 des 6 correctifs implémentés et testés en conditions réelles

Suite de l'audit défensif du 24/07 (`audit/AUDIT_SECURITE.md`). Contrairement à la session précédente
(revue en lecture seule uniquement), chaque correctif a été **appliqué et vérifié contre l'infra
réelle** (pas seulement relu) :
- **#1 SSRF** — nouveau `backend/services/net_guard.py` (`validate_public_url`, rejette IP privées/
  loopback/liens locaux), branché sur création **et** modification de source de veille + re-validation
  à chaque redirection dans `watch_fetcher.py` (`follow_redirects=False` + boucle manuelle). Testé :
  URL interne → 400, sync veille toujours fonctionnelle.
- **#2 SSH known_hosts** — nouveau `backend/services/ssh_trust.py`, TOFU (apprentissage au premier
  contact, rejet sans réapprentissage si la clé change). Cf. invariant dédié. Testé en direct contre
  `gitlab.aer.loc` (apprentissage → acceptation → rejet d'une fausse clé).
- **#3 LDAP en clair** — `AD_USE_TLS` (défaut `False` = StartTLS sur le `ldap://` existant, pas
  `ldaps://` implicite dont on ne sait pas si le DC l'expose). Testé contre le vrai DC
  `tintamarre.aer.loc` : import AD toujours fonctionnel, chiffré.
- **#4 XML non durci** — `defusedxml` remplace `ET.fromstring` dans `watch_fetcher.py`/`rss_fetcher.py`.
- **#6 secrets par défaut** — déjà fait le 24/07, reconfirmé.
- **#5 `.gitignore`** — **volontairement non fait**, pas de repo git pour l'instant (choix explicite
  de l'utilisateur).
- **`pip-audit`/`npm audit`** passés : CVE `starlette`/`python-multipart` corrigées (bump `fastapi`
  0.115.0 → 0.140.0, qui entraîne `starlette` 0.38.6 → 1.3.1 sans plafond de version ; `pydantic`
  2.13.4 déjà compatible). CVE `react-router-dom`/`esbuild`-dev **laissées ouvertes** (fix seulement en
  version majeure, potentiellement cassante, pas validée sans accord explicite).

#### Durcissement Docker runtime

`no-new-privileges` sur les 6 services ; `cap_drop: [ALL]` sur les 4 services applicatifs (pas
`db`/`redis`, dont l'entrypoint officiel a besoin de capacités root au démarrage) ; `mem_limit`/`cpus`
sur les 6. Deux pièges réels rencontrés en le faisant (détail dans les invariants ci-dessus) : une
limite mémoire trop basse laissait `backend` bloqué en silence au démarrage (`STARTUP_MATCHING` pique
à ~4.6GiB, pas mesuré avant) ; Compose construit une image par service même avec le même `Dockerfile`,
et reconstruire seulement `backend` après le bump `fastapi` avait laissé `worker`/`beat` casser au
démarrage.

#### Trois nouvelles fonctionnalités (demandées explicitement, pentest/bastion laissés de côté)

**1. Risque accepté avec expiration** — `accepted_risk` exige désormais justification + validateur +
date de revue (`accepted_risk_until`, nouvelle colonne). `review_overdue` calculé à la volée (jamais
stocké, jamais appliqué automatiquement — cf. invariant dédié). Action unitaire et groupée
(`bulk-accepted-risk`), badge ⚠ dans `Vulnerabilities.jsx`. `AnnotationModal`/`BulkQualifyModal`
étendus avec un champ date optionnel (`showReviewDate`) plutôt que dupliqués.

**2. Durcissement CIS-like en lecture seule** — nouveau bloc `compliance` dans le résultat de scan
(`asset_scanner.py`) : politique de mot de passe, SSH root/mdp (Linux), RDP-NLA/SMBv1/pare-feu
(Windows), ports exposés à risque. Deux vrais bugs trouvés en testant contre `DEPLOYAPP` réel (pas en
théorie) : dépassement de la limite de commande WinRM (script raccourci) et parsing `net accounts`
cassé par un encodage accentué corrompu + un libellé français mal deviné au premier jet. Résultat réel
sur DEPLOYAPP : **pare-feu Windows désactivé détecté** dès la première utilisation.

**3. Criticité métier par actif** — le calcul pondéré existait déjà dans `scoring.py`
(`asset.tags["criticite"]`, jamais relié à rien) ; juste branché : select + badge dans `Assets.jsx`,
`PUT /assets/{id}` appelle maintenant `recalculate_scores_for_asset()`.

Chaque feature testée de bout en bout après coup : garde-fous API (400 attendus), scan réel sur les
deux machines du parc, non-régression sur veille/inventaire/scans, aucun conteneur `OOMKilled`.

#### Méthode

Deux gestions d'incident en direct pendant la session, toutes deux avec cause identifiée et corrigée
avant de poursuivre plutôt que de contourner : dépassement de commande WinRM (théorie déjà dans
`docs/ARCHITECTURE.md`, reconfirmée en la dépassant réellement) et confusion entre mesure de taille de
script sur le texte source Python (avec `\\` littéraux) vs. la chaîne réellement transmise (échappée) —
mesurée correctement via `ast` plutôt qu'un regex naïf sur le fichier source.

#### Scanner lent (Actifs + Inventaire) — trois causes distinctes, empilées

Signalé par l'utilisateur : le scan relance toujours une connexion live, la modale est trop haute, et
le scan est lent. Trois correctifs indépendants, pas un seul :
- **Cache-first** : le bouton "Scanner" ouvre désormais le dernier résultat en cache
  (`getAssetPackages`, rapide) si l'actif a déjà été scanné ; un scan live reste possible via
  "🔄 Relancer un scan" **dans** la modale (`Assets.jsx` + `Inventaire.jsx`).
- **Vraie cause de la lenteur** : ce n'étaient pas les commandes SSH (chacune < 0,5s), mais chaque
  scan relançait un **rematching CPE contre tout le référentiel** (~30s, bloquant). Déporté sur le
  worker Celery (`tasks.scheduled_tasks.run_cpe_matching_for_asset_task`) — scan de 34-60s → ~1-3s.
  Piège en le faisant : `.delay()` publiait sur la mauvaise queue (le worker n'écoute que `default`),
  jamais consommé — corrigé avec `.apply_async(..., queue='default')`.
- **Régression découverte en testant ce correctif** : le worker s'est fait tuer par OOM (deux
  matchings concurrents à ~4,6 Go chacun, contre `mem_limit: 4g`). `multiprocessing.cpu_count()` lit
  le host (14 CPU) pas le quota `cpus:` du conteneur — Celery démarrait donc plusieurs process de
  fork. Corrigé : `--concurrency=1` sur le worker (une tâche à la fois, l'intention déjà documentée
  par `worker_prefetch_multiplier=1` mais jamais réellement appliquée) + `mem_limit: 6g`.
- **Parallélisation SSH** (gain secondaire, réel mais modeste comparé au point ci-dessus) : les 14
  commandes SSH du scan Linux étaient enchaînées une par une — désormais en lots de 5 concurrents
  (`asyncio.gather`), pas les 14 d'un coup : ça dépasse `MaxSessions` (10 par défaut dans
  `sshd_config`, nombre de canaux ouverts simultanément sur une connexion) → `open failed` constaté
  en direct avant ce correctif.

#### Bug CSS — modale mal centrée sur toutes les pages, pas que Inventaire/Actifs

`.route-fade` (wrapper de transition de page, `Layout.jsx`, sur **toutes** les routes) animait un
`transform`, et `animation: ... both` fige la dernière valeur de `transform` indéfiniment après la fin
de l'animation — un ancêtre avec un `transform` non-`none` crée un nouveau containing block pour ses
descendants `position: fixed`. Toute modale rendue dans une page se positionnait donc par rapport à ce
wrapper au lieu du viewport : mal centrée, tronquée, un clic sur le fond ne fermait plus rien. Corrigé
en retirant `translateY` de l'animation (fade seul). **Piège de vérification** : le premier correctif
avait été appliqué sans redémarrer le conteneur frontend — le hot-reload Vite ne l'avait jamais pris en
compte (déjà documenté plus haut comme peu fiable sur ce montage WSL, mais oublié sur le coup).
Vérifier le contenu réellement *servi* (`curl` sur le fichier via Vite), pas seulement le fichier
source, avant de conclure qu'un correctif frontend est actif.

Dans la foulée, un import manquant (`SeverityBadge` jamais importé dans `Assets.jsx`, faute de
frappe/oubli lors de l'ajout du badge vulnérabilité sur les paquets) causait un écran noir au scan —
`ReferenceError` non catchée par défaut en React (pas d'error boundary), l'app entière se démonte.
Corrigé en une ligne, mais un rappel : sans error boundary, **une erreur dans un composant profond
plante toute la page**, pas seulement ce composant.

#### Lien "Applications installées" ↔ vulnérabilités déjà connues

Question de l'utilisateur : "est-ce que ces applications sont à jour ?". Réponse apportée
(`services/cpe_matcher.py § get_installed_package_vulnerabilities`) : croise les vulnérabilités **déjà
matchées** pour l'actif (pas un nouveau matching contre tout le référentiel) avec chaque paquet
installé, badge coloré + compte dans la liste (`Assets.jsx` + `Inventaire.jsx`).

⚠️ **Ne fonctionne que pour Linux.** La dérivation nom de paquet → produit CPE
(`_package_candidates`) est conçue pour les conventions Debian/RPM (`libssh2-1` → `libssh2`) ; les noms
d'applications Windows (registre, texte libre : `"PuTTY release 0.81 (64-bit)"`, `"F-Secure Policy
Manager 15.30 build 96312 64-bit - Policy Manager Console"`) n'ont aucune règle fiable pour en extraire
un nom de produit sans deviner (un heuristique "premier mot" donnerait par exemple "microsoft" pour
"Microsoft Edge" — bruit garanti). Décision : ne rien faire d'approximatif, laisser "—" côté Windows en
attendant une vraie table de correspondance (prochain chantier, cf. § Points ouverts).

#### Historique des changements de statut de vulnérabilité

Nouvelle table `vulnerability_status_history` (jamais écrasée), alimentée par un helper unique
(`services/vuln_history.py`) branché aux **9 points** qui changent `Vulnerability.status` : les 6
endpoints manuels de `routers/vulnerabilities.py` (PATCH unitaire + 5 bulk) et le point de passage
unique de l'automatique, `apply_patch_result()` (`patch_checker.py`, désormais avec un paramètre
`session` explicite pour pouvoir y écrire). No-op si l'ancien et le nouveau statut sont identiques.
Nouveau `GET /api/vulnerabilities/{id}/status-history` + bouton "🕒 Historique" (page Vulnérabilités).
Prospectif, pas rétroactif — ne couvre que les transitions à partir de sa mise en service.

**Table créée après `app_role.sql`** : elle n'hérite d'aucun droit automatiquement pour `cbr_app` (rôle
applicatif) — sans le `GRANT` explicite ajouté dans le même `schema_patches.sql`, l'app aurait planté
en `permission denied` au premier `INSERT`. Réflexe à garder pour toute future table.

**Immédiatement utile** : en testant le chemin automatique, un `patch_detected: true` forcé
artificiellement (pas un vrai contrôle SSH) a fait basculer CVE-2026-55199/gitlab en `patched` alors
que Debian n'a toujours publié aucun correctif — repéré par l'utilisateur ("pourquoi elle a basculé ?"),
diagnostiqué en un coup d'œil grâce à l'historique tout juste posé (une seule transition, horodatée,
`validated_by="Auto (patch check)"`, contredite par l'annotation encore visible de l'état précédent),
et corrigé via l'API (jamais en SQL direct) avec une annotation expliquant l'incident.

#### Résolution du point ouvert "31 lignes patched produit absent"

L'entrée n'était plus vérifiable telle quelle : `patch_check_result` reflète toujours le dernier
contrôle, sans trace historique avant la table `vulnerability_status_history` (créée le 27/07, donc
prospective). Recherche par preuve technique directe plutôt que par fenêtre temporelle ou texte de
note (les deux se sont révélés trompeurs) : `status='patched' AND patch_check_result.not_applicable
= true` sur l'ensemble de la base — 3 lignes trouvées, pas 31, toutes **CRITICAL** (CVE-2015-1427,
CVE-2016-4607, CVE-2017-18349 sur `gitlab.aer.loc`), validées par un humain à la même seconde le
21/07 avec notes vides — cohérent avec des clics de test plutôt qu'une revue ligne par ligne. Le
patch check du jour même indiquait déjà "aucun paquet visé installé" : la ligne aurait dû être
`false_positive`, jamais `patched`. Confirmé par l'utilisateur puis requalifiées via l'API (jamais SQL
direct), justification citant l'incident. **Aucune ligne `patched`/`not_applicable` ne subsiste.**

#### Nouveau statut « correctif partiel » (`awaiting_fix_partial`) + incident de migration

Résolution du second point en suspens (« 3 Debian mixtes ») : au lieu de garder un `awaiting_fix`
générique, quatrième issue automatique dédiée au cas mixte (paquet absent + paquet installé sans
correctif Debian) — détail technique complet dans l'invariant dédié ci-dessus (§ Patch check &
statuts). Décidé avec l'utilisateur : pas de couple candidates+bulk (3 cas connus, tous HIGH),
Dashboard fusionné dans la section "en attente" existante (badge « partiel »), stats/rapports pliés
dans le compteur `awaiting_fix`. Les 3 CVE (CVE-2023-31486, CVE-2024-28757, CVE-2025-59375,
`gitlab.aer.loc`) migrées et vérifiées par un vrai contrôle SSH.

**Incident réel en cours de migration** : le PATCH unitaire n'avait pas de branche pour ce nouveau
statut, tombait dans le `else` prévu pour open/in_progress, et a effacé `validated_by`/
`last_patch_check`/`patch_check_result` sur les 3 lignes. Repéré immédiatement, corrigé (branche
`elif` dédiée), lignes réparées via l'API. Détail complet dans l'invariant dédié ci-dessus — leçon
générale : tout nouveau statut doit être ajouté à *chaque* switch/if-chain sur `Vulnerability.status`
avant d'être utilisé en écriture.

#### Profil de veille configuré

Correction d'une affirmation périmée de STATUS.md (« profil vide », 24/07) : le profil comptait déjà
195 termes, tous cochés — mais Matériel/Constructeurs était vide et VMware/Veeam/Zerto (mentionnés
comme classés dans une session antérieure) manquaient de la liste Applications. Sur validation de
l'utilisateur : conservé tel quel côté paquets Linux génériques (bash/curl/openssl...) — un composant
réellement installé reste pertinent même si l'article est générique, et le ratio observé (55/2179
éléments marqués ★) montre que ça ne noie pas le signal en pratique. VMware/Veeam/Zerto ajoutés via
`PUT /api/watch/profile` (198 termes au total). Pure configuration, aucun code touché.

#### Sauvegarde PostgreSQL + premiers tests automatisés

Deux manques identifiés à la demande de l'utilisateur (« qu'est-ce que tu vois à améliorer, hors ce
qu'on a déjà relevé ? »), en plus de deux autres proposés mais non retenus dans l'immédiat (rate
limiting, healthchecks Docker manquants sur backend/worker/beat/frontend — `/api/health` existe déjà
mais n'est pas câblé en `healthcheck:`).

**Sauvegarde** — `services/backup.py`, tâche Celery quotidienne (4h) + endpoint manuel
`POST /api/backup/run`. Détail technique complet (client PGDG, format `-Fc`, rétention, procédure de
restauration) dans `docs/ARCHITECTURE.md` § Sauvegarde et dans l'invariant dédié ci-dessus. Vérifié en
conditions réelles contre la vraie base (124 Mo, ~162k CVE) : dump réussi, structure validée
(`pg_restore -l`, 156 entrées de TOC), purge de rétention testée avec un faux fichier antidaté puis
confirmée supprimée au dump suivant. `backend`/`worker`/`beat` reconstruits (`postgresql-client-16` au
`Dockerfile`) et vérifiés sains après coup (compteurs de vulns inchangés, `/api/health` OK).

**Tests** — `backend/tests/`, premiers de tout le projet. Portée délibérément ciblée sur le code déjà
responsable de deux incidents réels (`apply_patch_result` : règle de sévérité, états terminaux,
décision humaine sur awaiting_fix/awaiting_fix_partial ; régression directe de l'incident
`update_vulnerability` du jour). Choix technique clé : aucune base de données requise (session mockée,
modèles instanciés en mémoire, route FastAPI appelée directement comme une fonction Python) — rapide,
zéro risque sur les données réelles, mais ne couvre donc pas (encore) le matching CPE ni le patch
check Windows/Linux réel. 31 tests, tous verts (`docker compose exec backend pytest -v`). Détail
complet dans `docs/ARCHITECTURE.md` § Tests.

#### Healthchecks + Error Boundary (suite de la même demande)

**Healthchecks** — `backend`/`worker`/`beat`/`frontend` n'en avaient aucun (seuls `db`/`redis`).
Ajoutés : `curl /api/health` (backend), `celery inspect ping` (worker — via le broker Redis, plus
robuste qu'un simple check de process), `pgrep` (beat, nécessite `procps` ajouté au `Dockerfile`),
`wget --spider` (frontend). **Bug réel découvert en testant** : `http://localhost:...` échouait par
intermittence (`Connection refused`) avant même d'être un problème d'app — `/etc/hosts` résout
`localhost` en `::1` (IPv6) avant `127.0.0.1`, alors qu'uvicorn/Vite n'écoutent qu'en IPv4. Repéré en
lançant chaque commande de healthcheck à la main avant de les figer dans `docker-compose.yml` plutôt
que de faire confiance à la première tentative — corrigé (`127.0.0.1` explicite), les 6 services
reconstruits/recréés et confirmés `healthy`.

**Error Boundary** — `components/ErrorBoundary.jsx`, autour de `<Outlet/>` dans `Layout.jsx`. Testé
par lecture de code et compilation Vite propre (fichier servi à jour, aucune erreur de build) — pas de
vérification visuelle en navigateur faute d'outil adapté dans cette session, signalé explicitement
plutôt que présenté comme entièrement vérifié.

#### Rotation des logs Docker + build de production du frontend

Deux nouvelles pistes identifiées à la demande de l'utilisateur (même question que pour la sauvegarde/
les tests/les healthchecks), toutes deux vérifiées en conditions réelles avant d'être considérées faites.

**Rotation des logs** — ajout de `logging: {driver: json-file, max-size: 10m, max-file: 5}` sur les 6
services. Vérifié : `json-file` sans limite ne tourne jamais tout seul sur cet hôte (`docker inspect`
confirmait un `LogConfig` vide). Recréation complète des 6 conteneurs (y compris `db`/`redis`, dont la
config a changé aussi) — données et compteurs de vulns inchangés après coup.

**Build de production frontend** — `frontend/Dockerfile` passé en multi-stage (`dev`/`build`/`prod`),
nouveau `nginx.conf` reproduisant le proxy `/api` et le forwarding d'IP du `vite.config.js` dev. Nouveau
service `frontend-prod` derrière un profil Compose plutôt qu'un fichier séparé (évite l'ambiguïté de
fusion YAML entre fichiers Compose sur les listes). Mode dev **inchangé par défaut** — `target: dev`
fixé explicitement pour ne pas basculer silencieusement vers le build figé au prochain rebuild.
Testé isolément (conteneur nginx sur un port de test, réseau du projet, sans toucher au frontend dev
en cours) : SPA servie, route inconnue retombe sur `index.html` (pas de 404 au rechargement), proxy
`/api/health` fonctionnel, `X-Forwarded-For` transmis et retrouvé dans `connection_logs` — vérifié avec
une IP factice, supprimée après coup (simple ligne de log, sans rapport avec l'invariant sur les
statuts de vuln).

### Session du 28/07/2026 — Intégration WithSecure + premier passage à l'échelle réel (déplacé de STATUS.md le 20/08/2026)

Deux sujets distincts traités dans la même session, mais qui se sont percutés en fin de parcours : une
intégration WithSecure pensée comme un complément (pas un remplacement) du pipeline existant, puis un
élargissement de l'import AD qui a fait passer CBR de 2 à 72 actifs d'un coup — premier vrai test à
l'échelle du parc réel, qui a immédiatement révélé un bug de passage à l'échelle latent.

#### Intégration WithSecure — complément, pas remplacement

Point de départ : le parc a déjà WithSecure Elements (EDR/EPP) déployé (licence confirmée sur facture :
**EDR AND EPP** pour PC et serveurs — **aucun module Vulnerability Management/ex-Radar souscrit**,
confirmé aussi côté UI, "Paramètres des vulnérabilités" y est verrouillé). Objectif reformulé en cours
de route : pas besoin de remplacer AD/SSH par WithSecure, la question était de savoir ce que WithSecure
pouvait apporter **en plus**.

Deux nouveaux services, lecture seule stricte (client API créé "Read-only" côté Security Center) :
- `services/withsecure_client.py` — client OAuth2 (`client_credentials`, token ~30 min, à renouveler).
  `get_devices()`, `get_missing_updates(device_id)` (correctifs manquants, CVE/CVSS réels — **confirmé
  Windows uniquement en testant en direct sur un appareil Debian : 0 résultat**), `get_security_events()`/
  `get_incidents()`/`get_detections()` (EDR, pas encore branchés à un consommateur).
- `services/withsecure_matcher.py` — apparie les appareils WithSecure aux `Asset` CBR **déjà
  existants** par hostname normalisé (`dnsAddress`/`name` vs `Asset.hostname`, ne crée jamais
  d'actif), puis crée des `Vulnerability` à partir des CVE remontées (même schéma exact que
  `cpe_matcher.py` : dédoublonnage par couple asset/cve, `calculate_risk_score`, statut `open` de
  départ — donc soumis au même cycle de qualification manuel/auto que le reste). Une CVE WithSecure
  absente de la base locale déclenche un `run_nvd_sync_by_id` de rattrapage plutôt que la création
  d'une CVE incomplète à la main.
- `routers/withsecure.py` (`POST /run`, `GET /status`) + tâche Celery quotidienne à 5h30
  (`withsecure-sync-daily`, décalée des autres jobs).

Testé en conditions réelles sur le tenant : 1161 appareils WithSecure au total (1100 PC, 60 serveurs,
1 connecteur), 59 serveurs Windows. Premier essai (avant l'élargissement d'`AD_OU`, voir plus bas) :
1 seul actif CBR appariable (`DEPLOYAPP`), 12 vulnérabilités créées, dédoublonnage vérifié (2e appel :
0 créée, 12 ignorées).

**Ce que WithSecure n'apporte pas** : aucun signal EPSS (absent de tout le schéma OpenAPI de l'API
Elements), aucune couverture Linux, et rien ne remplace la couche décisionnelle propre à CBR (scoring,
4 statuts automatiques, historique d'audit) — elle reste entièrement à la charge du pipeline existant
quelle que soit la source de la donnée brute.

#### Élargissement de l'import AD — de 2 à 72 actifs

`AD_OU` pointait sur `OU=OU Test,OU=Serveur,DC=AER,DC=LOC` — une **OU de test**, jamais l'arborescence
réelle. Élargi à `OU=Serveur,DC=AER,DC=LOC` (confirmé par l'utilisateur) : 71 serveurs Windows trouvés
(70 créés, `DEPLOYAPP` mis à jour). `LINUX_HOSTS` reste vide — aucune VM Linux importée cette fois,
`gitlab.aer.loc` inchangé.

Matching CPE relancé sur ce parc élargi : **264 748 nouvelles vulnérabilités créées** d'un coup (5 698
déjà existantes ignorées). ⚠️ **Ce sont des correspondances CPE au niveau OS uniquement** — l'import AD
ne collecte pas les logiciels/paquets installés (contrairement à l'import SSH sur Linux) — donc un
stock de candidats bruts, pas 264 748 failles confirmées activement exploitables. C'est exactement le
rôle du cycle de patch check (WinRM/SSH) de trier ce qui est réellement encore vulnérable.
Resynchronisation WithSecure ensuite : 43/59 serveurs Windows désormais appariés (16 encore orphelins,
écart de nommage hostname probable, pas creusé).

#### Incident — `patch_checker.py` non prévu pour ~265 000 vulnérabilités d'un coup

Au premier lancement du cycle de patch check sur ce volume, le backend s'est bloqué : mémoire à 100%
de sa limite (`mem_limit: 6g`, déjà documenté ci-dessus comme suffisant pour le *matching* — mais
jamais mesuré pour le *patch check* à cette échelle), `TimeoutError` en boucle sur les connexions
Postgres (`poolclass=NullPool` : une connexion neuve par requête, cf. `database.py`), `/api/health`
ne répondait plus du tout. Cause : `run_startup_patch_checks()`/`backfill_auto_patch()` faisaient
`select(Vulnerability).where(...).scalars().all()` **sans pagination** — fonctionnait jusque-là
(testé jusqu'à l'incident des ~4600 CVE sur un seul actif, documenté plus haut, qui portait sur la
lenteur WinRM, pas la mémoire) parce que jamais confronté à un vrai volume de parc.

**Correctif appliqué** (`services/patch_checker.py`) :
- `run_startup_patch_checks(only_asset_id=None)` — récupère d'abord la liste des `asset_id` concernés
  (petite), puis charge les vulnérabilités **par lot de `BATCH_SIZE=2000`, actif par actif** — garde
  intacte l'optimisation "un seul relevé WinRM/SSH par actif" (l'incident du 21/07 sur ~4600 CVE ne
  doit pas être réintroduit). Nouveau paramètre `only_asset_id` pour cibler un seul actif en
  validation avant de relâcher le cycle complet — sans impact sur l'appel normal (défaut `None`).
- `backfill_auto_patch()` — pagination par curseur (`Vulnerability.id > dernier vu`, même
  `BATCH_SIZE`) : le curseur avance à chaque ligne lue qu'elle soit réconciliée ou non, pas de risque
  de reboucler indéfiniment sur les lignes ignorées (`continue`).
- Comportement fonctionnel inchangé, 31/31 tests existants toujours verts après coup.

`STARTUP_MATCHING`/`STARTUP_PATCH_CHECK` repassés à `false` pendant l'investigation (redémarrage
technique du backend re-déclenchait sinon le même effondrement à chaque fois, cf. invariant déjà
documenté plus haut) — **à repasser à `true` une fois le cycle complet validé sur le parc élargi**,
pas avant.

**Découverte annexe, non résolue** : même une fois le correctif en place et le cycle patch check
inactif, le process serveur (pas mon script de test isolé, qui lui restait à ~60-100 Mo tout du long)
est remonté seul à plusieurs Go, apparemment sous l'effet du trafic HTTP normal du dashboard
(`/api/stats`, `/api/vulnerabilities`, `/api/patch-check/status`...) tapant maintenant sur ~265 000
lignes au lieu de ~5000. Confirmé par du trafic frontend actif même après que l'utilisateur ait fermé
tous ses onglets — source non identifiée (autre poste sur le réseau interne le plus probable, jamais
vérifié). **Chantier distinct, pas traité cette session** : auditer `services/stats.py` et les routes
`vulnerabilities`/`patch-check/status` les plus consultées par le Dashboard pour un comportement borné
au volume, indépendamment du patch check.

#### Validation ciblée — un seul actif avant le cycle complet

Test isolé (`docker compose exec backend python -c "..."`, en dehors de la couche HTTP pour écarter le
bruit du dashboard) sur `ARMADA` (3101 vulnérabilités jamais vérifiées, le lot le plus représentatif
du nouveau parc) : mémoire du script restée stable ~60-100 Mo tout du long — **le correctif de
pagination tient**. A révélé au passage un problème réel et distinct : **connexion WinRM refusée**
(« identifiants rejetés ») sur `armada.aer.loc` — le compte de service `WINRM_USER`, qui fonctionne sur
`DEPLOYAPP`, n'a manifestement pas les droits WinRM sur le reste du parc fraîchement importé (jamais
provisionné dessus). Hors du périmètre CBR : à régler côté AD/GPO, pas quelque chose que l'outil peut
corriger lui-même — cohérent avec le principe de non-intervention. **Session arrêtée à ce stade** :
l'utilisateur prend en charge le provisionnement AD ; le test sur `ARMADA` a été laissé tourner en fond
(faible empreinte, sans risque) mais son résultat final n'a pas été observé.

**Droits exacts requis (précisé le 28/07, ne PAS demander l'admin local)** — sur chaque serveur
Windows, via GPO Restricted Groups sur `OU=Serveur` :
- Membre du groupe local **« Remote Management Users »** — sans ça WinRM refuse d'ouvrir la session.
- Membre du groupe local **« Event Log Readers »** — nécessaire pour `Get-WinEvent` sur le journal
  System (source principale de détection KB, cf. `services/patch_checker.py` /
  `docs/MATCHING.md` § Vérification Windows). Suffisant à lui seul : `Get-HotFix`/`Get-WmiObject`
  (WMI/DCOM) échouent sur ce compte quels que soient les droits accordés, déjà géré en best-effort
  dans le code, aucun droit supplémentaire à demander pour ça.

**À faire à la prochaine session** :
- Vérifier si le test `ARMADA` en fond s'est terminé, regarder son résultat final.
- Une fois les deux groupes provisionnés sur `OU=Serveur` : relancer le cycle de patch check complet
  (probablement encore un seul actif d'abord, puis élargir), et repasser `STARTUP_MATCHING`/
  `STARTUP_PATCH_CHECK` à `true`.
- Regarder les 16 serveurs WithSecure toujours non appariés à un actif CBR (écart de nommage
  probable).

---

### Session du 28/07/2026, suite (plus tard le même jour) (déplacé de STATUS.md le 20/08/2026)

**Trois endpoints candidats corrigés** (`awaiting-fix-candidates`, `false-positive-candidates`,
`critical-review-candidates`, `routers/vulnerabilities.py`) — même famille de bug que `patch_checker.py`
plus haut, jamais auditée jusqu'ici : chargement `.all()` sans pagination sur les ~265k vulnérabilités
ouvertes, `false-positive-candidates` en plus interrogé toutes les 30s par le Dashboard avec une boucle
Python CPU-bound (`still_matches`) par ligne. Confirmé en réel : le conteneur backend repassait par le
même pic mémoire (6/6 Go) **et** l'event loop asyncio se bloquait assez longtemps pour faire timeouter
des requêtes concurrentes sans rapport (`/api/stats`, `/api/assets`... vus en 500 simultanément, symptôme
d'une boucle gelée, pas d'une panne applicative). Corrigé par pagination keyset + `asyncio.sleep(0)` fin
(tous les 50 lignes, pas seulement tous les 2000) + fenêtre par défaut de 2 ans sur `CVE.published`,
levée pour un seul actif via `asset_id` (bouton "CVE anciennes incluses" côté `Vulnerabilities.jsx`).
**Insuffisant à lui seul** : la fenêtre de 2 ans ne réduit le volume que de ~265k à ~86k lignes (NVD
publie énormément chaque année) — cause probable en amont, le matching CPE niveau OS rattache ~56% du
catalogue CVE par actif. Décision explicitement reportée par l'utilisateur ("s'arrêter là pour cette
session") — chantier toujours ouvert, à reprendre à la prochaine session (cf. bullet ci-dessous).

**Deux index DB posés** (`backend/db/schema_patches.sql`) : `cves.published` et `vulnerabilities.status`,
jamais indexés malgré des endpoints pollés en continu (`patch-check/status` toutes les 3s, `stats`).
Effet mesuré : `/api/health` de plusieurs secondes à ~2ms sous charge normale. N'accélère pas les 3
endpoints candidats ci-dessus (tri par `vulnerabilities.id`, sans rapport avec ces filtres).

**HMR Vite cassé sous WSL2, corrigé** (`frontend/vite.config.js`, `watch.usePolling`) — le dépôt vit sous
`/mnt/c/...`, le watcher natif ne voyait aucune écriture sur ce montage : des pages éditées restaient
invisibles dans le navigateur sans la moindre erreur, malgré un fichier à jour sur le disque et dans le
conteneur. Un redémarrage du conteneur frontend suffisait à faire apparaître les changements avant ce
correctif — sans lui, ça serait resté un piège silencieux à chaque session future.

**Deux petites fonctionnalités demandées, livrées et testées en conditions réelles** (Playwright, cf.
`docs/FRONTEND.md`/`docs/ARCHITECTURE.md` pour le détail) :
- `Assets.jsx` : filtre OS (liste pilotée par le parc, pas codée en dur) + recherche par nom, combinables.
- `Inventaire.jsx` : bouton "Exporter en PDF" (`GET /api/reports/inventory/pdf`, nouvelle dépendance
  `reportlab`) — tableau récapitulatif seul (nom, OS, CPU, arch, cœurs, RAM, disques, **nombre**
  d'apps). Le détail des applications par actif, présent dans la première version, a été retiré le
  jour même à la demande de l'utilisateur : 17 pages → 3 pages. Bloqué en mode Présentation.

**Doc WinRM précisée** (`docs/MATCHING.md`, en plus de ce fichier) : le prérequis "Remote Management
Users" (ouverture de session WinRM elle-même) documenté séparément d'"Event Log Readers" (lecture du
journal une fois la session ouverte) — les deux étaient mélangés/incomplets avant aujourd'hui.

#### Lenteurs généralisées de l'app — diagnostiquées et résolues (fin de session 28/07)

L'utilisateur signale des lenteurs sur **toutes** les pages. Mesuré : backend saturant un cœur à **101%
en continu** pour seulement ~6 requêtes/minute, pendant que **PostgreSQL restait à 3%** — le coût était
donc en **Python**, pas en SQL, ce qui explique que les index posés plus tôt n'aient rien changé aux
endpoints candidats. Latences de départ : `/api/health` 5s, `/api/stats` 35s, `/api/patch-check/status`
14s, `false-positive-candidates` >60s (timeout). Trois causes cumulées, toutes corrigées :

1. **`cves.raw_data` chargé pour rien** — le JSON NVD brut pèse **377 Mo** en base (2,2 Ko/CVE en
   moyenne, jusqu'à 268 Ko). Les endpoints candidats faisaient `select(Vulnerability, CVE, Asset)`, donc
   transféraient puis désérialisaient ~190 Mo de JSON **par appel**, pour un champ qu'aucun ne lit.
   Corrigé par `load_only(...)` sur les seules colonnes utilisées, avec **`raiseload=True`** : une
   colonne oubliée lève désormais une exception explicite au lieu de dégénérer en N+1 silencieux.
2. **Données de l'actif recalculées à chaque ligne** — `still_matches` appelait
   `_installed_package_products()` (300 paquets de `gitlab.aer.loc` passés à `_package_candidates`, avec
   regex) et `_keywords_from_asset()` par **ligne** au lieu de par actif : ~86 000 recalculs pour 72
   actifs. `services/cpe_matcher.py` expose maintenant `asset_match_context()` + `still_matches_ctx()`.
3. **Verdict recalculé par ligne au lieu de par couple distinct** — `still_matches` est une fonction pure
   de (profil de matching, CVE), et le parc est très homogène (72 actifs, une poignée de profils).
   `false_positive_candidates` procède désormais en **deux phases** : évaluer les couples distincts
   (~6 500 CVE × quelques profils), puis ne charger en entier que les lignes réellement candidates.
   `awaiting-fix-candidates` gagne en plus un pré-filtre SQL `patch_check_result IS NOT NULL` — il ne
   peut structurellement pas matcher sans rapport de contrôle, et **263 715 des 264 959** vulns ouvertes
   n'ont jamais été contrôlées, soit ~99,5% de scan pur gaspillage.

Résultats mesurés (résultats fonctionnels **identiques**, 156 faux positifs avant comme après, 31/31
tests passent) :

| Endpoint | Avant | Après |
|---|---|---|
| `/api/health` | 5 s | 0,002 s |
| `/api/stats` | 35 s | 1,0 s |
| `/api/patch-check/status` | 14 s | 0,10 s |
| `/api/vulnerabilities?status=open` | 20 s | 1,1 s |
| `awaiting-fix-candidates` | 68 s | 0,19 s |
| `false-positive-candidates` | >60 s (timeout) | 7,5 s |
| CPU backend au repos | 101 % | 3 % |
| Mémoire backend | 1,35 Go | 159 Mo |

Pages mesurées au navigateur (Playwright) : Dashboard 0,56 s, Actifs 3,7 s, Inventaire 1,0 s,
Vulnérabilités 0,21 s — contre 20-60 s ou timeouts avant. `/api/health` reste à ~2 ms **pendant** un scan
`false-positive-candidates`, preuve que l'event loop n'est plus gelé (c'était le symptôme réel du « lag »).

⚠️ **Piège rencontré en route, à ne pas refaire** : une première version poussait
`Asset.id.in_(select(...).distinct())` en sous-requête corrélée — les conditions de
`_candidate_conditions` portent sur `CVE.published`, donc **sans jointure explicite sur `cves`,
SQLAlchemy produit un produit cartésien** `vulnerabilities × cves`. Requête bloquée >13 min, 6 appels
empilés par le polling du Dashboard. Les actifs sont désormais chargés directement (72 lignes, aucune
sous-requête) et la jointure est explicite là où elle est nécessaire.

**Toujours ouvert** : le fond du problème de volume (le matching CPE niveau OS rattache ~56% du catalogue
CVE par actif, ~86k lignes dans la fenêtre de 2 ans) n'est **pas** traité — seul son coût de traitement
l'a été. L'app est désormais fluide, ce chantier n'est donc plus urgent, mais il reste la vraie cause.

**À faire à la prochaine session** :
- Chantier volume/matching CPE toujours ouvert (voir ci-dessus) — décider entre durcir encore le filtre
  par défaut des 3 endpoints candidats, ou revoir le matching OS-level lui-même. Plus urgent côté
  *justesse des données* que côté performance désormais.
- Vérifier si le test `ARMADA` en fond (section précédente) s'est terminé.

---

### Session du 28/07/2026 — Surveillance Identités : extension email/GitHub, restée 100% gratuite (déplacé de STATUS.md le 20/08/2026)

L'utilisateur a fourni un brouillon (`docs/SURVEILLANCE_ID.md`) listant 11 sources OSINT pour étendre
Surveillance Identités. Neuf écartées (payantes, déjà rejetées, ou hors-sujet — détail complet
`docs/VEILLE.md` § 9quater). Deux retenues, **toutes deux gratuites** :

- **XposedOrNot** — vérifie un email surveillé (nouveau `kind="email"`) contre des fuites connues,
  équivalent gratuit de HIBP (payant). Actif sans configuration.
- **GitHub code search** — cherche un domaine surveillé associé à un mot-clé d'identifiant dans du code
  public. Nécessite un token gratuit (`GITHUB_TOKEN`, aucun scope) — désactivé silencieusement sans lui.
  **`GITHUB_TOKEN` configuré dans `.env` le 28/07/2026 (fin de journée), backend recréé pour le
  charger (`printenv` vérifié dans le conteneur) — la recherche de code GitHub est désormais active.**
  ⚠️ **Premier test réel a trouvé un bug bloquant, corrigé le même jour** : `GITHUB_LEAK_KEYWORDS`
  groupait les mots-clés entre parenthèses, syntaxe rejetée systématiquement par l'API code search
  (`422`, avalé par le `except` générique) — la fonctionnalité n'avait donc **jamais** produit un seul
  résultat depuis sa création le matin même, sans jamais le signaler. Parenthèses retirées, confirmé en
  conditions réelles via `GET /api/identities/matches` (résultat non vide, lien GitHub réel). Détail
  technique complet dans `services/leak_lookup.py` (docstring module). Rate limit strict à connaître :
  10 requêtes/min sur l'endpoint search (`x-ratelimit-resource: code_search`), sans rapport avec le
  cache 6h de l'usage normal. 31/31 tests toujours au vert après coup.

Nouveau fichier `backend/services/leak_lookup.py`, cache 6h par valeur d'identité (pas un téléchargement
en masse comme les blocklists IP). `routers/identities.py` expose `osint_matches` dans
`GET /identities/matches`, `SurveillanceIdentites.jsx` affiche une nouvelle section tableau. Testé de
bout en bout en conditions réelles (Playwright + curl) : validation email, appel XposedOrNot réel, cache
(148ms au 2e appel), affichage, suppression — 31/31 tests toujours au vert.

---

### Chronique du 31/07/2026 au 17/08/2026 (déplacée de STATUS.md le 20/08/2026, réordonnée chronologiquement le 20/08/2026 — le bloc migré à l'origine était en ordre inverse)

#### 31/07/2026 (résumé)

**Session antérieure : 31/07/2026** (correspondance nom d'application Windows → produit CPE,
`WindowsAppMapping` ; Gestion de crise dans le module Incidents, `Crisis`/`CrisisTimelineEntry` ;
registre Rôles/Services ; nouveau module **Documentation** (gouvernance NIS 2) ; polish visuel
Home/Login (écran de bienvenue avec récap, animations de lancement) ; **puis, même jour** : icônes
de Service + mini organigramme par service (`OrganizationRole.reports_to_id`) ; scénario de test
incident → crise complet créé via l'API (**toujours en base**, cf. § Points ouverts) ; rapport
d'incident enrichi (plan d'action + escalade en crise) ; frise horizontale (`Stepper.jsx`) sur les
fiches Incident/Crise ; **droits d'accès par module pour les comptes `analyst`**
(`User.allowed_pages`, contrôle réel côté serveur `require_page`) + auto-liaison
Utilisateur → Analystes ; ligne « Administration » masquée aux non-admins dans Paramètres — cf. §
invariants ci-dessous — état du parc encore celui du 28/07/2026, non revu aujourd'hui).

#### 03/08/2026 — Module Audits construit (matin, résumé)

**Session d'avant (même jour, le matin) : 03/08/2026** (module **Audits** construit intégralement —
backend, frontend, intégrations, premier jeu de données — cf. § invariants ci-dessous et
`docs/AUDITS.md`, désormais marqué implémenté).

#### 03/08/2026 — Tour applicatif complet (après-midi, résumé)

**Session précédente : 03/08/2026, suite (même jour, l'après-midi)** — tour complet de l'application
(4 axes en parallèle : parcours navigateur UX, revue de code, revue sécurité, priorisation roadmap),
puis une longue série de correctifs qui en découlent, cf. § invariants ci-dessous pour le détail
complet de chacun :
- **Sécurité** : port 8000 restreint à `127.0.0.1` (n'était plus protégé que par nginx) ; injection
  de formule CSV sur `Incident.reported_by` (export auditeur) ; suppression Incident/Crise/Audit/
  Finding réservée admin (était ouverte à tout compte `analyst`).
- **Bugs Dashboard réels** (constatés en usage, pas juste en code review) : KPI "Vulns ouvertes"
  figé à 200 (liste plafonnée affichée à la place du vrai total serveur) ; KPI "Actifs exposés"
  bloqué sur "sur *undefined* actifs" + taux à 0% dès qu'un `fetch` transitoire échouait, sans
  jamais se rattraper.
- **Dette** : deux N+1 (`audits.py`/`crises.py`), code mort MSRC retiré, doublon de lignes dans
  `ConnectionLog` (StrictMode) corrigé, `AnalystContext` se rétablit désormais seul après un
  redémarrage backend (retry au focus fenêtre), erreurs réseau silencieuses câblées sur 9
  pages/onglets (un vrai 500 backend affichait "aucune donnée" sans le dire), contraste mode clair
  corrigé (bouton Déconnexion, badge Administration).
- **Matching/rescore ciblés enfin branchés** : `run_cpe_matching_for_cve`/`recalculate_scores_for_cve`
  existaient depuis le 31/07 sans jamais être appelées — branchées sur `POST /api/sync/nvd/{cve_id}`
  (le bouton de rattrapage NVD unitaire ne laisse plus la CVE invisible sur le parc en attendant un
  matching complet manuel).
- **Incident réel découvert et corrigé** : les images Docker `worker`/`beat` étaient restées au
  27/07/2026 (sans `reportlab`, ajouté le 28/07 côté `backend` seulement) — **les rapports
  hebdomadaires `cve` et `surveillance` échouaient en silence chaque lundi depuis**, seul `veille`
  s'en sortait. Images reconstruites, rapports S31 rattrapés (72 par actif + surveillance + veille).
- **Deuxième bug trouvé en rattrapant S31** : le rapport CVE global a fait planter le worker par OOM
  (264 949 lignes chargées d'un coup — la semaine de l'élargissement AD du 28/07 tombait dans sa
  fenêtre). Plafond + total réel ajoutés (`ACTIVITY_ROW_CAP=15`, CSV et markdown honnêtes sur la
  troncature), rétrocompatibilité vérifiée sur un rapport S30 déjà archivé au format non plafonné.

Méthode de test identique aux sessions précédentes : session admin temporaire créée directement en
base (token + hash SHA-256), jamais le mot de passe réel, supprimée après chaque vérification.
État du parc revu en cours de session (264 949 vulns `open` confirmées en direct, cf. ci-dessous) —
pas de régression sur les décisions de qualification existantes, seule la plomberie de génération de
rapports et l'exposition réseau ont changé.

#### 03/08/2026, suite (l'après-midi) — tour applicatif complet + série de correctifs (détail complet)

Demande utilisateur : « refait un tour de l'application, vois ce qu'on peut améliorer », précisée en
quatre axes (parcours navigateur UX, revue de code, revue sécurité, priorisation fonctionnelle/
roadmap) menés **en parallèle** par sous-agents, puis une longue série de corrections appliquées
au fil de l'eau à mesure que l'utilisateur validait chaque piste (« vasy »).

#### Méthode — session admin temporaire pour les tests

Comme lors des sessions précédentes (Gestion de crise 31/07, RBAC 31/07) : une ligne insérée
directement dans `sessions` (token aléatoire + hash SHA-256, jamais le mot de passe réel de
l'utilisateur), utilisée pour piloter Playwright et pour les vérifications `curl`, **supprimée après
chaque usage**. Le parcours navigateur a tourné dans le conteneur `mcr.microsoft.com/playwright:v1.62.0-jammy`
(`--network host`), méthode déjà validée pour le test E2E du module Audits le matin même.

#### Sécurité — 3 findings du re-audit, tous corrigés

Re-audit ciblé sur le code écrit après le précédent audit du 24/07 (`audit/AUDIT_SECURITE.md`) — modules
Incidents/Crises/Documentation/Audits/WithSecure, RBAC `allowed_pages`. Les 6 correctifs du 24/07
vérifiés intacts (pas de régression). Trois findings nouveaux, tous corrigés le jour même :

1. **Port 8000 exposé sur toutes les interfaces** (`docker-compose.yml`) — le port du backend était
   publié sans restriction, joignable directement par tout hôte du réseau local, **hors du proxy
   nginx** qui pose `X-Forwarded-For` (`frontend/nginx.conf`). `routers/auth.py::_client_ip` fait
   confiance à cet en-tête sans vérifier sa provenance : un client réseau pouvait le forger,
   contournant le verrou anti-bruteforce IP (`LOCKOUT_MAX_PER_IP`) et corrompant l'IP tracée dans
   `AuthAuditLog`/`ConnectionLog`/`UserSession` — pour un outil dont la traçabilité est la raison
   d'être (NIS 2, forensic), une IP falsifiable dans ces tables est un vrai problème. Corrigé :
   `ports: ["127.0.0.1:8000:8000"]` au lieu de `["8000:8000"]` — restreint à la machine hôte, les
   commandes `curl localhost:8000` documentées dans `CLAUDE.md` restent utilisables, plus depuis le
   reste du réseau. Vérifié en direct : `curl localhost:8000/api/health` → 200, `curl <IP réseau
   hôte>:8000/api/health` → aucune réponse.
2. **Injection de formule CSV résiduelle** (`routers/incidents.py::export_incidents`) — le fix #7 de
   l'audit du 24/07 (`csv_safe()`) n'avait pas été repris sur `Incident.reported_by` (champ texte
   libre, saisi par tout compte authentifié créant un incident) dans le nouveau module Incidents
   (créé 29/07, après cet audit). `title` passait déjà par `csv_safe()` deux lignes plus haut,
   `reported_by` non. Corrigé (une ligne).
3. **Suppression Incident/Crise/Audit/Finding non réservée admin** — `delete_incident`,
   `delete_crisis`, `delete_audit`, `delete_audit_finding` ne portaient que `require_page` (accès
   module), ouvert par défaut à tout compte `analyst` (`allowed_pages = NULL`). Incohérent avec le
   reste du modèle de droits (Analystes/Rôles/Services/Correspondances Windows déjà réservés admin
   en écriture) — et la suppression efface en cascade la timeline append-only et l'historique de
   statut des findings, y compris sur un audit `termine`/`archive` sans garde d'état. Corrigé
   (`Depends(require_admin)` sur les 4 endpoints) + boutons "Supprimer" masqués côté frontend pour
   les non-admins (`IncidentDetailModal.jsx`, `CrisisDetailModal.jsx`, `AuditDetail.jsx` — via
   `useAuth()`, même pattern que `Settings.jsx::AdministrationRow`), pour ne pas laisser un compte
   analyst se heurter à un 403 après confirmation. Vérifié en conditions réelles : compte analyst
   temporaire → 403 sur `DELETE /crises/{id}`, crise réelle non affectée ; compte admin → 200.

Durcissements optionnels identifiés mais non retenus (pas de vulnérabilité concrète) : en-têtes
`X-Frame-Options`/CSP/`X-Content-Type-Options` absents (`main.py`/`nginx.conf`).

#### Bugs Dashboard réels — deux causes distinctes sur la même page

Repérés par le parcours navigateur, pas seulement en relecture de code — la page affichait "sur
*undefined* actifs", "VULNS OUVERTES : 200" figé sur trois relevés différents, et "0% — 0/0" à côté
d'un "55 vulns bloquées" juste au-dessus, contradictoire visuellement. `frontend/src/pages/Dashboard.jsx` :

1. **KPI "Vulns ouvertes" utilisait `assetScopedOpen.length`** (la liste chargée, plafonnée par
   `per_page=200`) au lieu d'`openCount` — une variable **déjà correcte** (`totals.open`, le vrai
   total serveur) définie 500 lignes plus haut dans le même fichier et déjà utilisée pour d'autres
   badges. Exactement le bug déjà corrigé ailleurs le 21/07/2026 (cf. commentaire du code lui-même),
   oublié sur cette seule carte. Un oubli de branchement, pas une découverte à modéliser — une ligne.
2. **`kpis` restait bloqué à `null` pour toute la session** dès qu'un `fetchStats()` échouait une
   fois (`.catch(() => {})` sans retry, montage seul + changement de sélection d'actifs) — d'où
   "undefined"/"0%" jusqu'au rechargement de page. Rejoué désormais dans le polling silencieux de
   30 s déjà en place pour les 3 tableaux (même effet `useEffect`, `loadLists`/`loadFpCandidates`) :
   un raté transitoire (base sous charge pendant un cycle de patch check) se rattrape tout seul au
   tick suivant. Garde ajoutée en plus sur le texte affiché : `sub` du KPI "Actifs exposés" ne
   s'affiche plus du tout tant que `displayKpis` est `null`, plutôt que d'interpoler "undefined"
   littéralement dans la chaîne.

Point vérifié en direct pendant l'investigation, **pas un bug** contrairement à l'hypothèse prudente
du rapport UX initial : le "264 847" affiché sur la page Vulnérabilités est le vrai total de vulns
`open` (`GET /api/stats` → `open_vulnerabilities: 264847`, cohérent avec les ~264 900 déjà
documentés). Ce n'est pas une taille de page qui fuite comme total.

#### Dette technique corrigée

- **N+1** : `routers/audits.py::list_audit_findings` rechargeait `_asset_names(session)` par finding
  au lieu d'une fois pour la liste (le pattern correct existait déjà 150 lignes plus haut dans le
  même fichier, `list_audits`) — sorti de la boucle. `routers/crises.py::list_crises` appelait
  `_linked_incidents` une fois par crise ; nouvelle fonction `_linked_incidents_by_crisis` (requête
  groupée, un seul `IN (...)`) sur le même principe que `_finding_summary` d'`audits.py`.
- **Code mort retiré** : `services/patch_checker.py::fetch_kb_from_msrc` — aucun appelant nulle
  part dans le code (vérifié par grep), résidu de l'impasse MSRC CVRF v3 déjà documentée comme
  vide/purgée.
- **Doublon `ConnectionLog`** : `ConnectionTracker` (`App.jsx`) postait `logConnection()` dans un
  `useEffect` sans garde — React 18 `StrictMode` (`main.jsx`) monte/démonte/remonte chaque
  composant une fois en dev, donc chaque navigation posait deux lignes identiques à la seconde près
  (constaté en base). `docker compose up` (mode par défaut, cf. `CLAUDE.md`) sert la build dev, donc
  ça touchait tout usage courant, pas un artefact de test. Corrigé par un garde `useRef`
  (`firedRef`), pattern standard pour ce cas précis.
- **`AnalystContext` retry au focus fenêtre** : cf. postscript ci-dessus — `window.addEventListener('focus', refresh)`,
  le fetch (stable via `useCallback`) se rejoue tout seul quand l'utilisateur revient sur l'onglet
  après un redémarrage backend, sans exiger un rechargement complet de page.
- **Erreurs réseau silencieuses câblées sur 9 endroits** — le piège déjà vécu une fois (services
  vides après un 500 réel, `.catch(() => setSvcs([]))`, incident du 31/07 où l'utilisateur a cru
  avoir perdu ses données) n'avait jamais été généralisé. Un vrai 500 backend affichait "aucune
  donnée" sans le dire, sur : `AdministrationSecurity.jsx` (onglets Utilisateurs, Services + Rôles
  regroupés en `Promise.all`, Rôles seul, Correspondances Windows), `Crises.jsx`, `Audits.jsx`,
  `Incidents.jsx`, `Documentation.jsx` — dans chaque cas, `error` existait déjà comme état React
  (utilisé pour les échecs de suppression) mais n'était pas câblé sur l'échec du chargement initial
  ; câblage ajouté, bandeau d'erreur déjà présent dans le JSX de chaque page.
- **Contraste mode clair** (`Settings.jsx`) : bouton "Se déconnecter" et badge Administration en
  `#f85149` sur fond clair tombaient sous le seuil WCAG AA (~3:1). Rouge assombri en mode clair
  uniquement (`#cf222e`, via `useTheme().isDark` déjà disponible dans le fichier) — `#f85149`
  inchangé en mode sombre, où il reste conforme. Convention rouge "danger" du reste de l'app non
  touchée (changement scopé à ce fichier, pas une refonte globale de palette).

#### Matching/rescore ciblés — vrai trou comblé, pas du code mort

Question posée explicitement par l'utilisateur après la revue de code : `run_cpe_matching_for_cve`
(`cpe_matcher.py`) et `recalculate_scores_for_cve` (`scoring.py`) existaient depuis le 31/07
(branchement `WindowsAppMapping` compris) sans **aucun appelant** nulle part dans le code — code
mort, ou trou fonctionnel réel ? Investigation : leur seul appelant potentiel,
`POST /api/sync/nvd/{cve_id}` (bouton "filet de rattrapage" pour une CVE manquée par la sync
incrémentale), disait explicitement dans son docstring de ne rien relancer automatiquement et
d'appeler `POST /api/sync/match` ensuite — la version **complète** (72 actifs × ~181 000 CVE),
l'opération responsable des incidents mémoire déjà documentés (minutes, 6 Go de RAM), pour recroiser
**une seule** CVE fraîchement récupérée. Vrai trou : en pratique personne ne le fait, donc la CVE
reste invisible sur le parc jusqu'au prochain cycle automatique complet. Branché directement dans
`trigger_nvd_sync_by_id` (`routers/sync.py`) — même profil de sécurité que le cycle horaire déjà
automatique (crée des vulns `open`, ne qualifie/ferme jamais rien). Vérifié en conditions réelles sur
`CVE-2017-6542` (putty/DEPLOYAPP, cf. `WindowsAppMapping` du 31/07) : `matching: {matched: 1, created:
0, skipped: 1}` (vuln déjà existante, dédoublonnage correct), `rescore: {updated: 0}` (score déjà à
jour) — 404 sur un ID bogus toujours propre.

#### Incident réel découvert — images Docker `worker`/`beat` désynchronisées de `backend`

En creusant une désynchronisation des rapports hebdomadaires repérée par le parcours UX (`veille`
avait déjà S31/2026 généré ce lundi, `cve` et `surveillance` restaient bloqués à S30) : logs worker
`Échec génération rapport cve S31/2026 ... : No module named 'routers'`. Reproduit directement dans
le conteneur `worker` : la vraie erreur est `ModuleNotFoundError: No module named 'reportlab'` —
`services/weekly_report.py::build_cve_report` importe `routers/reports.py` (réutilise
`build_summary_payload`, pour ne jamais calculer les mêmes chiffres deux fois entre l'écran et
l'archive figée), qui importe `services/inventory_export.py`, qui importe `reportlab`.

Cause : `backend`, `worker` et `beat` partagent le même `Dockerfile`/contexte de build (`./backend`)
mais sont **trois images taguées séparément** (`cybervuln-backend`, `cybervuln-worker`,
`cybervuln-beat`) — elles avaient divergé. `reportlab` ajouté aux dépendances le 28/07/2026 (module
Inventaire) : `cybervuln-backend` reconstruite depuis (30/07/2026, confirmé par `docker images`
`CreatedAt`), `cybervuln-worker`/`cybervuln-beat` jamais reconstruites depuis le 27/07/2026 —
**`docker compose restart`/`--force-recreate` recrée un conteneur, ça ne reconstruit pas son image.**
`veille` s'en sortait parce que `services/watch_report.py` ne touche jamais `routers/reports.py` ;
`cve` et `surveillance` importent cette chaîne et plantaient à chaque tentative depuis le 28/07 —
**silencieusement**, seul le log worker le montrait, rien ne remontait à l'écran.

Corrigé : `docker compose build worker beat` puis recreate — `import reportlab` vérifié OK dans les
deux conteneurs après coup. Rapports S31 rattrapés manuellement (`generate_report`/
`generate_weekly_reports` rejoués directement dans le conteneur worker corrigé) : surveillance +
les 72 rapports CVE par actif générés sans erreur (aucune ligne de `Report` corrompue à nettoyer —
l'échec se produisait avant tout `commit()`). Le rapport CVE **global** ("Tous les actifs") a
lui-même fait planter le worker par OOM en le régénérant — cf. paragraphe suivant.

⚠️ **Leçon à ne pas oublier** : toute future modification de `backend/requirements.txt` doit être
suivie d'un rebuild des **trois** images (`docker compose build backend worker beat`), pas juste
`backend` — sans quoi `worker`/`beat` continuent de tourner sur une image périmée, en silence,
jusqu'au prochain import qui casse (ici : deux semaines complètes de rapports manqués avant d'être
repéré).

#### Deuxième bug trouvé en rattrapant S31 — OOM sur l'activité du rapport CVE global

`_activity_during_period()` (`routers/reports.py`, alimente la section "Ce qui a été fait" du
rapport exécutif CVE) chargeait la liste complète des vulnérabilités *détectées* sur la fenêtre du
rapport, sans plafond — pour "Tous les actifs", jointure + matérialisation de chaque ligne en objet
Python. Vérifié : **264 949 lignes** tombent dans la fenêtre S31 (27/07→03/08), exactement la
semaine de l'élargissement AD (2→72 actifs, 28/07/2026) qui a créé la quasi-totalité de ces lignes le
même jour. Régénération du rapport global tuée par OOM (`exit 137`) — par actif, le volume tombe à
~4 700 lignes chacun (aucun souci, les 72 rapports par actif sont passés du premier coup).

Piège ponctuel (la semaine du gros import), pas un bug permanent — les semaines suivantes n'ont
aucune raison de retomber dedans, **sauf** un futur import massif (onboarding d'un lot de serveurs,
gros run de matching) qui retomberait dans la fenêtre d'un rapport en cours.

**Décision utilisateur, question posée avant de coder** (3 options : plafonner+compter / tout garder
en agrégat SQL / ne rien changer maintenant) → **plafonner + compter**, choisi. Implémenté dans
`_activity_during_period` : chaque section (`patched`/`awaiting_fix`/`false_positive`/`detected`)
vaut désormais `{"items": [...], "total": N}` au lieu d'une liste brute — `items` plafonné à
`ACTIVITY_ROW_CAP = 15` via `LIMIT` **côté requête SQL** (pas juste tronqué après coup, ce qui
n'aurait rien réglé côté mémoire), `total` toujours le vrai compte (agrégat séparé). Même convention
que `identity_report.py` (`leak_matches`/`ip_matches`, déjà plafonnés à 15 côté affichage) et
`_activity_table` (markdown, déjà plafonné à 15) — réutilise le chiffre déjà établi plutôt que d'en
inventer un nouveau. Jamais silencieux sur la troncature (même principe que `openTruncated` côté
`Dashboard.jsx`) :
- **CSV** (`export_weekly_report_csv`) : ligne de synthèse ajoutée par section quand `total >
  len(items)` — `"… et 264934 de plus (total réel : 264949, liste plafonnée à 15)"`. Avant ce
  correctif, le CSV était implicitement la source de détail complet ("détail dans l'export CSV",
  texte du markdown) ; ce n'est plus vrai au-delà du plafond, texte du markdown mis à jour en
  conséquence.
- **Markdown exécutif** (`claude_analyzer.py::_activity_table`) : en-tête et "et N de plus"
  s'appuient désormais sur `total` explicite, plus sur `len(items)` (qui ne dépasse jamais 15 côté
  génération, contrairement à avant où `_activity_table` tronquait elle-même une liste potentiellement
  déjà énorme reçue en entrée).
- **`_report_row`** (compteurs de la liste d'archives) : gère les deux formes (`isinstance(v, dict)`
  → `.get("total")`, sinon `len(v)`) — **rétrocompatible** avec les rapports déjà archivés au format
  liste brute (ex: S30, généré le 27/07 avant ce correctif).

Vérifié en conditions réelles : rapport CVE global S31 régénéré en **2,9 s** (au lieu du crash OOM),
`detected: total=264949, items=15` ; export CSV du rapport S31 avec les 3 lignes de troncature
attendues ; export CSV du rapport S30 (ancien format, non plafonné) toujours fonctionnel à
l'identique — 11 214 lignes, aucune donnée archivée perdue. Session admin temporaire supprimée après
usage.

#### 03/08/2026, suite (même jour, encore plus tard) — traitement des reliquats, intégration Meraki, patch check applications Windows

**Session du 03/08/2026, suite (même jour, encore plus tard)** — traitement des reliquats
identifiés par le tour applicatif de l'après-midi (§ ci-dessous) : nettoyage du scénario de test
Ransomware/Crise du 31/07 (toujours en base), 56 tests ajoutés (`test_crisis_guardrails.py`,
`test_audit_attachments.py`, `test_document_storage.py` — 134 au total, tous verts), déduplication
`crisis_timeline.py`/`incident_timeline.py` (fabrique commune `services/timeline.py`) et des 3
onglets CRUD d'`AdministrationSecurity.jsx` (`useLoadList`/`useCrudModals`), bouton "Scanner tout"
sur Inventaire, vue carte mobile sur Vulnérabilités, second exemple de Correspondance Windows
(`Wireshark 4.6.6 x64` → `wireshark`) — ce dernier a fait remonter 242 vulnérabilités réelles
jusque-là invisibles sur DEPLOYAPP (cf. § État du parc). Tout testé en conditions réelles (API HTTP
+ Playwright, session admin temporaire supprimée après usage).

**Puis, même jour, nouvelle intégration — supervision réseau Meraki** : reprend l'idée PRTG
évoquée le 31/07 (jamais codée), avec Cisco Meraki à la place. Construit et testé en conditions
réelles avec une vraie clé API fournie par l'utilisateur en cours de session :
- Backend : `services/meraki_client.py` (lecture seule, clé API dans l'en-tête
  `X-Cisco-Meraki-API-Key`, jamais d'écriture côté Meraki), `services/meraki_matcher.py`
  (rapprochement par hostname aux `Asset` existants, jamais de création — même principe que
  `withsecure_matcher.py`), modèle `NetworkStatus` (une ligne par `(actif, source)`, `metrics` en
  JSON pour scaler vers d'autres données plus tard sans nouvelle migration), `routers/meraki.py`
  (`POST /run`, `GET /status`, même schéma que `routers/withsecure.py`). Table créée manuellement
  par le superuser (`schema_patches.sql`, `cbr_app` n'a pas de droit DDL — même procédure que
  `WindowsAppMapping` le 31/07).
- Frontend : `NetworkStatusBadge.jsx` (En ligne/Hors ligne/Alerte/Veille), colonne "Réseau" ajoutée
  sur **Actifs et Inventaire** (demande explicite), `GET /api/assets` porte `network_status` par
  actif (une seule requête pour toute la liste, pas une par actif).
- ⚠️ **Détail réel découvert en testant avec la vraie clé** : la clé voit **2 organisations**
  Meraki distinctes (`Aer Holding`, 48 bornes Wi-Fi + `AER HOLDING - PX1624955`, 22 pare-feux
  MX67C) — se limiter à la première (comportement initial) aurait silencieusement ignoré la
  seconde. Corrigé : agrégation de toutes les organisations visibles par la clé quand
  `MERAKI_ORGANIZATION_ID` n'est pas renseigné. ⚠️ Constaté aussi : l'endpoint `/organizations`
  de cette clé a été **instable** pendant le test (2 organisations puis 1 seule quelques minutes
  après, sans changement de configuration) — probablement un délai de propagation côté Meraki
  après activation de l'accès API sur la deuxième organisation, pas un bug côté CBR.
- **Premier sync réel : 0 actif rapproché** (`matched_assets: 0`, attendu) : les équipements
  Meraki actuels sont tous des bornes Wi-Fi/pare-feux (noms de sites, ex.
  "AP_Senonches_PROD_Couloir"), le parc CBR ce sont des serveurs Windows/Debian ("AOS10",
  "DEPLOYAPP") — aucun recoupement de nom possible. **Décidé avec l'utilisateur dans la foulée** :
  importer ces équipements comme actifs plutôt que de laisser le badge invisible partout.
- **Import des équipements Meraki comme `Asset`** (même jour, demande explicite) : contrairement à
  `withsecure_matcher.py` (n'enrichit que des serveurs déjà là, jamais de création),
  `sync_network_status(import_new_assets=True)` crée désormais un `Asset`
  (`asset_type="network"`, `source="meraki"`, `hostname` vide — pas de DNS pour un boîtier réseau
  et la colonne est UNIQUE, rapprochement futur par `name`) pour chaque équipement non reconnu.
  Défaut `False` : un cycle planifié ne doit jamais créer d'actifs silencieusement sans qu'on le
  demande à chaque appel. `GET /api/meraki/run?import_new_assets=true` (nouveau paramètre).
  `os` porte le modèle Meraki (ex. "MR42"), `hardware` les métadonnées réseau (mac, network_id,
  tags Meraki) — mêmes champs que l'inventaire matériel des serveurs, réutilisés avec des clés
  différentes plutôt qu'un nouveau champ. Nouvelle source `meraki` ajoutée à
  `SOURCE_STYLES`/`SOURCE_LABELS` (Assets.jsx).
- **Vérifié en conditions réelles** : 70 équipements importés (48 bornes Wi-Fi + 22 pare-feux),
  `matched_assets`/`assets_created`/`updated` tous à 70, `unmatched_devices` vide. Parc CBR passé
  de 72 à **142 actifs** (`GET /api/stats` recontrôlé : `exposed_assets` inchangé, aucune CVE
  matchée sur ces nouveaux actifs réseau — cohérent, ils n'ont ni OS ni paquets installés).
  Badge "Réseau" confirmé visible sur Actifs (filtré sur "AP_Senonches" : 10 lignes, statuts En
  ligne/Alerte corrects) et sur Inventaire, colonne "Réseau" ajoutée aux deux pages.
- Tests : 149 (inchangé — pas de test dédié ajouté, même précédent que `withsecure_matcher.py`
  qui n'en a pas non plus, la logique de matching dépend d'une session DB).

**Puis, même jour, à la suite d'une question utilisateur sur `CVE-2016-2563`** : trou réel découvert
dans le patch checker — aucune comparaison de version pour les applications Windows tierces
(PuTTY, Wireshark...), seulement l'OS (KB/build). Corrigé (`_check_windows_app_patch`, cf. §
invariants et § État du parc pour le détail) ; rattrapage lancé sur les 242 vulns PuTTY/Wireshark de
DEPLOYAPP — 241 basculées en `patched`, seules les 2 CRITICAL restent `open` pour revue manuelle.

#### 10/08 et 11/08/2026 — Reprise générale (bugs, perf, durcissement Docker, fuzzing, nettoyage) et détails associés

**Session précédente : 10/08/2026** — repartie d'une question ouverte ("qu'est-ce qu'on peut retravailler
pour prévenir d'éventuels bugs ?") plutôt que d'une liste de demandes précises : plusieurs bugs réels
(certains récurrents, déjà vus et corrigés ailleurs mais jamais appliqués partout) trouvés et corrigés
en les vivant en direct pendant la session. Détail complet de chaque chantier en cherchant sa date
dans ce fichier (tous datés 10/08/2026) :
- WinRM : limite de commande dépassée une **3e fois** (checks de durcissement SMB/LLMNR/WDigest/NTLM
  ajoutés) — cette fois corrigée durablement en scindant le scan Windows en deux appels WinRM séparés
  (inventaire + conformité), chacun avec sa propre marge, plutôt qu'en recompactant un seul script à
  chaque nouvel ajout (déjà fait 2 fois, jamais tenable).
- Cycle patch check : suivi par actif (`_asset_progress`/`_cycle_started_at`, ETA), bug d'affichage
  (UUID brut au lieu du nom pour un actif pas encore atteint) trouvé et corrigé le jour même,
  `STARTUP_PATCH_CHECK=true` — le cycle repart désormais tout seul à chaque redémarrage backend
  (`--reload` inclus), qui le tuait silencieusement auparavant à chaque édition de code.
- Perf/robustesse : cache process sur `false-positive-candidates` (9,3s → 57ms sur le cas non
  scopé) ; `run_cpe_matching` gelait l'event loop asyncio du backend entier pour tout le monde
  (13,4M itérations sans le moindre point de cession) — même classe de bug déjà corrigée ailleurs le
  28/07 mais jamais appliquée à ce endpoint précis.
- Qualification groupée : justification générée automatiquement par CVE/actif (`/bulk-validate`
  CRITICAL et `/bulk-false-positive`, reprend le détail technique du patch check ou le motif de
  matching) — plus de texte libre à saisir, seul le validateur reste manuel ; barre de progression
  par lots sur les 3 modales de qualification groupée (Vulnérabilités).
- Frontend : filtres configurés/non configurés sur Actifs et Inventaire (util partagé
  `assetCategory.js`) ; refonte du bloc "Analyse en cours" du Dashboard (barre de progression, ETA
  côté serveur, suivi par actif avec OS/espace disque, notification de fin d'actif) ; mise en page
  des boutons de qualification groupée sur Vulnérabilités.
- Suite de session : `STARTUP_PATCH_CHECK=true` s'est révélé insuffisant seul en dev (`--reload`
  déclenche des rechargements toutes les 10-60s pendant une session d'édition active, plus vite
  qu'un contrôle WinRM/SSH — le cycle ne finit jamais, juste "disparaît" côté dashboard sans dire
  qu'il a été coupé) — statut de cycle persisté en base (`sync_state`, clé `patch_check_cycle`,
  `running`/`completed`/`interrupted`/`failed`) pour un bandeau honnête. Toast de confirmation au
  clic sur "Patch check global" (lancé/déjà à jour/échec), `pending_count` calculé côté serveur sur
  le périmètre exact du cycle. 2 artefacts de test nettoyés (`Test bulk`/`Test bulk historique`,
  `gitlab.aer.loc`, réouverts en `open` via l'API). Actifs — mises à jour disponibles indépendamment
  d'une CVE connue : `available_updates_count`, Linux seulement (impasse Windows vérifiée, cf. §
  Impasses ci-dessous).
- Scan qui rafraîchit `installed_packages` sans jamais redéclencher un contrôle patch : une appli
  Windows mise à jour sur le serveur réel restait affichée comme vulnérable jusqu'à 24h après un
  rescan (`RECHECK_INTERVAL`). Corrigé : un scan déclenche désormais aussi un recheck patch scopé
  à l'actif (`reset_patch_check_timestamps` + `run_full_patch_check_cycle`), vérifié en conditions
  réelles sur DEPLOYAPP (3 CVE PuTTY débloquées automatiquement). Dashboard : criticité extraite de
  la colonne "Actif" vers sa propre colonne dans les 3 tableaux (décalage horizontal corrigé).
- **Audit de sécurité, nouveau tour complet** (post-authentification, le précédent datait du
  27/07) : 4 points trouvés et corrigés le jour même — IP falsifiable via `X-Forwarded-For`
  (nginx **et** vite.config.js, ce dernier pire : priorisait l'en-tête client) cassant le verrou
  anti-bruteforce et la piste d'audit NIS 2 ; `must_change_password` non vérifié côté serveur
  (identifiants provisoires utilisables indéfiniment via un appel API direct) ; en-têtes
  `X-Content-Type-Options`/`X-Frame-Options` absents ; comparaison non constante du jeton interne.
- **Durcissement Docker** (demande explicite, avant le passage en prod ~24/08) : backend/worker/
  beat + les deux stages frontend passés en non-root (UID 1000 `app`/`node`, UID 101 `nginx` en
  prod) — volumes nommés déjà peuplés réappropriés séparément (montés par-dessus l'image, un
  `chown` dans le Dockerfile ne les couvre pas). `./keys` repassé en lecture seule, `known_hosts`
  (seul fichier qui a besoin d'écrire, TOFU SSH) déplacé sur son propre volume nommé.
- **Fuzzing** (parseurs internes par propriétés avec `hypothesis`, API en lecture seule avec
  `schemathesis` dans un conteneur jetable) : aucun bug dans `net_guard`/`csv_safety`/
  `document_storage` (17 tests, confirme la robustesse contre les contournements SSRF classiques) ;
  côté API, un ID de chemin non-UUID faisait planter 79 endroits en 500 (handler global ajouté,
  `main.py`) et une rafale de requêtes concurrentes a fait geler le backend entier >2 min (mitigé
  par un sémaphore `asyncio.Semaphore(5)` sur `database.py::get_session`, `NullPool` conservé tel
  quel — décision explicite de l'utilisateur, "5 connexions simultanées"). Vérifié en conditions
  réelles : rafale de 40 requêtes traitée par vagues de 5, `/api/health` resté disponible en continu.
- `BOOTSTRAP_ADMIN_EMAIL`/`PASSWORD` retirés de `.env` (le vrai compte admin existait déjà, le
  bootstrap ne s'était jamais déclenché — retrait sans risque). Tour de code mort : deux
  dépendances jamais utilisées supprimées (`feedparser` côté backend, `@headlessui/react` +
  `@tremor/react` côté frontend — ce dernier déjà signalé comme mort dans CLAUDE.md), un
  reliquat `detected_items` non lu dans `claude_analyzer.py`. Sinon, base de code trouvée propre
  (vulture côté backend + cross-référencement de chaque fichier côté frontend : aucun fichier
  orphelin, aucun import mort).

Tout vérifié en conditions réelles au fil de la session (curl direct contre l'API avec sessions
admin temporaires, dry-run en lecture seule pour la logique de justification, mesures avant/après
sur les deux correctifs de perf) — détail complet de chaque point, avec les vérifications précises,
dans les entrées datées ci-dessous.

**Dashboard — bandeau "Analyse en cours" bloqué en permanence, bug réel corrigé (11/08/2026)** :
signalé par l'utilisateur ("bien bugé je pense, elle se lance à chaque actualisation de la page et
reste bloqué"). Le bandeau se base sur `GET /api/patch-check/status`, pollé toutes les 3s par
`Dashboard.jsx`. La condition d'activité côté frontend était :
```js
const active = data.current !== null || data.pending > 0
```
Or `pending` (`routers/patch_check.py`) n'est qu'un **décompte du backlog** — vulns `open`/
`in_progress`/`awaiting_fix*` dont `last_patch_check` est `null` ou plus vieux que `RECHECK_INTERVAL`
— calculé indépendamment de tout cycle en cours. Sur un parc réel avec des milliers de vulns, ce
backlog est quasi toujours non nul entre deux cycles planifiés (toutes les 6h) : le bandeau
s'affichait donc en continu, y compris juste après un rechargement de page sans aucun cycle actif,
et restait "bloqué" puisque le backlog ne bouge que quand un cycle tourne réellement.

Le bon signal existait déjà côté backend mais n'était exposé nulle part : `is_patch_check_cycle_running()`
(`services/patch_checker.py`, lit le booléen `_cycle_running` défini par `run_full_patch_check_cycle`)
— sa seule utilisation avait même été **retirée** de `POST /patch-check/run` le 07/08/2026 (garde
jugée inutile à cet endroit précis), la laissant orpheline dans le module. Corrigé :
- Backend : nouveau champ `"running": is_patch_check_cycle_running()` dans la réponse de `GET
  /api/patch-check/status`.
- Frontend : `const active = data.running === true` — `pending` reste utilisé pour le total de la
  barre de progression (`runTotalRef`) une fois un cycle confirmé actif, plus comme signal d'activité
  à lui seul.

Un seul call site concerné (`patchCheckStatus()` n'est appelé que depuis `Dashboard.jsx`) —
vérifié par recherche dans tout `frontend/src/`. Backend rechargé (`--reload`) et frontend (HMR) sans
erreur après le correctif ; endpoint recontrôlé via `curl` (200 OK, pas de régression).

**Identité visuelle + delight Login/Bienvenue Boss (11/08/2026)** : demande explicite ("je trouve CBR
un peu trop générique, j'aimerais donner plus de caractère et de dynamisme"), confirmée ensuite par
"aujourd'hui ça fait très site fait par l'IA, j'aimerais changer ça". Détail technique complet
(tokens, nouveau glyphe, classes d'animation, courbe `--ease-bounce`) dans `docs/FRONTEND.md` §
Identité de marque + delight Login/Bienvenue Boss — résumé ici :
- Violet à plat (`#5b21b6`) recopié en dur dans 5 fichiers → centralisé en tokens CSS (`--brand`,
  `--brand-grad` dégradé 3 tons, `--font-mono` JetBrains Mono) + composant partagé unique
  (`components/CbrMark.jsx`, nouveau).
- Glyphe du logo : l'ornement en deux clés superposées (peu lisible, remplacé) devient un prompt de
  terminal `> ▬` — cohérent avec la lecture seule en ligne de commande du produit (SSH/WinRM).
- Sidebar : liseré coloré sur l'item de nav actif (en plus du fond teinté déjà là).
- Hero (Home + Login) : trame de points technique sous le halo existant.
- Login + WelcomeOverlay ("Bienvenue Boss") : animations plus visibles (overshoot, ping radar,
  balayage sur le wordmark, tremblement d'erreur, halo qui respire sur le bouton "Continuer") — skills
  chargées pour ce lot : **emil-design-eng** (cadre de décision par fréquence : ces deux écrans sont
  rares, une fois par session/connexion, contrairement à Home.jsx revisité en boucle) et
  **apple-design** (physicalité du mouvement, traduite en overshoot CSS — toujours pas de
  framer-motion dans ce projet).
- Favicon régénéré pour matcher.

Vérifié en HMR (Docker `cybervuln-frontend-1`, déjà en tournant au moment de la session — aucun
rebuild nécessaire) : tous les fichiers touchés rechargés sans erreur de compilation. **Pas de
capture d'écran prise côté agent** — sandbox sans navigateur ni bibliothèques graphiques installables
(pas d'accès root) ; validation visuelle laissée à l'utilisateur via `http://localhost:3000`
(forwarding automatique WSL2).

**Auth — bootstrap admin (10/08/2026)** : l'utilisateur signalait des 401 systématiques au premier
lancement. Diagnostic : `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` absents de `.env`, donc
aucun compte créé au démarrage (`main.py::_bootstrap_admin`, cf. CLAUDE.md). Ajoutés (identifiants
provisoires forts, à retirer après première connexion comme documenté) — mais un compte admin réel
existait déjà en base (`yhortholary@eurofeu.fr`, créé le 30/07), donc le bootstrap ne s'est jamais
déclenché : aucune régression, juste un correctif inerte laissé en `.env` pour un futur redéploiement
à partir d'une base vide.

**Limite de commande WinRM — 3e dépassement, corrigé durablement cette fois (10/08/2026)** : ajout de
checks de durcissement (§ ci-dessous) sur `_build_compliance_windows`/`asset_scanner.py` → script
PowerShell du scan Windows repassé au-dessus de la limite d'~8191 caractères encodés (`La ligne de
commande est trop longue`), déjà vu et "corrigé" par compaction le 27/07 et le 03/08. Cette fois,
scindé en **deux appels WinRM séparés** (`ps_script` inventaire existant, `ps_compliance_script`
nouveau) au lieu de recompacter un seul script — chacun garde désormais sa propre marge (inventaire :
7240/8191, 951 de marge ; conformité : 3000/8191, 5191 de marge) au lieu des 143 caractères de marge
qui restaient avant ce correctif. Découvert en marge d'une demande utilisateur de checks SMB
(signature serveur/client, sessions anonymes, invité non sécurisé, chiffrement) puis LLMNR/WDigest/
NTLM (LmCompatibilityLevel) — tous ajoutés à `ps_compliance_script`, consolidation des lectures de
registre redondantes au passage (`LanmanServer\Parameters`/`LanmanWorkstation\Parameters`/`Control\Lsa`
lus une fois chacun via `$lm`/`$lw`/`$lsa` plutôt que par clé). Équivalent Linux ajouté à
`_build_compliance_linux` : `ssh_weak_algos` (KexAlgorithms/Ciphers/MACs cassés ou dépréciés — SHA1,
RC4, CBC, MD5, MAC tronqués — via `sshd -T`, déjà exécuté pour les checks root/mot de passe).

**Cycle patch check — suivi par actif + reprise automatique après coupure (10/08/2026)** : trois
correctifs successifs sur la même fonctionnalité, dans l'ordre où l'utilisateur les a repérés en
observant le Dashboard en direct.
1. Suivi par actif : `_asset_progress` (liste ordonnée `{asset_id, asset_name, hostname, checked,
   total}`, `services/patch_checker.py`) + `_cycle_started_at`, exposés par `GET
   /api/patch-check/status` (`assets`, `started_at`). Permet d'afficher côté Dashboard quels actifs
   sont déjà traités/en cours/pas encore atteints, pas seulement le dernier en cours
   (`_current_check` existant). Total par actif via une requête groupée (`GROUP BY asset_id`), pas une
   par actif.
2. ⚠️ **Bug réel trouvé par l'utilisateur immédiatement après** : les actifs pas encore atteints par
   le cycle séquentiel affichaient leur UUID brut au lieu de leur nom — `asset_name`/`hostname`
   n'étaient renseignés qu'au moment où la boucle atteignait chaque actif. Corrigé : les noms de
   *tous* les actifs du cycle sont résolus d'un coup au démarrage (une requête `Asset.id IN (...)`),
   pas au fil de l'eau.
3. **Reprise automatique après coupure** : le cycle vit en mémoire dans le process FastAPI
   (`_current_check` et consorts) — tuable par n'importe quel redémarrage backend, `--reload` en dev
   inclus (vécu en direct : 7 rechargements pendant cette seule session ont coupé le cycle en cours
   à chaque fois). Le mécanisme de reprise existait déjà (`main.py::_startup_patch_check`, relance le
   cycle à chaque démarrage, skip ce qui a déjà un `last_patch_check` récent) mais était désactivé
   (`STARTUP_PATCH_CHECK=false`). Activé — vérifié en conditions réelles : 41 vulns recontrôlées dans
   la minute suivant un redémarrage, sans action manuelle. Compromis assumé et communiqué à
   l'utilisateur : un cycle repart aussi après un redémarrage sans rapport (ex. une session de dev
   intensive sur le backend) — à repasser à `false` temporairement si ça devient gênant en train de
   coder.

**Dashboard — refonte du bloc "Analyse en cours" (10/08/2026, plusieurs itérations successives)** :
- Barre de progression : pourcentage explicite, dégradé + rayures animées (`.progress-bar-shimmer`,
  `index.css`, respecte `prefers-reduced-motion`) au lieu d'un aplat statique.
- ETA : calculé sur le rythme réel (`checked / temps écoulé`), seuil minimum 3 vérifications + 5s
  pour éviter une estimation délirante en tout début de cycle. Horodatage de départ pris côté
  **serveur** (`_cycle_started_at`) plutôt que dans un ref local React — un simple rechargement de
  page ne doit pas faire perdre le point de départ utilisé pour l'estimation.
- Cartes par actif : icône de statut (✓ vert / spinner bleu / point grisé), mini-barre de
  progression individuelle, OS + espace disque restant par disque (croisé avec `assetList` déjà
  chargé côté Dashboard, aucun appel réseau de plus) — texte du nom qui passe au vert une fois
  l'actif terminé (restait bleu par héritage de couleur avant correctif).
- Couleur d'ensemble du bloc repassée de violet à bleu (demande explicite) — `#a371f7`/
  `rgba(163,113,247,*)` → `#58a6ff`/`#1f6feb`/`rgba(88,166,255,*)`, scopé au seul bloc "Analyse en
  cours" (le violet reste la couleur du bouton "Patch check"/des faux positifs ailleurs sur la page).
- **Notification de fin d'actif** : toast (`pushToast`, `ToastStack.jsx`) déclenché quand un actif du
  cycle passe à `checked >= total` — nom de l'actif, nombre de bascules automatiques survenues
  pendant son contrôle (compté via `done.auto_patched` sur les événements `last_completed`, par actif,
  remis à zéro après notification), CVE ouvertes restantes par sévérité (calculé côté client depuis
  `openVulns` déjà chargé, filtré par `asset.id`). Rien ne se déclenche pour les actifs déjà terminés
  au moment où la page est ouverte — seuls ceux qui terminent pendant que le Dashboard est affiché
  notifient, sinon rouvrir la page mi-cycle spammerait un toast par actif déjà fini.

**Perf/robustesse — deux gels d'event loop trouvés et corrigés (10/08/2026)** :
- `GET /vulnerabilities/false-positive-candidates` : le plus lourd des 3 endpoints "candidats"
  (~7,5s après les optimisations du 28/07 pour le cas non scopé, désormais ~9,3s vu le parc élargi à
  481 actifs). Mémoïsé en cache process (dict + `time.time()`, même schéma que
  `services/ip_watch.py`, TTL 5 min, clé `(asset_id, configured_only)`), invalidé après tout
  `bulk_false_positive` réussi pour qu'un lot qu'on vient de qualifier ne réapparaisse pas comme
  "encore candidat". Mesuré en conditions réelles : 9,3s → 57ms sur cache hit, ~160x.
- `run_cpe_matching`/`run_cpe_matching_for_asset` (`services/cpe_matcher.py`) : `select(CVE)` chargeait
  `raw_data` (JSON NVD brut, 377 Mo en base) pour ~187 000 lignes à chaque clic sur "Matching CVE" —
  même bug déjà identifié et corrigé sur les endpoints "candidats" le 28/07, jamais appliqué ici.
  Plus grave : la double boucle actif × CVE (jusqu'à 72 × 186 791 ≈ 13,4M itérations Python pur) ne
  cédait jamais la main à l'event loop asyncio — gelait tout le backend pour tous les autres
  utilisateurs pendant toute la durée du calcul. Corrigé : `load_only(..., raiseload=True)` sur les
  seules colonnes utilisées (`id`, `cpe`, `description`, `cvss_score`, `epss_score`) +
  `asyncio.sleep(0)` tous les `MATCHING_YIELD_EVERY` (200) tours de boucle. Vérifié en conditions
  réelles : `/api/health` répond en 16ms pendant qu'un `run_cpe_matching` tourne encore en tâche de
  fond (avant correctif, aurait été bloqué jusqu'à la fin du calcul).

**Qualification groupée — justification automatique par CVE/actif (10/08/2026)** : demande explicite,
répétée sur `/bulk-validate` (CRITICAL, § existant depuis avant cette session) puis
`/bulk-false-positive`. Avant : soit un texte libre unique appliqué à toute la sélection, soit un
gabarit générique par motif — dans les deux cas, la même phrase pour toutes les vulns du lot même
sur des actifs/CVE différents. Maintenant, calculé côté serveur pour CHAQUE vuln individuellement :
- `bulk-validate` : reprend `patch_check_result.details` (le rapport technique déjà produit par le
  patch check pour cette CVE précise — paquet installé, version comparée, correctif de référence),
  préfixé par l'actif (`[actif] détail`) ; repli sur un texte générique si le patch check n'a produit
  aucun détail exploitable.
- `bulk-false-positive` : reprend le motif déjà calculé par `false-positive-candidates`
  (`matching_invalide` vs `produit_absent`), avec le détail exact (`not_applicable_reason` le cas
  échéant), même préfixe par actif.
- Les deux endpoints ne prennent plus de `notes` en paramètre — seul `validated_by` reste manuel.
  Vérifié en conditions réelles pour bulk-false-positive : 130 vulnérabilités qualifiées par
  l'utilisateur en 10 lots, `validated_by`/justification par actif corrects en base.
- Frontend : `BulkValidateModal.jsx` et `BulkQualifyModal.jsx` (partagé faux positifs/en attente de
  correctif/risque accepté) envoient désormais la sélection par lots de 20 avec barre de progression
  (au lieu d'un seul appel géant) — `BulkQualifyModal` gagne un mode `autoJustification` (actif
  uniquement pour les faux positifs ; en attente de correctif et risque accepté gardent leur
  justification manuelle, cette dernière restant un jugement humain non automatisable).

**Frontend — filtres et mise en page (10/08/2026)** :
- Filtre "configurés/non configurés" (3 états, remplace une case à cocher) sur **Actifs et
  Inventaire** — util partagé `utils/assetCategory.js` (`merakiModelLabel`/`assetCategory`/
  `categoryStyle`, dupliqués avant dans Assets.jsx seul) pour que les deux pages restent alignées.
  Actifs gagne en plus une sélection multiple (case par ligne + "tout sélectionner" scopé aux lignes
  filtrées) et un scan groupé séquentiel sur la sélection.
- Badges Catégorie/OS/Source (Actifs) : `whitespace-nowrap` ajouté — un badge dont le texte passait
  sur 2 lignes (ex. "Équipement réseau") cassait le rendu (fond/bordure fragmentés, coins carrés au
  milieu, propre au rendu `inline` d'un span multi-lignes).
- Vulnérabilités : les 4 boutons de qualification groupée (en attente / faux positifs / CRITICAL /
  risque accepté) étaient mélangés au titre et au sélecteur d'actif dans la même ligne
  `justify-between`, d'où un rendu en vrac signalé par l'utilisateur — séparés en deux lignes
  (en-tête, puis barre d'actions dédiée). Couleurs : faux positifs → violet (`#a371f7`, déjà la
  couleur par défaut de la modale), risque accepté → jaune/or (`#e3b341`, couleur déjà utilisée pour
  le module Documentation) — remplacent un gris uniforme qui ne distinguait pas les actions.

#### 11/08/2026 — Identité visuelle, bug bandeau, tour visuel, rebranding Allsafe, intégration GLPI

**Session précédente : 11/08/2026** — trois sujets sans lien entre eux, tous à la demande explicite
de l'utilisateur (le 3e, "tour complet de l'appli", résumé en tête, détail en fin d'entrée du jour
— § Tour complet 11/08/2026) :
- **Refonte de l'identité visuelle** (jugée "trop générique, comme un site fait par l'IA") : logo/
  wordmark, tokens de marque centralisés (`--brand-grad`, `--font-mono`), liseré actif sur la sidebar,
  trame de points sur le hero. **Puis**, sur demande de suite immédiate, animations "bien visibles et
  qualitatives" sur Login et l'écran "Bienvenue Boss" (overshoot, ping radar, balayage sur le
  wordmark, tremblement d'erreur) — scopées à ces deux écrans rares (skill emil-design-eng § fréquence)
  pour ne pas alourdir Home.jsx, visité en boucle. Détail complet dans `docs/FRONTEND.md` § Identité
  de marque + delight Login/Bienvenue Boss.
- **Bug réel signalé par l'utilisateur, corrigé** : le bandeau "Analyse en cours" du Dashboard restait
  affiché en permanence, y compris hors cycle, à chaque rechargement de page. Cause : le frontend
  déduisait l'activité d'un cycle depuis `pending > 0` (simple backlog de vulns à revérifier, quasi
  toujours non nul sur un vrai parc) plutôt que depuis l'état réel du cycle
  (`is_patch_check_cycle_running()`, existait côté backend mais n'était jamais exposé par `GET
  /api/patch-check/status`). Cf. § dédiée ci-dessous.
- **Suite, même jour** : animation de déconnexion (`LogoutOverlay.jsx`, nouveau — pendant du
  `WelcomeOverlay` côté sortie, cf. `docs/FRONTEND.md`) ; logo simplifié (bouclier imbriqué retiré, le
  glyphe terminal `> ▬` porté seul et agrandi — retour utilisateur "regarde surtout le logo", le
  premier jet restait chargé/flou aux tailles réellement utilisées) ; **tour visuel de toute
  l'application** (demande explicite, agent Explore dédié, 19 pages lues) — 6 corrections concrètes
  appliquées (couleurs hors-hue Incidents/Crises, `StatusBadge` désaligné de ses voisins, bleu
  d'action `#1f6feb` centralisé — trouvé dans 8 endroits par l'agent **et 6 de plus en vérifiant**,
  soit 14 au total, 2 volontairement laissés en dur car dans un document HTML autonome d'export PDF —
  hover manquant sur 3 tableaux, carte Documentation sans `.lift-card`). Point plus structurant laissé
  en attente d'arbitrage utilisateur, **tranché dans la foulée** ("oui, reteindre") : plusieurs pages
  plus anciennes (Vulnérabilités, Actifs, CVE, Veille, Inventaire, Rapports) n'utilisaient jamais la
  couleur de leur module (`MODULES`, cf. `constants/modules.js`) contrairement aux pages plus
  récentes (Incidents, Audits, Documentation) qui la reprennent sur leur CTA/hover. Fait : nouveau
  champ `MODULES.xxx.dark` (texte sur CTA plein, centralise une valeur déjà en dur x5 par endroits) ;
  `Vulnerabilities.jsx`/`CVEs.jsx` reteintés **au survol de ligne seulement** (pas les boutons — le
  rouge CyberVuln sert déjà de code "sévérité", risque de confusion action/danger) ; `Assets.jsx` CTA
  + hover, `Inventaire.jsx` hover seul (pas de CTA coloré sur cette page) ; `Watch.jsx` (le hover
  était déjà la bonne teinte par coïncidence de valeurs RGB, seul le bouton `Btn primary` a changé) ;
  `Reports.jsx`/`RapportVeille.jsx`/`RapportSurveillance.jsx` via un seul correctif dans le composant
  partagé `WeeklyArchives.jsx` (déjà largement violet, juste le survol au repos manquait). Détail
  complet dans `docs/FRONTEND.md` § Tour visuel (11/08/2026).
- **Suite, même jour, sur logo fourni par l'utilisateur** (`Logo.png`, bouclier+cadenas+empreinte
  digitale sur maillage réseau bleu/vert) : glyphe repris en 3e itération — bouclier + cadenas en
  violet, sans le maillage/empreinte (ne survivent pas à 24-40px, même leçon que l'itération
  précédente). `favicon.svg` régénéré. Cascade d'entrée de Home.jsx resserrée en deux temps
  distincts (`TILE_BASE_DELAY` 260ms → 520ms) — logo/titre d'abord, tuiles ensuite, plutôt que les
  deux vagues qui se chevauchaient.
- **Nouvelle session, même sujet — 4e itération du logo** : retour utilisateur, veut *plus* de la
  référence (empreinte + réseau réintégrés *dans* le cadenas) et une 2e palette noir + jaune à la
  place du violet. **Outillage trouvé en cours de route** : `@resvg/resvg-js` (npm, binaire Rust
  autonome) installé dans le scratchpad pour rendre le SVG en PNG et vérifier visuellement avant de
  livrer — chose qu'aucune des 3 itérations précédentes n'avait pu faire (pas de navigateur
  utilisable dans ce sandbox, cf. tentatives Playwright/chromium-cli documentées plus haut dans la
  session). A immédiatement payé : le premier jet empreinte+réseau ne ressemblait à rien à l'écran
  (bug de paramétrage d'arcs SVG, invisible sans rendu) — corrigé après inspection réelle, vérifié
  lisible à 24/32/36/40/56px avant intégration. Palette : nouveaux tokens séparés
  `--brand-icon`/`--brand-grad`/`--brand-glow` (toujours noir+jaune vif, tuile de logo indépendante
  du thème) vs `--brand`/`--brand-text-grad` (texte sur fond de page, variante `[data-theme="light"]`
  en or plus sombre — un jaune vif en texte sur fond blanc n'a pas un contraste suffisant, problème
  connu). Bug latent trouvé au passage : `.brand-text-shimmer`/`.welcome-title` gardaient un stop de
  dégradé violet codé en dur (`#c4b5fd`) resté invisible depuis le tout premier changement de
  palette — jamais remarqué faute de rendu réel. Détail complet dans `docs/FRONTEND.md` § Identité
  de marque + delight Login/Bienvenue Boss, "4e itération".
- **5e itération, tout de suite après** : la 4e rejetée quand même ("ça ne ressemble à rien") —
  le rendu avait été regardé mais surtout zoomé à 400px, pas assez aux vraies tailles, et jugé par
  son propre auteur. 3 pistes plus simples rendues et montrées ; l'utilisateur a préféré fournir
  directement un SVG source (silhouette capuche/masque "hacker anonyme", rangé depuis à
  `docs/assets/logo-source.svg`) plutôt que
  choisir parmi elles. Repris tel quel, recoloré en jaune, viewBox natif conservé (`0 0 512`, pas
  remis à l'échelle 24 comme avant) — une seule grande silhouette pleine, beaucoup plus lisible à
  petite taille que les 2 tentatives précédentes. Connotation *hacker/attaquant* plutôt que
  *défense* signalée à l'utilisateur en livrant, pas bloquant. `favicon.svg` régénéré (rangé depuis
  à `docs/assets/logo-source.svg`, plus à la racine). Suivi de deux petits ajustements Home.jsx
  (retrait du libellé "on-premise", non redemandé ailleurs) et Dashboard.jsx (colonne
  "corrigées/total" débordant sur HIGH — `min-w-*`/`tabular-nums` au lieu d'une largeur fixe).
- **Puis, même jour, bug réel signalé** ("je ne reçois pas la notification quand une analyse est
  terminée, avant j'avais l'info... je voudrais le même système que pour les CVE") : la notification
  toast "actif terminé" avait une garde (`firstPollRef`) absente de son équivalent CVE — un actif qui
  terminait pendant que l'onglet Dashboard était fermé/rechargé était marqué silencieusement "déjà
  notifié" sans que le toast n'ait jamais été affiché. Retirée — même logique de dédoublonnage que
  la notification CVE désormais (clé déjà vue, jamais de garde "premier poll"). Vérifiée par rejeu de
  la logique réelle de `poll()` en Node (pas de navigateur disponible), contre le scénario exact du
  bug — confirmé corrigé.
- **Puis, même jour, suite demandée** : le panneau 🔔 renommé "Bascules automatiques" → "Notifications"
  (titre, tooltip, message vide) — cohérent avec le fait qu'il sert déjà aux deux, cf. docstring
  backend déjà à jour depuis le 22/07. Utilisateur : "c'est ce que je veux" en confirmation d'inclure
  aussi les complétions d'actif dans ce panneau, pas juste le renommage. Fait : nouvelle table
  `patch_check_asset_completions` (`models.py`, pas de FK sur `asset_id` — snapshot texte
  `asset_name`/`hostname`, survit à la suppression de l'actif), écrite par
  `services/patch_checker.py::record_asset_completion` à la fin de la passe de CHAQUE actif (pas
  juste à la fin du cycle entier) ; nouvel endpoint `GET /api/patch-check/asset-completions` — **séparé**
  de `/vulnerabilities/auto-bascule-summary`, pas fusionné dedans : ce dernier alimente aussi le
  bandeau "depuis votre dernière visite" et le récap `WelcomeOverlay`, tous deux déjà écrits pour un
  format CVE, y mélanger un autre format les aurait cassés. Fusion faite **côté frontend**
  uniquement, dans `NotificationHistory` (Dashboard.jsx) : les deux endpoints interrogés en
  parallèle, résultats triés par date et affichés avec une icône distincte par type.
  ⚠️ **Incident réel pendant l'implémentation** : nouvelle table ajoutée à `models.py` avant d'être
  créée en base — au rechargement du backend (`--reload`, déclenché par cet edit), `create_all`
  (tourne sous `cbr_app`, rôle sans droit DDL, cf. `ddl_guard.sql`) a tenté de la créer, bloqué et
  journalisé par le garde-fou, et **l'exception n'était pas rattrapée** : `Application startup
  failed. Exiting.` — le backend est resté "unhealthy" jusqu'à un redémarrage manuel. Chronologie à
  respecter la prochaine fois : `schema_patches.sql` (rôle superuser `cybervuln`) **avant** tout
  edit de `models.py` qui ajoute une table, jamais après. `worker`/`beat` redémarrés aussi dans la
  foulée (Celery ne recharge pas à chaud comme `--reload`, restaient sur l'ancien code de
  `patch_checker.py` — le cycle planifié tourne dans `worker`, pas dans le process `backend`).

**Tour complet de l'application (11/08/2026, même session, demande explicite : "voir si on peut
améliorer des choses ou des corrections à faire")** — deux agents Explore lancés en parallèle
(backend : garde-fous CLAUDE.md, concurrence, N+1/perf, erreurs silencieuses ; frontend : bugs
fonctionnels, hors du tour visuel déjà fait plus tôt dans la session), 9 points retenus au total,
tous vérifiés en lisant le code exact avant correction :

- **[CRITIQUE] `Assets.jsx` — colonne "Vulnérabilités ouvertes" fausse pour la quasi-totalité du
  parc** : recalculée côté client depuis une liste plafonnée à 200 lignes triée par score sur *tout
  le parc* (`fetchVulns({status:'open', per_page:200})`) — seuls les actifs dont les CVE figuraient
  dans ce top 200 global avaient un compte juste. Corrigé : nouveau champ `open_vuln_count`
  (`routers/assets.py::list_assets`, une requête groupée server-side sur tout le parc, même principe
  que `vuln_count` déjà présent mais tous statuts confondus — gardé tel quel, utilisé par la modale
  de suppression). Vérifié en conditions réelles : TSTUDIO passe de (probablement) quasi 0 affiché à
  4749, son vrai total. `vulnCounts`/le second appel `fetchVulns` retirés d'Assets.jsx (imports
  `fetchVulns`/`anonymizeVuln`/`FAKE_VULNERABILITIES` devenus morts, supprimés).
- **[Sécurité] Injection de formule CSV non fermée sur le nom d'actif** : `csv_safe()` (déjà posée
  après `audit/AUDIT_SECURITE.md #7`) protégeait `notes`/`validated_by`/`title`/`reported_by` dans les
  exports CSV Rapports/Incidents mais pas `Asset.name`/`os`/`os_version`/`asset_type` — modifiables
  par tout compte `analyst` via `PUT /api/assets`. Corrigé dans `routers/reports.py` (export backlog)
  et `routers/incidents.py` (export auditeur, colonne "Actifs concernés").
- **`AdministrationSecurity.jsx` — erreurs réseau avalées sur Connexions IP et Base de données
  (détection d'intrusion par leurres)** : même incident déjà vécu et corrigé sur `ServicesTab`
  (31/07/2026, "l'utilisateur a cru avoir perdu ses données") jamais appliqué à ces deux onglets
  écrits à la main. Bannière d'erreur ajoutée aux deux, même gabarit que `ServicesTab`.
- **Acquittement d'alerte de sécurité toujours attribué à "Administration"** au lieu de l'admin
  réellement connecté (`DatabaseTab` n'appelait jamais `useAuth()`, contrairement à `UsersTab` du
  même fichier) — perdait la piste d'audit de qui avait traité quoi entre plusieurs admins. Corrigé :
  `ack_by = user?.full_name || 'Administration'`.
- **Badge "MAJ dispo" figé après un rescan réussi** (`Assets.jsx` + `Inventaire.jsx`, scan unitaire
  et groupé) : seuls `package_count`/`hardware`/`last_scan` étaient reportés dans la liste affichée
  après un scan, jamais `available_updates_count` — recalculé maintenant depuis `data.packages`
  (même formule que `routers/assets.py::_asset_dict`).
- **`WeeklyArchives.jsx` (Rapports) — échec de chargement des archives hebdomadaires avalé
  silencieusement** — composant partagé Reports/RapportVeille/RapportSurveillance, dont la vocation
  assumée est de servir de preuve opposable à un auditeur NIS 2. Bannière d'erreur ajoutée, même
  `error` state déjà utilisé par les autres actions du composant.
- **Filtre "Actifs" du Dashboard — "Tout décocher" ne marchait pas, sélectionner un seul actif
  demandait de tout décocher à la main** (signalé par l'utilisateur en cours de route, avant même la
  confirmation de s'attaquer aux 2 points backend ci-dessous) : `AssetDropdown` affichait
  `effectiveAssetIds` (choix du 07/08/2026, délibéré à l'époque où 3 actifs seulement étaient
  "configurés") au lieu de `selectedAssetIds` — précochait tous les actifs configurés par défaut,
  devenu ingérable à l'échelle actuelle du parc (centaines d'actifs). Repassé à `selectedAssetIds`
  brut ; le libellé du bouton ("Tous les actifs" quand rien n'est explicitement coché) reste
  suffisant pour signaler le périmètre par défaut.
- **`recalculate_all_scores` (`POST /api/sync/rescore`) — même anti-pattern que l'incident mémoire
  déjà corrigé sur `patch_checker.py`/`cpe_matcher.py`**, jamais appliqué à cet endpoint : requête non
  paginée sur tout le parc, `CVE.raw_data` (377 Mo en base) chargé une fois PAR VULNÉRABILITÉ
  rattachée à chaque CVE (pas une fois par CVE) — pire que l'incident d'origine sur ce point précis.
  Corrigé : pagination par lot (keyset sur `Vulnerability.id`, `_RESCORE_BATCH_SIZE=2000`) +
  `load_only(raiseload=True)` sur les 3 entités + `asyncio.sleep(0)` périodique.
  `recalculate_scores_for_asset`/`_for_cve` (gravité moindre, naturellement bornés) reçoivent le même
  `load_only` par cohérence. Vérifié en conditions réelles : `POST /api/sync/rescore` traite
  118 606 lignes en ~11s sans erreur.
- **Cycle de patch check — une relance en cours de cycle perdait le périmètre qui l'avait demandée**
  (le plus proche des garde-fous CLAUDE.md parmi les 9 points, sans en être une violation directe) :
  `_rerun_requested` était un simple booléen, sans mémoire du périmètre associé — un scan qui
  déclenche un recheck scopé à un seul actif pile au moment où le cycle périodique Celery
  (`refresh_configured=True`, tout le parc) tombe dans la même fenêtre faisait rejouer uniquement
  l'actif unique à la relance, jamais le balayage complet attendu, avec `_set_cycle_state("completed")`
  écrit quand même — le dashboard affichait un cycle "réussi" sans avoir couvert le périmètre demandé.
  Corrigé : `_rerun_requested` devient un dict mémorisant le périmètre effectivement demandé, fusionné
  entre plusieurs demandes concurrentes (`refresh_configured=True` l'emporte dès qu'une des demandes
  en attente le veut, sinon les `asset_ids` explicites sont réunis). Vérifié par un test direct contre
  le vrai code (`docker compose exec backend python3 -c "..."`, appel A scopé à un actif puis appel B
  `refresh_configured=True` pendant que A est "en cours" simulé) : la demande B prend bien le dessus.

**Détail complet des points visuels/UX déjà couverts par le tour précédent** (couleurs, hover,
alignement) : cf. `docs/FRONTEND.md` § Tour visuel (11/08/2026) — ce tour-ci ne les recouvre pas,
périmètre volontairement disjoint (fonctionnel/logique plutôt que visuel).

- **10e point, effet de bord signalé après coup (pas dans le tour initial), corrigé sur demande
  explicite ("vas-y")** : le `finally` de `run_startup_patch_checks` remettait
  `_current_check`/`_cycle_started_at`/`_asset_progress` à vide à **chaque passe**, pas seulement à la
  toute fin du cycle — cette fonction est rejouée à chaque itération de la boucle de relance enchaînée
  (§ point 9 ci-dessus, son unique appelant). Entre deux passes d'une relance, un poll `GET
  /api/patch-check/status` tombait sur `running: true` (au niveau `_cycle_running`) mais
  `assets: []`/`started_at: None` — flicker incohérent côté dashboard, pas un bug bloquant mais visible
  en usage réel avec des relances fréquentes. Corrigé : remise à zéro déplacée dans le `finally` de
  `run_full_patch_check_cycle` (son unique appelant), une seule fois, après la dernière passe.

**Rebranding CBR → Allsafe (11/08/2026, même session, demande explicite)** : renommage pur de
l'identité visible du produit — wordmark (Home/Login/sidebar), `<title>` HTML, tooltips et textes UI
qui nomment explicitement le produit (`AdministrationSecurity.jsx` § déception, `Bastion.jsx`,
`Audits.jsx`, `ConnectivityDot.jsx`, badges "MAJ dispo" Assets/Inventaire). Même principe déjà posé
pour "CyberVuln" (cf. CLAUDE.md § Rebranding) appliqué à "CBR" lui-même : identifiants internes
(`cybervuln` superuser DB, `cbr_app` rôle applicatif, `CbrMark.jsx`/`CbrLogoTile`, variables CSS
`--brand-*`), commentaires de code et **narration historique déjà écrite** (`docs/HISTORIQUE.md`,
entrées passées de ce fichier, `audit/AUDIT_SECURITE.md`, le titre littéral de l'audit déjà saisi en base
« Application CBR ») **non retouchés rétroactivement** — "CBR" y reste exact pour la période qu'ils
décrivent. CLAUDE.md/README.md/docs/ARCHITECTURE.md/AUDITS.md/FRONTEND.md/INCIDENTS.md/VEILLE.md/
ROADMAP_RNCP42335.md mis à jour intégralement (remplacement complet demandé explicitement par
l'utilisateur, docs de state courant plutôt que journal daté).

**Intégration GLPI, même jour, demande explicite** ("question utile de se connecter à GLPI comme
avec PRTG et Meraki") — troisième sonde externe après Meraki/PRTG, mais rôle différent : GLPI
n'alimente jamais `network_status` (ce n'est pas un outil de supervision réseau), il enrichit le
patrimoine des actifs déjà connus. **Scope tranché par l'utilisateur avant codage** : jamais de
création d'actif, contrairement à `import_new_assets` (Meraki/PRTG) — "je veux juste étoffer les
actifs déjà présents".
- **Préparatifs côté GLPI, faits en direct avec l'utilisateur** (pas de code) : activation de l'API
  REST (Configuration > Générale > API, désactivée par défaut — 1er test réel a échoué avec `{"ERROR",
  "API désactivée"}` avant activation), client API dédié "Allsafe" (App-Token, connexion loggée en
  "Journaux"), compte de service `svc-allsafe` avec profil lecture seule dédié, jeton personnel
  (User-Token) — **piège rencontré** : le champ User-Token n'est pas le mot de passe du compte, un
  jeton séparé généré sur sa fiche ; l'utilisateur a aussi tenté de se connecter en `svc-allsafe`
  pour le trouver, inutile (édition en admin suffit, un compte de service sans profil assigné refuse
  la connexion de toute façon). `GLPI_URL`/`GLPI_APP_TOKEN`/`GLPI_USER_TOKEN` ajoutés à `.env`/
  `.env.example` (après PRTG) ; première valeur d'URL fournie était celle de l'interface web
  (`index.php?noAUTO=1`), pas l'API — corrigée en `/apirest.php`. Connexion validée par
  `initSession`/`killSession` direct (`curl`) avant tout code.
- **Code écrit dans la foulée** ("on va le faire maintenant") : `services/glpi_client.py` (auth à
  deux jetons → Session-Token, pagination `Computer` par `range`, `expand_dropdowns=true` pour
  résoudre modèle/fabricant/localisation en texte sans appel séparé) ; `services/glpi_matcher.py`
  (rapprochement par `Computer.name` ↔ `Asset.hostname`/`Asset.name` normalisés, même schéma que
  `prtg_matcher.py` **sans** la branche `import_new_assets` — aucune création d'actif, jamais) ;
  `routers/glpi.py` (`POST /run`, `GET /status`) monté dans `main.py`. L'utilisateur assigné côté
  GLPI (`users_id`) volontairement pas repris (donnée nominative, pas de plomberie d'anonymisation
  mode Présentation pour ce module, contrairement à `OrganizationRole`).
- ⚠️ **Piège Docker rencontré en testant** : `docker compose restart backend` ne suffit pas à
  recharger de nouvelles variables ajoutées à `.env` (l'environnement du conteneur reste celui du
  dernier `up`/`create`) — `printenv | grep GLPI` vide dans le conteneur malgré `.env` à jour et
  `env_file: .env` dans `docker-compose.yml`. Il faut `docker compose up -d --force-recreate backend`
  (ou `down`+`up`). À retenir pour toute future variable ajoutée en cours de session.
- **Premier sync réel** : 1855 `Computer` GLPI récupérés, **1 seul actif Allsafe rapproché**
  (`Bcrafter`, une VM sans hostname renseigné — matché par `name` — enrichi avec succès : n° série
  VMware, modèle `VMware7,1`, fabricant `VMware, Inc.`, vérifié en base). Les 1854 autres sont très
  majoritairement des `PC-*`/`PORT-*` (postes utilisateurs/portables) — pas un bug de rapprochement,
  ce référentiel `Computer` de ce GLPI couvre le parc utilisateurs/helpdesk, pas le parc serveurs
  qu'Allsafe suit. **Question ouverte laissée à l'utilisateur** (pas de réponse à date) : les
  serveurs sont-ils inventoriés dans GLPI sous un autre type/nommage, ou GLPI ne sert-il chez eux
  qu'au parc utilisateurs ? Détermine si le rapprochement vaut la peine d'être creusé (ex. matcher
  aussi sur `serial`/IP plutôt que seulement `name`) ou si l'intégration reste à faible valeur telle
  quelle. Aucun affichage frontend ajouté (pas de bouton de déclenchement ni de section GLPI dans
  `PackagesModal`/Inventaire.jsx) — délibérément différé tant que le rapprochement reste quasi vide,
  même schéma manuel-only que Meraki/PRTG/WithSecure (déclenchement par `curl`, pas de bouton UI).

#### 12/08/2026 — Module Sécurité > Agents construit de bout en bout

**Session précédente : 12/08/2026** — module Sécurité > Agents construit de bout en bout (demande
explicite, cf. `docs/AGENTS.md` pour le détail complet) : agent Rust `allsafe-agent` pour postes
Windows/Linux, alternative de collecte au compte de service SSH/WinRM pour les postes qu'il atteint
mal (éteints, hors réseau, VPN) — jamais un remplacement des serveurs, choix par actif
(`Asset.collection_method`). Backend (modèles `Agent`/`AgentEnrollmentToken`, `require_agent`,
`routers/agents.py`, `apply_scan_result()` extrait et partagé avec le scan pull existant), frontend
(page `Agents.jsx`, colonne « Méthode » sur Actifs), binaire Rust (checks de durcissement Linux
**et** Windows, strict sur-ensemble du compte de service + checks propres à l'agent — BitLocker/LUKS,
comptes admin locaux, verrouillage d'écran, USB, journalisation PowerShell). Vérifié de bout en bout
en conditions réelles sur Linux (enrôlement + check-in réels, matching CPE déclenché, affiché sans
adaptation frontend) **et sur Windows** (`DEPLOYAPP`, serveur de production réel — cf. § plus bas,
via le stack de dev, pas besoin d'attendre une VM de prod pour ce premier test).
**Bug réel trouvé et corrigé en cours de route** : la modale de génération de jeton perdait son
état (retour à l'écran vierge) juste après affichage du jeton en clair — le rafraîchissement de la
liste des agents (`load()`, déclenché après création) retriggerait le garde `if (loading &&
agentList.length === 0) return <PageLoader />` de la page parente, démontant toute la page (donc la
modale) le temps du refetch. Corrigé en ne gatant le loader plein écran que sur le tout premier
chargement (`hasLoadedOnce`), pas sur chaque refresh.
**Suite, même jour** : renommage `cybervuln-agent` → `allsafe-agent` (nom produit, demande
explicite) ; empaquetage `.deb` (`cargo-deb`, vérifié — `dpkg-deb --contents`) et `.msi` (`wixl`,
alternative libre au WiX Toolset officiel qui est Windows-only/.NET — vérifié via `msiinfo`, fichier
`File`/`Directory` corrects). **Piège rencontré** : deux conteneurs Docker de build partageant le
même cache Cargo monté en bind (`.cargo-cache`) se sont bloqués mutuellement ~25 min sur un verrou
de fichier — `flock` peu fiable sur bind-mount WSL2/Docker Desktop, déjà une source de friction
documentée ailleurs dans ce fichier (incidents Docker Desktop). Résolu en tuant l'un des deux
conteneurs pour lever le verrou, puis en relançant les deux builds en séquentiel plutôt qu'en
parallèle — à refaire en séquentiel d'emblée la prochaine fois qu'un cache Cargo est partagé entre
conteneurs concurrents.
**Suite, test réel sur `DEPLOYAPP`** (Windows Server 2019 Datacenter, actif de production existant,
5011 CVE `patched`/22 `false_positive`/2 `awaiting_fix`) : jeton d'enrôlement généré et lié à l'actif
existant (pas de doublon créé). D'abord mis en pause faute de serveur de production joignable, puis
**relancé et réussi le jour même** — la stack de dev suffisait déjà (backend joignable depuis
`DEPLOYAPP` via le proxy Vite du frontend, port 3000, les deux sur le même réseau d'entreprise),
inutile d'attendre la VM de prod pour ce premier test. Installé via le `.msi`
(`msiexec /i ... /l*v` en ligne de commande — le double-clic direct ne montre presque rien, `.wxs`
sans UI définie), enrôlé et check-in lancés depuis une invite de commandes sur la machine elle-même.
**Résultat** : `collection_method` basculé `service_account` → `agent` sans recréer l'actif, 88
paquets détectés, 19 checks de durcissement remontés avec des données réelles — 3 findings concrets
sur ce serveur de production (pare-feu Windows désactivé, sessions SMB anonymes non restreintes,
stockage USB autorisé). **Aucune perte de travail sur les CVE déjà qualifiées** : les 5011/22/2
sont restés strictement inchangés après le check-in — le garde-fou des états terminaux (§1 CLAUDE.md)
a tenu en conditions réelles, pas seulement en théorie. Détail complet dans `docs/AGENTS.md` § Vérification.
**Préconisations matérielles fournies pour la future VM de production**, affinées en trois passes le
même jour : (1) premier jet trop généreux (16 cœurs/64 Go/1 To, pensé "large" sans tenir compte du
contexte) ; (2) recalibré après retour de l'utilisateur ("jamais mon entreprise pourra me donner ce
genre de serveur") une fois précisé qu'il s'agit d'une VM sur infra de virtualisation existante, pas
d'un serveur physique dédié — **8 vCPU / 32 Go / 500 Go SSD** ; (3) **doublé** (deux VM identiques,
pas une VM deux fois plus grosse) une fois précisé qu'une réplication avec bascule complète en cas de
panne est prévue. La réplication elle-même (PostgreSQL streaming, synchronisation des volumes
applicatifs, bascule manuelle ou automatique) **n'est pas construite** — `docker-compose.yml` n'a
aucune notion de primaire/secondaire aujourd'hui, provisionner la 2e VM ne suffit pas à elle seule.
**Suite immédiate, même jour** : contrainte 16 Go (au lieu de 32) évoquée par l'utilisateur — jouable
mais serré (les plafonds conteneurs actuels totalisent déjà 14 Go, quasi aucune marge hôte). Mitigation
documentée plutôt qu'un simple "ça devrait passer" : swap VM + `memswap_limit` Docker sur
`backend`/`worker` pour dégrader en performance sur un pic plutôt que planter (`OOMKilled`, déjà vécu
une fois en conditions réelles). Cf. `docs/ARCHITECTURE.md` § Prérequis matériels pour le détail
complet (specs par VM, réplication/bascule, mitigation 16 Go).
**Suite, même jour, restructuration demandée après avoir vu les 19 checks en vrai** ("on va sortir
la modal de durcissement conformité pour en faire un module à part dans Inventaire et les Agents on
va basculer le module dans Inventaire c'est plus cohérent") :
- **Nouvelle page `Durcissement.jsx`** (module Inventaire) — extraite de la modale « Résultat du
  scan » d'Actifs (choix confirmé par question : tableau d'actifs avec résumé ok/warn/indéterminé +
  détail au clic, même patron que Actifs/Inventaire, plutôt qu'un tableau plat tous-checks-confondus).
  Composant `ComplianceRow` extrait dans `components/ComplianceChecklist.jsx` (partagé, plus dupliqué
  dans Assets.jsx). **Aucun nouvel endpoint** — `GET /assets` portait déjà `last_scan_result.
  compliance`/`network_compliance` en entier pour chaque actif (confirmé par un agent Explore avant
  d'implémenter, ~2,5 Ko en moyenne par actif, sans commune mesure avec l'incident `cves.raw_data`
  377 Mo) — tout se recalcule côté client. Deep-link `?asset=<id>` depuis Actifs (le lien remplace la
  section retirée de la modale), même esprit que le bandeau de rattrapage CVE.
- **Module Agents déplacé de Sécurité vers Inventaire** — `Layout.jsx`, `constants/modules.js`,
  `constants/modulePages.js`, `access_control.py` (le vrai garde-fou serveur des droits d'accès
  analyste) tous mis à jour ensemble. Couleur de la page (`MODULE_COLOR`) basculée cyan Inventaire.
- **Suite immédiate** : logos OS réels (`OsLogo.jsx`, déjà utilisé sur Actifs/Inventaire) ajoutés à la
  colonne OS d'Agents.jsx, à la place du texte brut "windows"/"linux".
- 174 tests backend toujours au vert après le déplacement de `/agents` dans `access_control.py`.
  Vérifié en conditions réelles (Playwright) : page Durcissement, filtre "avec avertissements", modale
  de détail, nav restructurée, section retirée d'Assets.jsx + lien de remplacement, deep-link complet
  (clic sur Actifs → Durcissement avec la bonne modale déjà ouverte). Détail dans `docs/AGENTS.md`
  § Frontend.
- **Suite immédiate, même jour** : "quand je clique sur un cas j'ai des solutions et les commandes
  pour le faire" — chaque check devient cliquable (`ComplianceChecklist.jsx`), déplie une solution +
  des commandes copiables (nouveau `utils/hardeningRemediation.js`, 29 entrées Windows/Linux, mêmes
  chemins de registre que ceux lus par l'agent Rust). Même principe que `services/remediation.py`
  côté CVE : propose uniquement, jamais exécuté par Allsafe. Vérifié en conditions réelles sur les 19
  vrais checks de DEPLOYAPP (dont le pare-feu désactivé trouvé plus tôt).

#### 14/08/2026 — Refonte visuelle Paramètres/Veille/Notes + compte self-service + lenteurs Dashboard

**Session du 14/08/2026** — partie de la session à la demande "on va reprendre tout les
visuels du module paramètres", élargie en cours de route à Veille/Fuite de données/Notes, puis à des
fonctionnalités de compte self-service. Chronologie :
- **`components/PageHero.jsx` (nouveau)** — en-tête compact coloré par module (dégradé + icône + trame
  de points), extrait dès le 2e usage (Watch.jsx/FuiteDeDonnees.jsx) puis déployé par 5 agents en
  parallèle sur ~20 pages de contenu (une couleur par module, cf. `constants/modules.js`), en
  remplacement systématique de l'ancien en-tête `h1`+`p` plat. Réduit deux fois de taille sur retour
  utilisateur ("c'est un peu grand"), puis le titre recoloré en dégradé + police mono (`--font-mono`)
  sur retour "je trouve les titres banal" — et le compteur `(N)` retiré du composant ensuite ("pas
  besoin des chiffres à côté du titre"), touchant les 13 pages qui le passaient.
- **Veille technologique + Fuite de données — 3 passes successives sur la densité des tuiles KPI**,
  chacune en réponse à un retour utilisateur précis ("gros et chargé" → "réduit la taille... range-les
  horizontalement" → grille capée mais espace vide à droite sur Fuite de données avec seulement 3
  tuiles) : largeur plafonnée via `minmax(x, min(y, 1fr))` (s'étire pour remplir la ligne s'il y a peu
  de tuiles, sans jamais dépasser le plafond), puis rangée forcée en `flex nowrap` plutôt qu'un `grid`
  qui pouvait retomber à une tuile par ligne. Une couleur d'identité par KPI/stat (liseré gauche
  teinté + icône colorée) au lieu du gris/violet uniforme d'avant.
- **`Notes.jsx` — 3e itération de layout**, demande explicite de reproduire la logique de nav à icônes
  d'`AdministrationSecurity.jsx` (confirmée malgré les deux tentatives précédentes déjà rejetées le
  12/08 — cartes puis explorateur à deux volets bordés) : cette fois la nav elle-même reste sans
  bordure (fond teinté + liseré gauche), ce qui change la donne. Nav des thèmes à gauche + panneau des
  sujets à droite, sélection simple au lieu de l'accordéon multi-ouvert.
- **`Settings.jsx` retapé sur le même schéma que Notes.jsx** ("paramètre soit comme la page note sans
  les tuiles") — nav à icônes sans bordure + panneau unique, plus une carte par réglage. Deux pages
  oubliées dans le premier passage (Paramètres et Administration elles-mêmes n'avaient pas de
  `PageHero`) ajoutées après coup. `AdministrationSecurity.jsx` gagne au passage une nav réductible en
  icônes seules (bouton "Réduire", demande explicite séparée).
- **Bug réel trouvé en repassant sur Settings.jsx** : le sous-titre affichait encore "Configuration de
  CyberVuln" — reliquat du rebranding Allsafe du 11/08/2026, jamais retouché sur cette page précise.
  Corrigé ("Configuration d'Allsafe").
- **Gestion de son propre compte** (Settings.jsx > Compte, demande explicite "rajoute la possibilité de
  modifier son compte à côté de déconnecter") : changer son email et son mot de passe, mot de passe
  actuel requis dans les deux cas. **Politique de mot de passe renforcée** au passage (demande
  explicite) : `services/auth.py::validate_password_strength` centralise 16 caractères + majuscule +
  minuscule + chiffre + caractère spécial, avant dupliquée en deux endroits avec juste une longueur
  minimale. `components/PasswordStrengthHint.jsx` (nouveau) donne un indice de force en direct pendant
  la saisie, réutilisé aussi sur l'écran de changement de mot de passe forcé.
- **Deux idées supplémentaires proposées puis validées par l'utilisateur** ("1 et 2 pour l'instant") :
  **gérer ses propres sessions actives** (`GET`/`DELETE /api/auth/sessions`, pendant self-service du
  `revoke-sessions` admin déjà existant sur un *autre* compte) et **statut des intégrations externes**
  en lecture seule (`GET /api/integrations/status`, nouveau router — NVD/GitHub/AD/SSH/WithSecure/
  Meraki/PRTG/GLPI/vSphere, configuré/non configuré + dernière synchro, jamais un secret).
- **Nom d'analyste par défaut** (3e idée proposée, validée séparément) : préférence 100% client
  (`contexts/AnalystPreferenceContext.jsx`, `localStorage`, même patron que Theme/PresentationContext).
  Appliquée à `ValidateDropdown.jsx` (nom préféré remonté en tête + mis en avant, pas de valeur
  contrôlée à pré-remplir dans ce composant) et `AnnotationModal.jsx` (le `<select>` "Validé par" se
  pré-remplit, uniquement si `initialValidator` est vide — jamais sur une ré-édition d'une annotation
  déjà validée, seul `Dashboard.jsx` passant une valeur existante). Périmètre volontairement limité à
  ces deux composants sur les 21 qui consomment `useAnalysts()` dans l'app.
- Tout vérifié par compilation HMR (frontend) + reload (`--reload`, backend) sans erreur au fil de la
  session ; deux endpoints testés via `curl` (401 attendu sans cookie de session, confirme le montage).
  Détail technique complet (composants, endpoints, schémas) dans `docs/FRONTEND.md` §
  `PageHero.jsx` + refonte Paramètres/Veille/Fuite de données + self-service compte (14/08/2026)` et
  `docs/ARCHITECTURE.md` § Authentification.

**Suite de la même session, plus tard le même jour — lenteurs signalées par l'utilisateur** ("je reste
sur le site plus d'une heure et j'ai l'impression que les pages sont sans cesse rechargées dès que je
change de page, surtout le Dashboard") : diagnostic mené par un agent avec inspection **en direct**
des logs et conteneurs Docker déjà en cours d'exécution (pas seulement de la lecture de code), deux
causes confirmées avec preuve empirique, deux écartées :
- **Confirmé** — React Router démonte/remonte entièrement chaque page à chaque navigation (pas de
  cache de route, `<div key={location.pathname}>` autour de `<Outlet/>` dans `Layout.jsx`) : revenir
  sur `/dashboard` rejouait ~13 requêtes en rafale et l'écran de chargement plein écran à CHAQUE
  retour, pas seulement au premier chargement de la session — littéralement "le Dashboard se
  recharge dès que je change de page".
- **Confirmé par les logs backend en direct** — `DB_MAX_CONCURRENT_SESSIONS=5` (sémaphore partagé par
  les 162 routes de l'API) saturé par les rafales périodiques du Dashboard (8 requêtes/30s + 1/3s) :
  les 8 endpoints du bundle de 30s affichaient exactement le même compteur de requêtes sur 30 min de
  logs, confirmant qu'ils partent bien en rafale simultanée. Une navigation dont le premier fetch
  tombe pendant une de ces rafales fait la queue derrière — explique les lenteurs sur *d'autres*
  pages.
- **Écarté** — pas de fuite du sémaphore (`async with` relâche toujours le slot, y compris sur
  exception), pas de fuite d'intervalle/dépendance instable côté frontend (tous les `setInterval`
  trouvés sont proprement nettoyés avec des dépendances stables), pas de confusion avec le rechargement
  à chaud (HMR) du serveur de dev.
- **Corrigé** : `DB_MAX_CONCURRENT_SESSIONS` 5 → 15 (`.env`/`.env.example`/`backend/config.py`,
  conteneur backend recréé pour appliquer). Puis, sur demande explicite de creuser le rechargement du
  Dashboard ("oui, résoudre le rechargement complet") : convention de **cache module JS** (survit au
  démontage/remontage du composant, contrairement au state React) posée sur Dashboard.jsx, puis étendue
  par un audit dédié + 4 agents en parallèle à 11 pages de plus dont le fetch au montage était coûteux
  et gaté par un loader plein écran (`Notes.jsx`, `NoteSubject.jsx`, `Documentation.jsx`,
  `AuditDetail.jsx`, `Agents.jsx`, `Audits.jsx`, `Incidents.jsx`, `Crises.jsx`, `Assets.jsx`,
  `Inventaire.jsx`, `Durcissement.jsx`) — cf. `docs/FRONTEND.md` § Cache module par page pour le détail
  du patron et les règles suivies (map par id sur les pages à route dynamique, jamais de résultat
  filtré mis en cache, etc.).
  ⚠️ **Incident réel pendant l'implémentation, auto-corrigé** : un des agents a laissé passer une
  déclaration `isAnonymous` dupliquée dans `Durcissement.jsx` (erreur de compilation Vite), repérée et
  corrigée par l'agent lui-même avant la fin de sa tâche — confirmé sain en relisant le fichier final
  et les logs de compilation après coup, aucune intervention manuelle nécessaire.

#### 17/08/2026 — Reprise de dette technique (CVE frontend, note sur false-positive-candidates)

**Session précédente : 17/08/2026 (même date, partie antérieure)** — reprise de deux points de
dette identifiés en fin de session précédente (§ Dette identifiée ci-dessous) :
- **CVE `react-router-dom`/`esbuild-dev`, corrigées** : montée `react-router-dom` 6.30.4 → 7.18.2,
  `vite` 5.4.21 → 7.3.6, `@vitejs/plugin-react` 4.x → 5.2.0 (compatible vite 4-7, contrairement à la
  6.x qui n'accepte que vite 8). Vérifié avant de coder : aucune route splat (`path="*"` réduite à un
  redirect `/`, seul cas du projet), aucune navigation relative (`navigate('..')`/`to=".."`) — le
  changement de comportement par défaut des "future flags" v6→v7 (résolution relative dans les
  routes splat) ne concerne donc pas ce routeur, upgrade sans risque identifié. `npm audit` : 6
  vulnérabilités → 0 (react-router-dom, esbuild, vite corrigées par la montée majeure ; `dompurify`/
  `nanoid` en plus, patch mineur non lié). **Piège rencontré** : le premier rebuild d'image
  (`docker compose up -d --build frontend`) gardait Vite 5.4.21 au démarrage malgré `package.json`
  à jour — le volume anonyme `/app/node_modules` (posé pour survivre aux recréations de conteneur,
  cf. `docker-compose.yml`) avait persisté l'ancien `node_modules` par-dessus celui fraîchement
  installé dans l'image. Supprimé explicitesement (`docker volume rm`) avant de relancer le service
  pour forcer la reprise du contenu de l'image — à refaire à chaque futur changement de dépendance
  frontend, un simple `--build` ne suffit pas avec ce montage. Vérifié : conteneur sain (`Vite v7.3.6
  ready`), `npm run build` propre (827 modules), résolution runtime de `react-router-dom` confirmée
  via le bundle pré-optimisé de Vite (`/node_modules/.vite/deps/react-router-dom.js`, 200, aucune
  erreur de dépendance dans les logs). Pas de vérification navigateur (Playwright installé mais
  bibliothèques système du Chromium headless absentes, pas d'accès root pour les poser — même
  limite que les sessions précédentes).
- **`GET /false-positive-candidates` lent, faux problème — la note "Points ouverts" du 03/08/2026
  n'avait jamais été corrigée après les deux correctifs qui l'ont réglée entre-temps** (two-phase
  du 28/07, cache process du 08/08 — cf. entrées correspondantes ci-dessous) : mesuré en conditions
  réelles avec une session admin temporaire (créée en base, supprimée après coup) — **5,45s à froid,
  66ms à chaud** (TTL 5 min), loin des ~18s notés. Section "Points ouverts" et "Dette identifiée"
  corrigées en conséquence ci-dessous. Aucun code changé — juste la documentation remise en accord
  avec l'état réel, cf. leçon déjà tirée le 22/07/2026 sur ce même risque (une affirmation de
  blocage recopiée d'une session à l'autre sans revérification contre la base).

#### 17/08/2026 — Signaux d'exploitation active (KEV, Metasploit, CVSS-BTE)

**Session précédente : 17/08/2026 (même date, plus tôt)** — trois signaux d'exploitation ajoutés
(demande explicite, référence donnée par l'utilisateur : ce que fait Cyberwatch — "CVSS-B,
CVSS-BTE, EPSS, maturité d'exploit"). CVSS-B (`cvss_score`) et EPSS existaient déjà, seuls les
trois autres sont neufs :
- **KEV** (`services/kev_fetcher.py`) — catalogue CISA "Known Exploited Vulnerabilities", fait
  constaté (pas une prédiction comme l'EPSS). Source publique gratuite sans clé, export JSON
  régénéré au fil de l'eau. `cves.kev`/`kev_date_added`/`kev_ransomware`, sync quotidienne
  (Celery beat 3h45).
- **Maturité d'exploit** (`services/exploit_maturity_fetcher.py`) — présence dans le framework
  Metasploit (métadonnées publiques du dépôt, BSD-3-Clause), équivalent gratuit de la
  définition même de Cyberwatch ("rouge = présent dans Metasploit"). Read-only, aucun code
  d'exploitation téléchargé ni exécuté (cf. CLAUDE.md §1). `cves.msf_module`/`msf_best_rank`/
  `msf_module_count`, sync hebdomadaire (dimanche 5h45).
- Les deux : filtres `kev`/`msf_module` sur `GET /cves` et `GET /vulnerabilities` (index
  partiels), badge partagé `components/ExploitBadge.jsx` (CVEs.jsx + Vulnerabilities.jsx),
  statut affiché dans Paramètres > Intégrations, déclenchement manuel `POST /api/sync/kev` /
  `POST /api/sync/exploit-maturity`.
- **CVSS-BTE** (`services/cvss_bte.py`, nouveau) — score CVSS v3.1 Temporal+Environnemental
  réel, par `(CVE, actif)` contrairement à `cvss_score` (générique), porté par
  `Vulnerability.cvss_bte`/`cvss_bte_vector`. Coexiste avec `risk_score` (formule maison) sans
  le remplacer — calculé dans la même boucle que `scoring.py::recalculate_all_scores`/
  `_for_asset`/`_for_cve`, pas un second passage sur le parc. Calcul via la librairie pip
  `cvss` (Red Hat Product Security, LGPLv3+) plutôt qu'une réimplémentation main de l'arrondi
  CVSS v3.1 — source connue de bugs subtils. Périmètre limité à Temporal (E/RL/RC) +
  Environmental Requirements (CR/IR/AR), pas de Modified Base Metrics. Dérivation automatique :
  E depuis `kev`/`msf_module` (H/F/X), RL depuis `awaiting_fix*` (U/X), RC toujours C, CR/IR/AR
  depuis `asset.tags["criticite"]` (même dimension métier que `risk_score`, réutilisée sur les
  3 axes). `kev_fetcher.py`/`exploit_maturity_fetcher.py` déclenchent désormais un rescore en
  fin de sync (même schéma qu'`epss_fetcher.py`) puisque `E` en dépend directement. Exposé par
  l'API (`sort_by=cvss_bte`) sans colonne dédiée dans le tableau — même traitement que
  `risk_score`, qui n'en a pas non plus. Détail complet (dérivation, formule) dans
  `docs/MATCHING.md` § Exploitation active / § CVSS-BTE.
- **Vérification, conditions réelles (session coupée puis reprise le jour même, une fois Docker
  Desktop relancé par l'utilisateur)** : rebuild backend nécessaire (`cvss` absent de l'image
  existante) — `docker compose up -d --build backend`, démarrage propre. `compute_cvss_bte`
  testé en direct dans le conteneur sur un vecteur connu (Log4Shell) : `kev=True` → 10.0,
  `msf_module=True` → 9.7, `awaiting_fix` → RL:U correct, vecteur absent → `(None, None)` — mêmes
  résultats qu'en dehors de Docker. `recalculate_all_scores()` rejoué sur le vrai parc : 119 761
  vulnérabilités mises à jour ; vérifié en base — `cvss_bte` renseigné sur 119 761/122 558
  vulns ouvertes/en cours, les 2 797 restantes sont toutes des CVE en vecteur CVSS v2 (repli
  attendu, confirmé par requête dédiée). `POST /api/sync/kev` (1665 entrées CISA) et
  `POST /api/sync/exploit-maturity` (3147 CVE, 7138 modules Metasploit) déclenchés réellement
  via une session admin temporaire (créée en base, supprimée après coup, même procédé que le
  22/07) : 200 OK, `rescore` inclus dans la réponse. `GET /vulnerabilities?sort_by=cvss_bte` :
  200, tri appliqué. Suite `pytest` complète : **208 passés**, y compris
  `test_every_api_route_requires_auth_or_admin` — confirme que les deux nouveaux endpoints
  `/sync/kev`/`/sync/exploit-maturity` héritent bien de la protection du router comme prévu,
  sans dependency oubliée.
  ⚠️ **Piège rencontré, déjà documenté ailleurs dans ce fichier** : au redémarrage de Docker
  Desktop, le watcher `--reload` du backend a crashé une fois
  (`WatchfilesRustInternalError: Input/output error`, flakiness bind-mount WSL2/Docker Desktop
  déjà vue sur ce projet) — résolu par le rebuild qui était de toute façon nécessaire pour la
  dépendance `cvss`, pas d'action séparée requise.
- **Capture d'écran demandée par l'utilisateur pour voir le rendu réel** — occasion de repérer
  un trou de couverture : `ExploitBadge.jsx` n'était câblé que sur CVEs.jsx/Vulnerabilities.jsx,
  pas sur les 3 tableaux de qualification du Dashboard (CRITICAL à revalider, faux positifs,
  en attente de correctif) alors que `_vuln_dict()` renvoie déjà kev/msf_module dans `v.cve`
  pour ces 3 endpoints (`critical-review-candidates`/`false-positive-candidates`/
  `awaiting-fix-candidates`). Ajouté aux 3 (même schéma que les deux autres pages). Icône
  ajoutée au pill Metasploit sur demande explicite ("met le logo ou un icon pour métasploit") —
  1er jet : viseur générique en SVG inline (`TargetIcon`), signalé à l'utilisateur la réserve
  de marque (crâne Rapid7 déposé, produit positionné comme alternative commerciale à
  Cyberwatch cf. CLAUDE.md § Contexte). **Confirmé malgré la réserve** ("intègre le vrai
  logo") : remplacé par le tracé officiel via Simple Icons (`simple-icons/simple-icons`,
  licence CC0 — voie standard pour identifier un outil tiers dans une UI, badges "tech stack"
  GitHub/shields.io, pas une capture directe du brand kit Rapid7) — `MetasploitLogo`, même
  composant, juste le SVG interne remplacé.
  Vérifié par capture d'écran réelle (même procédé Playwright/Docker que ci-dessus) : CVE-2015-
  1635 (CRITICAL, 9.8) avec les deux pills — ⚠ KEV et le vrai logo Metasploit — côte à côte.
- **Suite immédiate, débordement signalé** ("dans le dashboard metasploit déborde de sévérité
  pour aller dans la colonne score") : les 3 tableaux du Dashboard sont plus étroits que
  Vulnerabilities.jsx/CVEs.jsx (colonne Sévérité 90px). Nouveau prop `compact` sur
  `ExploitBadge.jsx` — pill Metasploit réduite au logo seul, texte retiré, passé uniquement
  depuis les 3 call sites Dashboard (Vulnérabilités/CVE gardent le texte complet). Puis
  ("pareil pour KEV... qu'il soit pareil que metasploit pour être cohérant") : même traitement
  sur le pill KEV en mode `compact` — `⚠` seul, "KEV"/"Ransomware" retirés du texte visible
  (toujours dans le `title` au survol). Vérifié par capture réelle : les deux pills tiennent
  désormais dans la colonne Sévérité sans déborder sur Score.
- **Suite, alignement demandé** ("kev aligné à gauche de critical, pareil pour metasploit à
  droite, avec de l'espacement entre les deux") : 1er essai — pills KEV/Metasploit écartées via
  `justify-content: space-between` sur toute la largeur du conteneur (nouveau prop `spread`,
  parent passé en `flex-col w-full`) — **rejeté** ("pas comme ça, je préférais avant") : sans
  effet visible, le tableau (`table-layout` auto, pas de largeur de colonne fixée) dimensionne
  la colonne Sévérité exactement à la largeur du contenu le plus large (déjà KEV+Metasploit
  collés), donc aucun espace disponible à répartir — `spread` retiré entièrement (code mort).
  **Fait à la place** : logo Metasploit agrandi (`w-3 h-3` → `w-3.5 h-3.5`) + espacement fixe
  entre les deux pills porté à 10px — insuffisant ("je veux que les logos fassent la même
  taille et metasploit n'est pas aligné à droite de critical") : deux défauts distincts restaient.
  **Cause racine identifiée par mesure de bounding box réelle** (`page.locator(...).boundingBox()`,
  pas une estimation visuelle) : le pill KEV mesurait 26px de haut contre 20px pour Metasploit —
  l'emoji "⚠" (texte, métriques de police/line-height) ne peut jamais garantir la même taille
  qu'un SVG voisin, quel que soit le réglage de `width`/`height` tenté dessus. **Corrigé à la
  racine** : `KevIcon` (nouveau, heroicons `exclamation-triangle`, mêmes `viewBox`/dimensions que
  `MetasploitLogo`) remplace l'emoji partout, garantissant une taille strictement identique par
  construction (même mécanisme SVG des deux côtés) plutôt qu'un rapprochement au pixel près.
  **Alignement, 2e tentative, robuste cette fois** : `spread` réintroduit mais en `minWidth: 70`
  fixe sur le `<span>` d'`ExploitBadge` lui-même (~largeur du badge "CRITICAL", la plus large des
  4 sévérités) plutôt qu'un `width:'100%'` d'un parent — ce composant n'a alors plus besoin de
  connaître la largeur de son ancêtre (le point qui avait fait échouer la 1ère tentative), aucun
  changement necessaire sur les 5 wrappers `SeverityBadge`/`ExploitBadge` des pages. Vérifié par
  mesure réelle après coup : pills KEV/Metasploit strictement identiques (26×20px chacun),
  bord droit du pill Metasploit à 598px contre 592.8px pour CRITICAL sur le Dashboard (compact,
  écart de 5px = alignement visuel) — la page Vulnérabilités/CVE (texte complet) dépasse toujours
  au-delà de CRITICAL comme avant (le texte "Metasploit" est intrinsèquement plus large que 70px,
  comportement inchangé et jamais signalé comme un problème sur ces deux pages).
- **Ajustement, débordement résiduel signalé** ("le logo metasploit dépasse de critical") : les
  5px d'écart mesurés ci-dessus étaient dans le mauvais sens — `SPREAD_MIN_WIDTH` (70) dépassait
  légèrement la largeur réelle de "CRITICAL" (64.8px mesuré). Ramené à 63.
- **Signalé de nouveau, cette fois lié au zoom navigateur** ("il est aligné à critical [zoomé] et
  quand je dézoome il s'éloigne" + captures d'écran Critical.png/Critical2.png à l'appui) : `kev`
  restait parfait (confirmé par l'utilisateur, jamais retouché) mais `metasploit` dérivait —
  **cause racine trouvée en testant à plusieurs niveaux de zoom navigateur simulés**
  (`document.body.style.zoom`, pas juste un survol visuel) : le wrapper (`SeverityBadge` +
  `ExploitBadge`) était en `display: 'grid'`, un conteneur **block** par défaut — `width: auto`
  d'un bloc s'étire pour remplir tout le parent (`<td>`, dimensionné par le contenu le plus
  large de toute la colonne sur `table-layout` auto), pas seulement la largeur du badge de
  sévérité qu'il contient. À zoom=1 l'écart était minime par coïncidence (1.6px), mais à
  zoom=0.5 il montait à 57px — `SPREAD_MIN_WIDTH` n'y était pour rien, ce n'était jamais la
  bonne cause sur les 2 tentatives précédentes. **Corrigé** : `display: 'inline-grid'` au lieu de
  `'grid'` — conteneur en grille mais **inline** (se limite à son propre contenu, comme
  n'importe quel élément inline), donc systématiquement aussi large que `SeverityBadge` quelle
  que soit la sévérité, la largeur de la colonne du tableau ou le zoom.
  **Repensé au passage** : `spread` n'utilise plus de largeur calculée/partagée du tout —
  seul `Metasploit` passe en `position: absolute, right: 0, bottom: 0` (ancré au bord droit du
  wrapper, recalculé à chaque rendu), `KEV` reste dans le flux normal de la grille comme avant
  (n'y touche pas, conforme à la demande explicite). Un espaceur invisible (mêmes dimensions que
  le pill KEV) est rendu quand Metasploit est seul (sans KEV) en mode `spread`, pour que le
  conteneur ait quand même la hauteur nécessaire à l'ancrage `bottom: 0` — cas réel en base
  (CVE avec `msf_module=true` mais `kev=false`).
  **Revérifié à 5 niveaux de zoom** (`1, 0.8, 0.67, 1.25, 0.5`, mesure `boundingBox()` réelle,
  pas visuelle) : écart KEV/CRITICAL et Metasploit/CRITICAL strictement à **0.00px** aux 5
  niveaux — plus de dérive, cause racine réellement éliminée (pas un simple recalibrage de
  constante comme les 2 tentatives précédentes). Capture à zoom 67% confirmée visuellement
  alignée, identique au zoom 100%. Aucune erreur console sur Vulnérabilités/CVE/Dashboard après
  le changement de structure.

#### 17/08/2026 — Durcissement étoffé (OS EOL, sites web, icônes PRTG, correctifs UI)

**Session précédente : 17/08/2026 (même date, plus tôt)** — Durcissement étoffé (demande
explicite, citations d'une démo/présentation Cyberwatch : "un OS qui est obsolète, ça remontera
comme un défaut de sécurité", "si on scanne un site web et qu'il y a la possibilité de faire une
injection SQL ou
une attaque XSS... ce sera un défaut de sécurité", "une cinquantaine [de checks] dans la
bibliothèque"). Revue complète du backend avant de coder : 37 checks serveur (14 Linux/23
Windows via l'agent, sur-ensemble strict du compte de service) + 8 Cisco + 5 ESXi = déjà ~50
entrées dans `hardeningRemediation.js` — deux trous réels confirmés absents, pas plus :
- **Point sensible tranché avec l'utilisateur avant de coder** (AskUserQuestion) : détecter la
  *possibilité* d'injection SQL/XSS suppose d'envoyer des payloads de test — un scan actif,
  hors du principe de non-intervention (CLAUDE.md §1 ; `docs/AUDITS.md` exclut déjà
  explicitement sqlmap pour la même raison). **Choix acté : sous-ensemble passif seulement** —
  aucun test d'injection réel construit, noté comme piste future pour le module Audits.
- **Détection d'OS en fin de support** (`services/os_eol.py`, nouveau) — calculée à la volée
  depuis `Asset.os`/`os_version` déjà connus (`os_eol_check` dans `_asset_dict`), jamais stocké :
  reste exact même sans nouveau scan, un OS peut devenir obsolète simplement parce que le
  calendrier avance. `_EOL_TABLE` curatée à la main (Windows Server 2012→2022, Windows 10,
  Ubuntu/Debian/CentOS-RHEL LTS). **Bug réel trouvé et corrigé en vérifiant contre le vrai
  parc** : `Asset.os` est générique côté Windows ("Windows Server", sans année — l'année ne vit
  que dans `os_version`, cf. `_extract_windows_version`) — le 1er jet cherchait l'année dans
  `os` et ne matchait jamais rien en conditions réelles (1/442 actifs). Corrigé en croisant les
  deux champs : **40/442 actifs matchés, dont 21 Windows Server 2012 réellement en fin de
  support** (dépassé depuis 2023-10-10) — trouvaille concrète sur le vrai parc, pas un test
  synthétique.
- **Nouveau type d'actif "Site web" + checks passifs** (`services/web_hardening.py`, nouveau) —
  en-têtes de sécurité HTTP manquants (HSTS/CSP/X-Content-Type-Options/X-Frame-Options/
  Referrer-Policy), cookies sans Secure/HttpOnly, protocole TLS déprécié. Une requête GET
  normale + une négociation TLS standard, rien de plus. Suit exactement le précédent déjà en
  place pour `asset_type="network"` (colonne dédiée `Asset.web_compliance`/`Asset.url`, pas de
  scan SSH/WinRM — ces actifs n'ont ni l'un ni l'autre). `POST /api/assets/web-hardening/run`
  (déclenchement manuel, même précédent que `network-protocol-check`/`switch-hardening`).
  `Assets.jsx` : option "Site web" dans le formulaire, champ URL à la place de hostname/OS/SSH
  quand ce type est sélectionné.
  **Suite immédiate, demande explicite ("comment je teste ?")** : bouton "Lancer le scan web"
  ajouté sur Durcissement.jsx (barre de filtres) — les deux endpoints déjà existants
  (`network-protocol-check`/`switch-hardening`) n'en ont toujours pas (curl-only, inchangé),
  mais tester le nouveau check web sans passer par curl le justifiait ici (actif fraîchement
  créé, aucun autre moyen de le faire scanner depuis l'UI). `runWebHardeningCheck()` (nouveau,
  `api/client.js`), recharge la liste après coup, message de résultat (X vérifiés/Y avertissements).
  Nouvelle catégorie "Web" dans `ComplianceChecklist.jsx`/`hardeningRemediation.js` (7 entrées
  de remédiation, dont une avec exemple nginx). Vérifié en conditions réelles contre
  example.com (tous les en-têtes absents, TLS 1.3 ok) et github.com (en-têtes présents, mais un
  vrai cookie `_octo` sans HttpOnly détecté correctement) — puis bout en bout via un actif
  "Site web" créé/scanné/affiché dans Durcissement (capture d'écran réelle, catégorie "Web"
  dépliée avec la remédiation nginx), asset de test supprimé après coup.
- **Bonus mineur** : `_RISKY_PORTS` (`asset_scanner.py`) étendu (POP3/IMAP en clair, MSSQL/MySQL/
  VNC exposés) — même check `exposed_ports` existant, juste la liste élargie.
- `pytest` : 208 passés (inchangé), aucune régression. Schéma appliqué (`url`/`web_compliance`
  sur `assets`).
- **Bug réel introduit puis corrigé, signalé par l'utilisateur** ("le bouton 'actifs configurés
  uniquement' ne marche pas") : le filtre reposait sur `checks.length === 0` — un proxy indirect
  ("aucun check collecté") plutôt qu'un critère direct, cassé dès l'ajout d'`os_eol_check` (celui-
  ci apparaît dès qu'un OS est *déclaré*, même sans le moindre scan réel — un serveur jamais
  scanné se mettait donc à compter comme "configuré"). **Critère corrigé** vers ce que le bouton
  doit vraiment vérifier ("un compte de service ou un agent") : exclut directement
  `asset_type === 'network'`/`'website'`, puis exige `collection_method` = `service_account` ou
  `agent` — ne dépend plus d'aucun check particulier, ne recassera pas si un futur check
  "toujours présent" est ajouté. Vérifié en conditions réelles : 0 ligne "Équipement réseau"/
  "Site web" visible une fois le filtre activé, uniquement des serveurs avec un vrai historique
  de scan (`Dernier scan` renseigné).
- **Colonne Catégorie de Durcissement.jsx alignée sur Assets.jsx** (demande utilisateur, "des
  icônes seraient plus adaptées dans cette colonne non ?") — remplace le badge texte coloré par
  `components/CategoryIcon.jsx` (icône + `title` au survol), déjà utilisé sur Assets.jsx mais
  jamais repris sur Durcissement. Nouveau glyphe "Site web" ajouté à `CategoryIcon.jsx` (absent
  jusqu'ici, catégorie créée le jour même). **Sur "plus précis sur quel équipement réseau"** :
  vérifié contre le parc réel avant de coder quoi que ce soit — 331/400 actifs réseau sont
  PRTG sans aucun champ modèle exploitable (`os` vide, cf. `prtg_client.py::DEVICE_COLUMNS`,
  limite déjà documentée le 04/08/2026) ; les 69 Meraki restants ont déjà un modèle précis via
  `merakiModelLabel()` (MR/MX déjà tous couverts). Pas de nouvelle donnée disponible sans
  modifier `DEVICE_COLUMNS` — piste `icon` non vérifiée à ce stade, proposée pour exploration
  future.
- **Suite immédiate, piste explorée sur demande** ("creuse la piste PRTG icon") : requête directe
  contre le vrai serveur PRTG (lecture seule, même endpoint déjà utilisé) avec des colonnes
  candidates (`icon`, `deviceicon`, `hosttype`, `devicetype`) — `devicetype`/`hosttype`/
  `deviceicon` introuvables sur cette version de PRTG ("Introuvable"), mais **`icon` existe
  bel et bien et porte un vrai signal** : sur les 390 devices réels, 96 `vendors_Cisco.png`,
  16 `Device_WLAN.png`, 7 `vendors_synology.png` (cohérent avec le `vendor_hint` déjà détecté
  par capteur), plus quelques cas isolés (webcam, notebook, SQL, VMware) — pas le dead-end
  supposé plus haut. **Câblé de bout en bout** : `icon` ajouté à `DEVICE_COLUMNS`
  (`prtg_client.py`), stocké dans `Asset.hardware.prtg_icon` à la création **et** rafraîchi à
  chaque cycle (`prtg_matcher.py`, même patron que `vendor_hint`) ; nouvelle table
  `PRTG_ICON_CATEGORY_LABELS` (`assetCategory.js`) ne couvrant que les icônes réellement
  rencontrées (`A_Server_1/3.png` génériques volontairement exclus — aucune info de plus que
  le repli actuel) ; nouvelle catégorie "Équipement Cisco" (glyphe dédié `CategoryIcon.jsx`,
  couleur bleu Cisco `#049fd9` — teinte de badge, pas leur logo). Vérifié en conditions réelles :
  sync PRTG rejoué (381 actifs mis à jour), filtre catégorie "Équipement Cisco" sur Durcissement
  → résultats cohérents (bornes Wi-Fi de sites distants, ex. AP_TPLINK_*). **Point honnête à
  garder en tête** : l'icône reflète ce qui est configuré côté PRTG (auto-détecté ou posé à la
  main par l'admin PRTG), pas une vérification indépendante d'Allsafe — un device nommé
  "AP_TPLINK_*" catégorisé "Équipement Cisco" n'est pas une erreur du code, juste le reflet de
  l'icône réellement assignée côté PRTG.
- **Bug réel signalé par l'utilisateur** ("fond blanc quand je sélectionne un OS ou une
  catégorie") : même cause exacte qu'un bug déjà corrigé le 12/08/2026 sur les calendriers
  `<input type="date">` (popup dessiné par le navigateur, pas par l'app — `color-scheme` est la
  seule propriété qui l'influence, jamais étendue à `<select>` à l'époque). **Vérifié app-wide
  avant de corriger** : 31 fichiers utilisent un `<select>` natif — un seul ajout dans
  `index.css` (`select` dans la règle `color-scheme` déjà existante) corrige les 31 d'un coup,
  pas un correctif par page. Vérifié en conditions réelles sur deux pages distinctes
  (Durcissement, Vulnérabilités) — popup sombre, texte lisible, plus de fond blanc.
  **Toujours blanc signalé par l'utilisateur malgré rechargement forcé** (capture d'écran
  `frontend/bug.png` à l'appui — le `<select>` fermé est bien sombre, seul le popup d'options
  reste blanc) : `color-scheme` seul insuffisant sur Chrome pour dériver le fond des `<option>`
  (confirmé par recherche — comportement Chromium documenté, contrairement au calendrier de
  date où c'est la seule propriété qui compte). Pas reproductible avec le Chromium headless
  Linux utilisé pour vérifier ce projet (déjà sombre avant même ce correctif) — corrigé à
  l'aveugle sur la base de la recherche, sans capture de confirmation possible de mon côté.
  **Corrigé pour de vrai** : `select option { background-color: var(--bg-secondary); color:
  var(--text-primary) }` ajouté dans `index.css`, fond/texte des options posés explicitement
  plutôt que déduits de `color-scheme`. Confirmé par l'utilisateur sur son vrai Chrome. Puis
  vérifié app-wide sur 4 pages de plus (Incidents, Audits, CVE, Actifs) — même règle globale,
  aucun autre correctif nécessaire.
- **Incohérence relevée juste après** ("Durcissement est différent d'Actifs et Inventaire
  Complet — la police de l'élément sélectionné change de couleur sur Durcissement mais pas sur
  les autres") : réelle, pas une confusion — `Durcissement.jsx` teinte déjà son `<select>` fermé
  (couleur du module Inventaire) dès qu'un filtre OS/Catégorie est actif
  (`activeFilterStyle`/`filterSelectStyle`, 13/08/2026), jamais repris sur `Assets.jsx`/
  `Inventaire.jsx` qui gardaient un style statique gris sur leurs 5 `<select>` de filtre
  (OS/criticité/catégorie/statut réseau/configuré). Même formule exacte reprise sur les deux
  pages (même module Inventaire, même couleur). Vérifié en conditions réelles : sélectionner
  "Windows Server" teinte maintenant le menu en cyan sur Actifs et Inventaire Complet, identique
  à Durcissement.
- ~~**Chantier en cours, INTERROMPU (limite d'usage), à reprendre**~~ **terminé (session
  suivante)** ("tu vas faire la même chose sur chaque menu déroulant") — étendre le style
  "filtre actif" (fond/texte teintés à la couleur du module dès qu'un filtre a une valeur non
  vide) à tous les `<select>` de FILTRE de l'app (pas les champs de formulaire dans les modals —
  un select obligatoire dans un formulaire a toujours une valeur, le colorer en permanence
  n'aurait pas de sens, cf. raisonnement ci-dessous). Même pattern exact partout (const
  `ACTIVE_SELECT_STYLE`/`activeFilterSelectStyle` = `{ background: `${MODULE_COLOR}1f`, color:
  MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59`, ...reste du style existant }`, puis
  `style={filtre ? active : normal}` sur chaque `<select>` de filtre) :
  - `CVEs.jsx` (severity), `Vulnerabilities.jsx` (candidateAssetId/status/severity/validated_by
    — `status` compare à `!== 'open'`, pas à `''`, car 'open' est sa valeur par défaut) — fait
    avant l'interruption.
  - `Incidents.jsx` — statusFilter/severityFilter/categoryFilter (3 selects, `MODULES.incidents.color`).
  - `Crises.jsx` — statusFilter (1 select, `MODULES.incidents.color`).
  - `Audits.jsx` — statusFilter/typeFilter (2 selects, `MODULES.securite.color`).
  - `Dashboard.jsx` — `dashFilter.criticite` et `patchedStatusFilter` (2 selects,
    `MODULES.cybervuln.color`, import `MODULES` ajouté au fichier qui ne l'avait pas encore).
    Volontairement exclus (inchangé) : `openLimit`/`awaitingLimit`/`patchedLimit` (pagination,
    pas un filtre) et `SeverityDropdown` (composant custom, pas un `<select>` natif).
  - `AdministrationSecurity.jsx` — typeFilter (1 select), `MODULE_COLOR = '#8b949e'` ajouté en
    dur (pas d'import `MODULES` existant dans ce fichier, cohérent avec le `color="#8b949e"`
    déjà passé à son `PageHero`).
  **Hors périmètre, vérifié et à ne PAS toucher** (inchangé) : `Watch.jsx` (`form.reviewed_by`),
  `Settings.jsx` (`preferredAnalyst`), `AuditDetail.jsx` (champs d'édition d'un audit précis, pas
  des filtres de liste), `Agents.jsx` (pas de `<select>` natif) — et tous les
  `components/*Modal.jsx`/`*Roadmap.jsx` (formulaires de création/édition, jamais des filtres).
  **Vérifié** : HMR Vite propre sur les 5 fichiers modifiés (aucune erreur de compilation dans
  les logs du conteneur `frontend`). ⚠️ Pas de vérification visuelle par capture d'écran cette
  fois (pas de session admin ouverte pour se connecter à l'app depuis cet environnement) —
  contrairement à la vérification Actifs/Inventaire Complet juste au-dessus, à confirmer
  visuellement à l'occasion.

#### 17/08/2026 — Politiques de scan planifié par criticité

**Session précédente : 17/08/2026 (même date, plus tôt)** — Politiques de scan planifié par
criticité (demande explicite :
"scan tous les jours pour les critiques, une fois par semaine pour les autres, matching CVE tous
les jours à 22h, avec la possibilité de le faire manuellement comme actuellement"). Beaucoup de
questions posées en amont (`AskUserQuestion`) avant de coder — le périmètre exact n'était pas
évident (quels types d'actifs, patch check inclus ou non, planning figé ou vraie config en base) :
- **Nouvelle criticité "critique"**, au-dessus de haute/moyenne/faible (celles-ci n'avaient encore
  jamais de 4e palier — `frontend/src/constants/criticite.js`/`CriticiteBadge.jsx`, corrigé au
  passage : `Assets.jsx` avait une liste `<option>` codée en dur, jamais branchée sur
  `CRITICITE_LABELS` comme les autres pages). Multiplicateur de risque **2.0**
  (`scoring.py::CRITICITE_MULTIPLIERS`) ; pour CVSS-BTE, `critique`/`haute` partagent `H` (le
  standard CVSS n'a que L/M/H pour CR/IR/AR).
- **`models.py::ScanPolicy`** (nouvelle table, 4 lignes fixes une par criticité — pas un CRUD libre
  comme `Analyst`) — `enabled`/`frequency` (daily/weekly)/`hour`/`weekday`. Seedée par défaut
  (`db/schema_patches.sql`, migration appliquée en direct sur la base de dev) : critique quotidien
  minuit, le reste hebdomadaire dimanche minuit — librement réajustable ensuite depuis Paramètres
  \> Intégrations (demande explicite d'une vraie config en base plutôt qu'un planning figé dans le
  code, contrairement à toutes les autres tâches Celery du projet).
- **`services/scan_policy.py::run_scan_for_criticite`** — reproduit exactement l'enchaînement de
  l'endpoint manuel `POST /assets/{id}/scan` (`scan_asset` → `apply_scan_result`, qui déclenche
  déjà matching CPE + patch check pour l'actif) sur les actifs `service_account` du groupe, puis
  `run_all_website_checks(asset_ids=...)` (nouveau paramètre optionnel, rétrocompatible) sur ses
  sites web. Séquentiel, même précédent que `patch_checker.py` (pas de session partagée entre
  coroutines concurrentes, prudence vis-à-vis des ~80 serveurs on-premise).
  ⚠️ **Piège identifié avant d'écrire le code, pas après** : `apply_scan_result` déclenche le patch
  check via `asyncio.create_task()` sur la boucle d'événements de l'**appelant** — si cette fonction
  tournait directement dans un worker Celery (`asyncio.run()` propre à la tâche), cette tâche de
  fond serait annulée dès la fin de la tâche Celery, bien avant que le patch check n'ait fini, et
  serait de toute façon invisible au polling `GET /api/patch-check/status` (état en mémoire du
  process `backend`, pas `worker` — exactement le problème déjà résolu pour `patch_checker.py` via
  l'indirection HTTP+jeton interne). **Donc `run_scan_for_criticite` ne s'exécute jamais dans un
  worker** : le nouveau poller horaire (`check_scan_policies`, ci-dessous) appelle
  `POST /scan-policies/{criticite}/run-now` (process backend) exactement comme
  `patch_check_periodic` appelait `POST /patch-check/run`.
- **`auth_deps.py::require_admin_or_internal`** (nouveau, même mécanisme que
  `require_page_or_internal`) — nécessaire pour que `run-now` accepte à la fois une session admin
  (bouton manuel) et le jeton interne (poller). **Bug découvert en testant en conditions réelles
  avant même d'écrire le poller** : `sync.router` et le nouveau `scan_policies.router` étaient
  montés dans `main.py` avec une `dependency` de **niveau router** (`require_page(...)`/`_authed`)
  — celle-ci s'exécute avant toute dependency posée sur une route précise et rejette donc un appel
  au jeton interne avant même que `require_page_or_internal`/`require_admin_or_internal` de la
  route n'ait la moindre chance de s'exécuter. Corrigé en retirant la dependency de niveau router
  sur ces deux routers et en la reposant route par route (11 routes dans `sync.py`) — même
  précédent que `patch_check.py`, qui n'a jamais eu de dependency de niveau router pour cette
  raison exacte. Vérifié par `curl` réel avec le jeton interne et un mauvais jeton (200 vs 401)
  avant de considérer le correctif acquis.
- **Poller horaire** (`tasks/scheduled_tasks.py::check_scan_policies`, beat `crontab(minute=0)`) —
  Celery Beat ne relit jamais une politique en base à la volée (aucune tâche du projet n'est
  pilotée par la base), donc pas de cron dynamique possible : à chaque heure pile, vérifie les 4
  politiques (heure + jour si hebdomadaire, comparés à l'heure locale Europe/Paris via
  `zoneinfo` — fonctionne nativement dans l'image `python:3.12-slim`, vérifié en direct dans le
  conteneur, pas besoin du paquet `tzdata`) et déclenche celles dues, chacune dans son propre
  `try/except`. Un `SyncState` par criticité (`scan_policy_<criticite>`) évite un double
  déclenchement dans la même heure.
- **Matching CVE quotidien 22h** (`run_cpe_match_daily`, même schéma HTTP+jeton interne, appelle
  l'endpoint manuel existant `POST /api/sync/match` plutôt que le service directement — même
  raison que ci-dessus) — s'ajoute au démarrage backend et au bouton manuel, ne les remplace pas.
- **Patch check aligné sur la politique, décision explicite et reconfirmée après calcul de
  l'impact réel** : l'ancien `patch-check-periodic` (toutes les 6h, tous actifs confondus,
  supprimé du planning et la fonction elle-même retirée) faisait double emploi avec
  `RECHECK_INTERVAL` (24h) — pour les actifs `critique`, aucun changement réel (déjà revérifié
  quasi quotidiennement). Pour haute/moyenne/faible (l'essentiel du parc), la revérification passe
  d'environ 24h à 7 jours, puisque le patch check se déclenche désormais uniquement via la cascade
  après un scan (au rythme de la politique du groupe). Chiffré et reconfirmé par l'utilisateur
  avant d'implémenter, pas juste assumé depuis la réponse initiale à la question posée en amont.
- **Signal de fraîcheur agent** (`Durcissement.jsx`) — les actifs `collection_method="agent"` ne
  sont pas pilotables sur planning (ils poussent leurs données eux-mêmes) : badge d'avertissement
  si le dernier checkin dépasse le seuil attendu pour leur groupe, dérivé directement de
  `ScanPolicy.frequency` (1j si critique, 7j sinon) plutôt qu'un réglage séparé à maintenir.
- **Page de réglage** (Paramètres > Intégrations, choix de l'utilisateur — pas Durcissement comme
  proposé par défaut) : `ScanPolicyFormModal.jsx` (calqué sur `AnalystFormModal.jsx`), liste des 4
  politiques avec boutons "Modifier"/"Lancer maintenant" réservés admin, lecture ouverte à tout
  connecté.
- **Vérifié en conditions réelles, pas seulement en local** : migration appliquée sur la base de
  dev (4 lignes seedées) ; `run-now` déclenché via jeton interne réel sur `critique` (0 actif
  concerné, donc sans risque — personne n'a encore la valeur "critique" sur un actif réel) et sur
  `faible` en forçant temporairement son heure à l'heure courante (0 actif `service_account`
  taggé "faible" non plus, remis à sa valeur par défaut ensuite) ; poller et matching quotidien
  invoqués manuellement (`check_scan_policies.apply()`/`run_cpe_match_daily.apply()`) depuis le
  conteneur `worker` ; `beat`/`worker` redémarrés pour charger le nouveau planning (pas de
  hot-reload contrairement à `backend`/`frontend`), planning confirmé via
  `celery_app.conf.beat_schedule` en direct dans le conteneur. `pytest` complet : **208 passés**
  (inchangé, aucun test ajouté pour cette fonctionnalité), y compris
  `test_every_api_route_requires_auth_or_admin` — confirme que le retrait des dependencies de
  niveau router sur `sync.py`/`scan_policies.py` n'a laissé aucune route sans protection.

#### 17/08/2026 — Tests unitaires (os_eol/cvss_bte/web_hardening) + synchronisation agent/compte de service

**Dernière session : 17/08/2026** — Tests unitaires pour la logique ajoutée plus tôt dans la
journée (`os_eol.py`/`cvss_bte.py`/`web_hardening.py`, jusque-là sans le moindre test malgré le
patron déjà établi dans `backend/tests/` — signalé en répondant à "des jobs/pipeline à rajouter ?"
: le pipeline CI, générique, n'a besoin d'aucun nouveau job, juste de tests que `test-backend`
ramasserait automatiquement). 3 nouveaux fichiers, 40 tests (fonctions pures, aucune I/O réelle
sauf `_check_tls`/`check_website` volontairement exclus — vrai socket TCP, déjà vérifiés en
conditions réelles plus tôt dans la session) : `test_os_eol.py` (piège Windows Server déjà vécu —
l'année vit dans `os_version` pas `os`), `test_cvss_bte.py` (dérivation E/RL/RC/CR/IR/AR,
priorité KEV > Metasploit, régression réelle du `Decimal` non converti en `float`),
`test_web_hardening.py` (en-têtes/cookies, dont le cas réel `_octo` de GitHub sans HttpOnly).
248 tests passés (208 + 40), aucune régression.

**Suite immédiate, même session** ("on va faire ce qu'on a pas pu faire l'agent par rapport au
compte de service") : `_RISKY_PORTS` étendu côté `asset_scanner.py` plus tôt dans la journée
(POP3/IMAP/MSSQL/MySQL/VNC) jamais reporté vers l'agent Rust — cassait le principe "l'agent est
un strict sur-ensemble du compte de service" (docs/AGENTS.md) dans le sens inverse de d'habitude
(ici c'est le compte de service qui avait pris de l'avance). `agent/src/collect/linux.rs::
RISKY_PORTS` et `windows.rs` (liste inline équivalente) synchronisés avec la liste Python.
**Vérifié en conditions réelles, pas juste compilé** : `cargo check` propre, puis pipeline de
release complet (`./release.sh`, Linux+.deb, cross-compile Windows mingw-w64, .msi via wixl) —
les deux binaires 0.1.3 reconstruits dans `agent/dist/` (gitignoré, jamais commité — artefacts de
build) ; présence de "MSSQL exposé" confirmée dans le binaire compilé (`grep -a`, pas une
supposition sur le succès du build). Version Cargo.toml/wix inchangée (0.1.3) — pas de bump,
correctif de contenu seulement, pas de nouvelle fonctionnalité. `CURRENT_AGENT_VERSION`
(`backend/routers/agents.py`) volontairement pas touché non plus (bump manuel, cf. `release.sh`
en tête). **Point ouvert** : binaires reconstruits localement, pas encore redistribués aux postes
déjà enrôlés — à publier/déployer selon le processus habituel (`docs/AGENTS.md` § Mise à jour)
quand pertinent, pas fait automatiquement par ce correctif.

#### 17/08/2026, fin de session — Vérification « agent = sur-ensemble strict du compte de service » + incident runner CI

**Vérification demandée par l'utilisateur, pas prise sur la foi de la doc** : comparaison check par
check entre `asset_scanner.py` (compte de service, Python) et `agent/src/collect/{linux,windows}.rs`
(agent Rust) — suite à la brèche trouvée plus tôt dans la session sur les ports risqués (agent pas
synchronisé, corrigée dans `f2279bb`). Extraction des 4 listes de checks par grep, puis diff manuel.

- **Linux** : les 6 checks du compte de service sont tous dans les 14 de l'agent. Sur-ensemble
  confirmé, aucune surprise.
- **Windows** : premier passage en faux négatif — un grep sur `Check::new("...")` ne trouvait que 15
  checks côté agent contre 14 côté compte de service, avec 8 manquants en apparence (`rdp_nla`, `smb1`,
  `smb_signing_server/client`, `smb_guest_auth`, `smb_encryption`, `llmnr`, `firewall`). En relisant
  `windows.rs:247-312` directement : ces 8 checks existent bel et bien, construits via un helper
  différent (`registry_bool_check(...)`) que le grep ne capturait pas. Total réel côté agent : 23
  checks. Les 14 du compte de service y sont tous. **Sur-ensemble strict confirmé sur les deux OS**,
  vérifié en lisant le code, pas en confirmant la doc — piège méthodologique identique (extraction par
  pattern incomplète) déjà rencontré côté Python pour `smb1` un peu plus tôt dans la session.

**Commit `f2279bb`** (poussé, `a336f93..f2279bb`) : fix chevauchement KEV/Metasploit sur badge HIGH
(`SeverityBadge.jsx` : toutes les sévérités rendent à la largeur de CRITICAL, la plus longue), sync
ports risqués agent/compte de service, + 3 fichiers de tests (`test_os_eol.py`, `test_cvss_bte.py`,
`test_web_hardening.py`, 40 tests). Suite complète : 248 tests, tous verts. `fbf3e60` (politiques de
scan planifié par criticité, faite par une autre session dans l'intervalle) poussé dans la foulée.

**Incident runner CI, découvert au push** : pipeline bloquée, message GitLab "aucun runner actif...
tags: docker". Le runner (`wsl2-docker-runner`, cf. `.gitlab-ci.yml`) tourne en conteneur Docker
(`gitlab-runner`, image `gitlab/gitlab-runner:latest`) sur cette même machine de dev, sous Docker
Desktop (WSL2) — confirmé en trouvant le conteneur `Exited (127) 3 days ago` via `docker ps -a` (même
hostname `PORT-1875` que l'utilisateur : l'environnement d'exécution des commandes *est* la machine de
dev, pas un sandbox distinct). Sa restart policy est déjà `always` — pas la cause : Docker Desktop
lui-même n'avait probablement pas redémarré avec la machine, donc aucun daemon disponible pour honorer
cette policy au reboot. Fix immédiat : `docker start gitlab-runner`, a repris le job en file d'attente
dans la foulée. Fix durable, pas une commande CLI mais un réglage de l'appli Windows : Docker Desktop
> Settings > General > "Start Docker Desktop when you sign in to your computer" — communiqué à
l'utilisateur, pas appliqué (pas d'accès à l'UI Docker Desktop depuis ce terminal). Pipelines 22 et 23
relancées par l'utilisateur ensuite, jobs 110/121/122 tous `success` confirmé via `docker logs
gitlab-runner`. Détail du conteneur/de la policy documenté dans `.gitlab-ci.yml` à côté du commentaire
existant sur le runner.

**Point ouvert** : les binaires agent reconstruits (`agent/dist/*.deb`/`*.msi`, v0.1.3, avec le fix de
ports) restent locaux, pas encore redéployés sur les postes déjà enrôlés.

#### 21/08/2026 (suite 2) — 4 thèmes visuels + Dashboard personnalisable + audit complet du mode Présentation

**1. Système de 4 thèmes** (`ThemeContext.jsx` étendu de sombre/clair à `dark`/`light`/`neutral`/
`cyberpunk`, demande explicite — "un vrai thème différent, pas juste une couleur qui change") :
- **Neutre** : nuances de gris quasi monochromes (présentation pro), aplats sans ombre/dégradé
  (`tintedCard()`, `PageHero.jsx`), coins resserrés, `.hero-grid`/`.home-glow` masqués.
- **Cyberpunk** (rebaptisé **Néon** côté UI en fin de session, demande explicite, id interne
  `cyberpunk` inchangé — trop de sélecteurs à retoucher pour un simple changement de libellé) :
  néons/scanlines/tuiles à coins coupés (`clip-path`), tilt 3D à la souris (`utils/tilt3d.js`,
  nouveau), police mono capitales. Palette resserrée sur 3 familles bleu/vert/jaune reliées par
  nuances (demande explicite), puis adoucie une 2e fois en fin de session (retour utilisateur —
  "trop flashy" sur le bouton Analyser et les composants environnants) : `--accent-blue`
  `#00f0ff`→`#2dd4e8`, `--brand`/`--brand-glow` désaturés, les 9 couleurs de module réduites,
  glows de carte/hero/nav réduits d'un tiers.
- Modules colorés via `THEME_COLORS` dans `constants/modules.js`, résolu une fois à l'import
  (localStorage lu de façon synchrone) — dark/light partagent le même jeu (bascule instantanée),
  neutre/cyberpunk déclenchent un rechargement complet en entrant/sortant (~180 fichiers
  consomment `MODULE_COLOR` comme constante de module, hors composant).
- Bug corrigé en cours de route : bascule vers Neutre/Cyberpunk renvoyait sur Paramètres >
  Présentation au lieu de garder l'onglet ouvert (state local `section` non persisté à travers le
  rechargement déclenché par le changement de thème — fix : `sessionStorage`).

**2. Dashboard personnalisable** (Paramètres > Tableau de bord + édition en direct sur la page) :
- Grille unique à 24 colonnes (`constants/dashboardLayout.js`, `contexts/DashboardLayoutContext.jsx`
  nouveaux) couvrant KPI + barre de Filtres + les 7 blocs de contenu (findings d'audit, certificats
  SSL, taux de correction, graphiques, 3 tableaux de vulnérabilités) — un seul registre `order`/
  `sizes`, pas deux grilles séparées : essayé d'abord séparément (KPI dans sa propre grille 8
  colonnes), revenu en arrière suite au retour utilisateur ("je ne peux pas bouger les tuiles sous
  la barre de filtre au-dessus") — `order` CSS ne réordonne qu'entre enfants d'un même conteneur.
  5 tailles disponibles (1/8, 1/4, 1/3, 1/2, plein) pour toute tuile.
- Réordonnancement en CSS pur (`order: order.indexOf(id)`) sur des wrappers `<Widget>` — le JSX
  de chaque bloc reste physiquement à sa place dans le fichier, seule sa position visuelle change
  (pas d'extraction risquée sur un fichier de 3000+ lignes).
- Drag-and-drop HTML5 natif + boutons ◀/▶ ajoutés en complément (retour utilisateur — "pour
  bouger entre eux c'est compliqué", le drag-and-drop natif est peu fiable) : échangent la tuile
  avec sa voisine immédiate dans `order`, plus prévisible qu'un glisser-déposer pixel-précis.
  `gridAutoFlow: 'dense'` ajouté après coup (autre retour — tuiles "qui bloquent"/se chevauchent
  mal) : sans lui, une tuile pleine largeur entre deux tuiles étroites laisse un trou au lieu que
  les suivantes le comblent.
- 3 dispositions prédéfinies (Par défaut/Vue compacte/Priorité corrections) + bouton reset rapide
  directement sur la page en mode édition.
- Bouton "Personnaliser" initialement un pavé texte "⠿ Personnaliser" desservant l'alignement de
  la barre d'actions du Dashboard (retour utilisateur — "le bouton est gros alors qu'une icône
  suffisait") : remplacé par un bouton carré icône seule (crayon/coche), même gabarit que les
  autres boutons de la PageHero.

**3. Audit complet de la couverture du mode Présentation** (retour utilisateur — "il manque
beaucoup de fake data un peu partout, fait un tour complet") : audit délégué à un agent Explore
(lecture seule), corrections faites main. Cause racine identifiée : plusieurs pages ajoutaient les
`FAKE_*` à la suite des vraies lignes SANS jamais les anonymiser (`[...data.items, ...FAKE_X]`),
contrairement au bon pattern déjà en place sur Assets/Agents/Vulnérabilités
(`anonymizeAsset`/`anonymizeAgent`/`anonymizeVuln`). Corrections :
- Nouvelles fonctions `anonymizeIncident`/`anonymizeCrisis`/`anonymizeAudit`/
  `anonymizeAuditFinding`/`anonymizeWatchItem`/`anonymizeDocument` (`utils/fakeData.js`), texte
  libre passé par `redactText` (substitution des hostnames/noms réels connus), noms d'analystes
  par `anonymizeValidator` (déterministe, sans avoir besoin de connaître le nom réel à l'avance).
  Appliquées dans `Incidents.jsx`/`Crises.jsx`/`Watch.jsx`/`Audits.jsx` avant l'ajout des `FAKE_*`.
- `IncidentDetailModal.jsx`/`CrisisDetailModal.jsx` : la chronologie et les pièces jointes qu'ils
  récupèrent eux-mêmes par l'id réel (2e appel API, indépendant du parent) étaient encore en
  clair — auteur des entrées masqué via `anonymizeValidator`, noms de fichiers de pièces jointes
  génériques en mode Présentation.
- `AuditDetail.jsx` : ne gérait que les audits `demo-*` via `isFakeId` ; un audit réel s'ouvrait
  entièrement en clair (périmètre, RoE, mandataire, findings, mandat PDF, rapport généré). Ajout
  d'un garde-fou explicite (`maskReal = isAnonymous && !isFake`) partout où l'affichage lit
  `audit`/`findings` — les handlers de mutation (édition, findings, statut) continuent eux de lire
  les vraies données non masquées, jamais les copies d'affichage, pour ne jamais écraser une
  vraie valeur par du texte anonymisé/fictif au prochain "Enregistrer".
- `AdministrationSecurity.jsx` : seul l'onglet Connexions était couvert. Utilisateurs/Analystes/
  Services/Rôles (+ `ServiceOrgChartModal.jsx`) affichaient noms/emails réels en clair — masqués
  via `anonymizeRoleHolder`/`anonymizeValidator`, même garde-fou "édition sur l'objet réel" que
  ci-dessus. Onglet Correspondances Windows laissé tel quel (app↔CPE, pas de donnée nominative).
- `Documentation.jsx` (Gouvernance) : aucune couverture avant ce correctif. Nom de fichier réel/
  auteur/note masqués à l'affichage ; le contenu réel du PDF/image, lui, est bloqué à la source
  dans `DocumentPreviewModal.jsx` (aperçu + téléchargement désactivés) plutôt qu'"anonymisé" — un
  texte libre arbitraire ne peut pas être redigé de façon fiable comme un champ structuré.
  `type.name` (PSSI, Charte...) laissé en clair — catégorie de gouvernance, pas une donnée
  nominative.
- Sélecteurs d'actifs des formulaires de création (Incidents/Audits/AuditDetail/Watch) : passaient
  la liste d'actifs réelle non anonymisée — corrigés pour utiliser la même liste anonymisée que le
  reste de la page (pattern déjà correct sur Reports.jsx/Vulnerabilities.jsx/Dashboard.jsx).
- Export CSV de `RapportVeille.jsx` contournait complètement l'anonymisation (aucun appel à
  `redactText`, contrairement à `Reports.jsx`/`RapportIncidents.jsx`) — corrigé.

**Vérifié** : compilation (`docker compose logs frontend`, aucune erreur après chaque étape ; une
trace d'erreur ponctuelle dans les logs s'est avérée être un état intermédiaire périmé, confirmé
via fetch direct du module transformé par Vite) et santé des deux services (`/api/health` 200,
frontend 200). **Pas de vérification visuelle en navigateur** — aucun outil Playwright/Chromium
disponible dans cet environnement (tenté puis abandonné), tout repose sur la relecture de code et
les retours de l'utilisateur en test manuel.

**Point ouvert** : le dépôt a un très grand nombre de fichiers marqués modifiés dans `git status`
sur l'ensemble de l'arborescence (backend/agent/config compris), pour l'essentiel de simples
changements de fin de ligne (CRLF/LF) sans changement de contenu — pas causé par cette session,
déjà présent au démarrage. Seuls les fichiers réellement touchés par cette session ont été
committés ici, le reste laissé non indexé.

