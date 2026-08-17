# STATUS.md — État du projet Allsafe

## ⚠️ Échéance : passage en production ~24/08/2026

Annoncé par l'utilisateur le 10/08/2026 ("d'ici 2 semaines on passera en prod"). Avant cette
date : **refaire un tour de sécurité complet** (`AUDIT_SECURITE.md`), pas juste relire l'existant
— redémarrer une revue depuis zéro sur tout le périmètre, comme celle du 10/08/2026. L'utilisateur
préfère être celui qui relance ce chantier plutôt qu'un rappel automatique programmé (demandé
explicitement) — ne pas le déclencher de soi-même, mais le proposer si la date approche sans
qu'il en ait reparlé. Peut aussi être l'occasion de statuer sur les points Docker encore ouverts
(mode "prod" sans `--reload`/`vite dev`, cf. § Points ouverts de `AUDIT_SECURITE.md`) — un vrai
passage en prod est justement le moment où ces compromis "dev actif" cessent d'être valables.

## Lire au démarrage de chaque session, avec CLAUDE.md

Volontairement court : ce fichier est chargé à **chaque** session. Le déroulé chronologique des
sessions passées est dans `docs/HISTORIQUE.md`, à n'ouvrir que pour retrouver le contexte d'une
décision. Les détails techniques vivent dans `docs/` (cf. `CLAUDE.md` § Documentation détaillée).

**Dernière session : 17/08/2026** — Politiques de scan planifié par criticité (demande explicite :
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
  après `AUDIT_SECURITE.md #7`) protégeait `notes`/`validated_by`/`title`/`reported_by` dans les
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
entrées passées de ce fichier, `AUDIT_SECURITE.md`, le titre littéral de l'audit déjà saisi en base
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

**Session d'avant (même jour, le matin) : 03/08/2026** (module **Audits** construit intégralement —
backend, frontend, intégrations, premier jeu de données — cf. § invariants ci-dessous et
`docs/AUDITS.md`, désormais marqué implémenté).

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
  réel saisi (6 findings d'`AUDIT_SECURITE.md`)
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
  `AUDIT_SECURITE.md` avait été conduit le 24/07/2026, avant que le garde-fou d'autorisation
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

---

## Session du 03/08/2026, suite (l'après-midi) — tour applicatif complet + série de correctifs

Demande utilisateur : « refait un tour de l'application, vois ce qu'on peut améliorer », précisée en
quatre axes (parcours navigateur UX, revue de code, revue sécurité, priorisation fonctionnelle/
roadmap) menés **en parallèle** par sous-agents, puis une longue série de corrections appliquées
au fil de l'eau à mesure que l'utilisateur validait chaque piste (« vasy »).

### Méthode — session admin temporaire pour les tests

Comme lors des sessions précédentes (Gestion de crise 31/07, RBAC 31/07) : une ligne insérée
directement dans `sessions` (token aléatoire + hash SHA-256, jamais le mot de passe réel de
l'utilisateur), utilisée pour piloter Playwright et pour les vérifications `curl`, **supprimée après
chaque usage**. Le parcours navigateur a tourné dans le conteneur `mcr.microsoft.com/playwright:v1.62.0-jammy`
(`--network host`), méthode déjà validée pour le test E2E du module Audits le matin même.

### Sécurité — 3 findings du re-audit, tous corrigés

Re-audit ciblé sur le code écrit après le précédent audit du 24/07 (`AUDIT_SECURITE.md`) — modules
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

### Bugs Dashboard réels — deux causes distinctes sur la même page

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

### Dette technique corrigée

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

### Matching/rescore ciblés — vrai trou comblé, pas du code mort

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

### Incident réel découvert — images Docker `worker`/`beat` désynchronisées de `backend`

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

### Deuxième bug trouvé en rattrapant S31 — OOM sur l'activité du rapport CVE global

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

---

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
  audit défensif du 24/07 dans `AUDIT_SECURITE.md` (racine). #1 SSRF, #2 clé d'hôte SSH, #3 TLS LDAP,
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

## 🧾 Bilan de la session du 27/07/2026

*(le déroulé de la session du 24/07/2026 est dans `docs/HISTORIQUE.md`.)*

### Correction de précision — RAM Inventaire (Linux)

Signalé par l'utilisateur : `gitlab.aer.loc` affichait 3 Go de RAM au lieu de 3,8. Cause : le scan SSH
utilisait `free -g` (troncature en Go entiers) alors que la branche Windows était déjà précise à une
décimale. Remplacé par `free -b` + conversion Python arrondie (`services/asset_scanner.py`). Corrige
**toutes** les machines Linux au prochain scan, pas seulement celle signalée.

### Audit de sécurité — 5 des 6 correctifs implémentés et testés en conditions réelles

Suite de l'audit défensif du 24/07 (`AUDIT_SECURITE.md`). Contrairement à la session précédente
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

### Durcissement Docker runtime

`no-new-privileges` sur les 6 services ; `cap_drop: [ALL]` sur les 4 services applicatifs (pas
`db`/`redis`, dont l'entrypoint officiel a besoin de capacités root au démarrage) ; `mem_limit`/`cpus`
sur les 6. Deux pièges réels rencontrés en le faisant (détail dans les invariants ci-dessus) : une
limite mémoire trop basse laissait `backend` bloqué en silence au démarrage (`STARTUP_MATCHING` pique
à ~4.6GiB, pas mesuré avant) ; Compose construit une image par service même avec le même `Dockerfile`,
et reconstruire seulement `backend` après le bump `fastapi` avait laissé `worker`/`beat` casser au
démarrage.

### Trois nouvelles fonctionnalités (demandées explicitement, pentest/bastion laissés de côté)

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

### Méthode

Deux gestions d'incident en direct pendant la session, toutes deux avec cause identifiée et corrigée
avant de poursuivre plutôt que de contourner : dépassement de commande WinRM (théorie déjà dans
`docs/ARCHITECTURE.md`, reconfirmée en la dépassant réellement) et confusion entre mesure de taille de
script sur le texte source Python (avec `\\` littéraux) vs. la chaîne réellement transmise (échappée) —
mesurée correctement via `ast` plutôt qu'un regex naïf sur le fichier source.


### Scanner lent (Actifs + Inventaire) — trois causes distinctes, empilées

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

### Bug CSS — modale mal centrée sur toutes les pages, pas que Inventaire/Actifs

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

### Lien "Applications installées" ↔ vulnérabilités déjà connues

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

### Historique des changements de statut de vulnérabilité

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

### Résolution du point ouvert "31 lignes patched produit absent"

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

### Nouveau statut « correctif partiel » (`awaiting_fix_partial`) + incident de migration

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

### Profil de veille configuré

Correction d'une affirmation périmée de STATUS.md (« profil vide », 24/07) : le profil comptait déjà
195 termes, tous cochés — mais Matériel/Constructeurs était vide et VMware/Veeam/Zerto (mentionnés
comme classés dans une session antérieure) manquaient de la liste Applications. Sur validation de
l'utilisateur : conservé tel quel côté paquets Linux génériques (bash/curl/openssl...) — un composant
réellement installé reste pertinent même si l'article est générique, et le ratio observé (55/2179
éléments marqués ★) montre que ça ne noie pas le signal en pratique. VMware/Veeam/Zerto ajoutés via
`PUT /api/watch/profile` (198 termes au total). Pure configuration, aucun code touché.

### Sauvegarde PostgreSQL + premiers tests automatisés

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

### Healthchecks + Error Boundary (suite de la même demande)

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

### Rotation des logs Docker + build de production du frontend

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

## Session du 28/07/2026 — Intégration WithSecure + premier passage à l'échelle réel

Deux sujets distincts traités dans la même session, mais qui se sont percutés en fin de parcours : une
intégration WithSecure pensée comme un complément (pas un remplacement) du pipeline existant, puis un
élargissement de l'import AD qui a fait passer CBR de 2 à 72 actifs d'un coup — premier vrai test à
l'échelle du parc réel, qui a immédiatement révélé un bug de passage à l'échelle latent.

### Intégration WithSecure — complément, pas remplacement

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

### Élargissement de l'import AD — de 2 à 72 actifs

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

### Incident — `patch_checker.py` non prévu pour ~265 000 vulnérabilités d'un coup

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

### Validation ciblée — un seul actif avant le cycle complet

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

## Suite de session (28/07/2026, plus tard le même jour)

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

### Lenteurs généralisées de l'app — diagnostiquées et résolues (fin de session 28/07)

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

## Surveillance Identités — extension email/GitHub, restée 100% gratuite (28/07/2026)

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
