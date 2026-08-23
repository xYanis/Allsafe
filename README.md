# Allsafe — Plateforme de cybersécurité on-premise

Allsafe est une plateforme interne de gestion de la sécurité, conçue comme alternative open source à
**Cyberwatch** (~13 500 €/an) pour un parc de **80 VM on-premise** (majorité Windows Server jointes à
un Active Directory, minorité Linux). Aucune dépendance cloud.

Le principe directeur : **Allsafe est un outil d'aide à la décision.** Il collecte, corrèle et priorise,
mais n'écrit et n'exécute jamais rien sur les serveurs supervisés. Toutes les connexions distantes
sont en lecture seule, sans exception.

> **Pour Claude Code** : lire `CLAUDE.md` + `STATUS.md` en priorité. Ce README donne la vue
> d'ensemble ; les fichiers `docs/` contiennent le détail par domaine.

---

## Table des matières

1. [Vue d'ensemble fonctionnelle](#1-vue-densemble-fonctionnelle)
2. [Architecture technique](#2-architecture-technique)
3. [Démarrage rapide](#3-démarrage-rapide)
4. [Configuration](#4-configuration)
5. [Détection et vérification des correctifs](#5-détection-et-vérification-des-correctifs)
6. [Cycle de vie d'une vulnérabilité](#6-cycle-de-vie-dune-vulnérabilité)
7. [Les modules](#7-les-modules)
8. [Schéma de données](#8-schéma-de-données)
9. [API](#9-api)
10. [Tâches planifiées](#10-tâches-planifiées)
11. [Règles de sécurité non négociables](#11-règles-de-sécurité-non-négociables)
12. [Exploitation au quotidien](#12-exploitation-au-quotidien)
13. [Pièges connus et dette technique](#13-pièges-connus-et-dette-technique)

---

## 1. Vue d'ensemble fonctionnelle

Allsafe répond à une question simple, en continu : **« quelles vulnérabilités connues affectent réellement
mon parc, et lesquelles sont déjà corrigées ? »**

Le flux complet, de bout en bout :

```
   ┌─────────────┐   ┌──────────────┐   ┌───────────────┐   ┌──────────────────┐
   │ 1. INVENTAIRE│──▶│ 2. COLLECTE  │──▶│ 3. CORRÉLATION│──▶│ 4. VÉRIFICATION  │
   │  des actifs  │   │  des CVE     │   │  actif × CVE  │   │  des correctifs  │
   └─────────────┘   └──────────────┘   └───────────────┘   └──────────────────┘
    AD (LDAP)         NVD (NIST)          CPE matching        WinRM / SSH
    SSH / WinRM       + flux RSS          + paquets           lecture seule
    lecture seule                         + mots-clés                │
                                                                     ▼
                                                          ┌──────────────────┐
                                                          │ 5. DÉCISION      │
                                                          │  analyste        │
                                                          └──────────────────┘
                                                           corrigé / en attente
                                                           faux positif / accepté
```

1. **Inventaire** — les actifs sont importés depuis l'Active Directory (LDAP, lecture seule), ou
   ajoutés manuellement. Un scan read-only (WinRM côté Windows, SSH côté Linux) relève l'OS réel, les
   applications installées et les caractéristiques matérielles.
2. **Collecte** — les CVE sont synchronisées depuis la base NVD du NIST. Des flux RSS alimentent en
   parallèle le module de veille réglementaire.
3. **Corrélation** — chaque CVE est confrontée au parc selon trois mécanismes (CPE, paquets
   installés, mots-clés). Une correspondance crée une ligne dans `vulnerabilities`.
4. **Vérification** — Allsafe détermine si le correctif est déjà présent sur la machine, via quatre
   signaux complémentaires détaillés en [section 5](#5-détection-et-vérification-des-correctifs).
5. **Décision** — l'analyste tranche. Selon la sévérité, Allsafe peut basculer automatiquement le statut
   **dans sa propre base** (jamais sur le serveur), voir [section 6](#6-cycle-de-vie-dune-vulnérabilité).

---

## 2. Architecture technique

### Services Docker

| Service | Image / source | Rôle | Port exposé |
|---|---|---|---|
| `db` | `postgres:16-alpine` | Base de données | — (interne) |
| `redis` | `redis:7-alpine` | Broker Celery | — (interne) |
| `backend` | `./backend` | API FastAPI (uvicorn) | **8000** |
| `worker` | `./backend` | Worker Celery (queue `default`) | — |
| `beat` | `./backend` | Ordonnanceur Celery | — |
| `frontend` | `./frontend` | Vite / React (dev server) | **3000** |

`backend`, `worker` et `beat` partagent la même image et le même code (`./backend` monté en volume).
`keys/` est monté en lecture seule dans `backend` et `worker` pour la clé SSH du parc.

### Stack

- **Backend** : Python 3.12, FastAPI, SQLAlchemy 2 (async, `asyncpg`), Pydantic Settings
- **Tâches** : Celery + Redis (worker et beat séparés)
- **Frontend** : React 18, Vite, React Router v6, Tailwind CSS, Recharts, Axios, `marked` + `dompurify`
  (rendu Markdown sanitizé des annotations d'analyste)
- **Accès distants** : `pywinrm` (Windows), `asyncssh` (Linux), `ldap3` (Active Directory)

### Arborescence

```
cybervuln/
├── docker-compose.yml
├── .env / .env.example
├── keys/id_ed25519            ← clé SSH du parc (jamais commitée)
├── CLAUDE.md                  ← instructions projet (lire en priorité)
├── STATUS.md                  ← journal de sessions, décisions et incidents
├── docs/
│   ├── ARCHITECTURE.md        → BDD, Docker, endpoints détaillés
│   ├── SECURITY.md            → anonymisation, SSH, AD
│   ├── MATCHING.md            → matching CPE, scoring, signaux de patch check
│   ├── FRONTEND.md            → pages, composants, design system
│   └── VEILLE.md              → module veille NIS 2
├── backend/
│   ├── main.py                ← app FastAPI, montage des routers, tâches de démarrage
│   ├── config.py              ← variables d'environnement (Pydantic Settings)
│   ├── database.py            ← moteur async, `poolclass=NullPool` (cf. § 13)
│   ├── models.py              ← 12 tables SQLAlchemy
│   ├── routers/               ← 12 routers, un par domaine fonctionnel
│   ├── services/              ← logique métier (voir ci-dessous)
│   └── tasks/scheduled_tasks.py ← définition Celery + planning beat
└── frontend/src/
    ├── pages/                 ← 15 pages
    ├── components/            ← 15 composants partagés
    ├── contexts/              ← ThemeContext (dark/light), PresentationContext (mode anonyme)
    ├── utils/                 ← syntheticData (mode démo), countries, color
    └── api/client.js          ← instance Axios, baseURL `/api` (proxy Vite → backend:8000)
```

### Services backend

| Fichier | Rôle |
|---|---|
| `nvd_fetcher.py` | Synchronisation des CVE depuis l'API NVD (incrémentale, backfill, CVE unitaire) |
| `cpe_matcher.py` | Corrélation actif × CVE (CPE, paquets installés, mots-clés) |
| `scoring.py` | Score de risque = CVSS × EPSS × criticité de l'actif |
| `patch_checker.py` | Vérification read-only des correctifs (WinRM / SSH), cycle autonome |
| `kb_build.py` | Résolution KB Microsoft → numéro de build OS, avec cache permanent |
| `debian_tracker.py` | Debian Security Tracker (versions corrigées, backports inclus) |
| `asset_importer.py` | Import Active Directory (LDAP) et construction des CPE |
| `asset_scanner.py` | Scan read-only : fiabilité des infos, applications, matériel |
| `remediation.py` | Génération de recommandations et de scripts (jamais exécutés) |
| `stats.py` | Calcul des KPI, partagé par le dashboard et les rapports |
| `weekly_report.py` | Rapports hebdomadaires figés (semaine ISO, génération, archives) |
| `watch_report.py` | Contenu du rapport hebdomadaire de veille (NIS 2, SLA 48 h) |
| `identity_report.py` | Contenu du rapport hebdomadaire de surveillance des identités |
| `watch_fetcher.py` | Collecte des sources de veille (NIS 2) |
| `ip_watch.py` | Vérification d'IP contre des listes de blocage publiques |
| `watch_profile.py` | Profil de veille : OS/logiciels du parc, suggestions depuis l'inventaire |
| `rss_fetcher.py` | Collecte de flux RSS |
| `crypto.py` | Chiffrement Fernet des mots de passe SSH stockés par machine |
| `claude_analyzer.py` | ⚠️ **Ne contacte pas l'API Claude** — règles de mots-clés locales (cf. § 11) |

---

## 3. Démarrage rapide

### Prérequis

- Docker et Docker Compose
- Un accès réseau aux machines supervisées (WinRM 5985 côté Windows, SSH 22 côté Linux)
- Un compte de service Active Directory **en lecture seule**
- Optionnel mais recommandé : une clé API NVD (gratuite, multiplie le débit par 10)

### Installation

```bash
# 1. Configuration
cp .env.example .env
$EDITOR .env          # renseigner au minimum DB_PASSWORD, SECRET_KEY, AD_*, WINRM_*

# 2. Clé SSH pour le parc Linux (si applicable)
ssh-keygen -t ed25519 -f keys/id_ed25519 -N ""
# puis déployer la clé publique sur les hôtes Linux

# 3. Démarrage
docker compose up --build
```

### Premier remplissage

```bash
# Import des actifs depuis l'Active Directory
curl -X POST http://localhost:8000/api/sync/assets

# Première synchronisation NVD (30 derniers jours)
curl -X POST "http://localhost:8000/api/sync/nvd?days=30"

# Rattrapage complet des CVE applicables aux CPE du parc (long, plusieurs minutes)
curl -X POST http://localhost:8000/api/sync/nvd-backfill
```

La corrélation actif × CVE se déclenche automatiquement au démarrage du backend et après chaque
synchronisation. Le premier cycle de vérification des correctifs démarre également tout seul.

### Accès

- **Interface** : http://localhost:3000
- **API + documentation interactive** : http://localhost:8000/api/docs

> ⚠️ **Authentification par compte email/mot de passe** (session cookie HttpOnly, RBAC admin/analyste,
> cf. STATUS.md) — mais aucun TLS n'est configuré par défaut (`COOKIE_SECURE=false`, cf. `.env.example`).
> L'application suppose un déploiement sur un réseau interne de confiance. Ne pas exposer sur Internet
> sans reverse-proxy TLS devant (auquel cas passer `COOKIE_SECURE=true`).
>
> Premier compte : définir `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` dans `.env` avant le
> premier démarrage (créé une seule fois), puis retirer `BOOTSTRAP_ADMIN_PASSWORD` de `.env` après la
> première connexion.

---

## 4. Configuration

Toutes les variables sont lues par `backend/config.py`. Celles marquées **obligatoire** doivent être
renseignées avant tout usage réel.

| Variable | Défaut | Rôle |
|---|---|---|
| `DB_USER` / `DB_NAME` | `cybervuln` | PostgreSQL |
| `DB_PASSWORD` | `changeme` | **Obligatoire** |
| `DB_HOST` | `db` | Nom du service Docker |
| `REDIS_URL` | `redis://redis:6379` | Broker Celery |
| `SECRET_KEY` | `changeme` | **Obligatoire** — dérive la clé Fernet. La changer invalide tous les mots de passe SSH déjà chiffrés en base |
| `DEBUG` | `false` | Mode debug FastAPI |
| `STARTUP_MATCHING` | `true` | Corrélation CVE au démarrage du backend. `false` = redémarrer sans effet de bord sur les données (dev) |
| `STARTUP_PATCH_CHECK` | `true` | Cycle de patch check au démarrage. Idem — reste déclenchable via `POST /api/patch-check/run` |
| `NVD_API_KEY` | — | Sans clé : 5 req/30 s. Avec clé : 50 req/30 s |
| `ANTHROPIC_API_KEY` | — | Présent dans la config, **actuellement inutilisé** (cf. § 11) |
| `AD_SERVER`, `AD_USER`, `AD_PASSWORD`, `AD_BASE_DN` | — | Compte AD **lecture seule** |
| `AD_OU` | — | Optionnel : restreindre l'import à une OU |
| `SSH_USER`, `SSH_KEY_PATH` | — | Compte SSH du parc, **sans sudo** |
| `LINUX_HOSTS` | — | Hôtes Linux, séparés par des virgules |
| `WINRM_USER` | — | `DOMAINE\utilisateur`. Si vide, `AD_USER` est utilisé et converti automatiquement depuis le DN |
| `WINRM_PASSWORD` | — | Si vide, `AD_PASSWORD` est utilisé |
| `WINRM_PORT` | `5985` | 5985 (HTTP) ou 5986 (HTTPS) |
| `WINRM_TRANSPORT` | `ntlm` | `ntlm`, `kerberos` ou `credssp` |

> `WINRM_*` n'est pas listé dans `.env.example` mais est bien lu par `config.py`.

### Droits requis sur les machines Windows

Constat de terrain, vérifié en conditions réelles : un compte de service standard obtient
**« Accès refusé » sur WMI/DCOM** (`Get-HotFix`, `Get-WmiObject Win32_QuickFixEngineering`,
`Get-CimInstance`, `systeminfo`). Allsafe est conçu pour fonctionner **sans** ces droits :

- KB installés → journal d'événements (`Get-WinEvent`, appartenance au groupe **Lecteurs des journaux
  d'événements** / *Event Log Readers* suffisante)
- Build de l'OS, CPU → registre
- RAM → appel natif `GlobalMemoryStatusEx` (P/Invoke kernel32)
- Disques, MAC, IP, ports en écoute → API .NET

---

## 5. Détection et vérification des correctifs

C'est la partie la plus travaillée du projet, et celle où les pièges sont les plus nombreux.

### 5.1 Corrélation actif × CVE (`cpe_matcher.py`)

Trois mécanismes, par ordre de priorité :

1. **CPE, composant par composant** — `asset.cpe_list` contre `cve.cpe`, en comparant
   part/vendor/product/version séparément. Un `*`/`-` correspond à tout ; le composant version tolère
   le zéro implicite (`12` = `12.0`).
   *Pourquoi pas un simple préfixe de chaîne :* `"...debian_linux:12.0".startswith("...debian_linux:12")`
   est vrai uniquement par coïncidence de caractères — un actif « Debian 1 » aurait aussi bien
   correspondu à « Debian 12 » ou « Debian 120 ».
2. **Paquets installés** — `asset.installed_packages` contre les CPE applicatifs (`a:`) de la CVE.
   Indispensable : `cpe_list` ne contient que l'OS, donc toute CVE de bibliothèque (openssl, libssh2,
   libxml2…) sans CPE OS associé serait structurellement invisible sans ce chemin.
3. **Mots-clés** (repli, si la CVE n'a aucun CPE) — recherche en **mot entier** dans les 150 premiers
   caractères de la description. Le nom d'OS seul (« debian », « windows ») n'est jamais un mot-clé :
   trop générique, il capture des textes sans rapport avec le produit.

### 5.2 Vérification Windows — quatre signaux (`patch_checker.py`)

Chaque signal comble une limite du précédent. Ils sont évalués dans cet ordre :

| # | Signal | Fiabilité | Alimente le verdict ? |
|---|---|---|---|
| 1 | **KB installés** (journal Windows Update, WMI, PSWindowsUpdate) | Faible sur les CVE anciennes | Oui, en dernier recours |
| 2 | **Build OS vs plages NVD** | Preuve | **Oui** |
| 2bis | **Build OS vs build du KB Microsoft** | Preuve | **Oui** |
| 3 | **Date de dernière mise à jour** | Indice | **Non**, jamais |

Le détail de chaque signal — sources interrogées, limites, filtrage par branche d'OS, coût réseau —
est dans `docs/MATCHING.md` § Détection Windows. En résumé : le check KB seul produit des faux
négatifs systématiques (mises à jour cumulatives), d'où les deux signaux de build qui, eux, sont des
preuves ; le signal de date n'est qu'un indice et n'alimente jamais le verdict.

**Sources testées et écartées** pour obtenir un seuil de build sur les CVE anciennes : NVD
(`configurations` sans plage), MSRC sug v2 (`affectedBinaries` vide), MSRC CVRF v3 (`AffectedFiles`
vide), registre CBS (vieux KB purgés). Seul le titre de l'article support.microsoft.com le fournit.

### 5.3 Vérification Linux — deux voies

1. **Debian Security Tracker** — donne la version *Debian* qui corrige la CVE. Seule réponse correcte
   au problème des **backports** : Debian corrige sans changer le numéro amont, donc une comparaison
   contre NVD conclurait à tort « non corrigé ». Une CVE totalement absente du tracker ne concerne
   aucun paquet Debian (signal de non-applicabilité).
2. **Plages NVD** — repli pour les autres distributions. Ne voit pas les backports, limite assumée.

Si aucun des paquets visés n'est installé, la CVE est **sans objet** — statut `false_positive`, jamais
`patched` : rien n'a été corrigé. Détail et pièges (noyaux Secure Boot, `target_sw`) dans
`docs/MATCHING.md`.

### 5.4 Performance : un relevé par actif, pas par CVE

Le relevé distant (KB installés, build, paquets) est **identique pour toutes les CVE d'un même actif**
dans un même cycle. Il est donc effectué **une seule fois par actif** et réutilisé
(`_fetch_windows_patch_snapshot`, `_fetch_linux_package_snapshot`).

Avant cette optimisation, chaque CVE rouvrait sa propre session WinRM et rescannait l'intégralité du
journal d'événements — sur un actif à plusieurs milliers de CVE, le cycle n'avançait quasiment plus.
Effet secondaire bénéfique : un actif injoignable est détecté une fois pour tout le lot, au lieu d'un
délai d'expiration par CVE.

---

## 6. Cycle de vie d'une vulnérabilité

### Statuts

| Statut | Signification | Revérifié automatiquement ? |
|---|---|---|
| `open` | À traiter | Oui |
| `in_progress` | Prise en charge | Oui |
| `awaiting_fix` | Aucun correctif éditeur disponible | **Oui** — bascule dès publication |
| `patched` | Corrigée | Non (état terminal) |
| `false_positive` | Ne concerne pas réellement l'actif | Non (le correctif n'a jamais été le sujet) |
| `accepted_risk` | Risque accepté | Oui |

### Règle de bascule automatique

C'est la règle centrale du produit, et elle est **non négociable** :

| Sévérité | Correctif détecté | Comportement |
|---|---|---|
| **CRITICAL** | oui | Allsafe **signale uniquement**. La bascule en `patched` exige une validation humaine explicite, toujours. |
| HIGH / MEDIUM / LOW | oui | Bascule automatique en `patched`, avec `validated_by = "Auto (patch check)"`. Réouvrable à tout moment. |

Dans tous les cas, l'action reste confinée à la base Allsafe. **Aucune commande n'est jamais exécutée sur
le serveur** pour appliquer ou confirmer quoi que ce soit.

### Cycle autonome

- `RECHECK_INTERVAL = 24 h` — une vulnérabilité déjà contrôlée est revérifiée après ce délai. Sans
  cela, un correctif appliqué après un premier contrôle négatif ne serait jamais revu.
- `MIN_RECHECK_GAP = 30 s` — le bouton « Patch check » unitaire renvoie le résultat en cache si le
  contrôle date de moins de 30 s, pour ne pas resolliciter la machine sur un double-clic. Contournable
  via « 🔄 Relancer un scan ».
- **Réévaluation forcée** — le bouton **⟳** du dashboard (`?force=true`) lève le garde-fou des 24 h.
  Indispensable après l'amélioration d'un signal de détection : sans lui, tout le stock déjà contrôlé
  conserve un résultat calculé par l'ancienne logique. Confirmation obligatoire, car il peut basculer
  un volume important de vulnérabilités d'un coup.

### Traitement en masse

- **« ✓ Corrigé (N) »** (dashboard) — applique le geste manuel unitaire à une sélection. Aucune
  restriction de sévérité : c'est une décision humaine explicite, pas une automatisation.
- **« 🛡️ Validation groupée CRITICAL »** (page Vulnérabilités) — regroupe les CVE CRITICAL dont le
  patch check est positif. L'analyste coche et valide en un clic. Le serveur revérifie chaque ligne
  avant application et ignore celles qui ne remplissent plus les conditions.
- **Filtre « ✓ Patch détecté uniquement »** — isole les candidates à une validation groupée.

---

## 7. Les modules

L'accueil (`/`) est un sélecteur de 7 modules, chacun avec sa couleur reprise dans la barre latérale.

| Module | Couleur | État | Contenu |
|---|---|---|---|
| **CyberVuln** | `#f85149` rouge | ✅ Complet | Dashboard, Vulnérabilités, Actifs, CVE |
| **CyberVeille** | `#58a6ff` bleu | ✅ Complet | Veille technologique (registre NIS 2), Fuite de données, Surveillance Identités |
| **Inventaire** | `#b5793a` marron | ✅ Complet | Patrimoine IT : CPU, RAM, disques, applications |
| **Sécurité** | `#3fb950` vert | ⬜ Placeholder | Audits (5 types : architecture, configuration, code, pentest, Red Team — spécifié dans `docs/AUDITS.md`, pas encore implémenté) + Bastion (jump host serveurs critiques, portée à définir) |
| **Rapports** | `#a371f7` violet | ✅ Complet | Rapport exécutif CVE, Rapport Veille et Rapport Surveillance — chacun avec ses rapports hebdomadaires figés (`S30/2026`, export PDF/CSV) |
| **Paramètres** | `#8b949e` gris | ✅ | Thème, mode Présentation |

**Actifs vs Inventaire** — même parc, deux angles. *Actifs* est la vue **sécurité** (vulnérabilités,
correctifs, fiabilité des informations déclarées). *Inventaire* est la vue **patrimoine** (matériel,
applications installées).

**CyberVeille — Veille technologique** : registre auditable NIS 2. Agrège une vingtaine de sources
(officielles, médias, éditeurs), catégorise par thème, applique un SLA de 48 h sur les critiques, et
exporte pour un auditeur. Des sources personnalisées sont ajoutables **sans toucher au code** (table
`watch_sources`). Détail dans `docs/VEILLE.md`.

**CyberVeille — Surveillance Identités** : croise des identités surveillées (noms, domaines, IP,
plages IP — éditables en base) avec les fuites déjà collectées et des listes de blocage publiques
(IPsum, Blocklist.de, Feodo Tracker). Entièrement gratuit, aucune source propriétaire.

**Mode Présentation (« Anonyme »)** : anonymise à la volée noms d'hôtes, IP et analystes, et injecte
des données fictives. Destiné aux démonstrations. Aucune donnée fictive n'est jamais écrite en base.

---

## 8. Schéma de données

12 tables, créées automatiquement au démarrage (`Base.metadata.create_all`). **Il n'y a pas de système
de migration** — une modification de schéma sur une base existante doit être appliquée à la main.

| Table | Rôle |
|---|---|
| `cves` | Catalogue NVD : score CVSS/EPSS, sévérité, CPE, références, données brutes |
| `assets` | Parc : OS, CPE, matériel, applications, résultat du dernier scan, identifiants SSH chiffrés |
| `vulnerabilities` | **Table pivot** actif × CVE : statut, score de risque, résultat du patch check, validateur, horodatages |
| `kb_builds` | Cache permanent KB Microsoft → build OS |
| `watch_items` | Éléments de veille (registre NIS 2) |
| `watch_sources` | Sources de veille personnalisées, ajoutables sans code |
| `watched_identities` | Identités surveillées (nom, domaine, IP, plage) |
| `watch_profile` | Profil de veille : OS/logiciels du parc — **marque** les éléments concernés, ne filtre jamais |
| `sync_state` | Horodatage générique de dernière exécution, par clé de tâche |
| `connection_logs` | Traçabilité des connexions à l'interface |
| `feeds` | Flux RSS |
| `reports` | Rapports hebdomadaires figés (`S30/2026`), pour le parc et par actif — snapshot non recalculé |

**Principe important** : la base stocke **toutes** les CVE du NVD, mais l'interface, les statistiques
et les rapports n'exposent **que celles rattachées à au moins un actif**. Afficher des dizaines de
milliers de CVE sans rapport avec le parc serait du bruit, pas de l'information.

---

## 9. API

Documentation interactive complète : http://localhost:8000/api/docs

### Principaux points d'entrée

La **liste exhaustive et à jour** est dans la documentation interactive (http://localhost:8000/api/docs)
et dans `docs/ARCHITECTURE.md`. Les grands groupes :

| Préfixe | Rôle |
|---|---|
| `/api/stats` | KPI, restreignables à un sous-ensemble d'actifs |
| `/api/assets` | Parc : liste, ajout, scan read-only, applications installées |
| `/api/vulnerabilities` | Liste filtrable, changement de statut, actions groupées (corrigé / faux positif / validation CRITICAL) |
| `/api/patch-check` | Contrôle unitaire, cycle complet (`?force=true`), avancement |
| `/api/sync` | NVD (incrémentale, ciblée, backfill), import AD, corrélation |
| `/api/remediation` | Recommandation et script — **jamais exécutés** par Allsafe |
| `/api/reports` | Export CSV, résumé exécutif |
| `/api/watch`, `/api/identities` | Veille NIS 2 et Surveillance Identités (cf. `docs/VEILLE.md`) |

## 10. Tâches planifiées

Celery Beat, toutes en queue `default` :

| Tâche | Fréquence | Rôle |
|---|---|---|
| `sync_nvd_recent` | Toutes les 4 h | CVE des dernières 24 h |
| `sync_nvd_critical` | 03h00 | Passe approfondie sur 30 jours |
| `sync_rss_feeds` | Toutes les heures (H+5) | Flux RSS |
| `sync_watch_feeds` | Toutes les heures (H+10) | Sources de veille |
| `patch_check_periodic` | Toutes les 6 h (H+20) | Cycle de vérification des correctifs |
| `generate_weekly_reports_task` | Lundi 7h00 | Rapports hebdomadaires figés de la semaine écoulée (parc + un par actif) |

Les décalages horaires évitent que les tâches se concurrencent.

`patch_check_periodic` déclenche `POST /api/patch-check/run` **par HTTP vers le backend**, au lieu
d'appeler le service directement depuis le worker. C'est délibéré : l'état d'avancement (suivi par le
dashboard) et le verrou anti-concurrence vivent en mémoire dans le processus FastAPI. L'invoquer
depuis le worker créerait un état parallèle invisible et sans verrou.

Au démarrage du backend, deux tâches se lancent également : la corrélation CPE, puis le cycle de
vérification des correctifs en tâche de fond (non bloquant pour l'API).

---

## 11. Règles de sécurité non négociables

### Non-intervention

Allsafe **n'exécute et n'écrit jamais rien** sur un serveur supervisé, quelle que soit la sévérité.

| Action | Allsafe | Analyste |
|---|---|---|
| Collecter les informations d'une VM (lecture seule) | ✅ | |
| Détecter et prioriser les vulnérabilités | ✅ | |
| Proposer une recommandation ou un script | ✅ | |
| Vérifier si un correctif est présent (lecture seule) | ✅ | |
| **Tester et appliquer le correctif sur le serveur** | ❌ | ✅ toujours |
| Marquer une CRITICAL comme corrigée | ❌ | ✅ obligatoire |
| Marquer une HIGH/MEDIUM/LOW comme corrigée | ✅ si correctif prouvé | ✅ peut réouvrir |

Les connexions SSH et WinRM sont limitées à de la lecture (`hostname`, `dpkg -l`, lecture de registre,
journal d'événements). Le compte Active Directory est en lecture seule, aucune modification d'annuaire.

Les scripts générés par `remediation.py` sont des **propositions destinées à l'analyste**. Allsafe ne les
exécute jamais, ni localement ni à distance.

### Anonymisation vers l'API Claude

Règle à respecter **si et quand** un appel à l'API Claude sera implémenté :

| Donnée | Vers l'API | Stockage local |
|---|---|---|
| Nom d'hôte, adresse IP, liste des paquets | ❌ jamais | ✅ |
| OS, type d'actif | Générique uniquement (« Windows Server (recent) ») | ✅ complet |
| Identifiant CVE, description, CVSS, EPSS | ✅ (information publique) | ✅ |
| Statistiques agrégées | ✅ (aucune donnée nominative) | ✅ |

> ⚠️ **État réel aujourd'hui** : `services/claude_analyzer.py` **ne contacte pas l'API Claude**
> (vérifié : zéro appel HTTP externe dans ce fichier). Le bouton « Analyser » applique des règles de
> mots-clés **100 % locales**, malgré la présence de `ANTHROPIC_API_KEY` dans la configuration. Le
> tableau ci-dessus décrit la règle à appliquer le jour où un vrai appel sera ajouté, pas le
> comportement actuel. **Aucune donnée ne sort vers Claude à ce jour.**

---

## 12. Exploitation au quotidien

### Routine de l'analyste

1. Ouvrir le **Dashboard** : KPI, taux de correction par sévérité, avancement du contrôle en cours.
2. Traiter **« Vulnérabilités à traiter »**. Pour chaque ligne : « Analyser », « Patch check »,
   « Recommandation », puis trancher — ✓ Corrigé, ⏳ En attente, 🚫 Faux positif.
3. Filtrer sur **« ✓ Patch détecté uniquement »**, tout sélectionner, valider en masse avec
   « ✓ Corrigé (N) ».
4. Traiter les **CRITICAL** via « 🛡️ Validation groupée CRITICAL » : chaque ligne montre sa preuve,
   la confirmation reste individuelle et explicite.
5. Vérifier **« En attente d'un patch correctif »** : ces lignes basculent seules dès qu'un correctif
   est publié, aucune action requise.

Le bouton **« 📋 Justificatif »** de la table « traitées » affiche pourquoi une ligne est passée en
corrigé (KB, build, version de paquet) — utile pour un audit.

Les annotations d'analyste (« En attente », « Faux positif », « Corrigé ») acceptent la syntaxe
Markdown et sont rendues comme telles partout où elles s'affichent en entier ; la table « en attente »
propose en plus un bouton **« ✏️ Modifier »** pour corriger une annotation déjà enregistrée sans
changer le statut de la vuln.

### Commandes utiles

```bash
# État des services
docker compose ps

# Journaux
docker compose logs -f backend
docker compose logs -f worker

# Avancement du contrôle des correctifs
curl -s http://localhost:8000/api/patch-check/status | python3 -m json.tool

# Accès base
docker compose exec db psql -U cybervuln -d cybervuln
```

### Après une modification du code

- **Variables d'environnement** : `docker compose restart` **ne recharge pas** `.env`. Après
  modification, `docker compose up -d --force-recreate backend`. Vérifier avec
  `docker compose exec backend printenv | grep <VAR>`.
- **Backend** : rechargement à chaud automatique. Si le conteneur se bloque sur
  « Waiting for application startup » après plusieurs redémarrages rapprochés, utiliser
  `docker compose up -d --force-recreate backend` — un simple `restart` ne suffit pas.
- **Frontend** : le rechargement à chaud Vite est **peu fiable sur les montages WSL/Windows**. En cas
  de doute, `docker compose restart frontend` puis rechargement de la page.

---

## 13. Pièges connus et dette technique

Section volontairement franche : ces points ont tous été rencontrés en conditions réelles.

### Dette identifiée

- ~~Dossiers `services/` et `tasks/` à la racine~~ — **supprimés le 21/07/2026**. C'étaient des copies
  obsolètes de `backend/services/` et `backend/tasks/` (347 vs 525 lignes pour `nvd_fetcher.py`,
  207 vs 292 pour `scheduled_tasks.py`), hors du contexte de build Docker (`./backend`) donc jamais
  exécutées. Même cas que `backend/routers.py`, supprimé précédemment. **Ne pas les recréer** :
  `backend/` fait foi.
- **Aucune authentification** — cf. § 3.
- **Aucune migration de schéma** — cf. § 8.
- **Modale de patch check dupliquée** entre `Dashboard.jsx` et `Vulnerabilities.jsx`, sans composant
  partagé. Toute évolution doit être appliquée aux deux.
- **`@tremor/react` figure dans `package.json` mais n'est utilisé nulle part.** Le design réel est
  100 % Tailwind + variables CSS. Ne pas introduire de composant Tremor dans du code neuf.
- **Documentation partiellement obsolète** — plusieurs sections de `docs/FRONTEND.md` décrivaient des
  écrans qui n'existent plus (tables « Tremor », boutons disparus) ; elles ont été réécrites, mais
  d'autres passages peuvent l'être encore. Vérifier contre le code avant de s'y fier.

### Pièges techniques

- **`poolclass=NullPool` dans `database.py`** — indispensable. Les tâches Celery ouvrent chacune leur
  propre boucle asyncio ; un pool persistant survivant à la boucle qui l'a créé provoquait des
  `another operation is in progress` en cascade dès le moindre incident réseau.
- **`pending: 0` ne signifie pas « à jour »** — seulement « tout a été contrôlé il y a moins de 24 h ».
  Après amélioration d'un signal, croiser `last_patch_check` avec l'heure du déploiement, sinon on
  conclut à tort qu'il n'y a rien à faire. C'est le rôle du bouton ⟳.
- **Limite de taille des commandes WinRM** — le script PowerShell est encodé en base64 et passé à
  `powershell -encodedcommand`, plafonné à ~8191 caractères. Marge actuelle : ~7100. Tout ajout doit
  rester compact.
- **Piège React** : le polling (`useEffect(..., [])`) capture l'état du montage (listes vides). Toute
  fonction appelée depuis ce polling doit lire l'état courant via un `useRef` tenu à jour, jamais par
  la closure — sinon la recherche échoue silencieusement, définitivement.
- **Rate-limiting de support.microsoft.com** — se manifeste par une page « Service unavailable ». Ces
  réponses ne sont **jamais** mises en cache, contrairement à un article réellement dépourvu de build.
- **Tests d'interface qui écrivent en base** — un test automatisé ayant cliqué « Corrigé » attribue la
  validation à un **vrai analyste**. Le statut peut être exact, la piste d'audit devient fausse
  (problématique en contexte NIS 2). Toujours remettre l'état d'origine après un test.

---

## Documentation complémentaire

| Fichier | Contenu |
|---|---|
| `CLAUDE.md` | Instructions projet, règles absolues, structure |
| `STATUS.md` | État courant, invariants techniques, points ouverts — court, lu à chaque session |
| `docs/HISTORIQUE.md` | Journal chronologique des sessions passées — chargé uniquement à la demande |
| `docs/ARCHITECTURE.md` | Schéma de données détaillé, Docker, endpoints exhaustifs |
| `docs/MATCHING.md` | Corrélation CPE, scoring, signaux de patch check en profondeur |
| `docs/SECURITY.md` | Anonymisation, SSH, Active Directory |
| `docs/FRONTEND.md` | Pages, composants, design system, mode Présentation |
| `docs/VEILLE.md` | Module veille NIS 2 : sources, thèmes, procédure auditeur |
