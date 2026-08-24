# Pistes d'évolution — notes de session (25/08/2026)

> Backlog d'idées, pas un engagement de roadmap. À trier/prioriser plus tard — certaines rentrent
> dans le principe scalable (CLAUDE.md), d'autres sortent volontairement du périmètre du produit.

---

## 1. Rappel — les 3 signaux du patch checker Windows

Pour référence rapide (détail complet : `docs/MATCHING.md`).

| | Signal 2 — Build | Signal 2bis — KB | Signal 3 — Date |
|---|---|---|---|
| **Source** | `CurrentBuildNumber`/`UBR` (registre de la machine) | Article `support.microsoft.com` du KB cité par MSRC | `TimeCreated` du dernier Event ID 19 (Windows Update) |
| **Comparé à** | Plage de version vulnérable NVD (CPE OS) | Build extrait du titre de l'article KB | Date de sortie du correctif (MSRC `releaseDate`, sinon `cve.published`) |
| **Quand utilisé** | En premier, dès que NVD fournit une contrainte de version exploitable | Repli si le signal Build est inexploitable | Repli final, si ni Build ni KB ne tranchent |
| **Fiabilité** | Objective, insensible à la supersession CU | Même niveau de certitude que le Build | Indicative seulement |
| **Alimente `patch_detected`/auto-bascule** | ✅ | ✅ | ❌ jamais |

Les trois ne sont jamais combinés à égalité (vote) : cascade stricte par ordre de fiabilité, pour ne
pas transformer une heuristique faible (date) en confirmation automatique.

---

## 2. Bastion — piste "portail d'accès presta"

Idée de départ : faire passer les prestataires externes par Allsafe pour accéder au bastion
(jump host vers les serveurs critiques), avec un rôle dédié restreint à cette seule vue, sans fuite
d'info sur le reste du parc.

**Deux points à trancher avant tout développement :**

1. **Allsafe = porte d'entrée, jamais le relais.** Allsafe ne doit jamais proxyfier lui-même la
   session SSH/RDP — ça romprait le principe fondateur (non-intervention, jamais rien exécuté/relayé
   vers un serveur). Le vrai bastion (Wallix/Teleport/Guacamole/etc.) doit rester le seul à faire le
   relais et l'enregistrement de session. Allsafe se limite à authentifier le presta, autoriser
   l'accès, et tracer "qui a demandé quoi, quand".
2. **Le risque de fuite est dans l'API, pas dans l'UI.** Réutiliser un rôle `analyst` avec
   `allowed_pages` restreint à la page Bastion suffit côté écran (pas besoin d'un 3ᵉ rôle dans le
   RBAC binaire). Mais `/api/assets` et `/api/vulnerabilities` restent **ouverts à tout compte
   connecté** quelle que soit sa restriction de pages (limite assumée aujourd'hui, acceptable pour
   des collègues internes). Un compte presta externe pourrait taper ces endpoints directement et
   voir noms d'actifs/IP — fuite réelle. À fermer spécifiquement pour ce type de compte, ou à sortir
   complètement du système `User`/session classique (mécanisme d'auth à part, scopé au seul lanceur
   bastion, qui ne passe jamais par `require_auth` générique).

---

## 3. Scan de vulnérabilités hors CVE — état des lieux

**Ce qui existe déjà :**

- **Durcissement automatique** (`services/asset_scanner.py` + `network_protocol_check.py`,
  `web_hardening.py`, `switch_hardening.py`, `vsphere_hardening.py`) — checks CIS-like (mdp SSH root,
  RDP NLA, SMBv1, pare-feu...), stockés en JSON opaque sur `Asset.last_scan_result`/
  `network_compliance`/`web_compliance`. **Codé en dur** : chaque check est une fonction Python
  (`_check(id, label, status, detail)`), pas une table de définitions. Ajouter un check = éditer le
  code et redéployer.
- **`AuditFinding`** (module Audits) — seul endroit du code où une vulnérabilité peut être créée
  **sans aucune CVE** : `title` + `severity` obligatoires, tout le reste (`cvss_vector`, `cve_id`,
  `owasp_ref`...) optionnel. Mais c'est manuel (saisi par un auditeur), jamais scanné automatiquement.
- **`Vulnerability.cve_id`** est `NOT NULL` en base, y compris sur l'endpoint de création manuelle
  (`POST /vulnerabilities` exige `cve_db_id`) — impossible de créer une vuln "scannée en continu" (au
  sens Dashboard CyberVuln) sans CVE, à modèle de données constant.
- **Un seul référentiel de CVE** : NVD (`CVE.source = "nvd"` par défaut). KEV (CISA) et maturité
  d'exploit (Metasploit) sont des *enrichissements* de CVE déjà importées depuis NVD, pas une source
  alternative. GitHub Security Advisories existe dans le code (`services/rss_fetcher.py`) mais
  alimente uniquement CyberVeille (`WatchItem`), circuit totalement séparé du scan CyberVuln. Le
  Debian Security Tracker ne fait que vérifier un correctif sur une CVE déjà connue, jamais découvrir
  de nouvelles CVE.
- `services/withsecure_client.py` a des fonctions `get_detections()`/`get_incidents()` (détections
  EDR comportementales, hors CVE) **non branchées sur aucun router** aujourd'hui — code mort en
  l'état. Le module Vulnerability Management WithSecure (ex-Radar) n'est de toute façon pas souscrit.

**Conclusion actuelle** : pour un vrai scan automatique hors CVE sur tout le parc, il n'existe que
deux voies — coder un nouveau check dans `asset_scanner.py` (et siblings), ou saisir à la main via
`AuditFinding`. Rien entre les deux.

---

## 4. Comparaison Tenable / Cyberwatch — idées vs hors scope

**Dans la philosophie d'Allsafe (lecture seule, on-prem) — à considérer :**

| Idée | Ce que fait Tenable/Cyberwatch | Coût pour Allsafe |
|---|---|---|
| **Catalogue de checks piloté en base** | Fichiers `.audit` Nessus / CIS Benchmarks — un check = une entrée en base, ajoutable sans code | Résout le point 3 ci-dessus une fois pour toutes ; refonte de `asset_scanner.py` vers un modèle data-driven |
| **Fin de vie logicielle (EOL)** | Cyberwatch alerte sur OS/logiciel en fin de support, indépendamment de toute CVE | Faible — cf. détail § 5 |
| **Durcissement Active Directory** | Style PingCastle/BloodHound (comptes Kerberoastables, délégations non contraintes, politique de mdp domaine) | Moyen — extension du connecteur AD déjà lecture seule (`AD_SERVER`), nouvelles requêtes LDAP read-only |
| **SLA de remédiation** | Relance/escalade automatique d'une vuln non traitée après X jours selon sa sévérité | Moyen — rien d'équivalent aujourd'hui sur les vulns (contrairement aux délais NIS 2 côté Incidents) |

**Hors scope assumé — ne pas copier :**

- **Scan actif** (ports, bannières, exploitation "safe check") — Allsafe reste 100%
  credentialed/lecture seule par principe.
- **Déploiement de patch orchestré** (WSUS/package manager) — interdit explicitement par la règle de
  non-intervention (CLAUDE.md § 1).
- **Scan conteneurs/cloud** — hors périmètre (80 VM on-prem, pas de conteneurs).
- **Score de risque propriétaire (VPR)** — Allsafe a déjà CVSS + EPSS + KEV + maturité Metasploit, une
  combinaison équivalente et transparente, pas une boîte noire commerciale.

---

## 5. Détail — fin de vie logicielle (EOL)

**Pourquoi un ROI élevé** (rapport coût/bénéfice) :

- **Coût quasi nul** : `Asset.os`/`os_version`/`installed_packages` sont déjà en base, remplis à
  chaque scan. Le check consiste juste à interroger une API publique gratuite (endoflife.date) et
  comparer à ce qui est déjà stocké — zéro nouvelle collecte, zéro nouveau droit à demander, zéro
  commande de plus sur la machine.
- **Bénéfice élevé** : un OS/logiciel en fin de vie ne recevra **plus jamais** de correctif pour
  aucune CVE future — risque plus grave qu'une CVE isolée (qui a au moins une chance d'être patchée),
  et pourtant angle mort total aujourd'hui.

**Compatible agent ET compte de service, sans code séparé** : `Asset.os`/`os_version`/
`installed_packages` sont remplis par la même fonction partagée `apply_scan_result()`
(`services/asset_scanner.py:659`), qu'il s'agisse du scan pull SSH/WinRM (`collection_method =
"service_account"`) ou du check-in de l'agent Rust (`collection_method = "agent"`,
`routers/agents.py:670`). Le check EOL lirait ces colonnes déjà en base, peu importe leur origine —
aucune branche de code à dupliquer par méthode de collecte.
