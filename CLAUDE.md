# Allsafe — Plateforme cybersécurité on-premise
## Document principal — à lire en priorité

> **Pour économiser les tokens : lire CLAUDE.md + STATUS.md uniquement au démarrage.
> Charger les fichiers docs/ uniquement si la tâche le nécessite.**
>
> `STATUS.md` est volontairement court (état courant, invariants, points ouverts). Le déroulé
> chronologique des sessions passées vit dans `docs/HISTORIQUE.md` — à n'ouvrir que pour retrouver
> le contexte d'une décision, jamais au démarrage.

---

## 💬 Style de réponse

Phrases courtes, pas de préambule ni de formules de politesse. Résultat d'abord, explication
seulement si demandée. Pas de sur-ingénierie ni d'abstraction non demandée (cf. principe scalable
ci-dessous, qui reste la seule raison valable d'anticiper une extension). Ne s'applique qu'aux
réponses en conversation — ne touche pas aux conventions déjà en place dans le code/l'UI (emojis
dans les badges et boutons, tirets longs dans la doc française), qui restent la référence.

---

## 🏗️ Architecture produit

**Allsafe** est le nom du produit global (renommé depuis « CBR » le 11/08/2026, cf. § plus bas — pur
rebranding, aucun changement fonctionnel). Il se structure en modules, visibles dans la nav comme des
groupes (`Layout.jsx` `NAV_GROUPS`), chacun avec sa propre couleur reprise de la tuile d'accueil
correspondante (état actif **et** icône au repos) :

| Module | Couleur | Pages |
|---|---|---|
| **CyberVuln** | `#f85149` rouge | Dashboard, Vulnérabilités, Actifs, CVE — le seul module de fond pleinement implémenté |
| **CyberVeille** | `#58a6ff` bleu | Veille technologique (registre auditable NIS 2), Fuite de données (informatif, sources fuites/ransomware), Surveillance Identités (croise identités surveillées — nom/domaine/IP/plage IP/email — avec les fuites collectées ; IP et email vérifiés en direct contre des sources tierces gratuites, `services/ip_watch.py`/`leak_lookup.py`) — cf. docs/VEILLE.md |
| **Inventaire** | `#39c5cf` cyan | Inventaire Complet — patrimoine IT (CPU/RAM/disques/apps par actif) ; pointe vers les **mêmes actifs** que CyberVuln > Actifs sans s'y confondre : Actifs = vue *sécurité*, Inventaire = vue *patrimoine*. Export PDF global (`services/inventory_export.py`). **Agents** (`docs/AGENTS.md` — implémenté) : agent Rust `allsafe-agent` posé sur un poste Windows/Linux, alternative de collecte au compte de service SSH/WinRM pour les postes qu'il atteint mal — jamais un remplacement des serveurs, lecture seule stricte, choix par actif (`Asset.collection_method`). Test actif/offensif hors scope. **Durcissement** : vue dédiée des checks de conformité CIS-like de tout le parc (cf. `docs/ARCHITECTURE.md` § Durcissement). **Politiques de scan planifié** (`models.py::ScanPolicy`, Paramètres > Intégrations) : scan automatique par groupe de criticité, éditable sans coder, doublé du lancement manuel (cf. `docs/ARCHITECTURE.md` § Politiques de scan planifié). GUI Tauri, téléchargement des paquets et historique global des agents : cf. `docs/AGENTS.md`. **Détection d'évènements sensibles côté poste** (⏳ partiel, cf. `docs/AGENT_DETECTION.md`) |
| **Sécurité** | `#3fb950` vert | **Audits** (ex-« Pentest » — cf. `docs/AUDITS.md`, ✅ implémenté) : un seul modèle couvre les 5 types d'audit (architecture, configuration, code, pentest, Red Team). Principe posé : Allsafe **héberge et trace** l'audit, n'exécute jamais rien d'offensif. Garde-fou structurel : autorisation écrite bloquante, immuable une fois posée. **Bastion** (placeholder) : futur accès jump host vers les serveurs critiques, sans rapport avec l'ancien module « Bastion » retiré (cf. encadré ci-dessous) — entrerait en conflit frontal avec la règle de non-intervention, à trancher avant implémentation |
| **Rapports** | `#a371f7` violet | Rapport exécutif CVE, Rapport Veille, Rapport Surveillance — les trois avec des **rapports hebdomadaires figés** (générés le lundi 7h, export CSV, cf. `docs/ARCHITECTURE.md` § Rapports hebdomadaires figés) ; le rapport CVE se décline en plus par actif. Rapport Incidents à part : **par incident**, généré à la demande, jamais figé — un incident est rare, jamais plusieurs la même semaine (cf. docs/INCIDENTS.md § 7). ⚠️ "export PDF" n'existe pas côté serveur pour ces rapports — seul CSV est généré en backend (le seul export PDF serveur du projet est celui d'Inventaire, `reportlab`) ; le bouton "Exporter PDF" des 4 rapports (dont Incidents) est une impression navigateur côté client (`ReportMarkdown.jsx::exportPdf`), pas un fichier généré côté serveur |
| **Incidents** | `#b5793a` marron | Registre incidents — déclaration, qualification NIS 2 (`requires_notification`, **toujours manuelle**) et suivi des 3 échéances légales (Art. 23 : alerte précoce 24h, notification 72h, rapport final 1 mois calendaire). L'app ne notifie **jamais** elle-même l'ANSSI — trace qui a déclaré/qualifié/envoyé quoi et quand (`services/nis2_deadlines.py`). Préremplissage depuis Sécurité/Vulnérabilités/Veille, roadmap de réponse + annuaire de contacts (ANSSI/CERT-FR/CNIL/police), pièces jointes PDF — détail complet : `docs/INCIDENTS.md`. **Gestion de crise** (page séparée `/crises`) : escalade en crise, cellule nommée, journal de décisions/communications, jamais d'envoi réel (docs/INCIDENTS.md § 5ter) |
| **Gouvernance** (ex-« Documentation », renommé le 18/08/2026) | `#e3b341` or | Documents de gouvernance nécessaires à la conformité NIS 2 : PSSI, Charte Administrateur, Charte Utilisateur, Organigramme en seed — registre de types ouvert (`DocumentType`), ajoutable sans code (spécifique à ce module, contrairement à Services/Rôles). Formats acceptés : PDF/Word/Excel/PNG/JPEG (validation par signature de fichier, 10 Mo max, `services/document_storage.py`). Historique des versions conservé, prévisualisation native PDF/images + glisser-déposer — détail : `docs/ARCHITECTURE.md` § Module Gouvernance |
| **Paramètres** | `#8b949e` gris | Transverse — nav à deux volets sans tuile (cf. `docs/FRONTEND.md` § Settings.jsx) : Présentation (mode démo), Apparence (thème), **Compte** (identité, mot de passe, sessions actives, nom d'analyste par défaut), **Intégrations** (statut configuré + dernière synchro des connecteurs externes, lecture seule), **Sécurité** (ligne → Administration, réservée admin). Onglets « Services » et « Rôles » (organigramme poste → personne → email, `OrganizationRole`) consommés par Incidents et Gestion de crise. Le registre « Analystes » (dropdowns `validated_by`) est géré depuis Administration, pas Paramètres (cf. § Authentification) |
| **Notes de version** | `#f778ba` rose | Détaché de Paramètres — module à part entière, lien simple sous Paramètres dans la nav. Changelog produit (`models.py::ReleaseNote`, table unique `scope='allsafe'`/`'agent'`) : nouveautés/correctifs groupés par version, résumé replié par défaut, détail au clic (`ReleaseNotesPanel.jsx`) — alimenté en fin de session par l'assistant, relu/validé par l'utilisateur. Le scope `agent` reste sur sa propre page sous Inventaire > Agents (`/agents/notes-de-version`). Détail : `docs/ARCHITECTURE.md` § Table `release_notes` |

⚠️ **Module Bastion / Administration retiré le 30/07/2026** : l'ancien sélecteur « Je suis… » en bas
de sidebar (`visible_modules`, filtrage de nav par profil, aucun mot de passe ni session) a été
supprimé intégralement — pure personnalisation d'affichage sans valeur de sécurité, remplacée le même
jour par une vraie authentification (cf. § Authentification ci-dessous). Seul le registre de noms
d'analystes a été conservé (déplacé dans Paramètres) pour ne pas casser les dropdowns d'attribution
existants (`validated_by` et équivalents).

Dans le code, "CyberVuln" reste le nom historique de plusieurs modules internes (dossier `backend/`,
title `Gestion des vulnérabilités`...) — ne pas chercher à tout renommer, seule l'identité visible
(sidebar, `<title>` HTML) porte le nom actuel du produit.

**Rebranding CBR → Allsafe (11/08/2026)** : le produit s'appelait « CBR » jusqu'à cette date — pur
changement d'identité visible (wordmark, `<title>` HTML, textes UI), aucun changement fonctionnel.
Même règle que pour "CyberVuln" ci-dessus : identifiants internes (`cybervuln`, `cbr_app`,
`CbrMark.jsx`, `--brand-*`) et journal historique déjà écrit (`docs/HISTORIQUE.md`) ne sont **jamais**
retouchés rétroactivement — "CBR" y reste exact pour la période qu'il décrit. Détail : `docs/HISTORIQUE.md`
(11/08/2026) et (01/07/2026, rebranding CyberVuln → CBR initial).

**Page d'accueil (`/`, `pages/Home.jsx`)** : sélecteur de module, sans sidebar — une tuile par module
ci-dessus (mêmes couleurs), redirige vers la première page du module choisi (Dashboard CyberVuln vit
sur `/dashboard`, pas `/`). Le logo/titre "Allsafe" dans la sidebar (`Layout.jsx`) ramène toujours à
`/`. Sidebar réductible (bouton `<`, bascule vers une fine bande d'icônes), état persisté côté client.
Détail : `docs/FRONTEND.md` § Home.jsx.

**Guide d'aide contextuel** : bouton flottant monté une seule fois dans `Layout.jsx`
(`components/PageGuide.jsx`), résout son contenu selon la route courante (`constants/pageGuides.js`)
et se thème avec la couleur du module actif. Masquable globalement (Paramètres > Apparence,
`contexts/GuidePreferenceContext.jsx`). Détail : `docs/FRONTEND.md` § Guide d'aide contextuel.

### 🧭 Principe directeur : penser scalable

Ce projet est **en évolution permanente**, pas un livrable figé — chaque nouvelle fonctionnalité doit
être pensée pour être étendue sans réécriture. Concrètement : préférer une donnée pilotée en base
(ex. `WatchSource`, sources de veille ajoutables par l'utilisateur sans toucher au code ; `Analyst`,
registre des analystes remplaçant la liste `ANALYSTS` codée en dur, cf. Administration ci-dessus) à
une liste codée en dur quand l'utilisateur est susceptible d'en vouloir d'autres plus tard ; extraire
un composant/util partagé dès qu'une deuxième page a besoin de la même logique non triviale (formulaire,
modale...) plutôt que de la dupliquer une deuxième fois ; éviter les couplages étroits entre modules
placeholder (Audits, Bastion) et modules actifs, pour ne pas bloquer leur future implémentation.

## 🎯 Contexte

CyberVuln (le module) est une alternative open source à **Cyberwatch** (13 500 €/an).
Économie estimée : 82 à 93% du coût annuel.

**Périmètre : 80 VM on-premise**
- Majorité Windows Server (jointes Active Directory)
- Minorité Linux (nombre exact inconnu)
- 100% on-premise, pas de cloud

**Stack : FastAPI + React + PostgreSQL + Redis + Celery + Docker Compose**

---

## ⚠️ Règles absolues — Ne jamais enfreindre

### 1. Non-intervention sur les serveurs
CyberVuln est un outil d'**aide à la décision** : il n'exécute et n'écrit **jamais** rien sur un serveur, quelle que soit la sévérité de la CVE. Cette partie-là est absolue et non négociable.

En revanche, la bascule du **statut de la vulnérabilité dans CyberVuln lui-même** (pas sur le serveur) dépend de la sévérité :

| Action | CyberVuln | Analyste humain |
|--------|-----------|-----------------|
| Collecter infos VM (lecture seule) | ✅ | |
| Détecter et prioriser les vulnérabilités | ✅ | |
| Générer une recommandation / script | ✅ (proposé) | |
| Vérifier si un correctif est détecté (lecture seule) | ✅ (signalement) | |
| Valider, tester, appliquer le correctif sur le serveur | | ✅ (toujours, quelle que soit la sévérité) |
| Marquer une vuln **CRITICAL** comme corrigée | | ✅ (obligatoire, jamais automatique) |
| Marquer une vuln **HIGH / MEDIUM / LOW** comme corrigée | ✅ (auto si `patch_detected: true`) | ✅ (peut aussi valider/réouvrir) |
| Qualifier une vuln **CRITICAL** en faux positif | | ✅ (obligatoire, jamais automatique) |
| Qualifier une vuln **HIGH / MEDIUM / LOW** en faux positif | ✅ (auto si `not_applicable: true` — produit absent de la machine) | ✅ (peut aussi qualifier/réouvrir) |
| Passer une vuln **CRITICAL** en attente de correctif | | ✅ (obligatoire, jamais automatique) |
| Passer une vuln **HIGH / MEDIUM / LOW** en attente de correctif | ✅ (auto si `no_fix_available: true` — la distro n'a publié aucun correctif) | ✅ (peut aussi annoter/réouvrir) |
| Passer une vuln **CRITICAL** en attente de correctif partiel (cas mixte) | | ✅ (obligatoire, jamais automatique) |
| Passer une vuln **HIGH / MEDIUM / LOW** en attente de correctif partiel (cas mixte) | ✅ (auto si `partial_fix: true` — un paquet visé absent, un autre installé sans correctif) | ✅ (peut aussi annoter/réouvrir) |

La connexion SSH est **lecture seule** : `hostname`, `cat /etc/os-release`, `dpkg -l`, vérification de version de paquets. Aucune écriture, aucune exécution distante. Jamais.
Le compte AD est **lecture seule**. Aucune modification de l'annuaire.

**Workflow vérification de patch :**
1. CyberVuln détecte via SSH/WinRM (read-only) si le correctif semble appliqué
2. Selon la sévérité de la CVE :
   - **CRITICAL** → CyberVuln signale le résultat (`patch_detected: true/false`) ; l'analyste valide et marque manuellement la vuln comme `patched`. Jamais de bascule automatique sur du CRITICAL.
   - **HIGH / MEDIUM / LOW** → si `patch_detected: true`, CyberVuln bascule automatiquement la vuln en `patched` (`validated_by = "Auto (patch check)"`). L'analyste peut réouvrir à tout moment s'il constate une erreur.
3. Dans tous les cas, l'action reste limitée à la base CyberVuln — aucune commande n'est jamais exécutée sur le serveur pour "confirmer" ou "appliquer" quoi que ce soit.

**Deux issues automatiques distinctes, à ne jamais confondre** (session 21/07/2026) :
- `patched` — un correctif a été **détecté** sur la machine (`patch_detected: true`).
- `false_positive` — la CVE **ne s'applique pas** : aucun des paquets visés n'est installé
  (`not_applicable: true`). Rien n'a été corrigé, le produit n'a jamais été là. Annoncer "corrigé"
  dans ce cas fausserait la piste d'audit NIS 2. La raison est recopiée dans `notes` pour rester
  exploitable sans rouvrir le rapport technique.

Une troisième issue automatique s'y ajoute (21/07/2026) : `awaiting_fix` quand la distribution n'a
publié **aucun correctif** (`no_fix_available: true`, statut « open » du Debian Security Tracker) —
il n'y a rien à appliquer sur le serveur. Contrairement à `false_positive`, ce statut **reste dans le
cycle de recheck** : la vuln bascule seule en `patched` dès que le correctif sort.

Une quatrième s'y ajoute (27/07/2026) : `awaiting_fix_partial`, cas **mixte** — une CVE vise plusieurs
paquets, l'un absent de l'actif (hors sujet) et l'autre bien installé mais sans correctif Debian publié
(`partial_fix: true`, cf. `services/patch_checker.py`). Ni `false_positive` (un paquet concerné est
réellement là) ni `awaiting_fix` au sens strict (annoncer que *tout* le correctif est en attente serait
trompeur alors qu'une partie de la CVE ne s'applique pas) — statut dédié pour que le rapport reste
exact. Même comportement qu'`awaiting_fix` : reste dans le cycle de recheck, bascule seule en `patched`
dès publication. Avant ce statut, ce cas ne correspondait à aucune branche automatique et restait
ouvert sans signal exploitable (3 CVE sur `gitlab.aer.loc` qualifiées manuellement le 21/07, cf.
STATUS.md).

La règle de sévérité est **la même pour les quatre** : CRITICAL toujours manuel, HIGH/MEDIUM/LOW
automatique et réouvrable.

⚠️ **Garde-fou — une décision humaine n'est jamais écrasée**, en deux niveaux :
1. **États terminaux** (`false_positive`, `patched`, `accepted_risk`) : jamais modifiés
   automatiquement, quelle que soit l'origine de la décision.
2. **Décision humaine sur un état non terminal** (typiquement `awaiting_fix` annoté par un
   analyste) : seule la **détection d'un correctif** peut la faire évoluer, vers `patched`. C'est la
   raison d'être du statut « en attente » — il doit se résoudre seul dès publication. Toute autre
   requalification automatique (faux positif, remise en attente) est bloquée.

Le cycle autonome n'y touchait déjà pas, mais le bouton "Patch check" unitaire est cliquable sur
n'importe quelle ligne : sans ce garde-fou, contrôler une vuln déjà qualifiée écrasait son statut
**et son annotation** (incident réel, 21/07/2026). Attention à ne pas le durcir à l'excès non plus —
une première version bloquait aussi la progression légitime `awaiting_fix` → `patched`.

### 2. Anonymisation vers l'API Claude

| Donnée | Vers API Claude | Stockage local (PostgreSQL) |
|--------|----------------|-----------------------------|
| Nom d'hôte (`srv-prod-01`) | ❌ Jamais | ✅ Local uniquement |
| Adresse IP | ❌ Jamais | ✅ Local uniquement |
| Liste des paquets installés | ❌ Jamais | ✅ Local uniquement |
| OS exact + version build | Générique (`Windows Server (recent)`) | ✅ Complet en local |
| Type d'actif | Générique (`Serveur de production`) | ✅ Complet en local |
| CVE ID + description | ✅ Envoyé (information publique NVD) | ✅ Stocké |
| Scores CVSS / EPSS | ✅ Envoyé (information publique) | ✅ Stocké |
| Stats agrégées (rapports) | ✅ Envoyé (pas de données nominatives) | ✅ Stocké |

PostgreSQL tourne dans Docker sur votre réseau interne. Aucune donnée nominative ne sort de votre infrastructure.

⚠️ **État actuel de l'implémentation** : `services/claude_analyzer.py` (bouton "Analyser IA") n'appelle
**pas** l'API Claude — c'est 100% des règles de mots-clés locales (aucun `anthropic`/appel HTTP vers
l'API dans le code, malgré `ANTHROPIC_API_KEY` configuré dans `.env`). Le tableau ci-dessus décrit la
règle à respecter si/quand un vrai appel API est implémenté, pas le comportement actuel — aucune donnée,
anonymisée ou non, ne part vers Claude aujourd'hui.

### 3. Authentification

Authentification réelle (30/07/2026, remplace le module Bastion retiré le même jour — sans rapport
avec le nouveau placeholder « Bastion » du module Sécurité ci-dessus) : compte email/mot de passe
(`models.py::User`, hash `bcrypt`, champ avec bascule afficher/masquer `components/PasswordInput.jsx`),
session par cookie **HttpOnly** (jamais accessible en JS, jamais dans
`localStorage`), RBAC **binaire** `admin` / `analyst`. Toutes les routes `/api/*` exigent une session
valide (`Depends(require_auth)`, posé sur chaque router dans `main.py`), sauf `/api/health` et
`POST /api/auth/login`. `/api/connections` (lecture), `/api/security/*` (sauf le compteur badge),
`/api/users` et l'écriture sur `/api/analysts` (lecture ouverte à tous, cf. ci-dessous) sont en plus
réservés au rôle `admin` (`Depends(require_admin)`).

⚠️ **Le rôle `admin`/`analyst` ne change rien aux règles de sévérité** du tableau de non-intervention
ci-dessus (§1) : un `analyst` peut valider/qualifier n'importe quelle vuln HIGH/MEDIUM/LOW comme
aujourd'hui, CRITICAL reste toujours manuel quel que soit le rôle. `admin` gère uniquement les comptes,
les connexions IP et la console de déception — pas un niveau de confiance supérieur sur les vulns.

Le registre `Analyst` (noms utilisés dans les dropdowns `validated_by`/attribution) reste **séparé**
des comptes de connexion — décision reconfirmée après usage réel, pas de fusion. Sa gestion (CRUD) a
déménagé de Paramètres vers **Administration** (onglet « Analystes », 30/07/2026) : la lecture reste
ouverte à tout connecté (les dropdowns en ont besoin partout), l'écriture est réservée admin — avant
ce déplacement, n'importe quel compte pouvait modifier ce registre depuis Paramètres. Créer un compte
(Administration > Utilisateurs) intègre automatiquement son nom au registre `Analyst` s'il n'y est
pas déjà (31/07/2026, `routers/users.py::_ensure_analyst`) — simple raccourci de saisie, toujours pas
de fusion des deux tables. Détail complet du schéma et des endpoints : `docs/ARCHITECTURE.md` §
Authentification.

**Politique de mot de passe** (14/08/2026, centralisée dans `services/auth.py::validate_password_strength`,
avant dupliquée en deux endroits avec juste une longueur minimale) : 16 caractères minimum + au moins
une majuscule, une minuscule, un chiffre et un caractère spécial, appliquée à la création de compte
(admin) et au changement par soi-même. Le frontend calque un indice de force en temps réel sur
exactement ces mêmes règles (`components/PasswordStrengthHint.jsx`, Paramètres + écran de changement
forcé) — à garder synchronisés si la politique change.

**Gestion de son propre compte depuis Paramètres > Compte** (14/08/2026, demande utilisateur — jusque-là
seule la déconnexion était possible) : changer son email et son mot de passe (mot de passe actuel
requis dans les deux cas, `PATCH /api/auth/change-email` / `POST /api/auth/change-password`) ; voir et
révoquer ses propres sessions actives (`GET`/`DELETE /api/auth/sessions`, pendant self-service du
`POST /api/users/{id}/revoke-sessions` réservé admin sur un *autre* compte) ; nom d'analyste par défaut
(préférence 100% client, `localStorage`, `contexts/AnalystPreferenceContext.jsx` — met en avant son nom
dans `ValidateDropdown.jsx`/pré-remplit `AnnotationModal.jsx`, jamais sur une ré-édition d'une
annotation qui a déjà un validateur enregistré).

**Statut des intégrations externes** (14/08/2026, page Paramètres > Intégrations, `GET
/api/integrations/status`) : configuré/non configuré (présence de la config, jamais la valeur d'un
secret) + dernière synchro connue pour NVD/GitHub/AD/SSH/WithSecure/Meraki/PRTG/GLPI/vSphere — lit
directement `sync_state` plutôt que de rappeler chaque `GET /api/<service>/status` existant.

**Droits d'accès par module/page pour un compte `analyst`** (31/07/2026, `User.allowed_pages`) :
`admin` voit toujours tout module confondu (inchangé, § ci-dessus). Un `analyst` a par défaut accès
total (`allowed_pages = NULL`) ; un admin peut le restreindre à une liste de pages précises
(granularité module + sous-module, ex. « Registre incidents » sans « Gestion de crise »), depuis le
formulaire de compte (Administration > Utilisateurs). Contrôlé **côté serveur**
(`auth_deps.py::require_page`, posé par module sur les routers dans `main.py` — même mécanisme que
`require_admin`), pas seulement masqué dans la nav : un masquage purement visuel n'aurait aucune
valeur de sécurité (c'est exactement pour ça que l'ancien sélecteur « Je suis… » avait été retiré le
30/07/2026, § ci-dessus). ⚠️ **Limite assumée** : `/api/assets` et `/api/vulnerabilities` restent
ouverts à tout compte connecté quelle que soit sa restriction — lus en cross-référence par de
nombreuses autres pages (Dashboard, Incidents, Rapports, Veille pour les noms d'actifs/vulns), les
gater casserait ces pages pour un analyste sans accès à Inventaire/CyberVuln. `/settings` n'est
jamais restreignable (thème, déconnexion, changement de mot de passe forcé).

Pas de badge utilisateur/déconnexion dans la sidebar (retiré le 30/07/2026, jugé redondant vu qu'il
n'y a qu'un admin permanent) — la déconnexion se fait depuis Paramètres > section « Compte », en bas
de page.

---

## 📁 Structure des fichiers

> Arborescence complète (frontend inclus) : `docs/FRONTEND.md`. Ci-dessous, backend uniquement.

```
cybervuln/
├── CLAUDE.md                    ← CE FICHIER — lire en priorité
├── STATUS.md                    ← Suivi de session — lire à chaque démarrage
├── docker-compose.yml           ✅
├── .env.example                 ✅
├── .env                         (ne jamais commiter)
├── keys/
│   └── id_ed25519               (clé SSH Linux, ne jamais commiter)
├── docs/
│   ├── ARCHITECTURE.md          → Stack, BDD, Docker, endpoints API
│   ├── SECURITY.md              → Anonymisation, SSH, AD, non-intervention
│   ├── MATCHING.md              → CPE matcher, scoring, patch checker (Windows + Linux/Debian tracker)
│   ├── FRONTEND.md              → Dashboard, composants React, design
│   ├── VEILLE.md                → Module veille cyber NIS 2 (sources, workflow, export auditeur)
│   ├── INCIDENTS.md             → Module Incidents (délais NIS 2 Art. 23, garde-fous, workflow)
│   ├── AUDITS.md                → Module Audits (5 types, autorisation bloquante, findings, retest)
│   ├── AGENTS.md                → Agent Rust allsafe-agent (enrôlement, checks, empaquetage)
│   ├── AGENT_DETECTION.md       → ⏳ Détection d'évènements sensibles côté poste
│   └── HISTORIQUE.md            → Journal des sessions passées
├── frontend/                    ✅ — arborescence détaillée dans docs/FRONTEND.md
├── agent/                       ✅ — agent Rust `allsafe-agent` (module Inventaire > Agents), lecture
│                                  seule, complète le scan centralisé SSH/WinRM sur les postes qu'il
│                                  atteint mal — jamais un remplacement des serveurs. Détail complet
│                                  (empaquetage .deb/.msi/.exe, GUI Tauri, mode service) : docs/AGENTS.md
└── backend/
    ├── Dockerfile               ✅
    ├── requirements.txt         ✅
    ├── main.py                  ✅ — lifespan lance le cycle patch check en tâche de fond au démarrage
    │                              + bootstrap du 1er compte admin (BOOTSTRAP_ADMIN_EMAIL/PASSWORD)
    ├── config.py                ✅
    ├── database.py              ✅ — poolclass=NullPool (cf. docs/ARCHITECTURE.md)
    ├── auth_deps.py             ✅ — dependencies FastAPI require_auth/require_admin/require_page +
    │                              require_agent (en-tête X-Agent-Token, identité non-humaine distincte
    │                              des comptes utilisateurs — cf. routers/agents.py)
    ├── models.py                ✅ — CVE, Asset, Vulnerability, VulnerabilityStatusHistory, Feed, WatchItem, WatchSource, SyncState, WatchedIdentity, ConnectionLog, KbBuild, Report, WatchProfileItem, SecurityEvent, Incident, IncidentTimelineEntry, IncidentNotificationContact, IncidentAttachment, Crisis, CrisisTimelineEntry, CrisisContact, Analyst, OrganizationRole, Service, DocumentType, Document, WindowsAppMapping, User, UserSession, AuthAuditLog, Audit, AuditAsset, AuditFinding, AuditFindingHistory, AuditAttachment, NetworkStatus, PatchCheckAssetCompletion, Agent, AgentEnrollmentToken, ScanPolicy, ReleaseNote
    ├── db/
    │   ├── legacy_views.sql  ✅ — honeypots DB (vues + rôles leurres, honeytokens) → security_events.
    │   │                          Idempotent. NE JAMAIS référencer ces objets dans le code (cf.
    │   │                          docs/ARCHITECTURE.md § Déception)
    │   ├── app_role.sql         ✅ — rôle applicatif `cbr_app` à privilèges réduits (DML only, non
    │   │                          superuser) ; l'app tourne avec lui, pas le superuser `cybervuln`
    │   ├── ddl_guard.sql        ✅ — event trigger : bloque + journalise toute DDL par un rôle non
    │   │                          whitelisté → security_events (source `ddl_attempt`)
    │   └── schema_patches.sql   ✅ — `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`/`CREATE TABLE IF NOT
    │                              EXISTS` centralisés (pas d'Alembic). À exécuter avec `cybervuln`,
    │                              jamais `cbr_app` (bloqué par ddl_guard.sql)
    ├── services/                → nvd_fetcher/rss_fetcher/watch_fetcher (docs/VEILLE.md), net_guard
    │                              (anti-SSRF, `validate_public_url`), asset_importer/asset_scanner/
    │                              scan_policy/ssh_trust/crypto (scan + durcissement du parc),
    │                              vuln_history/incident_timeline/audit_finding_history (3 journaux
    │                              append-only distincts, un par module — pas fusionnés), cpe_matcher/
    │                              scoring/remediation/patch_checker/debian_tracker/kb_build (docs/
    │                              MATCHING.md), stats, watch_profile/ip_watch (Surveillance Identités),
    │                              weekly_report/watch_report/identity_report (rapports hebdo figés —
    │                              Incidents a son propre rapport non figé, incident_report.py),
    │                              nis2_deadlines (docs/INCIDENTS.md), incident_attachments/
    │                              document_storage/audit_attachments (validation pure de pièces
    │                              jointes, même schéma), incident_report/audit_report (markdown à la
    │                              demande, jamais persisté), backup, inventory_export (seul export PDF
    │                              serveur du projet), withsecure_client/meraki_client/prtg_client/
    │                              glpi_client + leurs `*_matcher.py` (clients API lecture seule +
    │                              appariement hostname ↔ Asset par intégration externe — seul GLPI
    │                              n'écrit jamais `network_status` ni ne crée d'actif), auth (bcrypt,
    │                              sessions cookie, `validate_password_strength()`). Détail
    │                              architectural complet par fichier : docs/ARCHITECTURE.md.
    │   ├── claude_analyzer.py   ⚠️ règles de mots-clés locales — n'appelle PAS l'API Claude malgré le
    │   │                          nom (cf. § Anonymisation ci-dessus, état actuel de l'implémentation)
    │   ├── asset_scanner.py     — `apply_scan_result()` partagé par le scan pull (SSH/WinRM) et le push
    │   │                          agent (`routers/agents.py::checkin`), jamais de logique dupliquée
    │   └── agent_detection.py   ⏳ PARTIEL — cf. docs/AGENT_DETECTION.md
    ├── routers/                 → cves.py, assets.py, vulnerabilities.py, stats.py, analysis.py,
    │                              remediation.py, reports.py, sync.py, patch_check.py, connections.py,
    │                              watch.py, identities.py, security.py, backup.py, withsecure.py,
    │                              meraki.py, prtg.py, glpi.py, incidents.py, crises.py, analysts.py,
    │                              organization_roles.py, services.py, documents.py,
    │                              windows_app_mappings.py, audits.py, users.py, agents.py,
    │                              integrations.py, scan_policies.py ✅ (tous montés dans main.py).
    │                              `auth.py` seul sans dependency globale (`/login` public, le reste
    │                              protégé par route) ; `patch_check.py`/`scan_policies.py` montés sans
    │                              dependency de niveau router (jeton interne `X-Internal-Token`, pas de
    │                              session — une dependency de router s'exécuterait avant et le rejetterait)
    ├── tasks/
    │   └── scheduled_tasks.py   ✅ — Celery beat, planning détaillé dans docs/ARCHITECTURE.md
    └── tests/                   ✅ — sans base de données : test_patch_checker_guardrails.py,
        test_vulnerabilities_status_transitions.py, test_nis2_deadlines.py, test_incidents_guardrails.py,
        test_incident_attachments.py, test_auth_guardrails.py
```

`backend/routers.py` (fichier plat à la racine, code mort jamais importé) a été supprimé — ne pas le
recréer, le package `routers/` fait foi.

Les dossiers `services/` et `tasks/` **à la racine du dépôt** (hors `backend/`) ont été supprimés le
21/07/2026 : copies obsolètes, hors du contexte de build Docker (`./backend`) donc jamais exécutées.
Ne pas les recréer — `backend/services/` et `backend/tasks/` font foi.

---

## 🚀 Commandes essentielles

```bash
# Démarrer
docker compose up --build

# Premier import des actifs
curl -X POST http://localhost:8000/api/sync/assets

# Première sync NVD
curl -X POST "http://localhost:8000/api/sync/nvd?days=30"

# Docs API
open http://localhost:8000/api/docs
```

---

## 📋 Variables d'environnement (.env)

```env
DB_USER=cybervuln      # superuser (init db, admin, migrations, déception) — PAS utilisé par l'app
DB_PASSWORD=           # ← À remplir
APP_DB_USER=cbr_app    # rôle applicatif à privilèges réduits (DML only) — l'app tourne avec lui
APP_DB_PASSWORD=       # ← À remplir (rôle créé par backend/db/app_role.sql). Si vide → repli sur DB_USER
DB_MAX_CONCURRENT_SESSIONS=15  # sémaphore sur database.py::get_session — pas un pool de connexions
                       # (NullPool conservé, nécessaire pour Celery), juste un plafond de requêtes
                       # HTTP simultanées. Historique de la valeur (5→15) : docs/HISTORIQUE.md
REDIS_URL=redis://redis:6379
ANTHROPIC_API_KEY=     # ← À remplir
NVD_API_KEY=           # Optionnel, recommandé (gratuit nvd.nist.gov)
GITHUB_TOKEN=          # Optionnel, gratuit, aucun scope (Surveillance Identités § domaine, cf. leak_lookup.py)
AD_SERVER=ldap://dc01.domaine.local
AD_USER=CN=svc-cybervuln,OU=ServiceAccounts,DC=domaine,DC=local
AD_PASSWORD=           # ← À remplir
AD_BASE_DN=DC=domaine,DC=local
AD_OU=OU=Servers,DC=domaine,DC=local
AD_USE_TLS=false       # false = StartTLS sur ldap:// existant (défaut) ; true = ldaps:// implicite (port 636)
SSH_USER=svc-cybervuln
SSH_KEY_PATH=/app/keys/id_ed25519
SSH_KNOWN_HOSTS=       # défaut résolu à /app/ssh-state/known_hosts (TOFU, cf. services/ssh_trust.py) —
                       # volume nommé séparé de /app/keys (:ro depuis le 10/08/2026, cf. audit/AUDIT_SECURITE.md)
LINUX_HOSTS=10.0.1.50,10.0.1.51
SECRET_KEY=            # ← À remplir
DEBUG=false
STARTUP_MATCHING=true      # false = redémarrer le backend sans effet de bord sur les données
STARTUP_PATCH_CHECK=true   # idem ; les deux restent déclenchables manuellement via l'API
BACKUP_RETENTION_DAYS=14   # pg_dump quotidien (4h) — optionnel, défaut 14
WITHSECURE_API_CLIENT_ID=      # ← À remplir (client OAuth2 "Read-only", Security Center > Gestion >
WITHSECURE_API_CLIENT_SECRET=  #   Paramètres de la société > Clients API). Module VM/ex-Radar non utilisé.
MERAKI_API_KEY=                 # Clé API perso (Dashboard > Profil > My profile > API access) — supervision
MERAKI_ORGANIZATION_ID=         #   réseau en ligne/hors ligne (services/meraki_client.py). Organisation
                                 #   optionnelle : sans elle, agrège toutes celles visibles par la clé.
PRTG_URL=                       # URL de base du serveur PRTG (API cœur, pas Multiboard), ex.
PRTG_API_TOKEN=                 #   https://prtg.exemple.local:8443 — supervision réseau en ligne/hors
                                 #   ligne des actifs déjà connus d'Allsafe (services/prtg_client.py). Ne
                                 #   crée jamais d'actif, contrairement à l'option Meraki équivalente.
GLPI_URL=                       # URL de l'API REST GLPI (le fichier apirest.php, pas l'interface web),
GLPI_APP_TOKEN=                 #   ex. https://glpi.exemple.local/apirest.php. App-Token = client API
GLPI_USER_TOKEN=                #   dédié (Configuration > Générale > API) ; User-Token = jeton personnel
                                 #   d'un compte de service en lecture seule (jamais l'admin GLPI).
                                 #   Enrichit le patrimoine (modèle/n° série/fabricant/localisation) des
                                 #   actifs déjà connus (services/glpi_matcher.py) — ne crée jamais
                                 #   d'actif, contrairement à Meraki/PRTG.
BOOTSTRAP_ADMIN_EMAIL=          # 1er compte admin créé au démarrage si la table users est vide —
BOOTSTRAP_ADMIN_PASSWORD=       #   ← à retirer de .env après la première connexion (cf. CHECKLIST_DOCKER.md)
COOKIE_SECURE=false             # true seulement derrière un reverse-proxy TLS (aucun aujourd'hui)
```

---

## 📖 Documentation détaillée

Charger uniquement si nécessaire pour la tâche en cours :

- `docs/ARCHITECTURE.md` → BDD, Docker, API endpoints complets
- `docs/SECURITY.md`     → Détails anonymisation, SSH, AD
- `docs/MATCHING.md`     → CPE matcher, scoring, workflow correctifs
- `docs/FRONTEND.md`     → Dashboard React, composants, design UI
- `docs/VEILLE.md`       → Outil de veille cyber NIS 2 : modèle WatchItem, sources, workflow auditeur
- `docs/INCIDENTS.md`    → Module Incidents : modèle de données, délais NIS 2 (Art. 23), garde-fous, workflow
- `docs/AUDITS.md`       → Module Audits (implémenté le 03/08/2026) : 5 types d'audit, autorisation
                           bloquante, findings, retest
- `docs/AGENTS.md`       → Agent Rust `allsafe-agent` (postes Windows/Linux) : modèle de données, auth
                           par jeton d'enrôlement, checks de durcissement collectés, empaquetage .deb/.msi
- `docs/AGENT_DETECTION.md` → ⏳ PARTIELLEMENT IMPLÉMENTÉ (19/08/2026) : détection d'évènements
                           sensibles côté poste (compte créé, privesc, process suspect, altération d'audit)
                           par lecture des journaux natifs + diff d'état — lecture seule, cible Niveau 2 hybride.
                           Fondations backend (`services/agent_detection.py`) + socle diff agent
                           (Linux/Windows) livrés et vérifiés en conditions réelles ; reste l'enrichissement
                           journal natif (process suspect, altération d'audit) et tout le frontend
- `docs/HISTORIQUE.md`   → Journal des sessions passées (pourquoi telle décision, incidents déjà vus)
- `docs/vulnerabilites_securite.md` → Backlog vivant de vulnérabilités/checks à couvrir (WSTG, OWASP,
                           AD, durcissement poste), étiqueté 🔍 détection passive / ⚔️ test actif,
                           statut ✅/⚠️/❌ par item — a nourri les checks de durcissement de l'agent

`ROADMAP_RNCP42335.md` (racine) → pilotage de l'alignement du projet sur le titre RNCP visé par
l'utilisateur (échéance juillet 2028) : matrice de traçabilité compétence → artefact, séquencement.
À consulter avant de proposer un nouveau chantier — il dit ce qui sert le titre et ce qui n'y sert pas.

## 🎨 Design Frontend
Avant tout travail sur le frontend, lire `docs/FRONTEND.md` en entier.
Le design réel de l'app est **Tailwind + styles inline avec variables CSS** (dark/light mode) —
`@tremor/react` est dans `package.json` mais n'est utilisé nulle part, ne pas l'introduire dans du
code neuf (détonnerait avec le reste de l'app). Détail dans `docs/FRONTEND.md` § Stack Frontend.
