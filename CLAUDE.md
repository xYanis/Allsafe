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
| **CyberVeille** | `#58a6ff` bleu | Veille technologique (registre auditable NIS 2), Fuite de données (informatif, sources fuites/ransomware), Surveillance Identités (croise des identités surveillées — nom, domaine, IP/plage IP, email — avec les fuites déjà collectées ; nom/domaine sans source externe propre, IP et email vérifiés en direct contre des sources tierces 100% gratuites — `services/ip_watch.py`, `services/leak_lookup.py` — cf. docs/VEILLE.md) |
| **Inventaire** | `#39c5cf` cyan | Inventaire Complet — patrimoine IT (CPU/RAM/disques/apps par actif) ; pointe vers les **mêmes actifs** que CyberVuln > Actifs sans s'y confondre : Actifs = vue *sécurité* (vulns/patch), Inventaire = vue *patrimoine*. Export PDF global (28/07/2026, `services/inventory_export.py`) : tableau récapitulatif + détail des apps par actif. **Agents** (12/08/2026, `docs/AGENTS.md` — implémenté, pas un placeholder ; rattaché à Inventaire depuis le même jour, pas Sécurité — plus cohérent : méthode de collecte du patrimoine, pas une fonction de sécurité offensive/opérationnelle) : agent Rust `allsafe-agent` posé sur un poste Windows/Linux, alternative de collecte au compte de service SSH/WinRM centralisé pour les postes qu'il atteint mal (éteints, hors réseau, VPN) — jamais un remplacement des serveurs. Lecture seule strictement (mêmes règles de non-intervention que le reste d'Allsafe) ; par actif, l'utilisateur choisit la méthode de collecte (`Asset.collection_method`, page Actifs). Jeton d'enrôlement à usage unique (48h, admin), identité par poste (TOFU-like, même idiome que `services/ssh_trust.py`). Test actif/offensif explicitement hors scope — futur module séparé, ses propres garde-fous d'autorisation à concevoir (comme Audits). **Durcissement** (12/08/2026, même jour) : checks de conformité CIS-like de tout le parc (compte de service **et** agent), extrait de la modale « Résultat du scan » d'Actifs (qui pointe désormais vers cette page) pour devenir une vue dédiée — tableau d'actifs avec résumé ok/warn/indéterminé, détail au clic ; aucun nouvel endpoint, `GET /assets` portait déjà `last_scan_result.compliance`/`network_compliance` en entier. **Politiques de scan planifié** (17/08/2026, `models.py::ScanPolicy`, page de réglage Paramètres > Intégrations) : scan automatique par groupe de criticité (nouvelle valeur `critique`, au-dessus de haute/moyenne/faible) — quotidien pour `critique`, hebdomadaire pour le reste, éditable sans coder ; toujours doublé de la possibilité de lancer manuellement (par actif comme avant, ou par groupe depuis la page de réglage). Périmètre : serveurs `service_account` + sites web (durcissement web) ; réseau (Meraki/PRTG) reste manuel, agents ont un simple signal de fraîcheur (cf. docs/ARCHITECTURE.md § Politiques de scan planifié). **GUI Tauri en thème sombre** (18/08/2026, remplace `native-windows-gui`) : assistant graphique installation/réparation/mise à jour/désinstallation de l'`.exe` autonome, identité visuelle Allsafe reprise à l'identique (cf. `docs/AGENTS.md` § Interface graphique). **Téléchargement des paquets** (même jour, page Agents) : `.exe` autonome (zippé avec `WebView2Loader.dll`, indispensable à côté de lui), `.msi` (GPO/déploiement de parc), `.deb` — mêmes routes publiques `GET /agents/latest/*` déjà utilisées par les scripts de mise à jour planifiée. **Historique global des agents** (19/08/2026, `/agents/historique`, `AgentsGlobalHistory.jsx`) : vue de parc complémentaire à l'historique par poste — tous les agents ayant existé (vivants ∪ révoqués ∪ supprimés via `AgentDeletionLog`), lien depuis la page Agents. **Détection d'évènements sensibles côté poste** (19/08/2026, ⏳ partiellement implémenté, cf. `docs/AGENT_DETECTION.md`) : extension de l'agent lisant les journaux natifs (Event Log Security/auditd) + diff d'état (comptes/admin/persistance) pour repérer compte créé/privesc/process suspect/altération d'audit — lecture seule stricte. Fondations backend + socle diff agent (Linux/Windows) livrés et vérifiés en conditions réelles ; enrichissement journal natif et frontend (page dédiée, badge, bandeau Dashboard) restent à faire |
| **Sécurité** | `#3fb950` vert | **Audits** (ex-« Pentest », renommé le 30/07/2026, **implémenté le 03/08/2026** : cf. `docs/AUDITS.md`) : un seul modèle couvre les 5 types d'audit (architecture, configuration, code, pentest, Red Team) plutôt qu'un module pentest-only. Principe posé : Allsafe **héberge et trace** l'audit, n'exécute jamais rien d'offensif — les outils tournent en labo, seuls les résultats rédigés à la main entrent. Garde-fou structurel : autorisation écrite bloquante (aucun finding saisissable avant), immuable une fois posée. Premier audit réel saisi : « Audit de code — Application CBR » (nom du produit au moment de la saisie, cf. § rebranding), 6 findings issus d'`audit/AUDIT_SECURITE.md`. **Bastion** (30/07/2026, placeholder) : futur accès jump host vers les serveurs critiques, sans rapport avec l'ancien module « Bastion » retiré la même session (cf. encadré ci-dessous) — celui-là entrerait, lui, en conflit frontal avec la règle de non-intervention, à trancher avant implémentation |
| **Rapports** | `#a371f7` violet | Rapport exécutif CVE, Rapport Veille, Rapport Surveillance — les trois avec des **rapports hebdomadaires figés** (`S30/2026`, générés le lundi 7h, export CSV) ; le rapport CVE se décline en plus par actif. Rapport Incidents à part (29/07/2026) : **par incident**, généré à la demande, jamais figé — un incident est rare, jamais plusieurs la même semaine (cf. docs/INCIDENTS.md § 7). ⚠️ "export PDF" n'existe pas côté serveur pour ces rapports — seul CSV est généré en backend (le seul export PDF serveur du projet est celui d'Inventaire, `reportlab`) ; le bouton "Exporter PDF" des 4 rapports (dont Incidents) est une impression navigateur côté client (`ReportMarkdown.jsx::exportPdf`), pas un fichier généré côté serveur |
| **Incidents** | `#b5793a` marron | Registre incidents (29/07/2026, complet) — déclaration, qualification NIS 2 (`requires_notification`, **toujours manuelle**, jamais automatique) et suivi des 3 échéances légales (Art. 23 : alerte précoce 24h, notification 72h, rapport final 1 mois calendaire). L'app ne notifie **jamais** elle-même l'ANSSI — elle trace qui a déclaré/qualifié/envoyé quoi et quand (`services/nis2_deadlines.py`). Préremplissage (jamais création auto) depuis Sécurité/Vulnérabilités/Veille via `DeclareIncidentButton.jsx`. Roadmap par catégorie (plan d'action chronologique interne/externe, `RESPONSE_STEPS` — remplace l'ancienne checklist "bonnes pratiques" séparée, fusionnée dedans le 29/07/2026 pour éliminer la redondance ; chaque étape cochée porte qui l'a réalisée et quand, `completed_response_steps` — + annuaire ANSSI/CERT-FR/CNIL/police-gendarmerie, coordonnées vérifiées le 29/07/2026, contacts perso ajoutables sans code — `IncidentRoadmap.jsx`). Jalons envoyés consultables (contenu/date/auteur, bouton "Consulter"). Rapport final : pièces jointes PDF (5 Mo max, disque + métadonnées, `IncidentAttachment`). **Gestion de crise** (31/07/2026, page séparée `/crises`) : escalade d'un ou plusieurs incidents en crise (`Crisis`, `Incident.crisis_id`) — cellule de crise (rôles nommés), journal de décisions/communications interne-externe (`CrisisTimelineEntry`), jamais d'envoi réel. Cf. docs/INCIDENTS.md § 5ter |
| **Gouvernance** (ex-« Documentation », renommé le 18/08/2026 — demande utilisateur, plus cohérent avec son contenu) | `#e3b341` or | Documents de gouvernance nécessaires à la conformité NIS 2 (31/07/2026) : PSSI, Charte Administrateur, Charte Utilisateur, Organigramme en seed — registre de types ouvert (`DocumentType`), ajoutable sans code, spécifique à ce module (pas géré dans Administration, contrairement à Services/Rôles qui sont consommés par plusieurs modules). Formats acceptés : PDF/Word/Excel/PNG/JPEG (validation par signature de fichier, 10 Mo max, `services/document_storage.py`). **Historique des versions conservé** : chaque upload crée une nouvelle ligne (`Document`), rien n'est supprimé automatiquement — pas de table de versions séparée, la liste triée par date EST l'historique. **Prévisualisation** (PDF/images affichés nativement par le navigateur, `Content-Disposition: inline` — Word/Excel restent en téléchargement, aucune API web ne peut ouvrir l'appli native depuis une page) + **glisser-déposer** (modale d'upload et directement sur la carte d'un type) |
| **Paramètres** | `#8b949e` gris | Transverse — nav à deux volets sans tuile (14/08/2026, même schéma que Notes : icônes à gauche, panneau à droite) : Présentation (mode démo), Apparence (thème), **Compte** (nom/email/déconnexion + changer son email/mot de passe avec indice de force, gérer ses sessions actives, nom d'analyste par défaut), **Intégrations** (statut configuré/non configuré + dernière synchro de NVD/GitHub/AD/SSH/WithSecure/Meraki/PRTG/GLPI/vSphere, lecture seule), **Sécurité** (ligne → Administration, réservée admin, nav elle-même réductible en icônes seules). Le registre « Analystes » (noms pour les dropdowns `validated_by`...) a déménagé dans Administration (30/07/2026, cf. ci-dessous), plus dans Paramètres directement. Onglet « Services » (RH/DSI/Juridique/Direction en seed, liste ouverte, code couleur) puis onglet « Rôles » juste après (31/07/2026) : organigramme poste → personne → email (`OrganizationRole`, ex. RSSI → Michel Lacroix), poste optionnellement rattaché à un service (couleur de la carte), consommé par Incidents et Gestion de crise pour savoir à qui se référer selon le poste — noms réels, anonymisés en mode Présentation |
| **Notes de version** | `#f778ba` rose | Détaché de Paramètres (18/08/2026, demande explicite) — module à part entière, lien simple juste en dessous de Paramètres dans la nav (pas d'en-tête de groupe, même schéma). Changelog produit (`models.py::ReleaseNote`, table unique `scope='allsafe'`/`'agent'`) : nouveautés/correctifs groupés par version, résumé replié par défaut, détail au clic (`ReleaseNotesPanel.jsx`, composant partagé). Versionné rétroactivement le même jour (1er vrai numéro de version du produit, 1.0.0, en lisant STATUS.md/HISTORIQUE.md sur le mois précédent) — alimenté en fin de session par l'assistant, relu/validé par l'utilisateur directement sur la page. Le scope `agent` reste sur sa propre page sous Inventaire > Agents (`/agents/notes-de-version`), pas ici — seul `allsafe` vit dans ce module |

⚠️ **Module Bastion / Administration retiré le 30/07/2026** : l'ancien sélecteur « Je suis… » en
bas de sidebar (`visible_modules`, filtrage de nav par profil, aucun mot de passe ni session) a été
supprimé intégralement — pure personnalisation d'affichage sans valeur de sécurité, remplacée par
une vraie authentification (en cours de conception, cf. STATUS.md). Seul le registre de noms
d'analystes a été conservé (déplacé dans Paramètres, cf. ci-dessus) pour ne pas casser les menus
déroulants d'attribution existants (`validated_by` et équivalents).

Dans le code, "CyberVuln" reste le nom historique de plusieurs modules internes (dossier `backend/`,
title `Gestion des vulnérabilités`...) — ne pas chercher à tout renommer, seule l'identité visible
(sidebar, `<title>` HTML) porte le nom actuel du produit.

**Rebranding CBR → Allsafe (11/08/2026)** : le produit s'appelait « CBR » jusqu'à cette date, renommé
« Allsafe » ce jour-là — pur changement d'identité visible (wordmark sidebar/Home/Login, `<title>`
HTML, tooltips et textes UI qui nomment explicitement le produit), aucun changement fonctionnel. Même
principe que ci-dessus appliqué à "CBR" lui-même : les mentions dans les commentaires de code, les
identifiants internes (`cybervuln` rôle DB superuser, `cbr_app` rôle applicatif, dossier `backend/`,
composant `CbrMark.jsx`/`CbrLogoTile`, variables CSS `--brand-*`) et le journal historique
(`docs/HISTORIQUE.md`, entrées passées de `STATUS.md`) ne sont **pas** retouchés rétroactivement —
"CBR" y reste exact pour la période qu'ils décrivent, exactement comme "CyberVuln" est resté non
retouché lors du rebranding vers "CBR" initial (01/07/2026, cf. `docs/HISTORIQUE.md`).

**Page d'accueil (`/`, `pages/Home.jsx`)** : sélecteur de module, sans sidebar — 8 tuiles (une par
module ci-dessus, mêmes couleurs) qui redirigent chacune vers la première page du module choisi. Le
Dashboard CyberVuln a été déplacé de `/` vers `/dashboard` pour laisser la place à cette page d'accueil.
Le logo/titre "Allsafe" dans la sidebar (`Layout.jsx`) ramène toujours à `/`. La sidebar est réductible
(bouton `<` en haut à droite, bascule vers une fine bande d'icônes) — état persisté côté client.

**Guide d'aide contextuel** (19/08/2026, demande utilisateur) : bouton flottant monté une seule fois
dans `Layout.jsx` (`components/PageGuide.jsx`), résout son contenu selon la route courante
(`constants/pageGuides.js`) et se thème avec la couleur du module actif. Masquable globalement
(Paramètres > Apparence, préférence 100% client `localStorage`, `contexts/GuidePreferenceContext.jsx`
— même patron que `AnalystPreferenceContext.jsx`/`ThemeContext.jsx`). Généralise l'ancien guide
spécifique à la page Agents (rendu "paquets" avec logo OS + commandes conservé pour `/agents`).

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
│   └── INCIDENTS.md             → Module Incidents (délais NIS 2 Art. 23, garde-fous, workflow)
├── frontend/                    ✅ — arborescence détaillée dans docs/FRONTEND.md
├── agent/                       ✅ — agent Rust `allsafe-agent` (12/08/2026, module Sécurité > Agents),
│                                  lecture seule, complète le scan centralisé SSH/WinRM sur les postes
│                                  qu'il atteint mal (éteints, hors réseau, VPN) — jamais un remplacement
│                                  des serveurs. Deux sous-commandes (`enroll`/`checkin`), pas de
│                                  service/daemon packagé dans ce MVP (planification externe, cron/
│                                  Planificateur de tâches). Empaquetage `.deb` (`cargo-deb`) et `.msi`
│                                  (`wixl`, alternative libre au WiX Toolset officiel) documentés dans
│                                  `agent/README.md`. Par actif, l'utilisateur choisit la méthode de
│                                  collecte (`Asset.collection_method`, cf. ci-dessous)
└── backend/
    ├── Dockerfile               ✅
    ├── requirements.txt         ✅
    ├── main.py                  ✅ — lifespan lance le cycle patch check en tâche de fond au démarrage
    │                              + bootstrap du 1er compte admin (BOOTSTRAP_ADMIN_EMAIL/PASSWORD)
    ├── config.py                ✅
    ├── database.py              ✅ — poolclass=NullPool (cf. docs/ARCHITECTURE.md)
    ├── auth_deps.py             ✅ — dependencies FastAPI require_auth/require_admin (30/07/2026) +
    │                              require_agent (12/08/2026, en-tête X-Agent-Token, identité non-humaine
    │                              distincte des comptes utilisateurs — cf. routers/agents.py)
    ├── models.py                ✅ — CVE, Asset, Vulnerability, VulnerabilityStatusHistory, Feed, WatchItem, WatchSource, SyncState, WatchedIdentity, ConnectionLog, KbBuild, Report, WatchProfileItem, SecurityEvent, Incident, IncidentTimelineEntry, IncidentNotificationContact, IncidentAttachment, Crisis, CrisisTimelineEntry, CrisisContact, Analyst, OrganizationRole, Service, DocumentType, Document, WindowsAppMapping, User, UserSession, AuthAuditLog, Audit, AuditAsset, AuditFinding, AuditFindingHistory, AuditAttachment, NetworkStatus, PatchCheckAssetCompletion, Agent, AgentEnrollmentToken, ScanPolicy
    ├── db/
    │   ├── deception_setup.sql  ✅ — honeypots DB (vues + rôles leurres, honeytokens) → security_events.
    │   │                          Idempotent, à rejouer sur toute base. NE JAMAIS référencer ces objets
    │   │                          dans le code (cf. docs/ARCHITECTURE.md § Déception)
    │   ├── app_role.sql         ✅ — rôle applicatif `cbr_app` à privilèges réduits (DML only, non
    │   │                          superuser). L'app tourne avec lui (APP_DB_USER), pas avec le superuser
    │   │                          cybervuln. Idempotent (cf. docs/ARCHITECTURE.md § Rôle applicatif)
    │   ├── ddl_guard.sql        ✅ — event trigger : bloque + journalise toute DDL par un rôle non
    │   │                          whitelisté (seul `cybervuln` autorisé) → security_events (source
    │   │                          `ddl_attempt`). Log autonome via dblink. Idempotent (cf. ARCHITECTURE.md)
    │   └── schema_patches.sql   ✅ — `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` centralisés (pas d'Alembic,
    │                              `create_all` ne modifie jamais une table existante). À exécuter avec le
    │                              rôle superuser `cybervuln`, jamais `cbr_app` (bloqué par ddl_guard.sql)
    ├── services/
    │   ├── nvd_fetcher.py       ✅
    │   ├── rss_fetcher.py       ✅
    │   ├── watch_fetcher.py     ✅ — veille cyber NIS 2, sources natives codées en dur + sources
    │   │                          personnalisées ajoutables sans code (table `WatchSource`, cf. docs/VEILLE.md)
    │   ├── net_guard.py         ✅ — validation anti-SSRF des URLs de sources de veille (`validate_public_url`),
    │   │                          rejette les hôtes non publics ; re-appelée à chaque redirection HTTP
    │   ├── asset_importer.py    ✅ — import AD/SSH ; bind LDAP chiffré (`AD_USE_TLS`, StartTLS par défaut)
    │   ├── asset_scanner.py     ✅ — scan read-only (fiabilité, apps, hardware) + durcissement CIS-like
    │   │                          (politique mdp, SSH root/mdp, RDP-NLA/SMBv1/pare-feu Windows, signature/
    │   │                          chiffrement SMB, LLMNR, WDigest, niveau NTLM, algos SSH faibles — 10/08/2026).
    │   │                          Windows : **deux appels WinRM séparés** (inventaire + conformité, chacun sa
    │   │                          propre marge de ~8191 caractères encodés) depuis le 10/08/2026 — un seul
    │   │                          script avait déjà dépassé cette limite 3 fois à force d'ajouts, cf. STATUS.md.
    │   │                          `apply_scan_result(asset, result, session)` (12/08/2026) : logique de
    │   │                          persistance extraite de `routers/assets.py::scan_asset_endpoint` pour être
    │   │                          partagée par DEUX producteurs du même shape de résultat — le scan pull
    │   │                          SSH/WinRM ci-dessus, et le push d'un agent posé sur un poste
    │   │                          (`routers/agents.py::checkin`) — jamais de logique dupliquée entre les deux
    │   ├── scan_policy.py       ✅ — politiques de scan planifié par criticité (17/08/2026, cf.
    │   │                          models.py::ScanPolicy) : `run_scan_for_criticite` réutilise exactement
    │   │                          la séquence de `scan_asset_endpoint` ci-dessus (scan_asset ->
    │   │                          apply_scan_result) sur les actifs service_account du groupe, puis
    │   │                          `run_all_website_checks(asset_ids=...)` sur ses sites web. Toujours
    │   │                          appelé depuis le process backend (jamais un worker Celery direct, cf.
    │   │                          docs/ARCHITECTURE.md § Politiques de scan planifié)
    │   ├── ssh_trust.py         ✅ — TOFU SSH (`connect_trusted`) : apprend et pinne la clé hôte au premier
    │   │                          contact dans `keys/known_hosts`, rejette toute clé différente ensuite
    │   ├── crypto.py            ✅ — chiffrement Fernet des mots de passe SSH par machine
    │   ├── vuln_history.py      ✅ — historique des transitions de statut (`record_status_change`),
    │   │                          branché aux 9 points qui modifient Vulnerability.status (6 manuels
    │   │                          dans routers/vulnerabilities.py + apply_patch_result pour l'auto)
    │   ├── claude_analyzer.py   ⚠️ règles de mots-clés locales — n'appelle PAS l'API Claude malgré
    │   │                          le nom (aucun `anthropic`/`httpx` vers l'API dans ce fichier ni
    │   │                          ailleurs) ; le tableau d'anonymisation ci-dessus décrit la règle à
    │   │                          respecter si/quand un vrai appel API est ajouté, pas l'état actuel
    │   ├── cpe_matcher.py       ✅ — matching CPE composant par composant + paquets installés + mots-clés.
    │   │                          `still_matches()` a deux variantes pour le volume : `asset_match_context()`
    │   │                          (données dérivées de l'actif, une fois par actif) + `still_matches_ctx()`
    │   │                          — à utiliser dès qu'on teste beaucoup de CVE (cf. STATUS.md 28/07).
    │   │                          Windows : dérivation des candidats produit via `WindowsAppMapping`
    │   │                          (table réglable en base, `models.py`), pas `_package_candidates`
    │   │                          (conventions Debian/RPM, sans rapport avec le texte libre des noms
    │   │                          d'applications Windows) — cf. STATUS.md 31/07. `run_cpe_matching`/
    │   │                          `run_cpe_matching_for_asset` : `load_only(..., raiseload=True)` sur les
    │   │                          CVE (évite `raw_data`, 377 Mo en base) + `asyncio.sleep(0)` périodique
    │   │                          dans la double boucle actif × CVE — sans ça, gelait l'event loop du
    │   │                          backend entier le temps du calcul (10/08/2026, cf. STATUS.md)
    │   ├── scoring.py           ✅ — cvss × epss × criticité (`asset.tags.criticite`, réglable depuis
    │   │                          Actifs, cf. docs/MATCHING.md § Scoring)
    │   ├── stats.py             ✅ — KPI (compute_stats), partagé par routers/stats.py ET reports.py
    │   ├── remediation.py       ✅
    │   ├── patch_checker.py     ✅ — WinRM (KB) + SSH (Debian Security Tracker, fallback plages NVD).
    │   │                          `_asset_progress`/`_cycle_started_at` (10/08/2026) : suivi par actif du
    │   │                          cycle en cours (checked/total, noms résolus dès le démarrage) + horodatage
    │   │                          de départ, exposés par `GET /api/patch-check/status` pour le Dashboard
    │   ├── debian_tracker.py    ✅ — Debian Security Tracker (comparaison version fiable, backports inclus)
    │   ├── kb_build.py          ✅ — KB Microsoft → build OS (titre article support.microsoft.com),
    │   │                          cache permanent en base (`kb_builds`) ; tranche avec certitude les
    │   │                          CVE Windows anciennes que NVD/MSRC ne couvrent pas (cf. docs/MATCHING.md)
    │   ├── watch_profile.py     ✅ — profil de veille (OS/logiciels/matériel du parc) : suggestions
    │   │                          depuis l'inventaire (dont `hardware.vendor_hint` des actifs PRTG,
    │   │                          04/08/2026) + correspondance. **Marque, ne filtre jamais**
    │   ├── ip_watch.py          ✅ — Surveillance Identités, vérif IP/plage IP contre listes de blocage
    │   │                            gratuites (IPsum, Blocklist.de, Feodo Tracker), cache process 30 min
    │   ├── weekly_report.py     ✅ — rapports hebdomadaires **figés** (semaine ISO, table `reports`),
    │   │                          générique ; les 3 types (cve/veille/surveillance) sont branchés
    │   │                          (cf. docs/ARCHITECTURE.md) — Incidents n'en fait pas partie, cf. ci-dessous
    │   ├── watch_report.py      ✅ — contenu du rapport hebdo de veille (NIS 2) : volume collecté,
    │   │                          traités, SLA 48h sur les critiques, décisions consignées
    │   ├── identity_report.py   ✅ — contenu du rapport hebdo de surveillance : périmètre surveillé,
    │   │                            fuites correspondantes, IP blocklistées (volet IP non rétroactif)
    │   ├── nis2_deadlines.py    ✅ — module Incidents (29/07/2026) : calcul des 3 échéances légales
    │   │                            NIS 2 (24h/72h/1 mois calendaire) + garde-fous (qualification/
    │   │                            envoi/aware_at toujours manuels, jamais automatiques, cf. docs/INCIDENTS.md)
    │   ├── incident_timeline.py ✅ — journal auditable append-only des incidents (`record()`), même
    │   │                            pattern que vuln_history.py
    │   ├── incident_attachments.py ✅ — pièces jointes PDF du rapport final : validation pure (taille
    │   │                            5 Mo max, signature `%PDF-`), constantes de stockage disque
    │   ├── document_storage.py  ✅ — module Documentation (31/07/2026) : validation pure PDF/Word/Excel
    │   │                            (signature de fichier par format, 10 Mo max), constantes de
    │   │                            stockage disque (volume `documents`), même esprit qu'incident_attachments.py
    │   └── incident_report.py   ✅ — rapport **par incident** (pas hebdo, cf. docs/INCIDENTS.md § 7) :
    │                                `build_incident_report()`, markdown généré à la demande, jamais
    │                                persisté — contenu des jalons envoyés + liens PDF joints
    │   ├── backup.py            ✅ — pg_dump vers le volume `backups`, rétention (`BACKUP_RETENTION_DAYS`),
    │   │                            toujours exécuté côté worker (cf. docs/ARCHITECTURE.md § Sauvegarde)
    │   ├── inventory_export.py  ✅ — export PDF du module Inventaire (28/07/2026, `reportlab` — premier
    │   │                            export PDF du projet, les rapports hebdo ne font que du CSV malgré
    │   │                            l'intitulé "export PDF/CSV" plus haut) : tableau récapitulatif +
    │   │                            détail des apps par actif (cf. docs/ARCHITECTURE.md)
    │   ├── withsecure_client.py ✅ — client OAuth2 API Elements (28/07/2026, lecture seule, client
    │   │                            "Read-only" côté Security Center) : devices, correctifs manquants
    │   │                            CVE/CVSS (confirmé Windows uniquement), security-events/incidents.
    │   │                            Module Vulnerability Management (ex-Radar) non souscrit, pas utilisé
    │   ├── withsecure_matcher.py ✅ — appariement hostname WithSecure ↔ Asset existant (ne crée jamais
    │   │                            d'actif) + création de Vulnerability, même schéma que cpe_matcher.py.
    │   │                            Complément à AD/SSH, pas un remplacement (cf. STATUS.md 28/07/2026)
    │   ├── auth.py               ✅ — authentification (30/07/2026) : hash/verify mot de passe (bcrypt),
    │   │                            sessions par cookie (token opaque, hash SHA-256 stocké), verrou
    │   │                            anti-bruteforce (email + IP, cf. docs/ARCHITECTURE.md).
    │   │                            `validate_password_strength()` (14/08/2026) centralise la politique
    │   │                            (16 car. + majuscule/minuscule/chiffre/spécial), avant dupliquée
    │   ├── audit_attachments.py  ✅ — module Audits (03/08/2026) : pièces jointes PDF/PNG/JPEG (mandat
    │   │                            d'audit ou preuve de finding), validation pure, calqué sur
    │   │                            document_storage.py restreint à ces 3 formats
    │   ├── audit_finding_history.py ✅ — transitions de statut d'un finding, append-only, même pattern
    │   │                            que vuln_history.py (pas incident_timeline.py, décision assumée
    │   │                            de ne pas fusionner les 3 formes de journal du projet)
    │   ├── audit_report.py       ✅ — rapport d'audit, markdown généré à la demande, jamais persisté,
    │   │                            calqué sur incident_report.py (cf. docs/AUDITS.md)
    │   ├── meraki_client.py      ✅ — client API Dashboard Meraki (04/08/2026, lecture seule, clé API en
    │   │                            en-tête) : état en ligne/hors ligne des équipements réseau. Agrège
    │   │                            toutes les organisations visibles par la clé si aucune n'est
    │   │                            précisée (constaté en conditions réelles : une même clé peut voir
    │   │                            plusieurs organisations bien réelles et distinctes)
    │   ├── meraki_matcher.py     ✅ — appariement hostname Meraki ↔ Asset existant (ne crée jamais
    │   │                            d'actif), même schéma que withsecure_matcher.py, mais alimente
    │   │                            NetworkStatus (état réseau) et non des Vulnerability. Reprend l'idée
    │   │                            PRTG évoquée le 31/07/2026, codée le même jour à la suite (ci-dessous)
    │   ├── prtg_client.py        ✅ — client API cœur PRTG Network Monitor (04/08/2026, lecture seule,
    │   │                            `apitoken` en paramètre de requête — pas Multiboard, produit à part
    │   │                            qui agrège des widgets visuels entre instances) : état en ligne/
    │   │                            hors ligne des devices (content=devices)
    │   ├── prtg_matcher.py       ✅ — appariement host/hostname/nom PRTG ↔ Asset existant, alimente
    │   │                            NetworkStatus comme meraki_matcher.py. `import_new_assets` comme
    │   │                            Meraki (décision revue en session, 339 actifs créés au premier
    │   │                            import réel), avec une exclusion propre à PRTG : les objets
    │   │                            internes à la plateforme (sonde, serveur central) ne sont jamais
    │   │                            créés (host vide/loopback, exclusion structurelle, pas une liste
    │   │                            de noms — cf. `_is_prtg_internal`)
    │   ├── glpi_client.py        ✅ — client API REST GLPI (11/08/2026, lecture seule, CMDB patrimoine) :
    │   │                            auth à deux jetons (App-Token client API + User-Token compte de
    │   │                            service dédié) → Session-Token via `initSession`/`killSession`,
    │   │                            contrairement à Meraki (clé seule) et PRTG (`apitoken` en query
    │   │                            param). Pagine `Computer` par `range` (pas d'équivalent au
    │   │                            `count=50000` de PRTG en un seul appel)
    │   ├── glpi_matcher.py       ✅ — appariement `Computer.name` GLPI ↔ Asset existant, enrichit
    │   │                            `Asset.hardware` (modèle/n° série/n° d'inventaire/fabricant/
    │   │                            localisation, clés `glpi_*`) — **jamais** de création d'actif
    │   │                            (décision explicite, contrairement à Meraki/PRTG et leur
    │   │                            `import_new_assets`) ni d'écriture dans `network_status` (GLPI
    │   │                            n'est pas un outil de supervision réseau). Premier sync réel :
    │   │                            1855 computers GLPI, 1 seul actif Allsafe rapproché (`Bcrafter`,
    │   │                            enrichissement vérifié en base) — le catalogue `Computer` de ce
    │   │                            GLPI couvre le parc utilisateurs (`PC-*`/`PORT-*`), pas le parc
    │   │                            serveurs qu'Allsafe suit ; pas un bug, cf. STATUS.md 11/08/2026
    │   └── agent_detection.py    ⏳ PARTIEL (19/08/2026, cf. docs/AGENT_DETECTION.md) — diff d'état
    │                                (comptes/admins/persistance) contre le dernier `AgentStateSnapshot`
    │                                connu, no-backfill au 1er check-in, dédoublonnage du journal natif
    │                                sur `(agent_id, native_event_id)`, plafonds serveur indépendants de
    │                                ce que l'agent respecte. Branché sur `POST /agents/checkin` via
    │                                `apply_security_events()` (fonction dédiée, pas `apply_scan_result`)
    ├── routers/
    │   ├── cves.py, assets.py, vulnerabilities.py, stats.py, analysis.py, remediation.py,
    │   │   reports.py, sync.py, patch_check.py, connections.py, watch.py, identities.py, security.py,
    │   │   backup.py, withsecure.py, meraki.py, prtg.py, glpi.py, incidents.py, crises.py, analysts.py,
    │   │   organization_roles.py, services.py, documents.py, windows_app_mappings.py, audits.py
    │   │   ✅ (tous montés dans main.py)
    │   ├── auth.py                ✅ — login/logout/me/change-password (30/07/2026), seul router sans
    │   │                             dependency globale (/login public, le reste protégé par route).
    │   │                             `/change-email`, `/sessions` (GET/DELETE) ajoutés le 14/08/2026 —
    │   │                             self-service sur son propre compte, cf. CLAUDE.md § Authentification
    │   ├── users.py               ✅ — CRUD des comptes, réservé admin (30/07/2026)
    │   ├── agents.py              ✅ — module Sécurité > Agents (12/08/2026), protection déclarée par
    │   │                             route comme auth.py/connections.py ci-dessus (pas au niveau du
    │   │                             router) : jetons d'enrôlement (admin), `/enroll` (public, protégé
    │   │                             par le jeton lui-même), `/checkin` (`require_agent`), liste/révocation
    │   │                             (`require_page("/agents")`/admin)
    │   ├── integrations.py        ✅ — Paramètres > Intégrations (14/08/2026) : `GET /status`, statut
    │   │                             agrégé configuré/non configuré + dernière synchro (lecture directe
    │   │                             de `sync_state`, pas de rappel des `GET /<service>/status` existants)
    │   └── scan_policies.py       ✅ — Politiques de scan planifié par criticité (17/08/2026, même page
    │                                 Paramètres > Intégrations) : `GET`/`PATCH` (admin), `POST .../run-now`
    │                                 (`require_admin_or_internal` — appelé aussi bien par le bouton manuel
    │                                 que par le poller horaire `scan-policy-check-hourly`). Monté SANS
    │                                 dependency de niveau router (comme patch_check.py) : le jeton interne
    │                                 n'a pas de session, une dependency de router s'exécuterait avant celle
    │                                 de la route et le rejetterait avant même qu'elle ne s'exécute
    ├── tasks/
    │   └── scheduled_tasks.py   ✅ — Celery beat, planning détaillé dans docs/ARCHITECTURE.md
    └── tests/                   ✅ — premiers tests du projet (27/07/2026), sans base de données
        └── test_patch_checker_guardrails.py, test_vulnerabilities_status_transitions.py,
            test_nis2_deadlines.py, test_incidents_guardrails.py, test_incident_attachments.py,
            test_auth_guardrails.py
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
DB_MAX_CONCURRENT_SESSIONS=15  # sémaphore sur database.py::get_session (10/08/2026, cf.
                       # audit/AUDIT_SECURITE.md) — pas un pool de connexions (NullPool conservé,
                       # nécessaire pour Celery), juste un plafond de requêtes HTTP simultanées.
                       # Relevé de 5 à 15 le 14/08/2026 : Dashboard.jsx génère à lui seul 8
                       # requêtes simultanées toutes les 30s (+1/3s) — 5 saturait dès qu'un 2e
                       # onglet/utilisateur était actif (lenteurs signalées par l'utilisateur)
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
