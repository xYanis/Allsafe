# VEILLE.md — Module CyberVeille (Allsafe)
## Veille technologique (conforme NIS 2) + Fuite de données + sources personnalisées

---

## 1. Vue d'ensemble

Le groupe de nav **CyberVeille** couvre deux pages qui partagent le même modèle de données
(`WatchItem`) et le même pipeline de collecte (`services/watch_fetcher.py`), mais n'ont **rien à voir**
fonctionnellement :

| | Veille technologique (`/veille`) | Fuite de données (`/fuite-de-donnees`) |
|---|---|---|
| Nature | Registre **auditable NIS 2** | Onglet **100% informatif** |
| Workflow | statut/analyste/décision/SLA obligatoires | aucun — juste une grille de cards à consulter |
| Sources | CERT-FR, ANSSI, CNIL, éditeurs sécu... | ZATAZ, fuitesinfos.fr, ransomware.live, DataBreaches.net, Have I Been Pwned |
| Filtre | source, sévérité, thèmes, SLA | source, pays (avec drapeaux) |
| Export | CSV auditeur (items critiques) | aucun |

Les deux pages peuvent aussi recevoir des **sources RSS/Atom ajoutées par l'utilisateur sans toucher
au code** (table `WatchSource`, § 10) — une source ajoutée depuis l'une des deux pages n'apparaît
jamais dans l'autre (`category` = `general` ou `leak`, cf. § 10.1).

Le module permet de :
- **Collecter automatiquement** les alertes/publications des sources natives + personnalisées
- **Catégoriser** chaque item par sévérité et thèmes (auto-détection)
- Sur Veille technologique : **tracer** le traitement de chaque item (analyste, date, délai, décision)
  et **exporter** un registre CSV pour tout audit NIS 2 / ANSSI
- Sur Fuite de données : donner une vue rapide, par pays et par source, des fuites/violations de
  données et ransomware récents — sans registre ni traçabilité, à titre de veille informative

**URLs** : http://localhost:3000/veille · http://localhost:3000/fuite-de-donnees  
**API commune** : `GET /api/watch`, `PATCH /api/watch/{id}`, `GET /api/watch/stats`,
`GET /api/watch/export`, `POST /api/watch/sync`, `GET /api/watch/sync-status`  
**API sources personnalisées** : `GET /api/watch/leak-sources`, `GET/POST/PATCH/DELETE /api/watch/sources`

---


## 2. Sources configurées — Veille technologique

Ces sources alimentent le registre auditable NIS 2 (`/veille`). Les sources dédiées "fuite de
données"/ransomware (§ 9) en sont exclues par construction (`GET /api/watch/leak-sources`,
`exclude_source` — cf. § 1) : même si l'une d'elles évoque occasionnellement une CVE ou un sujet
NIS 2, elle ne remonte jamais ici, pour garder le registre focalisé sur la veille cyber générale.

### 2.1 Sources officielles françaises

| Source | Label | Flux RSS/Atom | Sévérité par défaut | Thèmes par défaut |
|--------|-------|---------------|---------------------|-------------------|
| `cert-fr-avis` | CERT-FR Avis | `https://www.cert.ssi.gouv.fr/avis/feed/` | important | Cyber, Vulnérabilité |
| `cert-fr-alerte` | CERT-FR Alertes | `https://www.cert.ssi.gouv.fr/alerte/feed/` | **critical** | Cyber |
| `cert-fr-bulletin` | CERT-FR Bulletins | `https://www.cert.ssi.gouv.fr/actualite/feed/` | important | Cyber |
| `anssi` | ANSSI | `https://www.ssi.gouv.fr/actualites/rss/` | important | Cyber, Réglementation |
| `cnil` | CNIL | `https://www.cnil.fr/fr/rss.xml` | important | Données, Réglementation |
| `cybermalveillance` | Cybermalveillance | `https://www.cybermalveillance.gouv.fr/feed/atom-flux-actualites` (Atom) | important | Cyber |

### 2.2 Médias & trackers

| Source | Label | Flux RSS/Atom | Sévérité par défaut | Thèmes par défaut |
|--------|-------|---------------|---------------------|-------------------|
| `it-connect` | IT Connect | `https://www.it-connect.fr/feed/` | informational | Admin, Software |
| `global-security-mag` | Global Security Mag | `https://www.globalsecuritymag.fr/spip.php?page=backend` | informational | Cyber |

> `zataz` et `fuitesinfos` sont toujours des sources natives du pipeline, mais servent désormais
> exclusivement l'onglet **Fuite de données** (§ 9) — elles n'apparaissent plus dans le sélecteur de
> Veille technologique. `bonjourlafuite` (Bonjour la fuite) a été retiré du pipeline (demande
> explicite, plus aucune référence dans le code).

### 2.3 Éditeurs de sécurité

| Source | Label | Flux RSS/Atom | Sévérité par défaut | Thèmes par défaut |
|--------|-------|---------------|---------------------|-------------------|
| `sekoia` | Sekoia Blog | `https://www.sekoia.com/blog/rss.xml` | informational | Cyber, APT |
| `harfanglab` | HarfangLab Blog | `https://harfanglab.io/feed/` ⚠️ cassé, voir note ci-dessous | informational | Cyber |
| `synacktiv` | Synacktiv Blog | `https://www.synacktiv.com/feed/lastblog.xml` | informational | Cyber, Vulnérabilité |
| `intrinsec` | Intrinsec Blog | `https://www.intrinsec.com/feed/` | informational | Cyber |
| `nolimitsecu` | No Limit Secu | `https://www.nolimitsecu.fr/feed/` | informational | Cyber |

> ⚠️ **HarfangLab** est la seule source native en échec permanent (sur 18 : 16 flux RSS/Atom + les 2
> API JSON de Fuite de données, § 9) : `harfanglab.io/feed/` est protégé par un vrai challenge JS
> Cloudflare ("Just a moment…"), pas un simple filtre User-Agent — infranchissable avec un client HTTP
> classique (`httpx`). Contourner ça demanderait un navigateur headless (Playwright) rien que pour ce
> flux, jugé disproportionné pour une source unique. L'échec est loggé (`Erreur veille HarfangLab
> Blog : ...`) et n'affecte pas les autres sources — chaque flux est isolé dans son propre
> `try/except` (`_fetch_feed`, et son équivalent pour les 2 API JSON). Toutes les autres URLs
> ci-dessus ont été retrouvées/corrigées le 02/07/2026 après un audit complet (cf. `STATUS.md`) ; les
> sites changent occasionnellement d'URL/plateforme (ex. Sekoia a migré vers un nouveau domaine
> Webflow) — si une source recommence à retourner 0 item, vérifier d'abord le code HTTP réel et le
> `Content-Type` de la réponse avant de conclure à un problème Allsafe.

### 2.4 Règles de sévérité

La sévérité est déterminée selon l'ordre de priorité suivant :

1. **Élévation par mots-clés dans le titre** (priorité maximale) :
   - `critical` si le titre contient : `critique`, `0-day`, `zero-day`, `ransomware`, `remote code execution`,
     ou **le mot entier** `apt`/`rce`
2. **Sévérité par défaut de la source** (voir tableau ci-dessus)
3. **Élévation à `important`** si la sévérité de base est `informational` et le titre contient : `alerte`, `vulnérabilité`, `patch`, `correctif`

**Mots entiers vs sous-chaîne** : `apt` et `rce` sont vérifiés en tant que mot entier (`\bapt\b`,
`\brce\b`), pas en simple sous-chaîne, contrairement aux autres mots-clés. Raison : ce sont des
suites de lettres courtes qui apparaissent aussi au milieu de mots courants sans rapport —
"source"/"resource" contiennent "rce", "capteur"/"adaptation" contiennent "apt". Avant ce correctif,
des articles purement informatifs étaient classés `critical` à tort (ex : *"Docky : le Dock de
macOS réinventé, gratuit et open source"* → faux positif sur "rce" dans "source"). Les autres
mots-clés (plus longs et spécifiques) restent en sous-chaîne pour continuer à matcher les pluriels
et conjugaisons ("vulnérabilité" matche aussi "vulnérabilités").

---

## 3. Thèmes auto-catégorisés

12 thèmes sont assignés à chaque item par combinaison de :
- **Thèmes par défaut de la source** (voir tableaux ci-dessus)
- **Détection de mots-clés** dans le titre + résumé

Ordre alphabétique dans l'interface (chips de filtre) — tableau ci-dessous dans le même ordre :

| Thème | Mots-clés détectés (exemples) |
|-------|-------------------------------|
| **Admin** | active directory, windows server, group policy, powershell, kerberos |
| **APT** | threat actor, apt-, espionnage numérique, acteur étatique, campagne ciblée |
| **Cyber** | cyberattaque, cybermenace, incident de sécurité, malware, phishing, botnet |
| **Données** | rgpd, gdpr, données personnelles, protection des données |
| **Fuite de données** | fuite de données, data leak, data breach, exfiltration, dump sql |
| **Hardware** | firmware, bios, uefi, iot, bmc, ipmi, microprocesseur |
| **IA** (session 20/07/2026) | intelligence artificielle, ia générative, chatgpt, genai, large language model, modèle de langage, deepfake, machine learning, deep learning, prompt injection, ai act, règlement ia — volontairement pas de token court "ia"/" ia " seul (trop ambigu en substring, matcherait "diagnostic", "sociale"...) |
| **Ransomware** | ransomware, rançongiciel, cryptolocker |
| **Réglementation** | nis2, nis 2, directive ue, conformité, homologation |
| **Réseau** | firewall, vpn, routeur, dns, bgp, tcp/ip, proxy |
| **Software** | patch tuesday, navigateur web, office 365, framework, librairie |
| **Vulnérabilité** | cve-20XX, 0-day, exploit, proof of concept |

Les thèmes sont cumulatifs (un item peut avoir plusieurs thèmes).

> Le thème **Fuite de données** reste attribué en interne (utile aux items de l'onglet Fuite de
> données, § 9) mais son chip de filtre a été retiré de l'interface Veille technologique — redondant
> depuis que les sources dédiées fuite ont leur propre onglet et n'apparaissent plus jamais dans ce
> registre (§ 2).

**Recalcul rétroactif** (`POST /api/watch/recompute-themes`, session 20/07/2026) — la classification par
thème ne tourne qu'à la collecte (`_themes_for_item`, appelé une seule fois à l'insertion) : un item déjà
importé ne se reclasse jamais tout seul quand un thème ou un mot-clé est ajouté/modifié après coup. Cet
endpoint recalcule `themes` pour tous les items déjà en base à partir des règles actuelles — fonction
pure de source/titre/résumé, sans risque d'écraser une donnée saisie par un analyste puisque les thèmes
ne sont jamais édités manuellement. À relancer après tout ajout de thème (comme "IA" ci-dessus) ou
affinement d'une liste de mots-clés existante, sinon les articles déjà collectés restent invisibles pour
le nouveau filtre alors qu'ils correspondraient bien aux règles actuelles.

---

## 4. Workflow de traitement

> S'applique uniquement à **Veille technologique**. Fuite de données (§ 9) n'a aucun statut/analyste/
> décision — c'est une consultation informative, pas un registre à traiter.

### Profil de veille — 6 catégories (session 22/07/2026, étoffé deux fois le même jour)

Après les 5 catégories initiales (ci-dessous), une 6e a été distinguée à la demande de l'utilisateur :
**`software` (Logiciels) ≠ `application` (Applications)**, toutes deux manuelles ou semi-manuelles :

| | `software` (Logiciels) | `application` (Applications) |
|---|---|---|
| Source | Inventaire (`installed_packages`) | Saisie manuelle uniquement |
| Contenu | Chaîne exacte remontée par le paquet ("VMware Tools") | Nom de marque large ("VMware") |
| Pourquoi les deux | Un article de veille sur une faille VMware ne dit jamais "VMware Tools 12.3.5" — matcher sur le nom exact installé raterait l'article ; matcher sur le nom de marque le trouve |

Les deux catégories peuvent porter des variantes du même produit sans que ce soit une redondance
gênante : `software` capte ce qui est réellement installé, `application` capte ce sous quel nom la
presse en parle. Classification réelle effectuée avec l'utilisateur sur une vingtaine d'outils
(Veeam, Zerto, VMware, Office 365, Talend, Zoho Projects, Meraki...) — 5 noms sont restés non
classés faute de certitude (Armony, Stoïk, Gandhi, Eur'Invest, StreamLine), volontairement laissés
de côté plutôt que devinés sur des outils propres à l'entreprise.

### Profil de veille — 5 catégories (session 22/07/2026, étoffé le même jour)

Le profil couvre désormais **5 catégories**, définies dans `services/watch_profile.PROFILE_CATEGORIES`
(seule source de vérité — utilisée par la validation du `PUT`, et renvoyée telle quelle par le `GET`
pour que le frontend n'ait rien à dupliquer) :

| Catégorie | Source |
|---|---|
| Systèmes d'exploitation | Suggestions depuis l'inventaire (`assets.os`) |
| Logiciels | Suggestions depuis l'inventaire (`installed_packages`) |
| Firewall / Équipements réseau | Saisie manuelle uniquement |
| SaaS / Services cloud | Saisie manuelle uniquement |
| Matériel / Constructeurs | Suggestions depuis l'inventaire (`hardware.vendor_hint`, PRTG uniquement) + saisie manuelle |

Firewall/SaaS n'ont **aucune source d'inventaire possible** : Allsafe ne scanne que les VM du parc
(`services/asset_scanner.py`, WinRM/SSH) — un pare-feu ou un service cloud n'apparaissent dans
aucun relevé automatique. Ajoutées à la demande de l'utilisateur, qui pointait un vrai point
aveugle : les failles d'équipement réseau (Fortinet, SonicWall — déjà mentionné dans une vraie
annotation de veille, "On est sur PaloAlto") ne sont couvertes ni par l'OS ni par les logiciels
installés.

**Matériel / Constructeurs** basculée en source d'inventaire le 04/08/2026, à la suite de
l'intégration PRTG (cf. STATUS.md) : la table `devices` PRTG ne porte aucune colonne vendor/modèle,
mais certains capteurs SNMP le révèlent indirectement (`type_raw` stable, ex. `snmpsynology*` →
"Synology", cf. `prtg_client.VENDOR_SENSOR_TYPE_HINTS`, tenue à la main sur les cas observés).
Rendement volontairement faible et assumé (14 devices sur 410 au premier import) — la grande
majorité des équipements réseau (routeurs/bornes nommés par site) n'a aucune donnée exploitable et
reste en saisie manuelle, comme Firewall/SaaS.

**Le moteur de correspondance ne distingue pas les catégories** : `load_profile_terms()` sélectionne
`value` sur tout `WatchProfileItem` actif quel que soit `kind` — un terme Firewall/SaaS/Matériel est
badgé exactement comme un OS ou un logiciel, sans code supplémentaire. C'est tout l'intérêt d'avoir
gardé le matching agnostique du `kind` dès la première version.

Ajouter une 6e catégorie plus tard = une entrée dans `PROFILE_CATEGORIES`, rien d'autre (pas de
migration, la colonne `kind` est déjà un `String` libre).

### Profil de veille — cibler sur son parc (session 22/07/2026)

Icône ⚙️ à côté de « Synchroniser » → modale **Profil de veille** : les OS et logiciels réellement
présents dans le parc, **proposés depuis l'inventaire** (`assets.os` + `assets.installed_packages`)
et cochés par l'analyste. Les éléments de veille qui les mentionnent sont marqués d'un badge
« ★ terme » et filtrables par la case **« Concerne mon parc »**.

**Le profil marque, il n'écarte jamais** — décision explicite de l'utilisateur face aux deux
alternatives proposées (ne plus afficher / ne plus collecter), écartées parce qu'un mot-clé mal réglé
ferait disparaître un élément du registre NIS 2 sans laisser de trace. Un auditeur doit pouvoir
constater qu'on a bien tout reçu ; le profil ne décide que de l'ordre de lecture.

**Cocher un OS restreint la liste des logiciels** aux machines qui l'exécutent (Debian → 90,
Windows Server → 86, sur 176 au total) — c'est le geste naturel : on configure un OS, puis ce qui
tourne dessus. Aucun OS coché = aucune restriction. Un bouton **« Tout sélectionner »** agit sur la
liste **affichée** (donc filtrée par OS et par recherche), jamais sur les 176 suggestions : le bouton
doit faire ce que l'utilisateur voit. Un logiciel déjà coché reste visible même hors du périmètre de
l'OS — sinon il disparaîtrait de l'écran tout en restant dans le profil, donc impossible à décocher.

Trois choix de conception :
- **Proposition à cocher, jamais import en bloc** : le parc remonte ~387 paquets, dont la quasi-
  totalité est du bruit (`adduser`, `base-files`…). Tout cocher reviendrait à ne rien marquer. Un
  filtre de bruit conservateur (`_NOISE_PREFIXES`, `services/watch_profile.py`) ramène la liste à ~176
  propositions, triées, chacune indiquant sur quels actifs le terme a été vu.
- **Correspondance calculée à la volée**, jamais stockée sur l'élément : le profil évolue (nouveau
  scan, logiciel ajouté) et un indicateur figé deviendrait faux sans que rien ne le signale.
- **Mot entier** (`(?<!\w)…(?!\w)`), comme le matching d'identités — en sous-chaîne, « apt »
  matcherait « adapter ».

Termes hors inventaire (équipement réseau, service SaaS…) : champ de saisie libre dans la modale,
`origin="manual"`. Un terme enregistré qui disparaît de l'inventaire reste visible et coché plutôt que
de s'effacer silencieusement.

Endpoints : `GET /api/watch/profile` (profil + suggestions), `PUT /api/watch/profile` (remplace tout —
la modale envoie l'état final des cases, pas un diff). Filtre : `GET /api/watch?profile_only=true`.

### Filtrer par état de traitement (session 22/07/2026)

La barre de filtres a une ligne **Traitement** (Nouveau / En cours / Traité / Non concerné,
multi-sélection) et un raccourci **« Reste à traiter »** (Nouveau + En cours). C'est le filtre du
suivi quotidien : voir ce qui reste à qualifier, ou relire ce qui a déjà été décidé — utile aussi
pour préparer un passage d'auditeur (§ 7).

### Actifs concernés par un élément (session 22/07/2026)

La modale de traitement (Veille technologique) permet de rattacher un élément de veille à un ou
plusieurs **actifs du parc** — champ « Actifs concernés », facultatif, via le sélecteur partagé
`AssetDropdown`. Plusieurs actifs et non un seul : une alerte CERT-FR sur un composant répandu peut
viser plusieurs machines.

Intérêt : la trace « cette alerte concernait DEPLOYAPP » suit l'élément jusque dans l'export CSV du
registre et dans le rapport hebdomadaire de veille (colonne « Actifs concernés »), ce qui répond à la
question qu'un auditeur pose ensuite — *sur quoi portait la décision ?*

Détail technique (stockage, résolution des noms, garde-fous) : `docs/ARCHITECTURE.md` § table
`watch_items`.

### Consultation d'un élément déjà traité (session 22/07/2026)

- Le **badge de statut** du tableau est cliquable et ouvre le détail de l'élément.
- Le bouton d'action passe de « Traiter » à « **Consulter** » (vert) dès que l'élément est `treated`
  ou `not_applicable` — un élément qualifié n'est plus à traiter, l'analyste voit son reste-à-faire
  sans lire la colonne Statut.
- La **décision est rendue en Markdown** (bloc « Décision enregistrée » avec analyste et date), et
  reste modifiable dans le champ juste en dessous. Même moteur de rendu que les annotations de
  vulnérabilité (`MarkdownNote.jsx`).

```
[Collecte automatique H+10]
         │
         ▼
   Item reçu (status: new)
   received_at = horodatage
         │
         ▼
   Analyste consulte la veille
         │
    ┌────┴─────────────────────┐
    │                          │
    ▼                          ▼
Prendre en charge         Non concerné
(status: in_review)       (status: not_applicable)
    │                          │
    ▼                          │
Traiter                        │
(status: treated)              │
    │                          │
    └─────────┬────────────────┘
              │
              ▼
     reviewed_by = analyste
     reviewed_at = maintenant
     decision = texte libre
     linked_cve_id = CVE-XXXX (si applicable)
```

### 4.1 SLA — 48 heures

- Seuls les items **`severity=critical`** en statut `new` depuis plus de 48h déclenchent le flag
  `sla_exceeded` — les items `important`/`informational` ne sont jamais concernés par cette alerte,
  quelle que soit leur ancienneté (la pression du délai de traitement ne se justifie que pour le
  vraiment critique ; l'appliquer à tout aurait noyé le signal utile sous du bruit informatif)
- La colonne "Reçu le" affiche ⚠ et la ligne est surlignée en rouge (uniquement pour ces items)
- La KPI "SLA critique dépassé" compte ces items en temps réel
- La KPI "Critiques non traités" compte les items `critical` en statut `new` ou `in_review`

### 4.2 Champs auditables (par item)

| Champ | Description |
|-------|-------------|
| `received_at` | Date/heure d'import dans CyberVuln (UTC) |
| `published_at` | Date de publication par la source |
| `severity` | Sévérité : critical / important / informational — attribuée automatiquement à la collecte, **modifiable manuellement** par l'analyste depuis la modale de traitement (session 20/07/2026, `PATCH /api/watch/{id}` body `{severity}`). Aucune trace de qui a changé quoi n'est gardée pour ce champ (contrairement au statut) — une modification affecte rétroactivement le SLA (§ 4.1) et l'export CSV (§ 6), tous deux restreints à `severity=critical` |
| `status` | État de traitement : new / in_review / treated / not_applicable (affiché "Non concerné" — valeur enum stockée inchangée) |
| `reviewed_by` | Identité de l'analyste ayant traité l'item |
| `reviewed_at` | Date/heure de clôture du traitement (UTC) |
| `delay_hours` | Délai de traitement calculé : reviewed_at − received_at |
| `decision` | Action décidée ou justification de non-applicabilité |
| `linked_cve_id` | CVE associée manuellement |
| `cve_ids_found` | CVE-IDs détectés automatiquement dans le contenu |
| `themes` | Thèmes auto-assignés |

---

## 5. Collecte automatique

La collecte est déclenchée par Celery beat **toutes les heures à H+10** (crontab `minute=10`).

Elle peut aussi être déclenchée manuellement :
- Via l'interface : bouton **Synchroniser** sur la page Veille
- Via l'API : `POST /api/watch/sync`
- Via la CLI : `curl -X POST http://localhost:8000/api/watch/sync`

Chaque collecte :
1. Charge la liste des sources personnalisées actives (`WatchSource`, § 10.1) puis télécharge les flux
   RSS/Atom de **toutes** les sources — natives + personnalisées confondues (HTTP uniquement, aucune DB)
2. Insère les nouveaux items en base avec déduplication par URL
3. Attribue thèmes et sévérité automatiquement
4. Retourne des statistiques : `{"inserted": N, "skipped": N, "feeds": N, ..., "synced_at": ISO8601}` —
   `feeds` varie selon le nombre de sources personnalisées actives au moment de la synchro (18 natives +
   N personnalisées)

`synced_at` est aussi persisté en base (table `sync_state`, clé `watch`, cf. `docs/ARCHITECTURE.md`),
que la collecte ait trouvé 0 ou N nouveaux items — une sync qui ne trouve rien de neuf reste une sync
effectuée. Lu via `GET /api/watch/sync-status` au chargement des pages Veille technologique et Fuite de
données pour afficher "Dernière sync : jj/mm/aaaa hh:mm" sous le bouton **Synchroniser** (session
20/07/2026) sans dépendre d'un clic manuel dans la session en cours — nécessaire puisque le cycle
Celery horaire met aussi à jour cet horodatage, indépendamment de l'UI.

### 5.1 Déduplication à l'insertion + regroupement à l'affichage (session 24/07/2026)

Deux mécanismes distincts, à ne pas confondre :

**Déduplication à l'insertion — par URL exacte** (étape 2 ci-dessus). Empêche de réimporter un item déjà
en base. Limite : une même actualité arrive souvent à des **URLs différentes** — un avis CERT-FR
republié tel quel par Global Security Mag (domaines différents), ou le même article à deux URLs sur une
même source (variante avec/sans identifiant numérique). Titres identiques, URLs différentes → la dédup
par URL ne les voit pas. Constat 24/07 : 57 doublons sur ~1961 items.

**Regroupement à l'affichage — par titre normalisé** (`GET /api/watch`, param `group_duplicates`, défaut
`true`). Les items de **titre strictement identique** (minuscules, espaces normalisés) sont regroupés en
une seule ligne dans Veille technologique, avec toutes leurs sources en badges. **Rien n'est supprimé en
base** : le registre NIS 2 reste complet et auditable — c'est un regroupement de présentation, jamais un
filtrage (cohérent avec le principe « marque, ne filtre jamais » du profil de veille). Points clés :
- Représentant du groupe = statut le plus avancé (un groupe dont un membre est traité s'affiche traité) ;
  `received_at` affiché = plus ancienne occurrence.
- **Traiter une ligne groupée applique la décision à tous ses membres** (`group_item_ids`, cascade côté
  frontend) — sinon le groupe réapparaîtrait en « à traiter » (un membre encore `new`).
- Critère volontairement limité au titre identique : pas de regroupement « sujet proche » (même CVE,
  même produit), trop risqué pour un registre auditable — il fusionnerait à tort des actus distinctes.
- `group_duplicates=false` désgroupe (vue d'audit, une ligne par item réellement collecté). Le param
  reste exposé côté backend ; le toggle UI a été retiré (regroupement toujours actif à l'usage courant).
- Implémentation : `_group_rows_by_title` / `_group_dict` dans `routers/watch.py` (pagination Python,
  même chemin que `profile_only`).

---

## 6. Export auditeur (CSV)

L'export CSV est accessible via :
- Interface : bouton **Export CSV auditeur** (thèmes actifs pris en compte comme filtre)
- API : `GET /api/watch/export?date_from=2026-01-01&date_to=2026-12-31`

**Restreint aux items `severity=critical`** : ce sont les seuls soumis au SLA 48h (§ 4.1), donc les
seuls pour lesquels l'auditeur a besoin de voir la traçabilité complète du traitement — un export
mêlant les 100+ items informatifs/importants noyait le signal utile et rendait le registre difficile
à lire. Les items non critiques restent consultables à tout moment dans l'interface (filtre Sévérité).

**Colonnes exportées** (séparateur `;`, encodage UTF-8 avec BOM — nécessaire pour qu'Excel FR
détecte l'encodage et affiche correctement les caractères accentués) :

| Colonne | Description |
|---------|-------------|
| Date réception | Horodatage UTC de réception |
| Source | Label de la source |
| Titre | Titre de l'alerte |
| URL | Lien vers la publication originale |
| Thèmes | Liste des thèmes séparés par virgule |
| Statut | État de traitement, libellé FR (Nouveau / En cours / Traité / Non concerné) |
| Analyste | Identité du responsable |
| Date traitement | Horodatage UTC de clôture |
| Délai traitement (h) | Délai calculé en heures |
| Décision | Action décidée |
| CVE liée | CVE associée manuellement (validée par l'analyste) |
| Actifs concernés | Actifs du parc rattachés à l'élément (session 22/07/2026) |

*(la colonne Sévérité n'est plus exportée — elle vaut toujours "critique" vu le filtre ci-dessus ;
les CVE auto-détectées brutes ne sont plus exportées non plus, au profit de la seule CVE liée
validée par l'analyste, plus fiable pour l'audit)*

---

### Rapport hebdomadaire figé (session 22/07/2026)

En complément de cet export à la demande, le module Rapports produit chaque lundi un **rapport de
veille figé** par semaine ISO (`S30/2026`) : volume collecté, éléments traités, respect du SLA 48 h,
répartition par sévérité/source/thème, décisions consignées (avec actifs concernés) et stock restant.

Différence de nature, et c'est le point : l'export CSV reflète l'**état courant** du registre, alors
qu'un rapport hebdomadaire est un **instantané figé** — les chiffres de S30 ne bougeront plus, ce qui
en fait une preuve datée opposable. Cf. `docs/ARCHITECTURE.md` § Rapports hebdomadaires.

## 7. Procédure auditeur NIS 2

### 7.1 Prouver la surveillance continue

**Question auditeur** : *"Disposez-vous d'un processus de veille sur les vulnérabilités et menaces ?"*

**Réponse** : Accéder à http://localhost:3000/veille et montrer :
- Les sources surveillées (officielles françaises, médias, éditeurs — § 2), extensibles sans code
  (§ 10.1)
- La collecte automatique toutes les heures (scheduler Celery beat, logs `sync_watch_feeds`)
- Le nombre d'items reçus sur la période

**Commande de vérification** :
```bash
curl -s "http://localhost:8000/api/watch/stats?days=365" | python3 -m json.tool
```

### 7.2 Prouver le traitement dans les délais

**Question auditeur** : *"Traitez-vous les alertes dans des délais raisonnables ?"*

**Réponse** : Exporter le CSV (items critiques) et montrer :
- La colonne "Délai traitement (h)" (SLA interne 48h)
- La KPI "Taux traitement 30j" (% d'items traités sur le dernier mois, toutes sévérités confondues)
- La KPI "Délai moyen traitement" (en heures)
- La KPI "SLA critique dépassé" (idéalement = 0)

**Export de la période auditée** :
```bash
curl -s "http://localhost:8000/api/watch/export?date_from=2026-01-01&date_to=2026-12-31" \
  -o registre-veille-2026.csv
```

### 7.3 Prouver la traçabilité des décisions

**Question auditeur** : *"Pouvez-vous justifier les décisions prises sur chaque alerte ?"*

**Réponse** : Ouvrir n'importe quel item traité et montrer :
- `reviewed_by` : analyste identifié nominativement
- `reviewed_at` : date/heure de décision
- `decision` : texte décrivant l'action (patch planifié, non applicable car OS différent, etc.)
- `linked_cve_id` : CVE associée si pertinent

### 7.4 Prouver la couverture des sources réglementaires

**Question auditeur** : *"Suivez-vous les publications de l'ANSSI et du CERT-FR ?"*

**Réponse** : Filtrer par source "CERT-FR Alertes", "CERT-FR Avis", "ANSSI" dans l'interface ou via API :
```bash
curl -s "http://localhost:8000/api/watch?source=cert-fr-alerte,cert-fr-avis,anssi&per_page=50"
```

### 7.5 Prouver la gestion des incidents de données personnelles

**Question auditeur (RGPD)** : *"Effectuez-vous une veille sur les fuites de données ?"*

**Réponse** : Montrer l'onglet dédié **Fuite de données** (`/fuite-de-donnees`, § 9) — sources ZATAZ,
fuitesinfos.fr, ransomware.live, DataBreaches.net, Have I Been Pwned, filtrable par pays. Précision
utile pour l'auditeur : cet onglet est **informatif**, distinct du registre NIS 2 traçable (pas de
statut/analyste/décision) — le registre NIS 2 reste Veille technologique.
```bash
curl -s "http://localhost:8000/api/watch/leak-sources"
curl -s "http://localhost:8000/api/watch?source=zataz,fuitesinfos,ransomware-live,databreaches-net,hibp&per_page=50"
```

---

## 8. KPIs de veille (tableau de bord)

| KPI | Calcul | Seuil d'alerte |
|-----|--------|----------------|
| **Critiques non traités** | `COUNT WHERE severity=critical AND status IN (new, in_review)` | > 0 → rouge |
| **SLA critique dépassé (>48h)** | `COUNT WHERE severity=critical AND status=new AND received_at < NOW()-48h` | > 0 → rouge |
| **Taux traitement (30j)** | `treated_or_na / total_received * 100` | < 80% → attention |
| **Délai moyen traitement** | `AVG(reviewed_at - received_at)` des items traités sur 30j | > 24h → attention |

---

## 9. Fuite de données

Onglet informatif (`/fuite-de-donnees`) — grille de cards, sans workflow ni SLA. Objectif : donner un
coup d'œil rapide sur les fuites de données et attaques ransomware récentes, en France et dans le
monde.

### 9.1 Sources

| Source | Label | Type | Pays |
|--------|-------|------|------|
| `zataz` | ZATAZ | RSS | FR (défaut) |
| `fuitesinfos` | fuitesinfos.fr | RSS | FR (défaut) |
| `ransomware-live` | Ransomware.live | API JSON (`/v2/recentvictims`) | depuis l'API, par victime |
| `databreaches-net` | DataBreaches.net | RSS | — (non renseigné) |
| `hibp` | Have I Been Pwned | API JSON (`/v3/breaches`) | — (non renseigné) |

**ransomware.live** — `services/watch_fetcher.py::_fetch_ransomware_live()` — utilise uniquement
`/v2/recentvictims` : l'autre endpoint public (`/v2/countryvictims/{code}`) a un schéma de champs
différent (`post_title`/`post_url`/`group_name` au lieu de `victim`/`url`/`group`) et son seul lien
"public" est en réalité un lien `.onion` — jamais utilisé. Le champ `claim_url` (onion, lien direct
vers le site de fuite du groupe ransomware) n'est **jamais** exposé, seul `url` (page publique
ransomware.live) sert de lien sortant. Le titre de l'item est composé `"{victime} — {groupe}
({activité})"` ; le frontend (`FuiteDeDonnees.jsx::parseCompany()`) l'éclate pour afficher le nom de
l'entreprise à côté du badge source et le reste (groupe/activité) en sous-titre.

**Have I Been Pwned** — `services/watch_fetcher.py::_fetch_hibp()` — l'API `/v3/breaches` renvoie tout
l'historique connu (1000+ brèches depuis 2007) sans filtre serveur par date ; filtré côté client à
`AddedDate` < 120 jours (`HIBP_LOOKBACK_DAYS`) pour éviter d'insérer des centaines d'entrées
historiques dès la première synchro.

### 9.2 Pays et drapeaux

`WatchItem.country` (ISO 3166-1 alpha-2) est peuplé :
- Directement depuis l'API pour ransomware.live (`country` par victime)
- Par défaut `FR` pour ZATAZ et fuitesinfos.fr (trackers dédiés français, pas de champ pays natif)
- `NULL` pour DataBreaches.net, Have I Been Pwned, et toute source personnalisée sans pays par défaut
  renseigné (§ 10.1)

Drapeaux affichés en **SVG** (`components/FlagIcon.jsx`, paquet npm `country-flag-icons`), pas en
emoji unicode — les séquences d'indicateurs régionaux (🇫🇷 = "F"+"R") ne sont pas rendues comme un
vrai drapeau par tous les systèmes/navigateurs : Windows (hors Windows 11 avec police emoji à jour) et
certaines versions de Chrome affichent le texte brut "FR"/"DE" au lieu d'une image — repéré en test
réel côté utilisateur. `NULL`/pays inconnu affiche un globe (🌐, emoji simple non-drapeau, sûr partout).

Filtre pays (`FuiteDeDonnees.jsx`) : France sélectionnée par défaut, bascule "Monde entier" (aucun
filtre pays envoyé au backend) ou sélection multiple via `utils/countries.js` (~40 pays).

### 9.3 Différences avec Veille technologique

- Pas de statut/analyste/décision/SLA — `WatchItem.status` reste à `new` indéfiniment pour ces items,
  jamais affiché ni modifiable depuis cette page
- Filtre par **source** uniquement (pas de thèmes/sévérité) + filtre pays
- Cards en grille (1/2/3 colonnes responsive), une couleur distincte par source (chip + badge de
  carte) — palette fixe pour les sources natives, dérivée du slug (hash) pour les sources
  personnalisées (`colorForSlug()`, pas de couleur pré-assignable pour un nombre arbitraire de sources)

---

## 9bis. Surveillance Identités (session 20/07/2026)

Page `/surveillance-identites` (CyberVeille, couleur bleue `#58a6ff`). Objectif : repérer les fuites de
données **concernant l'entreprise elle-même**, là où Fuite de données (§ 9) est une veille générale
tous acteurs confondus.

**Principe — aucune source externe propre, 100% gratuit.** Le module ne collecte rien : il croise des
*identités surveillées* (table `watched_identities`, éditables dans l'interface) avec les `watch_items`
**déjà agrégés par `run_watch_sync`**, restreints aux sources leak (mêmes clés que
`GET /api/watch/leak-sources` : ZATAZ, fuitesinfos, ransomware.live, DataBreaches.net, HIBP + sources
personnalisées `category=leak`). Croisement calculé **à la volée** à chaque `GET /api/identities/matches`
(pas de stockage — toujours frais, volume faible).

**Quatre types d'identité** (`kind`) :
- `name` — nom d'entreprise (ex : "AER"). Matché en **mot entier** (`(?<!\w)…(?!\w)`, insensible à la
  casse) pour éviter les faux positifs en sous-chaîne, même précaution que le thème IA (§ 3). Pour
  ransomware.live, le nom est aussi comparé au **champ victime** isolé (partie du titre avant " — ",
  plus fiable que le titre entier).
- `domain` — domaine (ex : "aer.fr", normalisé en minuscules). Matché en **sous-chaîne** sur titre +
  résumé (les points le rendent déjà peu ambigu).
- `ip` / `ip_range` (session 20/07/2026) — voir § 9ter, mécanisme entièrement différent (pas de
  matching texte, vérification contre des listes de blocage).

**API** : `GET/POST/DELETE /api/identities` (CRUD, `POST` body `{value, kind}`, dédup 409 ; `kind=ip`
validé/normalisé via `ipaddress.ip_address`, `kind=ip_range` via `ipaddress.ip_network(strict=False)` —
400 si invalide),
`GET /api/identities/matches` → `{total, items[], identities_count, ip_total, ip_matches[]}` où chaque
item de `items` porte `matched_identities` (liste des valeurs ayant matché, affichées en badges rouges
sur la card) — `ip_matches` a un format différent, cf. § 9ter.

**Limite assumée** (identique au reste du gratuit) : on ne voit que ce qui est **publiquement rapporté**
par ces sources. Une fuite d'identifiants employés jamais relayée reste invisible — la vraie
surveillance par domaine (HIBP *Domain Search*, qui remonte les emails compromis) nécessite un
abonnement payant + vérification de propriété du domaine, hors périmètre gratuit. Piste d'enrichissement
gratuit envisagée mais non retenue au départ : Intelligence X (intelx.io), palier gratuit très limité en
crédits.

---

## 9quater. Vérification email/domaine en direct — XposedOrNot + GitHub (session 28/07/2026)

Extension demandée à partir d'un brouillon (`docs/SURVEILLANCE_ID.md`, fourni par l'utilisateur) qui
listait 11 sources OSINT (HIBP, IntelX, Hunter.io, Shodan, Censys, SecurityTrails, crt.sh, GitHub,
Reddit, Wayback Machine, XposedOrNot). Neuf écartées : payantes (HIBP, Hunter.io, Shodan, Censys,
SecurityTrails), déjà rejetée pour la même raison (IntelX, cf. § 9bis), ou hors-sujet pour ce module —
détection de fuite, pas reconnaissance d'infrastructure (crt.sh) — ou signal trop bruyant/instable
(Reddit, Wayback). Décision explicite de l'utilisateur : rester 100% gratuit, "si ça vaut pas le coup on
laisse tomber" plutôt que d'introduire un coût récurrent.

**Deux sources retenues, cinquième type d'identité (`kind="email"`) ajouté à `WatchedIdentity`** :

- **XposedOrNot** (`services/leak_lookup.py`) — `GET https://api.xposedornot.com/v1/check-email/{email}`,
  public, gratuit, sans clé. Testé en réel le 28/07/2026 : `{"breaches": [[...]], "status": "success"}`
  si trouvé, `{"Error": "Not found"}` sinon — **toujours HTTP 200**, jamais 404 (piège potentiel si on se
  fie au status code plutôt qu'au corps). Équivalent gratuit de HIBP (payant depuis 2023, cf. § 9bis).
- **GitHub code search** (même fichier) — cherche un domaine surveillé (`kind="domain"`) à côté d'un
  mot-clé d'identifiant (`password`, `secret`, `apikey`, `credentials`) dans du code public : signe
  qu'une configuration a pu être committée par erreur. **Nécessite un token personnel** (`GITHUB_TOKEN`,
  gratuit, aucun scope) — testé en réel le 28/07/2026 : `GET /search/code` renvoie **401 "Requires
  authentication" même sans clé pour du contenu 100% public**, contrairement aux autres endpoints de
  recherche GitHub (piège potentiel, ne pas supposer que "public" = "sans auth" sur cette API précise).
  Désactivé silencieusement sans `GITHUB_TOKEN` configuré (même logique que `NVD_API_KEY`), jamais une
  erreur — XposedOrNot reste actif indépendamment.

**Cache par valeur d'identité**, pas un téléchargement en masse comme les blocklists IP (§ 9ter) : ces
deux API sont interrogées par valeur, pas des listes disponibles en bloc. TTL de 6h (`CACHE_TTL_SECONDS`
dans `leak_lookup.py`), plus long que les 30 min des blocklists IP — une fuite ou un secret committé ne
varie pas d'une minute à l'autre, et ça ménage le quota gratuit de ces deux services.

**Réponse `osint_matches`** (même forme que `ip_matches` du § 9ter, pour un affichage frontend uniforme) :
`{identity_value, identity_kind, source_label, detail, url}` — `url` pointe vers le résultat GitHub le
cas échéant, toujours `null` côté XposedOrNot (pas de page à ouvrir pour une fuite). Affiché en section
tableau séparée sur `SurveillanceIdentites.jsx`, sous la section IP.

Testé en conditions réelles de bout en bout (email `test@example.com`, volontairement dans une fuite
connue pour valider le chemin complet) : validation 400 sur un email malformé, ajout, appel XposedOrNot,
cache (second appel : 148ms tous checks compris), affichage frontend, suppression — aucune erreur
console, 31/31 tests toujours au vert.

---

## 9ter. Surveillance IP / plage IP (session 20/07/2026)

Demande explicite de surveiller une IP ou plage IP publique. Vérifié avant d'implémenter : **0 des
1500+ items de veille déjà collectés ne contient une seule adresse IP** dans son titre/résumé — ces
sources parlent toujours au niveau "l'entreprise X a été piratée", jamais au niveau infrastructure. Le
matching texte (§ 9bis) ne fonctionnerait donc jamais pour une IP ; mécanisme différent retenu :

**Vérification contre des listes de blocage tierces** (`services/ip_watch.py`) plutôt qu'un matching
texte — le signal utile pour une IP surveillée n'est pas "un article vous cite" mais "une machine de
votre parc semble compromise" (bot, scan, bruteforce…). Sources 100% gratuites, sans inscription,
fraîcheur vérifiée avant intégration (même vigilance qu'à chaque ajout de source RSS, cf. § 5) :

| Source | Contenu | Volume | Fraîcheur constatée |
|--------|---------|--------|---------------------|
| **IPsum** (stamparm/ipsum, GitHub) | Agrégat de nombreuses blocklists publiques, `score` = nb de listes l'ayant signalée | ~115k IP | Mise à jour quotidienne (horodatage dans le fichier lui-même) |
| **Blocklist.de** | IP signalées par des fail2ban (bruteforce SSH/mail/web…) | ~23k IP | `Last-Modified` à quelques heures au moment du test |
| **Feodo Tracker** (abuse.ch) | Infrastructure C2 de malwares connus (Emotet, QakBot…) | Volontairement petit (quelques IP actives) | Projet actif, entrées avec `last_online` récent |

**Candidat écarté** : *ransomwatch* (github.com/joshhighet/ransomwatch), agrégateur ransomware
indépendant de ransomware.live — semblait prometteur mais l'historique des commits sur `posts.json`
montre **plus aucune mise à jour depuis juin 2025** (bot d'alimentation à l'arrêt). Une source figée
n'aurait jamais remonté de fuite récente ; écarté avant intégration plutôt qu'après coup.

**Seuil minimum sur le score IPsum** (`IPSUM_MIN_SCORE = 2`, session 20/07/2026) — le score compte le
nombre de blocklists indépendantes (parmi celles qu'IPsum agrège) ayant signalé l'IP. Distribution
réelle constatée sur ~113k IP : **score 1 = 78 355 IP, soit 69% du total** (une seule liste d'accord —
bruit/faux positifs fréquents), score 2 = 16 396, score 3 = 11 049, score 4+ = ~7 300 (haute confiance).
Filtrer sous 2 élimine le plus gros du bruit à source unique sans perdre les IP corroborées par au
moins une 2e liste. Blocklist.de et Feodo Tracker n'ont pas de score (listes déjà curées à leur façon),
donc rien à filtrer côté ces deux sources.

**Cache process** (`CACHE_TTL_SECONDS = 1800`, module `services/ip_watch.py`) — ces listes (jusqu'à
~115k lignes) sont retéléchargées au plus toutes les 30 min, pas à chaque `GET /api/identities/matches`,
pour ne pas marteler ces services tiers gratuits sans SLA. Un échec réseau sur l'une des 3 sources ne
fait pas échouer les autres (chacune conserve sa dernière version en cache en cas de panne ponctuelle).

**Matching** : `ip` comparé en égalité exacte (`ipaddress.ip_address`) ; `ip_range` vérifie
l'appartenance de chaque IP blocklistée à la plage (`ipaddress.ip_network`, `in`). Une plage peut
matcher plusieurs IP d'une même liste — chacune remontée séparément (`ip_matches`) pour que l'analyste
voie l'ampleur réelle plutôt qu'un simple "oui/non".

**Réponse `ip_matches`** (forme différente de `items`, pas de titre/résumé/URL — ce ne sont pas des
articles) : `{identity_value, identity_kind, source_label, ip, detail}` où `detail` est le score IPsum
ou le nom du malware Feodo (`null` pour Blocklist.de, qui ne fournit pas de détail).

Affiché dans l'interface en **section séparée** des cards de fuites (tableau, pas des cards — la donnée
est tabulaire par nature) puisque c'est un signal de nature différente.

---

## 10. Modèle de données

Table `watch_items` (PostgreSQL) — détail complet aussi dans `docs/ARCHITECTURE.md` :

```sql
CREATE TABLE watch_items (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source        VARCHAR NOT NULL,          -- identifiant source (cert-fr-avis, zataz, ou slug WatchSource)
    source_label  VARCHAR,                   -- nom affiché
    title         VARCHAR NOT NULL,
    url           VARCHAR UNIQUE,            -- clé de déduplication
    summary       TEXT,
    published_at  TIMESTAMPTZ,              -- date publication source
    received_at   TIMESTAMPTZ,              -- date import Allsafe (horodatage audit)
    severity      VARCHAR DEFAULT 'informational',  -- critical/important/informational
    status        VARCHAR DEFAULT 'new',    -- new/in_review/treated/not_applicable
    reviewed_by   VARCHAR,                  -- analyste
    reviewed_at   TIMESTAMPTZ,             -- date traitement (horodatage audit)
    decision      TEXT,                     -- action décidée
    linked_cve_id VARCHAR,                  -- CVE liée manuellement
    cve_ids_found JSON DEFAULT '[]',        -- CVE auto-détectées
    themes        JSON DEFAULT '[]',        -- thèmes auto-assignés
    country       VARCHAR                   -- ISO alpha-2, Fuite de données uniquement (§ 9.2)
);
```

Table `watch_sources` (PostgreSQL) — sources personnalisées, détail § 10.1 :

```sql
CREATE TABLE watch_sources (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       VARCHAR NOT NULL,
    slug       VARCHAR UNIQUE NOT NULL,     -- dérivé du nom, = watch_items.source
    url        VARCHAR NOT NULL,
    feed_type  VARCHAR DEFAULT 'rss',       -- rss / atom
    category   VARCHAR DEFAULT 'general',   -- general (Veille technologique) / leak (Fuite de données)
    country    VARCHAR,                     -- pays par défaut assigné aux items de ce flux
    enabled    BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ
);
```

---

## 10.1 Ajouter une source sans toucher au code

Depuis Veille technologique **ou** Fuite de données, bouton **+ Ajouter une source** (dropdown sources
pour Veille technologique — colonne "Personnalisées" ; barre de filtres pour Fuite de données) : nom,
URL du flux RSS/Atom, format, pays par défaut (optionnel, Fuite de données uniquement pertinent). La
source ajoutée est immédiatement synchronisée (`POST /api/watch/sync` déclenché automatiquement après
la création).

- **Validation d'URL contre le SSRF** (session 27/07/2026, `services/net_guard.py`) : l'URL est
  rejetée (400) si elle résout vers une adresse non publique (privée/loopback/lien-local/réservée) —
  avant, n'importe qui sur le réseau pouvait pointer une source vers l'interne (`127.0.0.1`, VLAN...),
  sans authentification sur l'API pour filtrer en amont. Revalidé à **chaque redirection** lors de la
  collecte (`watch_fetcher.py`), pas seulement à la création. Détail : `docs/SECURITY.md` § SSRF.
- `category` est fixée par la page d'origine, pas un choix dans le formulaire — **general** (ajoutée
  depuis Veille technologique) apparaît dans son registre et jamais dans Fuite de données ; **leak**
  (ajoutée depuis Fuite de données) fait l'inverse. `GET /api/watch/leak-sources` est la seule source
  de vérité consommée par les deux pages pour ce routage — jamais de liste dupliquée côté frontend.
- Le `slug` technique est dérivé du nom (`_slugify()`, `routers/watch.py`) : translittéré en ASCII
  (`unicodedata.normalize("NFKD", ...)`, ex. "Générale" → "Generale") avant d'être normalisé en
  minuscules/tirets — nécessaire pour les noms de source en français, qui contiennent presque toujours
  au moins une lettre accentuée. Une collision avec une source native ou déjà existante renvoie 409.
- Supprimer une source (`×` sur son chip) arrête sa collecte future mais **conserve tous les items déjà
  importés** — pas de FK entre `WatchItem` et `WatchSource`, le `source_label` est figé sur chaque item
  au moment de son import.
- Composants frontend partagés entre les deux pages : `components/AddSourceModal.jsx`,
  `components/FlagIcon.jsx`, `utils/countries.js`, `utils/color.js` (`hexToRgba`) — extraits dès la
  2e page consommatrice plutôt que dupliqués, cf. principe de scalabilité (`CLAUDE.md`).

---

## 11. Configuration et maintenance

### Ajouter une source native (codée en dur)

Pour la grande majorité des cas, préférer l'ajout sans code (§ 10.1) — ce qui suit ne concerne que les
sources qu'on veut committer dans le dépôt (pérennes, pas propres à une instance).

Éditer `backend/services/watch_fetcher.py` :

```python
# 1. Ajouter dans WATCH_FEEDS
{"name": "Nom affiché", "url": "https://..../feed/", "source": "slug-unique", "type": "rss"},

# 2. Ajouter dans SOURCE_DEFAULT_SEVERITY
"slug-unique": "important",

# 3. Ajouter dans SOURCE_DEFAULT_THEMES
"slug-unique": ["Cyber"],
```

Puis ajouter la source dans `frontend/src/pages/Watch.jsx` dans le tableau `SOURCES` et le groupe approprié de `SOURCE_GROUPS`.

### Modifier le SLA

Éditer `backend/routers/watch.py` :
```python
SLA_HOURS = 48  # ← modifier ici
```

### Modifier la fréquence de collecte

Éditer `backend/tasks/scheduled_tasks.py` :
```python
"watch-sync-hourly": {
    "task": "tasks.scheduled_tasks.sync_watch_feeds",
    "schedule": crontab(minute=10),  # ← H+10 de chaque heure
},
```

### Purger les anciens items

```bash
# Supprimer les items traités de plus de 12 mois
docker compose exec db psql -U cybervuln -c "
  DELETE FROM watch_items
  WHERE status IN ('treated', 'not_applicable')
  AND reviewed_at < NOW() - INTERVAL '12 months';
"
```

> ⚠️ Avant toute purge, effectuer un export CSV complet pour archivage.
