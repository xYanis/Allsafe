# Module Audits — spécification

> ✅ **IMPLÉMENTÉ (03/08/2026).** Ce document reste la référence de conception — l'implémentation
> réelle la suit fidèlement (backend `backend/routers/audits.py`, `backend/models.py::Audit` et
> suivants, `backend/services/audit_attachments.py`/`audit_finding_history.py`/`audit_report.py` ;
> frontend `frontend/src/pages/Audits.jsx`/`AuditDetail.jsx`, `components/AuditFormModal.jsx`/
> `AuditFindingModal.jsx`). Détail de session : `STATUS.md` (03/08/2026). Premier jeu de données
> saisi : audit « Audit de code — Application CBR » (nom du produit au moment de la saisie, cf.
> CLAUDE.md § Rebranding), 6 findings d'`AUDIT_SECURITE.md` (§9).
>
> Contexte : ce module est le chantier prioritaire de `ROADMAP_RNCP42335.md` (Bloc 3 du titre visé —
> audits techniques et simulations d'intrusion).

---

## ⏮ Précédent — ce module a déjà été construit puis retiré (03/07/2026)

**À lire avant de relancer le chantier.** Un module Pentest a été **intégralement implémenté et testé
le 03/07/2026, puis supprimé à la demande de l'utilisateur avant merge** (cf. `docs/HISTORIQUE.md`
§ « Module Pentest construit puis retiré »).

Ce qui existait alors : modèles `PentestEngagement` / `PentestFinding`, `backend/routers/pentest.py`,
réécriture de `Pentest.jsx`, généralisation d'`AnnotationModal`/`AnnotationDetailModal` (props
`title`/`target`). CRUD, transitions de statut et cascade de suppression validés au `curl`, création
vérifiée en navigateur. Tout a été effacé : router supprimé, modèles retirés de `models.py`, montage
retiré de `main.py`, tables droppées en base, `Pentest.jsx` restauré, exports `pentest*` retirés de
`client.js`, props d'`AnnotationModal` reverties.

**Motif du retrait à l'époque : « pas de besoin confirmé pour l'instant ».** Ce n'était pas un rejet
de la conception — le design retenu alors (hub de suivi d'engagements/findings, aucun scan actif,
cohérent avec la non-intervention) est *le même* que celui spécifié ci-dessous, retrouvé
indépendamment. C'est plutôt une validation croisée de la forme.

**Ce qui a changé depuis** : le besoin est désormais confirmé et daté — le Bloc 3 du RNCP42335
(échéance juillet 2028) exige de conduire et restituer des audits. Reconstruire est justifié
aujourd'hui alors que ça ne l'était pas en juillet 2026.

**Trois enseignements à réutiliser :**

1. La généralisation d'`AnnotationModal`/`AnnotationDetailModal` (props `title`/`target`) avait été
   nécessaire pour ce module et rebalayée avec lui — le même besoin réapparaîtra, autant le prévoir.
2. Le nommage a changé : `PentestEngagement`/`PentestFinding` → `audits`/`audit_findings`, parce que
   le périmètre s'élargit de « pentest » aux cinq types d'audit (§ 1). Si des traces de l'ancien
   nommage réapparaissent quelque part, c'est du résidu de 2026, pas de l'existant.
3. Le module avait été construit avant que le besoin soit établi. Cette fois l'ordre est inverse :
   la spécification et la justification (`ROADMAP_RNCP42335.md`) précèdent le code.

---

## 1. Pourquoi « Audits » et pas « Pentest »

Le module s'appelait « Pentest » jusqu'au 30/07/2026. Renommé parce qu'un module pentest-only ne
couvre que deux des cinq compétences d'audit attendues. Les cinq types partagent le même cycle de vie
(cadrage → autorisation → conduite → findings → restitution → contre-vérification) : **un seul modèle
avec un champ `type`**, pas cinq modules.

| Type | Ce qui change | Référentiel typique |
|---|---|---|
| `architecture` | Revue de conception, analyse des flux | ANSSI, schémas d'architecture |
| `configuration` | Durcissement des composants | CIS Benchmarks |
| `code` | Recherche de failles applicatives | OWASP ASVS, CWE |
| `pentest` | Exploitation sur un périmètre défini | PTES, OWASP Top 10 |
| `redteam` | Scénario d'attaque complet, TTPs | MITRE ATT&CK |

Le `referential` est un **champ libre piloté en base**, pas une énumération codée en dur — cf.
principe scalable (CLAUDE.md) : l'utilisateur ajoutera ses propres référentiels sans toucher au code.

---

## 2. Règle absolue — Allsafe n'exécute jamais l'audit

Le module **héberge et structure** le travail d'audit. Il ne lance aucun scan, n'invoque ni Nmap, ni
Burp, ni sqlmap, et ne stocke aucun identifiant d'exploitation. Les outils offensifs tournent dans un
labo, en dehors de la plateforme ; seuls les résultats — triés et rédigés à la main — entrent dans
Allsafe.

C'est la même règle de non-intervention que pour les serveurs (CLAUDE.md § 1), appliquée au domaine
offensif. Ce n'est pas une limitation à contourner plus tard : c'est la frontière qui rend le module
cohérent avec le reste de l'outil.

⚠️ **Tension à connaître** : un futur module Bastion (accès jump host aux serveurs critiques, cf.
`frontend/src/pages/Bastion.jsx`) entrerait, lui, en conflit frontal avec cette règle. Les deux
vivent sous le même groupe de nav « Sécurité » mais ne posent pas le même problème — à ne pas
confondre au moment de trancher.

---

## 3. Garde-fou central — l'autorisation bloquante

C'est ce qui distingue le module d'un simple bug tracker.

Un audit démarre en statut `cadrage`. Pour passer en `autorise`, **tous** ces champs doivent être
renseignés :

- `scope` — périmètre technique explicite
- `rules_of_engagement` — ce qui est permis et interdit (horaires, DoS, ingénierie sociale…)
- `authorized_by` — qui a mandaté l'audit
- `authorized_at` — quand
- une pièce jointe : le mandat écrit

**Tant que l'audit n'est pas `autorise`, aucun finding ne peut y être saisi.** Une fois posés, ces
champs deviennent immuables — même logique que `aware_at_locked` sur les incidents
(`services/nis2_deadlines.py`) : une trace d'audit ne se réécrit pas après coup.

Motivation : un audit technique sans mandat écrit est une intrusion. Rendre la règle *structurelle*
plutôt que documentaire évite de la contourner par inadvertance, et rend la conformité démontrable.

---

## 4. Modèle de données

À créer via `backend/db/schema_patches.sql` (rôle superuser `cybervuln`, jamais `cbr_app` — cf.
`docs/ARCHITECTURE.md` § Verrou DDL), avec les `GRANT` explicites pour `cbr_app`.

### `audits`

```sql
id                   UUID PRIMARY KEY
title                VARCHAR NOT NULL
type                 VARCHAR NOT NULL   -- architecture|configuration|code|pentest|redteam
methodology          VARCHAR            -- boite_noire|boite_grise|boite_blanche
referential          VARCHAR            -- libre : OWASP ASVS, CIS, PTES, ANSSI...
status               VARCHAR NOT NULL   -- cadrage|autorise|en_cours|termine|archive
scope                TEXT
rules_of_engagement  TEXT
authorized_by        VARCHAR            -- immuable une fois posé
authorized_at        TIMESTAMPTZ        -- immuable une fois posé
conducted_by         VARCHAR            -- registre `analysts` existant
started_at           TIMESTAMPTZ
ended_at             TIMESTAMPTZ
executive_summary    TEXT               -- rédigé en fin d'audit
created_at           TIMESTAMPTZ
```

### `audit_assets` (liaison)

Un audit cible des actifs **déjà connus d'Allsafe** (les 72 machines importées d'AD/SSH). Pas de saisie
libre d'un parc parallèle.

```sql
audit_id  UUID REFERENCES audits(id) ON DELETE CASCADE
asset_id  UUID REFERENCES assets(id) ON DELETE CASCADE
PRIMARY KEY (audit_id, asset_id)
```

### `audit_findings`

```sql
id                  UUID PRIMARY KEY
audit_id            UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE
title               VARCHAR NOT NULL
description         TEXT
severity            VARCHAR NOT NULL   -- CRITICAL|HIGH|MEDIUM|LOW|INFO (réutilise SeverityBadge.jsx)
cvss_vector         VARCHAR            -- optionnel, tous les findings n'en ont pas
cvss_score          FLOAT              -- optionnel
cwe_id              VARCHAR            -- ex: CWE-89
owasp_ref           VARCHAR            -- ex: A03:2021
affected_asset_id   UUID REFERENCES assets(id) ON DELETE SET NULL
affected_component  VARCHAR            -- URL, endpoint, fichier:ligne (audit de code)
cve_id              VARCHAR REFERENCES cves(cve_id)  -- si le finding retombe sur une CVE connue
proof_of_concept    TEXT               -- étapes de reproduction
impact              TEXT
recommendation      TEXT
status              VARCHAR NOT NULL   -- ouvert|remediation_planifiee|corrige|risque_accepte|faux_positif
mitre_techniques    JSONB              -- ["T1078", "T1021.001"] — surtout redteam
discovered_at       TIMESTAMPTZ
retested_at         TIMESTAMPTZ
retest_result       VARCHAR            -- corrige|partiellement_corrige|non_corrige
retested_by         VARCHAR
created_at          TIMESTAMPTZ
```

### `audit_finding_history`

Transitions de statut append-only, même pattern que `services/vuln_history.py::record_status_change`
(`old_status`, `new_status`, `changed_at`, `changed_by`, `notes`).

**Décision de conception** : ne PAS généraliser les trois journaux existants (`vuln_history`,
`incident_timeline`, celui-ci) en un seul. Leurs formes diffèrent — l'un trace des transitions de
statut, l'autre des événements libres. Le refactor coûterait plus qu'il ne rapporterait, et
toucherait deux modules stables.

### Pièces jointes

Réutiliser le pattern `IncidentAttachment` (`services/incident_attachments.py` : validation de
taille, signature de fichier, stockage disque + métadonnées en base). Deux différences : le mandat
d'autorisation est rattaché à l'`audit`, les captures d'écran de preuve aux `findings`, et il faut
**étendre les types acceptés aux images** (PNG/JPEG) en plus du PDF — donc valider aussi les
signatures `\x89PNG` et `\xFF\xD8\xFF`.

---

## 5. Le retest — la partie que tout le monde oublie

Un audit ne se termine pas au rapport, il se referme par une **contre-vérification** : on revient
vérifier que les findings ont réellement été corrigés. D'où `retested_at` / `retest_result` /
`retested_by` sur chaque finding.

C'est ce qui distingue un processus d'audit mature d'une liste de problèmes. À la restitution, la
question « et vous avez vérifié que c'était corrigé ? » doit avoir une réponse tracée.

Conséquence côté UI : un audit `termine` dont des findings restent `ouvert` sans retest doit être
visuellement signalé — pas bloqué, signalé.

---

## 6. Intégrations avec l'existant

Sans elles, un tableur suffirait. C'est ce qui justifie de construire le module *dans* Allsafe.

| Intégration | Détail |
|---|---|
| **Finding → Actif** | La fiche d'un actif affiche ses findings d'audit à côté de ses vulnérabilités. Renforce la distinction Actifs = vue sécurité (cf. CLAUDE.md § Inventaire) |
| **Finding → Incident** | `DeclareIncidentButton.jsx` gère déjà le préremplissage depuis vulns / veille / événements de sécurité. Ajouter `source_type="audit_finding"` : un finding révélant une compromission réelle devient un incident NIS 2 |
| **Finding → CVE** | Si le pentest retombe sur une CVE déjà en base, on lie (`cve_id`) au lieu de dupliquer |
| **Rapport d'audit** | `services/audit_report.py`, calqué sur `incident_report.py` : markdown généré **à la demande, jamais persisté**, rendu par `ReportMarkdown.jsx` (impression PDF navigateur, pas de génération serveur) |
| **Priorisation** | Un finding sur un actif à criticité haute remonte — réutilise `asset.tags.criticite` (cf. `services/scoring.py`) |
| **Dashboard** | Compteur de findings ouverts non retestés |

---

## 7. Ce qui n'est délibérément PAS prévu

**Import automatique depuis Nmap / Burp / Nessus.** Envisagé puis écarté :

- Effort d'ingénierie réel pour une valeur nulle en restitution — un jury n'évalue pas un parseur.
- Ça pousse à déverser de la sortie brute de scanner, exactement ce qui fait un mauvais rapport
  d'audit. Un vrai rapport contient des findings triés, hiérarchisés et rédigés à la main.
- Parser du XML de provenance externe ajoute une surface d'attaque (XXE) qu'il faudrait traiter avec
  `defusedxml` (déjà présent dans `requirements.txt` pour WinRM).

La saisie manuelle est le mode principal, par choix. Si un import arrive un jour, il devra rester un
confort secondaire, jamais le chemin nominal.

---

## 8. Frontend

| Écran | Contenu |
|---|---|
| `/audits` | Liste des audits : type, statut, période, conduit par, compteurs de findings par sévérité |
| `/audits/:id` | Détail : bloc cadrage/autorisation (verrouillé une fois autorisé), tableau des findings, synthèse exécutive, bouton « Rapport » |
| Modale finding | Création/édition — tous les champs du § 4, pièces jointes |
| Rapport | `ReportMarkdown.jsx` existant, aucun rendu à réécrire |

Composants réutilisés tels quels : `SeverityBadge.jsx`, `ConfirmModal.jsx`, `PageLoader.jsx`,
`ReportMarkdown.jsx`, `DeclareIncidentButton.jsx`.

---

## 9. Premier jeu de données

`AUDIT_SECURITE.md` (racine, 24/07/2026) contient déjà 6 findings priorisés sur Allsafe lui-même, rédigés
à la main. Ils constituent le premier audit à saisir : type `code`, périmètre « application CBR »
(nom du produit au moment de la saisie),
conduit par l'analyste, avec le statut de remédiation réel de chacun (5 des 6 ont été implémentés le
27/07/2026 — donc directement retestables).

Le module n'est jamais vide, et l'audit de code du Bloc 3 démarre sans rien inventer.

---

## 10. Effort estimé

Comparable au module Incidents, le plus gros chantier récent du projet.

- **Backend** : 4 tables (`schema_patches.sql`), `models.py`, `routers/audits.py`,
  `services/audit_report.py`, extension de `incident_attachments.py` aux images.
- **Frontend** : 2 pages, 2-3 modales, points d'intégration.
- **Tests** (`backend/tests/`, sans base de données) : le garde-fou d'autorisation (impossible de
  saisir un finding sur un audit non autorisé), l'immuabilité de `authorized_by`/`authorized_at`, les
  transitions de statut.

Compter 2 à 3 sessions.
