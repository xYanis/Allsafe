# INCIDENTS.md — Module Incidents (Allsafe)
## Registre d'incidents de sécurité + suivi des délais légaux de notification NIS 2

---

## 1. Vue d'ensemble

Le module **Incidents** (créé le 29/07/2026) est un registre auditable des incidents de sécurité,
distinct des trois autres registres du projet (Vulnérabilités, Veille technologique, Surveillance
Identités) mais qui peut s'alimenter de chacun d'eux. Il permet de :

- **Déclarer** un incident (titre, description, catégorie, sévérité, actifs concernés) — toujours à
  la main, jamais automatiquement, même quand l'origine est un signal déjà collecté par l'app (alerte
  de déception, vulnérabilité critique, item de veille sensible).
- **Qualifier** un incident comme relevant de l'obligation de notification NIS 2 (Directive, Art. 23)
  et suivre les 3 échéances légales qui en découlent.
- **Tracer** toute la chronologie (statut, notes, qualification, jalons envoyés) dans un journal
  append-only, à des fins d'audit.
- **Générer** un rapport **par incident**, à la demande (pas de figeage hebdomadaire — cf. § 7), et
  exporter un CSV du registre complet.

**URL** : http://localhost:3000/incidents · Rapport : http://localhost:3000/rapport-incidents  
**API** : `GET/POST /api/incidents`, `GET/PATCH/DELETE /api/incidents/{id}`,
`GET /api/incidents/{id}/timeline`, `GET /api/incidents/{id}/report`,
`POST /api/incidents/{id}/notes`, `POST /api/incidents/{id}/qualify-notification`,
`POST /api/incidents/{id}/unqualify-notification`, `POST /api/incidents/{id}/aware-at`,
`POST /api/incidents/{id}/milestones/{milestone}/mark-sent`,
`GET/POST /api/incidents/{id}/attachments`, `GET .../attachments/{aid}/download`,
`DELETE .../attachments/{aid}`, `GET /api/incidents/prefill`,
`GET /api/incidents/export`, `GET /api/incidents/nis2/pending-count`

---

## 2. Cadre légal — NIS 2, Art. 23

La Directive NIS 2 impose, pour les incidents **significatifs**, trois échéances à compter de la
**prise de connaissance** (`aware_at` — pas forcément la même date que la détection technique
`detected_at`, qui peut la précéder) :

| Jalon | Délai | Champ |
|---|---|---|
| Alerte précoce | 24 h | `early_warning_due_at` / `early_warning_sent_at` |
| Notification d'incident | 72 h | `incident_notification_due_at` / `incident_notification_sent_at` |
| Rapport final | 1 mois (calendaire) | `final_report_due_at` / `final_report_sent_at` |

⚠️ **Ce que l'application NE fait PAS** — même esprit que la règle absolue de non-intervention de
CyberVuln (CLAUDE.md) :
- Elle ne décide **jamais** elle-même qu'un incident est "significatif" — `requires_notification` est
  **toujours** posé par un acte humain explicite (`POST /qualify-notification`), avec justification
  obligatoire.
- Elle n'envoie **jamais** rien à l'ANSSI ou à une autre autorité. "Marquer un jalon comme envoyé"
  (`POST /milestones/{milestone}/mark-sent`) ne fait que consigner qu'un envoi a eu lieu **hors
  application** — l'app ne contacte aucun tiers.
- Elle ne recalcule **jamais** une échéance déjà atteinte par un envoi réel : un jalon marqué envoyé
  est un fait acquis, plus jamais modifiable (`aware_at_locked` verrouille alors toute la fiche).

Toute la logique de ces garde-fous vit dans `backend/services/nis2_deadlines.py` — le fichier le plus
sensible du module, documenté en tête avec le même niveau d'explicitation que
`services/patch_checker.py` pour CyberVuln.

---

## 3. Modèle de données

### `Incident` (table `incidents`)

Champs principaux : `title`, `description`, `category`, `severity`, `status`, `detected_at`,
`aware_at`, `aware_at_locked`, `reported_by`, `requires_notification` + les 9 champs des 3 jalons
(`{milestone}_due_at`/`_sent_at`/`_sent_by`), plus 3 liens optionnels vers l'origine du signal
(`security_event_id`, `vulnerability_id`, `watch_item_id` — `ON DELETE SET NULL`, jamais `CASCADE` :
l'incident et son audit trail survivent à la suppression de sa source) et `affected_asset_ids` (liste
d'UUID en JSON, même pattern que `WatchItem.asset_ids`).

### `IncidentTimelineEntry` (table `incident_timeline_entries`)

Journal **append-only**, générique (pas seulement les statuts, contrairement à
`VulnerabilityStatusHistory`) : chaque action auditable écrit une ligne — `created`, `status_change`,
`note`, `notification_qualified`, `notification_unqualified`, `milestone_sent`, `aware_at_changed`.
`ON DELETE CASCADE` sur `incident_id` : ici, contrairement aux 3 FK ci-dessus, la timeline appartient
bien à l'incident.

Suppression d'incident possible (`DELETE /api/incidents/{id}`), avec confirmation en modale côté
frontend — contrairement à `security_events`, un incident déclaré par erreur (doublon, test) doit
pouvoir être retiré du registre.

### `IncidentAttachment` (table `incident_attachments`)

Pièce jointe **PDF** du rapport final — 5 Mo max. Fichier écrit sur disque (volume Docker
`incident_attachments`, monté uniquement dans `backend`), toujours renommé en `{uuid4()}.pdf`
avant écriture (`filename` du client n'est conservé qu'en métadonnée d'affichage, jamais comme
chemin réel — path traversal). Validation pure dans `services/incident_attachments.py`
(`validate_pdf` : taille, extension, signature `%PDF-` en tête — un fichier texte renommé en
`.pdf` est rejeté). `ON DELETE CASCADE` sur `incident_id`.

`GET/POST /api/incidents/{id}/attachments`, `GET .../attachments/{aid}/download` (`FileResponse`,
nom d'origine restitué), `DELETE .../attachments/{aid}` (retire fichier + ligne — le fait que le
jalon "Rapport final" a été marqué envoyé reste, lui, immuable dans la chronologie).

---

## 4. Vocabulaire (listes fixes, V1)

Contrairement aux sources de veille (`WatchSource`, ajoutables sans code), ces trois listes sont
codées en dur des deux côtés (`backend/services/nis2_deadlines.py` et
`frontend/src/components/IncidentFormModal.jsx`) : taxonomie bornée et connue à l'avance, pas ouverte
par nature.

| Catégories | Sévérités | Statuts |
|---|---|---|
| Ransomware, Fuite de données, Intrusion, Déni de service, Hameçonnage, Logiciel malveillant, Erreur de configuration, Autre | Critique, Majeur, Mineur | Déclaré → En cours → Contenu → Résolu → Clôturé |

La sévérité est une échelle **dédiée**, distincte de la sévérité CVSS (`SeverityBadge.jsx`) — d'où un
composant de badge séparé (`IncidentSeverityBadge.jsx`).

---

## 5. Workflow

1. **Déclaration** — depuis zéro (`+ Déclarer un incident`) ou préremplie depuis un autre module
   (§ 6). Rien n'est jamais créé automatiquement : même préremplie, la création reste un clic
   explicite après relecture des champs suggérés.
2. **Suivi** — statut, notes libres (chronologie), actifs concernés, édition des champs généraux.
3. **Qualification NIS 2** (facultative) — `Qualifier à notifier`, justification obligatoire. Fige les
   3 échéances depuis `aware_at`. Réversible (`Déqualifier`) tant qu'aucun jalon n'a été envoyé.
4. **Jalons** — `Marquer envoyé` sur chacun des 3, au fur et à mesure. Verrouille `aware_at` dès le
   premier jalon envoyé. Une fois envoyé, bouton `Consulter` en regard du jalon : retrouve la
   justification consignée (date, auteur, contenu) sans devoir fouiller la chronologie.
   Sur "Rapport final" : section pièces jointes PDF (upload/téléchargement/suppression, 5 Mo max).
5. **Clôture** — statut `Résolu` puis `Clôturé`, sans effacer l'historique.

---

## 5bis. Roadmap & annuaire de contacts

Section affichée dans le détail de chaque incident (`IncidentRoadmap.jsx`), contextualisée à sa
catégorie — pas une page de référence séparée. Deux volets :

- **Plan d'action** — checklist de traitement par catégorie (`RESPONSE_STEPS`,
  `frontend/src/constants/incidentPlaybooks.js`), dans l'ordre **chronologique** où les étapes
  se présentent réellement (containment immédiat → évaluation → qualification/notifications
  externes aux échéances légales → remédiation → clôture). Chaque étape porte une étiquette
  Interne/Externe, affichée en ligne (pas en deux colonnes séparées, pour ne pas casser l'ordre).
  Fusionne l'ancienne checklist "bonnes pratiques" séparée (retirée le 29/07/2026 : elle faisait
  doublon une fois le plan d'action étoffé, cf. `completed_playbook_steps` dans
  `schema_patches.sql`) — la distinction utile n'était pas practique/rappel-légal mais **quand**
  l'étape intervient, d'où un seul flux ordonné. Persisté (`completed_response_steps` — liste
  `{index, by, at}`, pas de simples indices) pour ne pas perdre la progression entre deux
  ouvertures **et** savoir qui a réalisé chaque action : un sélecteur "Réalisé par" (pré-rempli
  depuis l'analyste actif, cf. `AnalystContext.jsx`) est obligatoire avant de cocher une étape,
  affiché ensuite sous l'étape cochée (nom + date). Simple aide-mémoire, pas une pièce d'audit :
  cocher une étape externe ("envoyer l'alerte précoce...") n'envoie ni n'atteste rien, la
  traçabilité réelle reste la qualification NIS 2 et les jalons "Marquer envoyé" eux-mêmes (§ 5).
- **Qui contacter** — organismes officiels codés en dur (`NATIVE_CONTACTS`, même fichier) +
  contacts personnalisés ajoutables sans toucher au code (`IncidentNotificationContact`, même
  principe que `WatchSource` pour la veille : natif en code, personnalisé en base). Une case
  "Des données personnelles sont concernées", indépendante de la catégorie, force l'affichage de
  la CNIL même hors catégorie `data_breach` (un ransomware ou une intrusion s'accompagnent souvent
  d'une exposition de données personnelles).

Contacts natifs (coordonnées **vérifiées le 29/07/2026** via les pages officielles — ce sont des
points d'entrée publics stables, pas des contacts nominatifs ; à reconfirmer périodiquement) :

| Organisme | Quand | Contact |
|---|---|---|
| ANSSI / CERT-FR | Toujours pertinent — déclaration NIS 2, assistance 24/7 | `cert-fr@ssi.gouv.fr` · 3218 · [portail](https://club.ssi.gouv.fr/#/declarations) |
| CNIL | Violation de données personnelles — délai RGPD 72h (régime distinct de NIS 2, même durée) | [portail notifications.cnil.fr](https://notifications.cnil.fr/notifications/) |
| Police / Gendarmerie | Infraction pénale (ransomware, intrusion) — dépôt de plainte | [service-public.fr](https://www.service-public.fr/particuliers/vosdroits/F1447) |
| Cybermalveillance.gouv.fr | Orientation, prestataires qualifiés | [cybermalveillance.gouv.fr](https://www.cybermalveillance.gouv.fr/) |

`GET/POST/PATCH/DELETE /api/incidents/notification-contacts` pour les contacts personnalisés.
**Aucun envoi n'a lieu depuis l'app** — les liens `mailto:`/portail ouvrent le client mail/navigateur
de l'utilisateur, même garde-fou que le reste du module (cf. § 2).

---

## 5ter. Gestion de crise

Escalade au-delà d'un incident seul (31/07/2026, cf. `models.py::Crisis`/`CrisisTimelineEntry`,
`routers/crises.py`, page `Crises.jsx` — nouvel item de nav « Gestion de crise », module Incidents).
Comble le vide identifié par `ROADMAP_RNCP42335.md` (Bloc 1.5 « Gestion de crise cyber ») :
la Roadmap (§ 5bis) hébergeait déjà un plan d'action par catégorie, mais aucune structure
d'escalade/cellule de crise.

Une **crise** est une entité séparée, distincte d'un incident, qui peut en regrouper **plusieurs**
(ex : un ransomware qui déclenche aussi une fuite de données) — `Incident.crisis_id`, nullable,
`ON DELETE SET NULL` (supprimer la crise ne supprime jamais les incidents qu'elle regroupait, même
logique que les 3 FK optionnelles § 3). Un incident appartient à zéro ou une crise à la fois.

- **Activation** — toujours un acte humain explicite (`activated_at`/`activated_by` obligatoires à
  la création, la création EST l'activation), jamais automatique — même esprit que
  `requires_notification` sur `Incident`.
- **Cellule de crise** — rôles nommés assignés à un analyste (`crisis_roles`, JSON, même pattern
  que `affected_asset_ids` : pas de table de liaison séparée). Rôles suggérés (pas une liste
  fermée) : Décideur, Communication, Technique, Juridique, RH.
- **Incidents liés** — rattachement/détachement, refusé si l'incident est déjà rattaché à une
  autre crise active (pas de double-rattachement) ou si la crise est désactivée.
- **Journal** (`CrisisTimelineEntry`, sibling exact d'`IncidentTimelineEntry`) — décisions et
  communications internes/externes horodatées et attribuées. **Aucun envoi réel depuis l'app** :
  même garde-fou que le reste du module (§ 2) — la communication est **tracée**, jamais envoyée.
- **Désactivation** — justification obligatoire, jamais automatique.
- **Plan d'action** (`CRISIS_STEPS`, `frontend/src/constants/crisisPlaybook.js`) — checklist
  générique (pas de branchement par catégorie, contrairement à `RESPONSE_STEPS` : une crise n'a
  pas de catégorie), cochable et attribuée (`Crisis.completed_crisis_steps`, même forme
  `{index, by, at}` et même garde-fou qu'`Incident.completed_response_steps` — simple
  aide-mémoire, pas une pièce d'audit).
- **Intervenants à prévenir** (`CrisisContact`, natif `NATIVE_CRISIS_CONTACTS` + personnalisé en
  base) — Direction générale, RSSI, DPO, Communication/RP, Juridique, Assureur cyber, RH. Distinct
  de l'annuaire `IncidentNotificationContact` (autorités réglementaires ANSSI/CNIL, filtrées par
  catégorie d'incident) : la crise vise la mobilisation interne, pas de notion de catégorie.
  Composant `CrisisRoadmap.jsx`, réutilise `ContactRow`/`ScopeTag` (exportés d'`IncidentRoadmap.jsx`)
  tels quels — pas de duplication.
- **Registre « Rôles » (organigramme)** — nouvelle section dans « Intervenants à prévenir »
  (crise) et « Qui contacter » (incident, sous-section « Postes internes à contacter ») :
  affiche `OrganizationRole` (Administration > onglet Rôles, poste → personne → email, ex.
  RSSI → Michel Lacroix), géré indépendamment du module Incidents/Crise mais consommé par les
  deux. Distinct des contacts ad-hoc (`CrisisContact`/`IncidentNotificationContact`, texte libre
  non garanti nominatif) : ce registre contient des noms réels, donc **anonymisé en mode
  Présentation** (`utils/fakeData.js::anonymizeRoleHolder`) — le poste reste affiché tel quel
  (non sensible), seuls le nom et l'email basculent en fictif. Chaque poste peut être rattaché à
  un **Service** (`Service`, Administration > onglet Services — RH/DSI/Juridique/Direction en
  seed, liste ouverte avec code couleur) : la grille de cartes se colore alors par service
  plutôt que par un hash du poste.
- **Lien bidirectionnel avec un incident** — le rattachement existait déjà dans le sens Crise →
  Incident (`POST /api/crises/{id}/incidents`). `IncidentDetailModal.jsx` porte désormais le geste
  symétrique : bouton « 🚨 Escalader en crise » (affiché quand l'incident n'est pas déjà rattaché),
  ouvrant `EscalateToCrisisModal.jsx` — créer une nouvelle crise ou rattacher à une crise active
  existante. **Aucun nouvel endpoint** : composition de `createCrisis`/`linkCrisisIncident`/
  `getIncident` déjà existants, côté frontend uniquement.

Hors scope de cette version (délibérément) : pas de mode « simulation d'exercice » distinct des
incidents réels — un exercice de crise réellement joué (compétence 🎯 du Bloc 1.5) pourrait
réutiliser `Crisis`/`CrisisTimelineEntry` tels quels le moment venu, mais ce n'est pas construit
aujourd'hui. Cf. `ROADMAP_RNCP42335.md` : construire l'outil ne prouve pas la compétence, seul
l'exercice réellement conduit le fera.

---

## 6. Intégrations avec les autres modules

Un unique point de couplage, volontairement minimal (`components/DeclareIncidentButton.jsx`) : un
lien vers `/incidents?from=<source_type>&id=<source_id>`, présent sur :

| Module | Page | `source_type` |
|---|---|---|
| Paramètres > Sécurité | `AdministrationSecurity.jsx` (journal `security_events`) | `security_event` |
| CyberVuln | `Vulnerabilities.jsx` (toutes sévérités) | `vulnerability` |
| CyberVeille | `Watch.jsx` (items critiques/importants) | `watch_item` |

`GET /api/incidents/prefill?source_type=...&id=...` renvoie des suggestions (titre, description,
catégorie, sévérité, actifs) — **strictement lecture seule**, ne crée jamais rien. La modale de
création s'ouvre préremplie ; la création reste un acte humain explicite.

---

## 7. Rapport par incident

Contrairement aux 3 autres rapports du module Rapports (CVE, Veille, Surveillance — hebdomadaires,
figés sur une semaine ISO, `services/weekly_report.py`), les Incidents n'ont **pas** de rapport
hebdomadaire : un incident est rare, jamais plusieurs la même semaine, et son suivi se fait à
l'unité. Le rapport porte donc sur **un incident**, généré **à la demande**, jamais figé/archivé.

Pas besoin de geler un instantané comme pour les 3 autres rapports : une fois un jalon marqué
envoyé ou `aware_at` verrouillé, ces champs n'évoluent plus jamais — le rapport peut être recalculé
en direct à chaque consultation sans risque d'incohérence avec ce qui a été "prouvé" à un instant T.

`GET /api/incidents/{id}/report` → `{"summary": <markdown>}`, produit par
`services/incident_report.py::build_incident_report()`, sans aucune écriture en base. Contenu :

- En-tête : titre, catégorie, sévérité, statut, prise de connaissance, déclarant, description
- Qualification NIS 2 : justification si qualifié, sinon "non qualifié" (pas d'échéances suivies)
- Alerte précoce / Notification : échéance, et si envoyée → date, auteur, **contenu réel** de la
  justification consignée au moment du "Marquer envoyé" (récupéré depuis la chronologie, pas
  juste un statut "envoyé/pas envoyé")
- Rapport final : échéance, date d'envoi, et **liens de téléchargement** des PDF joints
  (`IncidentAttachment`, § 3) — le PDF fait foi, pas de texte ici
- Chronologie complète en fin de rapport

Frontend : `pages/RapportIncidents.jsx` liste tous les incidents (réutilise les mêmes badges que
`Incidents.jsx`) avec un bouton "Consulter le rapport" par ligne, ouvrant un panneau inline sous le
tableau (rendu markdown + export PDF navigateur, mêmes briques que les archives hebdomadaires —
`components/ReportMarkdown.jsx`). L'export CSV du registre complet (§8), en haut de page, reste
indépendant de ce rapport nominatif.

---

## 8. Export CSV

`GET /api/incidents/export` — colonnes : titre, catégorie, sévérité, statut, prise de connaissance,
déclarant, qualification NIS 2, échéances/envois des 3 jalons, actifs concernés. Même protection
anti-injection de formule que les autres exports (`services/csv_safety.py`).

---

## 9. Procédure auditeur

**Question auditeur** : *"Disposez-vous d'un processus de notification des incidents conforme à
NIS 2 ?"*

**Réponse** : Ouvrir http://localhost:3000/incidents, filtrer "À notifier NIS 2", et montrer pour un
incident qualifié :
- `aware_at` et les 3 échéances calculées automatiquement (24h/72h/1 mois calendaire)
- La justification de qualification (`notification_justification`, horodatée, nominative)
- Les jalons déjà envoyés (date + qui) et ceux encore en attente/dépassés
- La chronologie complète (`GET /api/incidents/{id}/timeline`) — jamais modifiable après coup

**Vérification** :
```bash
curl -s "http://localhost:8000/api/incidents?requires_notification=true" | python3 -m json.tool
curl -s "http://localhost:8000/api/incidents/export" -o registre-incidents.csv
```
