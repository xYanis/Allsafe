# Roadmap RNCP42335 — « Expert de la sécurité des données, des réseaux et des systèmes »

> **Échéance : juillet 2028.** Document révisé le 30/07/2026 (première version le même jour, refondue
> après précision de la date et clarification de ce que le jury évalue réellement).
>
> Fiche enregistrée jusqu'au 29/05/2029 → le référentiel ne bougera pas d'ici le passage.
>
> Ce document est un **outil de pilotage**, pas une liste de fonctionnalités. Il se relit
> **tous les trimestres** : c'est le seul garde-fou contre la dérive sur 24 mois (construire ce qui
> plaît plutôt que ce qui sert le titre).

---

## Principe directeur — deux natures de preuve

L'erreur la plus coûteuse serait de croire qu'une fonctionnalité dans Allsafe démontre une compétence.
Les cinq blocs sont **tous** évalués par *rapport + soutenance devant jury*. Le jury n'évalue pas le
code d'Allsafe.

Chaque compétence se prouve par l'une de ces trois natures :

| Nature | Ce que c'est | Exemple |
|---|---|---|
| 🔧 **Outil** | Une capacité implémentée dans Allsafe | Module Incidents → suivi des délais NIS 2 |
| 🎯 **Acte** | Quelque chose que **tu as fait**, documenté | Conduire un pentest, mener une enquête OSINT |
| 📄 **Écrit** | Un livrable rédigé | PSSI, rapport d'audit, note de souveraineté |

**Une compétence 🎯 ne se prouve jamais par du 🔧.** Construire un gestionnaire d'audits démontre que
tu sais faire un CRUD, pas que tu sais auditer. L'outil *héberge* la preuve, il ne l'est pas.

C'est le principal correctif apporté à la première version de ce document, qui rangeait tout en
« fonctionnalités à construire ».

---

## Modalités d'évaluation (extraites de la fiche officielle)

| Bloc | Modalité |
|---|---|
| 1 | Étude de cas avec rapport et soutenance devant jury + scénario de crise (présentation technique et situationnelle) |
| 2 | Mise en situation : protection du SI d'une entreprise ciblée par des cyberattaques, rapport et soutenance |
| 3 | Audit technique d'une organisation, rapport détaillé et présentation devant jury |
| 4 | Enquête OSINT complète, analyse de traces numériques, rapport de Cyber Threat Intelligence |
| 5 | Soutenance de projet professionnel démontrant la capacité à renforcer la résilience |

À lire à l'envers : il faut produire **un rapport d'étude de cas, un scénario de crise, un rapport de
mise en situation, un rapport d'audit, un rapport CTI et une soutenance de projet.** Tout le reste
n'existe que pour alimenter ces six livrables.

---

## Matrice de traçabilité

État : ✅ prouvable aujourd'hui · 🟡 base existante à compléter · ⬜ rien.
À maintenir en continu — c'est ici qu'on retrouve, en 2028, quel artefact prouve quoi.

### Bloc 1 — Piloter la stratégie de sécurité des SI

| # | Compétence | Nature | État | Artefact |
|---|---|---|---|---|
| 1.1 | Gouvernance / PSSI | 📄 | 🟡 | Module Documentation (31/07/2026) héberge PSSI/chartes/organigramme avec historique de versions — **l'outil existe, la PSSI elle-même reste à rédiger** (l'un ne prouve pas l'autre, cf. principe ci-dessus) |
| 1.2 | Gestion des risques | 🔧📄 | 🟡 | `services/scoring.py` (risque technique). Manque un registre de risques métier |
| 1.3 | Conformité RGPD / NIS 2 / CRA / DORA | 🔧 | ✅ NIS 2 | Module Incidents (Art. 23), Veille (registre auditable), mode Présentation (RGPD). CRA/DORA hors contexte |
| 1.4 | PCA / PRA + tests | 🔧📄 | 🟡 | `services/backup.py`. Manque : document PCA + **traçabilité d'un test de restauration réel** 🎯 |
| 1.5 | Gestion de crise cyber | 🎯 | 🟡 | `Crisis`/`CrisisTimelineEntry` (31/07/2026, page `/crises`) hébergent désormais escalade + cellule de crise + journal. Manque toujours : **un exercice de crise réellement joué** |
| 1.6 | Conseil direction | 📄 | 🟡 | Rapports exécutifs (`ReportMarkdown.jsx`) |

### Bloc 2 — Détecter les intrusions et traiter les incidents

| # | Compétence | Nature | État | Artefact |
|---|---|---|---|---|
| 2.1 | SIEM / EDR-XDR / IDS-IPS | 🔧🎯 | 🟡 | `withsecure_client.py` (EDR réel, lecture seule). Pas de SIEM — à compléter par une pratique en labo |
| 2.2 | Analyse / qualification d'alertes SOC | 🎯 | 🟡 | `security_events` + `EventDetailModal` = triage réel sur honeypots |
| 2.3 | Detection Engineering (YARA/SIGMA) | 🔧🎯 | ⬜ | À construire — **règles appliquées aux `security_events`**, pas une bibliothèque passive |
| 2.4 | Investigation numérique (Forensic) | 🎯 | ⬜ | Timeline d'incident enrichie (sources de preuve rattachées) + un cas réellement instruit |
| 2.5 | Reverse engineering malware | 🎯 | ⬜ | **Hors Allsafe** — labo isolé, sur 24 mois c'est atteignable |
| 2.6 | Piloter le DFIR (CERT/CSIRT) | 🔧 | ✅ | Module Incidents complet (déclaration → qualification → jalons → rapport) |

### Bloc 3 — Audits techniques et simulations d'intrusion

> Module implémenté le 03/08/2026 (cf. `STATUS.md`). Spécification complète : **`docs/AUDITS.md`**.

| # | Compétence | Nature | État | Artefact |
|---|---|---|---|---|
| 3.1 | Audit d'architecture | 🎯📄 | ⬜ | À conduire sur Allsafe lui-même — l'architecture est documentée (`docs/ARCHITECTURE.md`), le module pour l'héberger existe désormais |
| 3.2 | Audit de configuration | 🔧 | ✅ | `services/asset_scanner.py` — durcissement CIS-like (mdp, SSH root, RDP-NLA, SMBv1, pare-feu), lecture seule. Preuve directe |
| 3.3 | Audit de code source | 🎯 | ✅ | `AUDIT_SECURITE.md` (6 findings, 24/07/2026) **formalisé** dans le module Audits (03/08/2026) : audit autorisé, findings saisis avec statut réel (5 corrigés+retestés, 1 ouvert) |
| 3.4 | Audit sécurité IA/ML | 🎯 | ⬜ | **Hors Allsafe** (aucun modèle à auditer — l'« Analyser IA » est du mot-clé local). Labo |
| 3.5 | Test d'intrusion | 🎯 | ⬜ | À conduire — le module Audits pour l'héberger existe désormais |
| 3.6 | Red Team | 🎯 | ⬜ | Idem, avec axe narratif (TTPs, chemin d'attaque) — `mitre_techniques` déjà au modèle |
| 3.7 | Rédaction / restitution | 📄 | ✅ | `services/audit_report.py` + `ReportMarkdown.jsx` — rapport d'audit généré et vérifié en conditions réelles |
| 3.8 | Cadrage + conformité légale | 🔧📄 | ✅ | **Autorisation bloquante** implémentée (`POST /audits/{id}/authorize`, immuable, aucun finding avant) — la conformité rendue structurelle, pas documentaire |

### Bloc 4 — Analyser et anticiper les menaces

| # | Compétence | Nature | État | Artefact |
|---|---|---|---|---|
| 4.1 | Collecte OSINT (+ SOCMINT/GEOINT/HUMINT) | 🔧🎯 | ✅ OSINT | Surveillance Identités (`ip_watch.py`, `leak_lookup.py`). Les autres disciplines : hors périmètre outil |
| 4.2 | Cycle du renseignement | 📄 | 🟡 | Veille le suit informellement — à formaliser explicitement |
| 4.3 | Caractériser les menaces (acteurs, TTPs, IoCs) | 🔧 | ⬜ | Tags MITRE ATT&CK sur `WatchItem` + page « Acteurs de la menace » |
| 4.4 | Corrélation technique / stratégique | 📄 | 🟡 | Rapports exécutifs |
| 4.5 | Détection d'ingénierie sociale | 🎯 | ⬜ | **Hors Allsafe** (exigerait passerelle mail/proxy) — analyse ponctuelle documentée |
| 4.6 | Cadre éthique et légal | 📄 | ✅ | `docs/VEILLE.md` — choix documenté de sources gratuites/légales, sans scraping agressif |
| 4.7 | Rapports CTI | 📄 | 🟡 | Type de rapport « Threat Intelligence » à ajouter, une fois 4.3 posé |

### Bloc 5 — Piloter un projet de résilience

Ce bloc se démontre par **la conduite d'Allsafe**, pas par une fonctionnalité.

| # | Compétence | Nature | État | Artefact |
|---|---|---|---|---|
| 5.1 | Cadrer / piloter un projet | 📄 | ✅ | `STATUS.md` + `docs/HISTORIQUE.md` — journal daté, décision par décision |
| 5.2 | Animer des équipes | 🎯 | ⬜ | **Point faible réel.** Projet solo. À traiter honnêtement en soutenance, ou trouver une collaboration d'ici 2028 |
| 5.3 | Secure by Design | 📄 | ✅ | Rôle `cbr_app`, verrou DDL, TOFU SSH, Fernet, anonymisation, RBAC — **à rassembler dans une note dédiée** |
| 5.4 | Mise en œuvre + maintien | 🔧 | ✅ | `backend/tests/`, `schema_patches.sql`, `CHECKLIST_DOCKER.md` |
| 5.5 | Argumenter les choix | 📄 | ✅ | `HISTORIQUE.md` est déjà rédigé sous cette forme (le « pourquoi » systématique) |
| 5.6 | Impact environnemental / souveraineté | 📄 | ⬜ | On-premise, zéro donnée cloud — argument fort **jamais formulé comme tel** |
| 5.7 | Retour d'expérience | 📄 | ✅ | `docs/HISTORIQUE.md` = REX continu |

---

## Séquencement 2026 → 2028

24 mois, donc pas de tri par le risque : l'ordre suit la cohérence et la dynamique. Le seul jalon
dur est le gel.

### S2 2026 — construire l'ossature

- ✅ **Module Audits** (`docs/AUDITS.md`) — construit le 03/08/2026. Couvre 3.8 en structurel,
  héberge 3.1/3.5/3.6 à venir (actes encore à conduire — un jury n'évalue pas l'outil).
- ✅ Audit d'Allsafe (`AUDIT_SECURITE.md`) saisi comme premier jeu de données → 3.3 formalisé.
- **Démarrer la matrice ci-dessus dès maintenant**, tenue en continu.

### S1 2027 — renseignement et détection

- Detection engineering : règles appliquées aux `security_events` (2.3).
- Tags MITRE ATT&CK + page Acteurs de la menace (4.3), puis rapport CTI (4.7).
- Module PSSI (1.1) et registre de risques métier (1.2).

### S2 2027 — les actes

La phase où l'on *fait*, en s'appuyant sur les modules construits pour héberger les résultats :

- Conduire un **audit complet d'Allsafe** — architecture, configuration, code, pentest (3.1/3.2/3.3/3.5).
- Mener une **enquête OSINT réelle** de bout en bout → livrable Bloc 4.
- Jouer un **exercice de crise** déception → incident → notification NIS 2 (1.5, et mise en situation
  du Bloc 2).
- Tester une **restauration de sauvegarde** et la tracer (1.4).
- Labo à côté : reverse engineering (2.5), pratique pentest.

### S1 2028 — gel et rédaction

**Gel des fonctionnalités.** Plus une ligne de feature. Uniquement :

- Rédaction des six livrables (cf. § Modalités d'évaluation).
- Note « Secure by Design & Souveraineté » (5.3 + 5.6).
- REX final, préparation de la soutenance.

Le gel est le point le plus important du calendrier : sans lui, tu codes encore en juin 2028 au lieu
d'écrire.

---

## Hors périmètre Allsafe (à prouver autrement)

Sur 24 mois ces items redeviennent atteignables — **hors de l'application**, en labo ou par un
livrable écrit. Ne pas les forcer dans Allsafe : ça dénaturerait l'outil pour une preuve médiocre.

| Compétence | Pourquoi hors Allsafe | Alternative |
|---|---|---|
| 2.5 Reverse engineering | Exige une sandbox isolée | Labo dédié, rapport d'analyse |
| 3.4 Audit IA/ML | Aucun modèle dans Allsafe à auditer | Labo, modèle tiers |
| 4.1 SOCMINT/GEOINT/HUMINT | Hors domaine d'un outil de gestion de vulnérabilités | Enquête documentée |
| 4.5 Ingénierie sociale | Exigerait passerelle mail / proxy web | Analyse ponctuelle de campagne réelle |
| 1.3 CRA / DORA | DORA = secteur financier, hors contexte | Traitement théorique en étude de cas |

---

## Revue trimestrielle

À chaque trimestre, trois questions :

1. La matrice a-t-elle avancé, ou seulement le code ?
2. Ce que j'ai construit ce trimestre sert-il un livrable identifié ?
3. Quelles compétences 🎯 restent sans acte réalisé ?

La troisième est la plus importante : ce sont celles qui ne se rattrapent pas en codant.
