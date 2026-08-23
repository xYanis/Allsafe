# Pitch soutenance — RNCP42335

> Premier jet, rédigé le 23/08/2026, à raccrocher à la matrice de `ROADMAP_RNCP42335.md`. À réviser
> tous les trimestres avec elle : chaque case qui passe de 🟡/⬜ à ✅ doit se traduire ici par une
> phrase, pas juste par une ligne de tableau. Écrit pour être **dit à voix haute**, pas lu — phrases
> courtes, pas de jargon non expliqué. Durée cible : 12-15 min, laisse de la marge pour les questions
> du jury (le format réel prévoit une soutenance par bloc + une soutenance de projet professionnel
> pour le bloc 5 — ce texte sert de trame commune, à découper selon le bloc visé le jour J).

---

## 0. Rappel du cadrage (à ne pas dire au jury, juste pour toi)

Le jury n'évalue pas le code d'Allsafe. Il évalue ce que sa construction et sa conduite prouvent sur
tes compétences, via les livrables écrits + la soutenance orale. Chaque section ci-dessous doit donc
retomber sur un **acte** ou un **écrit**, jamais sur "regardez, j'ai codé ce bouton".

---

## 1. Accroche (30 secondes)

> "Une entreprise qui gère 80 serveurs manuellement pour savoir lesquels sont vulnérables perd deux
> choses : du temps d'analyste, et de la fiabilité — un oubli sur une CVE critique, et c'est une porte
> d'entrée ouverte. Cyberwatch, l'outil du marché, coûte 13 500 € par an pour ça. J'ai construit
> Allsafe pour répondre à la même question, en on-premise, sans dépendance cloud, et je m'en sers comme
> colonne vertébrale de mon parcours vers ce titre."

---

## 2. Le problème et le contexte (1-2 min)

- Parc réel : 80 VM on-premise, majorité Windows Server jointes à un Active Directory, minorité Linux.
- Le besoin de départ est simple à énoncer, difficile à bien faire : *quelles vulnérabilités connues
  affectent réellement mon parc, et lesquelles sont déjà corrigées ?*
- Contrainte non négociable posée dès le départ : **l'outil n'exécute et n'écrit jamais rien sur un
  serveur supervisé**. C'est un outil d'aide à la décision, pas un outil d'intervention — la décision
  reste humaine, tracée, assumée.
- Choix de souveraineté : zéro donnée envoyée à un tiers, zéro service cloud. Argument que je formule
  explicitement ici (cf. bloc 5.6, resté "jamais formulé comme tel" jusqu'à cette version du pitch).

---

## 3. Ce qu'Allsafe fait, concrètement (3-4 min)

Dérouler le pipeline en une phrase par étape, avec **une preuve technique par étape** pour montrer que
ce n'est pas superficiel :

1. **Inventaire** — import Active Directory en lecture seule, complété par un agent Rust léger côté
   poste pour les machines mal atteintes en SSH/WinRM. *Preuve de rigueur* : le compte de service AD
   n'a aucun droit d'écriture, vérifié en conditions réelles.
2. **Collecte des CVE** — synchronisation NVD (NIST), incrémentale + rattrapage complet.
3. **Corrélation actif × CVE** — trois mécanismes en cascade (CPE, paquets installés, mots-clés), parce
   qu'un simple matching de version se trompe sur les cas réels (ex. "Debian 1" matcherait "Debian 12"
   par coïncidence de préfixe). *C'est le genre de bug que seul un vrai run en conditions réelles fait
   remonter.*
4. **Vérification du correctif** — sans les droits WMI qu'un compte de service standard n'a en réalité
   jamais (constat de terrain), donc reconstruite sur journal d'événements, registre et API .NET.
   Windows croisé sur build OS vs build du KB Microsoft (preuve), pas seulement sur le KB installé
   (faux négatifs systématiques avec les mises à jour cumulatives). Linux via le Debian Security
   Tracker, seule source qui voit correctement les backports.
5. **Décision** — un HIGH/MEDIUM/LOW avec correctif prouvé peut basculer automatiquement en "corrigé" ;
   une CRITICAL, jamais — validation humaine explicite obligatoire, toujours.

*Ligne de fermeture de section* : "Chaque étape a son piège documenté et son choix justifié — c'est
dans `docs/MATCHING.md` si le jury veut le détail technique complet."

---

## 4. Ce que la sécurité de l'outil lui-même démontre (2 min)

Ne pas se contenter de dire "c'est sécurisé" — donner des faits datés :

- Scan de sécurité applicative (Strix, white-box) mené sur le backend, résultats conservés
  (`strix_runs/`) : posture jugée bonne, zéro injection SQL/RCE/SSRF exploitable.
- Findings réels trouvés et corrigés en conditions réelles : contrôle d'accès manquant sur l'export de
  sauvegarde (BFLA), fuite cross-utilisateur sur des notes (BOLA), falsification de score de risque côté
  client, injection CSV résiduelle — chacun avec un correctif et un retest documentés dans `STATUS.md`.
- Ce n'est pas un audit ponctuel oublié ensuite : c'est un cycle répété avant chaque mise en production,
  avec un audit complet formalisé prévu avant le passage en prod (24/08/2026).

*Message à faire passer* : je ne prétends pas qu'Allsafe est parfait — je montre que je sais trouver
ses failles et les corriger, ce qui est exactement la compétence évaluée.

---

## 5. Ce que ce projet prouve, bloc par bloc (4-5 min — le cœur de la soutenance)

Reprendre `ROADMAP_RNCP42335.md` § Matrice de traçabilité et ne citer que les lignes ✅ ou 🟡 solides,
en insistant sur la distinction outil/acte à chaque fois :

- **Bloc 1 (Gouvernance)** — module Gouvernance héberge PSSI/chartes avec historique de versions ;
  conformité NIS 2 tracée via le registre de veille auditable et le module Incidents (art. 23).
  *Ce que je dois encore livrer* : la PSSI elle-même rédigée — l'outil qui l'héberge ne la remplace pas.
- **Bloc 2 (Détection et incidents)** — pilotage DFIR complet (déclaration → qualification → jalons →
  rapport) sur les 3 échéances légales NIS 2 (alerte 24h, notification 72h, rapport 1 mois). Connexion
  EDR réelle en lecture seule (WithSecure). *Acte encore à faire* : un vrai cas de triage SOC instruit
  de bout en bout, pas seulement l'outil qui l'hébergerait.
- **Bloc 3 (Audit et intrusion)** — module Audits couvrant les 5 types (architecture, configuration,
  code, pentest, Red Team), avec autorisation écrite bloquante et immuable avant tout finding : la
  conformité légale est structurelle, pas juste documentée. Premier audit de code réel saisi (6 findings,
  5 corrigés et retestés). *Actes à conduire d'ici S2 2027* : audit d'architecture et pentest complets
  sur Allsafe lui-même.
- **Bloc 4 (Renseignement et menaces)** — module de veille technologique (~20 sources, SLA 48h sur les
  critiques) et surveillance d'identités (fuites, listes de blocage publiques, 100% sources gratuites et
  légales — choix éthique documenté). *Reste à poser* : tags MITRE ATT&CK et un vrai rapport CTI.
- **Bloc 5 (Piloter un projet de résilience)** — celui-ci se prouve par la conduite du projet, pas par
  une fonctionnalité : `STATUS.md` et `docs/HISTORIQUE.md` sont un journal de décisions daté et
  argumenté depuis le début, pas une documentation reconstruite a posteriori. Secure by design tenu de
  bout en bout (rôle DB restreint, verrou DDL, chiffrement Fernet, anonymisation, RBAC). Tests
  automatisés et checklist de déploiement en place.

---

## 6. Ce que je n'ai pas et pourquoi je le dis (1-2 min — anticiper la question du jury)

Section volontairement honnête, à ne pas éviter :

- **"Animer des équipes" (5.2)** — projet solo. Je l'assume : je n'ai pas d'exemple à donner ici
  aujourd'hui. Soit je trouve une collaboration réelle d'ici 2028, soit je le traite frontalement en
  soutenance plutôt que d'essayer de le maquiller.
- **Reverse engineering malware, audit IA/ML, ingénierie sociale** — hors périmètre volontaire
  d'Allsafe (un outil de gestion de vulnérabilités n'a rien à auditer côté IA, et le reverse exige une
  sandbox isolée qu'il serait absurde de greffer dessus). Prouvés autrement, en labo, d'ici la fin du
  parcours.
- Ce cadrage lui-même — savoir dire "ceci ne prouve pas cela" — est aussi une preuve de maturité
  professionnelle, pas juste un aveu de manque.

---

## 7. Clôture et trajectoire (1 min)

> "Allsafe n'est pas fini, et ce n'est pas le but à ce stade : c'est un outil qui évolue avec mon
> parcours jusqu'à 2028. Le calendrier est clair — construire l'ossature restante en 2026, mener les
> actes réels (audits, enquête OSINT, exercice de crise) en 2027, geler les fonctionnalités début 2028
> pour ne plus faire que rédiger et préparer cette soutenance. Ce que je vous ai présenté aujourd'hui
> est l'état à mi-parcours, avec sa traçabilité complète et ses manques assumés."

---

## Notes pour la prochaine révision

- Mettre à jour la section 5 dès qu'une ligne 🟡/⬜ de la matrice RNCP passe à ✅ avec un acte réel
  (audit d'architecture, pentest, enquête OSINT, exercice de crise — cf. séquencement S2 2027).
- Une fois la PSSI rédigée : l'ajouter en preuve écrite du bloc 1, pas seulement citer le module qui
  l'héberge.
- Vérifier si une collaboration (5.2) est apparue avant la rédaction finale S1 2028 ; sinon, préparer la
  réponse honnête à avoir en soutenance plutôt que de la découvrir sur le moment.
- Chiffrer précisément l'argument souveraineté (5.6) : temps de traitement, coût comparé, absence totale
  de flux sortant — actuellement affirmé, pas encore démontré par des chiffres.
