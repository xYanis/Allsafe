// Contenu des guides pas à pas par page (19/08/2026, demande utilisateur — un guide d'aide
// flottant sur chaque page, aussi détaillé que celui des Agents). Data-driven : ajouter/étendre
// un guide = éditer une entrée ici, aucun composant à toucher (principe scalable, CLAUDE.md).
// Rendu par components/PageGuide.jsx, monté une seule fois dans Layout.jsx et résolu selon la
// route courante (guideForPath). Contenu rédigé à partir du code réel de chaque page.
//
// Forme d'un guide : { title, subtitle, steps: [{ title, body, packages? }] }.
// `packages` (optionnel, réservé à /agents) : [{ os, label, desc, cmds }] — rendu avec le logo
// OS (OsLogo) et un bloc de commandes copiable.

export const PAGE_GUIDES = {
  // ─── CyberVuln ───────────────────────────────────────────────────────────────
  '/dashboard': {
    title: 'Guide — Tableau de bord',
    subtitle: "Piloter la posture de sécurité du parc : suivre, prioriser et qualifier les vulnérabilités, sans jamais agir sur les serveurs.",
    steps: [
      { title: "Les actions globales en haut de page", body: "Dans l'en-tête « Dashboard », trois commandes. « Matching CVE » relance en fond le rapprochement CVE ↔ actifs (barre de progression, dernière synchro affichée dessous). « Patch check global » relance le contrôle read-only des correctifs — son libellé devient « Patch check (N actifs) » si un filtre Actifs est posé ; le petit bouton fléché à côté force une réévaluation complète (fenêtre de confirmation obligatoire). La cloche ouvre l'« Historique des notifications » des 7 derniers jours." },
      { title: "Le bandeau « Depuis votre dernière visite »", body: "Bandeau vert (👋) qui récapitule ce qui s'est passé pendant votre absence, cycle de nuit compris : vulns corrigées ou qualifiées faux positif automatiquement, nouvelles vulnérabilités détectées, actifs ajoutés/supprimés, alertes de sécurité et échéances NIS 2. Purement informatif — cliquez un CVE pour voir son justificatif, ou la croix pour fermer. Il ne redemande jamais d'action à ce niveau." },
      { title: "Suivre l'« Analyse en cours »", body: "Quand un cycle de patch check tourne, un bandeau bleu affiche l'actif contrôlé (SSH ou WinRM), le CVE en cours, le pourcentage global et une estimation du temps restant, puis le détail par actif (barre de progression, OS, espace disque libre). Ce contrôle est en lecture seule : Allsafe lit l'état, n'exécute jamais rien sur le serveur." },
      { title: "Lire les indicateurs clés", body: "Quatre cartes en haut : « Actifs exposés » (sur le total, avec le nombre restant à configurer), « Vulns ouvertes », « En attente d'un patch » (taux + nombre bloqué) et « Taux de correction global » (couleur selon le score). Juste en dessous, « Taux de correction par sévérité » détaille CRITICAL/HIGH/MEDIUM/LOW avec barre et ratio corrigées/total. Peuvent s'y ajouter les cartes « Findings d'audit » et « Certificats SSL (PRTG) »." },
      { title: "Explorer les graphiques", body: "Deux visualisations : « Répartition des vulnérabilités ouvertes » (camembert par sévérité) et « Actifs les plus exposés » (barres horizontales, top 5). Tout se recalcule selon le filtre Actifs actif." },
      { title: "Filtrer les trois tableaux", body: "La barre « Filtres » agit sur tout (KPI, graphiques, tableaux). Choisissez un ou plusieurs actifs (« Tous les actifs » par défaut), une ou plusieurs sévérités, une criticité métier, ou tapez un identifiant CVE. Trois cases affinent : « ✓ Patch détecté uniquement », « 🚫 Faux positifs proposés » et « ✅ Correctif déjà appliqué ailleurs ». Le bouton « Réinitialiser » remet tout à zéro." },
      { title: "Traiter les vulnérabilités ouvertes", body: "Le tableau « Vulnérabilités à traiter » liste les vulns ouvertes (triables par Sévérité, Score, Publié). Sur chaque ligne : « Analyser », « 🔍 Patch check », « ⏳ En attente », « 🚫 Faux positif » et « ✓ Corrigé ». Cochez des lignes pour agir en masse (« 🔍 Patch check (N) », « ✓ Corrigé (N) », « 🚫 Faux positif (N) »). Rappel : Allsafe propose, l'analyste valide — une vuln CRITICAL n'est jamais basculée automatiquement, seul un humain la marque corrigée." },
      { title: "Suivre les vulns en attente et traitées", body: "En dessous, « Vulnérabilités en attente d'un patch correctif » (le correctif n'est pas encore publié — badge « partiel » pour les cas mixtes) et « Vulnérabilités traitées » (regroupe « Corrigée » et « Faux positif », filtrables par statut). Chaque ligne y reste réouvrable via « ↩ Réouvrir », et un clic sur le badge/l'annotation ouvre le justificatif de clôture." },
    ],
  },
  '/vulnerabilities': {
    title: 'Guide — Vulnérabilités',
    subtitle: "Suivre et qualifier les vulnérabilités par actif. Allsafe aide à décider ; il n'écrit et n'exécute jamais rien sur un serveur, quelle que soit la sévérité.",
    steps: [
      { title: "Filtrer et retrouver une vulnérabilité", body: "La barre « Filtres » combine : champ « Rechercher une CVE… », sélecteur d'actifs, « Tous statuts », « Toutes sévérités », « Tous valideurs », et trois cases : « Masquer les CVE > 2 ans » (affichage seulement), « ⚠ KEV » (exploitation active confirmée) et « Metasploit » (module dispo). Le tableau s'ouvre par défaut sur le statut « open ». Le bouton « Réinitialiser » remet tout à zéro. Tri en cliquant sur les colonnes « Sévérité », « Score » et « Publié »." },
      { title: "Lire une ligne du tableau", body: "Colonnes : « CVE » (lien vers la fiche NVD), « Actif » (avec pastille de connectivité), « Statut », « Sévérité » (+ badges KEV/Metasploit), « Score » (CVSS), « Publié », « Détecté », et « Date patch »/« Validé par » quand le statut le justifie. Le score de priorité croise CVSS, EPSS et la criticité de l'actif. Un « ⚠ » rouge signale une revue de risque accepté en retard. Le badge « Correctif déjà appliqué sur N autre(s) actif(s) » (ou « Déjà qualifié… ») renvoie au diagnostic posé ailleurs pour cette même CVE." },
      { title: "Analyser, vérifier et obtenir des pistes", body: "Sur chaque ligne : « Analyser » (analyse IA), « 🔍 Patch check », « Recommandation » et « Script ». Le « 🔍 Patch check » ouvre une connexion WinRM (Windows) ou SSH (Linux) strictement en LECTURE SEULE — il rapporte « Patch détecté », « Patch non détecté » ou « CVE sans objet sur cet actif », plus le build installé. Aucune commande n'est jamais exécutée pour appliquer un correctif ; la validation, le test et l'application sur le serveur restent la responsabilité de l'analyste." },
      { title: "Marquer une vulnérabilité comme corrigée", body: "Le bouton « ✓ Marquer comme corrigé » (menu de validation) demande le validateur et une note. Rappel des règles de sévérité : une vuln HIGH/MEDIUM/LOW peut basculer en « corrigé » automatiquement si un correctif est détecté, et rester réouvrable ; une vuln CRITICAL doit TOUJOURS être validée à la main, jamais automatiquement. Le bouton « ↩ Réouvrir » annule une correction. La bascule ne touche que la base Allsafe, jamais le serveur." },
      { title: "Qualifier autrement : faux positif, en attente, risque accepté", body: "« 🛡 Risque accepté » ouvre une modale où justification, validateur et date de revue sont obligatoires (versée à la piste d'audit NIS 2). Deux autres statuts existent, alimentés par le patch check : « Faux positif » (produit absent de la machine — rien n'a été corrigé) et « En attente d'un correctif » / « (partiel) » (la distribution n'a publié aucun correctif — bascule seule en corrigé dès publication). Une décision humaine n'est jamais écrasée automatiquement." },
      { title: "Traiter en masse via les bandeaux de candidats", body: "En haut de page, des raccourcis groupés apparaissent selon les cas : « ⏳ En attente de correctif », « 🚫 Faux positifs à qualifier », « 🛡️ Validation groupée CRITICAL » et « 🛡 Accepter en masse ». Chaque modale traite un lot avec une barre de progression, mais chaque élément reste à confirmer — rien n'est basculé sans action explicite, et le CRITICAL reste validé un par un." },
      { title: "Historique, justificatif et déclaration d'incident", body: "« 🕒 Historique » montre toutes les transitions de statut (manuelles et automatiques). « 📋 Justificatif » ré-affiche l'annotation de l'analyste et le résultat technique ayant motivé une clôture. Le bouton de déclaration d'incident pré-remplit un incident depuis cette vulnérabilité (jamais de création automatique). Le bouton « ↩ Réutiliser cette justification » d'un autre actif ne fait que pré-remplir l'annotation — vérifiez-la puis validez avec « ✓ Marquer comme corrigé »." },
    ],
  },
  '/cves': {
    title: 'Guide — CVE',
    subtitle: "Catalogue de toutes les CVE publiées sur les 15 derniers jours, pas seulement celles touchant le parc. Vue de veille en lecture seule.",
    steps: [
      { title: "Comprendre le périmètre de la page", body: "Contrairement à « Vulnérabilités » (qui croise les CVE avec vos actifs), cette page liste TOUTES les CVE publiées dans les 15 derniers jours, qu'elles concernent votre parc ou non. C'est une base documentaire de veille : aucune action de remédiation ni de qualification ici, uniquement de la consultation." },
      { title: "Actualiser la base depuis NVD", body: "Le bouton « Actualiser », en haut à droite, ouvre le menu « Synchroniser NVD » avec deux fenêtres : « 7 derniers jours » et « 15 derniers jours ». La synchro peut prendre 1 à 3 min (l'API NVD est le facteur limitant). Un bandeau affiche l'avancement puis le bilan : nombre de CVE créées et mises à jour." },
      { title: "Filtrer la liste", body: "La barre « Filtres » propose : « Rechercher CVE ID ou description… », « Toutes sévérités », un champ « CVSS min » (0 à 10), et deux bascules « ⚠ KEV uniquement » (exploitation active confirmée) et « Metasploit uniquement » (module d'exploit disponible). Les filtres se cumulent et relancent la recherche immédiatement." },
      { title: "Lire une ligne du tableau", body: "Colonnes : « CVE ID » (lien vers la fiche NVD dans un nouvel onglet), « Publiée », « Description » (tronquée, survol pour le texte complet), « CVSS », « EPSS » (probabilité d'exploitation, en %), « Sévérité » et « Source ». Le score CVSS est coloré par gravité (rouge ≥ 9, orange ≥ 7, bleu ≥ 4)." },
      { title: "Interpréter les badges de sévérité et d'exploitabilité", body: "La colonne « Sévérité » affiche le niveau (CRITICAL/HIGH/MEDIUM/LOW) et, en dessous, les badges d'exploit : KEV (et KEV rançongiciel), Metasploit avec son rang. CVSS mesure la gravité théorique, EPSS la probabilité réelle d'exploitation — les deux ensemble aident à prioriser ce qui mérite attention." },
      { title: "Parcourir les résultats", body: "Le tableau pagine par 50 (50 CVE par page). En bas, « ← Préc. », l'indicateur « Page X / Y » et « Suiv. → » permettent de naviguer. Le total des résultats correspondant aux filtres est rappelé à gauche de la pagination. Pour agir sur une CVE qui touche réellement le parc, passez par la page « Vulnérabilités »." },
    ],
  },

  // ─── CyberVeille ─────────────────────────────────────────────────────────────
  '/veille': {
    title: 'Guide — Veille technologique',
    subtitle: "Registre de veille auditable conforme NIS 2 : collecte, tri, qualification et traçabilité des alertes cyber.",
    steps: [
      { title: "Synchroniser la collecte", body: "En haut à droite, cliquez « Synchroniser » pour lancer une collecte. Le message flash indique le nombre de nouveaux items et de doublons ignorés. La date de « Dernière sync » s'affiche juste en dessous. À l'ouverture, le tableau montre uniquement les items « Critique » et « Nouveau » (présélection par défaut de ce qui est urgent)." },
      { title: "Lire les indicateurs", body: "La rangée de tuiles en haut résume l'état : « Critiques non traités », « SLA critique dépassé (>48h) », « Taux traitement (30j) » et « Délai moyen traitement ». Une tuile devient rouge quand un seuil critique est franchi." },
      { title: "Filtrer les items", body: "Le bloc de filtres combine : le sélecteur « Sources » (officielles, médias & trackers, éditeurs sécu, personnalisées), la case « SLA critique dépassé », les puces « Sévérité » (Critique/Important/Informatif), « Traitement » (Nouveau/En cours/Traité/Non concerné) et « Thèmes ». Le raccourci « Reste à traiter » coche d'un coup Nouveau + En cours. « Réinitialiser tout » efface les filtres actifs." },
      { title: "Cibler sur votre parc", body: "L'icône engrenage (à côté de « Synchroniser ») ouvre le « Profil de veille » pour renseigner les OS et logiciels réellement présents. Une fois configuré, les items concernés portent un badge « ★ » et une case « Concerne mon parc » apparaît dans les filtres. Le profil marque et trie — il ne masque jamais la collecte." },
      { title: "Traiter un item", body: "Sur une ligne « Nouveau » ou « En cours », cliquez « Traiter » ; sur une ligne déjà qualifiée, cliquez « Consulter ». La modale permet de choisir la sévérité, le statut (« Prendre en charge », « Traité », « Non concerné »), l'analyste, une CVE liée, les « Actifs concernés » et une « Décision / Action » (Markdown pris en charge). Cliquez « Enregistrer ». Si l'item regroupe plusieurs sources, la décision s'applique à tous." },
      { title: "Ouvrir la source et déclarer un incident", body: "Dans le tableau, le titre est un lien vers l'article source (nouvel onglet) ; la modale liste un lien « Ouvrir la source → » par source du groupe. Pour les items « Critique » ou « Important », le bouton « Déclarer un incident » préremplit une déclaration dans le module Incidents." },
      { title: "Gérer les sources et paginer", body: "Dans le sélecteur « Sources », colonne « Personnalisées », le lien « + Ajouter une source » ouvre la modale d'ajout d'un flux RSS/Atom ; le « × » à côté d'une source la retire (les items déjà importés restent visibles). En bas du tableau, naviguez avec « ← Préc. » / « Suiv. → »." },
    ],
  },
  '/fuite-de-donnees': {
    title: 'Guide — Fuite de données',
    subtitle: "Onglet informatif : fuites de bases de données et ransomware, issues de sources dédiées. Pas de statut ni de qualification.",
    steps: [
      { title: "Synchroniser", body: "Cliquez « Synchroniser » en haut à droite pour rafraîchir les fuites. La date de « Dernière sync » apparaît juste en dessous, un message confirme le nombre de nouveaux items. Cette page est purement informative : aucun statut, analyste, décision ni SLA (contrairement à Veille technologique)." },
      { title: "Lire les statistiques", body: "Trois tuiles en haut : « Fuites détectées » (total filtré), « Sources suivies » (dont le nombre de sources personnalisées) et « Dernière synchronisation »." },
      { title: "Filtrer par source", body: "La rangée de puces filtre la source : « Toutes sources », puis les natives dédiées fuites (ZATAZ, fuitesinfos.fr, Ransomware.live, DataBreaches.net, Have I Been Pwned) et vos sources personnalisées. Seules ces sources « fuite » remontent ici — jamais CERT-FR ou les éditeurs sécu." },
      { title: "Filtrer par pays", body: "Sur la ligne « Pays : », choisissez « France », « 🌍 Monde entier », ou ouvrez « Choisir des pays… ▾ » pour cocher plusieurs pays. Par défaut, la France est sélectionnée." },
      { title: "Consulter une fuite", body: "Chaque carte affiche la source, l'entité concernée, le drapeau du pays, un résumé et la date de réception. Cliquer une carte ouvre l'article d'origine dans un nouvel onglet. Pour Ransomware.live, le groupe et l'activité sont affichés sous le nom de la victime." },
      { title: "Gérer les sources et paginer", body: "Le bouton « + Ajouter une source » ouvre la modale d'ajout d'un flux dédié fuite ; le « × » à côté d'une source personnalisée la retire (les fuites déjà importées restent visibles). En bas, naviguez avec « Préc. » / « Suiv. »." },
    ],
  },
  '/surveillance-identites': {
    title: 'Guide — Surveillance Identités',
    subtitle: "Croise vos identités surveillées (nom, domaine, IP, email) avec les fuites collectées et des vérifications gratuites en direct.",
    steps: [
      { title: "Comprendre la page", body: "La surveillance repose 100% sur des sources gratuites. Les noms et domaines sont croisés avec les fuites déjà collectées par la Veille ; les IP sont vérifiées contre des listes de blocage publiques (IPsum, Blocklist.de, Feodo Tracker) ; les emails et domaines sont vérifiés en direct via XposedOrNot et GitHub." },
      { title: "Ajouter une identité", body: "Dans « Identités surveillées », choisissez le type via les boutons « Nom », « Domaine », « IP », « Plage IP » ou « Email », saisissez la valeur (le champ propose un exemple selon le type) puis cliquez « Ajouter ». En mode Anonyme, l'ajout et la suppression sont désactivés (données fictives de démonstration)." },
      { title: "Gérer les identités", body: "Les identités ajoutées s'affichent regroupées par type (Noms, Domaines, IP, Plages IP, Emails). Le « × » sur un badge retire l'identité. Chaque ajout relance automatiquement la surveillance." },
      { title: "Lire les correspondances de fuites", body: "La grille de cartes liste les fuites mentionnant vos identités : source, titre de l'entité, drapeau du pays, badges rouges des identités correspondantes, résumé et date. Cliquer une carte ouvre l'article source." },
      { title: "Vérifier les IP compromises", body: "Le tableau « IP surveillées sur des listes de blocage publiques » signale qu'une machine correspondant à l'IP est probablement compromise (bot, scan, bruteforce). Colonnes : « Votre identité », « IP détectée », « Source », « Détail ». Ce n'est pas un article de presse mais un signal de compromission." },
      { title: "Vérifier emails et domaines en direct", body: "Le tableau « Emails et domaines vérifiés en direct » montre les emails trouvés dans une fuite connue (XposedOrNot) ou les domaines associés à un identifiant potentiel dans du code public (GitHub). Colonnes : « Votre identité », « Source », « Détail » (avec lien cliquable si disponible). La vérification GitHub est désactivée sans GITHUB_TOKEN." },
      { title: "Interpréter l'absence de résultat", body: "Si aucune identité n'est surveillée, un message invite à en ajouter. Si rien ne correspond, « Aucune fuite détectée » s'affiche : aucune source ne mentionne vos identités, aucune IP n'est blocklistée, et aucun email/domaine n'a été retrouvé." },
    ],
  },

  // ─── Inventaire ──────────────────────────────────────────────────────────────
  '/assets': {
    title: 'Guide — Actifs',
    subtitle: "Vue sécurité du parc : vulnérabilités, criticité, méthode de collecte et scan à la demande, en lecture seule.",
    steps: [
      { title: "Filtrer et retrouver un actif", body: "En haut de page, tapez dans « Rechercher un actif… » ou combinez les menus « Tous les OS », « Toutes criticités », « Toutes catégories », « Tout statut réseau » et « Configurés et non configurés ». Un filtre posé se teinte en cyan. « Configuré » = au moins un scan SSH/WinRM réussi ayant remonté des applications." },
      { title: "Lire une ligne du tableau", body: "Chaque ligne porte le nom (avec pastille de connectivité et badge « New » les premières 24h), l'OS, la catégorie, la « Criticité », le statut « Réseau », la « Source » (Active Directory, SSH, Meraki, Agent…) et la « Méthode » de collecte (icône : compte de service ou agent). Survolez une icône pour son libellé complet." },
      { title: "Ajouter ou modifier un actif (admin)", body: "Cliquez « Ajouter un actif ». Renseignez le « Nom » (obligatoire), le « Type d'actif » (Serveur, Poste de travail, Réseau, Site web) et la « Criticité métier » qui pondère le score de risque (×1.5 / ×1.0 / ×0.7). Pour un serveur : hostname et/ou IP, OS, et « Méthode de collecte ». Pour un site web : seule l'« URL » est requise (checks passifs, aucune connexion à l'actif)." },
      { title: "Choisir la méthode de collecte", body: "Dans le formulaire, « Méthode de collecte » propose « Compte de service (SSH/WinRM) » ou « Agent posé sur le poste ». Si vous choisissez l'agent, générez ensuite un jeton d'enrôlement depuis la page « Inventaire > Agents ». Les identifiants SSH par machine sont réservés à Linux : sur un actif Windows, le scan utilise toujours le compte de service WinRM partagé." },
      { title: "Lancer un scan et lire le résultat", body: "La loupe de la colonne « Actions » affiche le dernier scan en cache ; dans la fenêtre, « Relancer un scan » relance une connexion SSH/WinRM en lecture seule (réservée admin). La modale montre la « Fiabilité des infos déclarées » (hostname/IP/OS/version, ✓ conforme, ⚠ divergent), les specs matérielles et les « Applications installées » (version obsolète en rouge, version cible en vert, vulnérabilités). Un scan par agent est asynchrone : la fenêtre se met à jour dès le prochain sondage (jusqu'à 60 s)." },
      { title: "Agir en masse et croiser les modules", body: "Cochez plusieurs actifs pour faire apparaître la barre d'actions : « Scanner la sélection » ou « Supprimer la sélection » (admin). Depuis la modale de scan, le lien « Voir le durcissement/conformité de cet actif → » ouvre la page Durcissement, et les « Findings d'audit » renvoient vers le module Audits." },
      { title: "Supprimer un actif", body: "L'icône corbeille (admin) ouvre une confirmation : tapez exactement le nom de l'actif pour valider. L'action est définitive et supprime aussi l'historique de scan et les vulnérabilités liées, y compris les corrections déjà validées." },
    ],
  },
  '/inventaire': {
    title: 'Guide — Inventaire Complet',
    subtitle: "Patrimoine IT du parc : CPU, RAM, disques et applications installées par actif, en lecture seule.",
    steps: [
      { title: "Filtrer le parc", body: "Utilisez « Rechercher un actif… » et les menus « Tous les OS », « Toutes criticités », « Toutes catégories », « Tout statut réseau » et « Configurés et non configurés ». Ce sont les mêmes filtres que la page Actifs, appliqués ici à la vue patrimoine." },
      { title: "Lire le tableau matériel", body: "Les colonnes affichent « Nom », « Réseau », « CPU », « Arch. », « Cœurs », « RAM », « Disques », « Apps », « Dernier scan » et « Actions ». Une case vide « — » signale une donnée non encore collectée pour cet actif." },
      { title: "Consulter les applications d'un actif", body: "Cliquez le badge bleu « N apps » (ou « N MAJ dispo » en jaune) pour ouvrir la fenêtre de détail : specs matérielles complètes (CPU, RAM, architecture, disques, IP, MAC, ports ouverts) puis « Applications installées » avec un champ « Rechercher… », la version installée, la « MAJ disponible » et les vulnérabilités connues." },
      { title: "Scanner un actif", body: "Le bouton « Scanner » d'une ligne affiche le dernier scan déjà en base s'il existe ; dans la fenêtre, « Relancer un scan » force une nouvelle connexion SSH/WinRM en lecture seule. Aucune écriture n'est jamais faite sur le serveur." },
      { title: "Scanner tout le parc", body: "Le bouton « Scanner tout » en haut lance un scan de tous les actifs réels un par un (concurrence limitée). La progression s'affiche « Scan… X/Y » ; les actifs injoignables sont signalés mais ne bloquent pas les suivants." },
      { title: "Exporter l'inventaire en PDF", body: "« Exporter en PDF » génère côté serveur un document reprenant, par actif, nom, CPU, architecture, cœurs, RAM, disques et applications installées. L'export est indisponible en mode Présentation (les données réelles ne sont pas anonymisées dans le PDF)." },
    ],
  },
  '/durcissement': {
    title: 'Guide — Durcissement',
    subtitle: "Conformité CIS-like de tout le parc (compte de service, agent, réseau, site web) — lecture seule, aucune commande exécutée par Allsafe.",
    steps: [
      { title: "Évènements détectés par les agents (admin)", body: "Au-dessus du tableau des actifs, une section repliée par défaut liste ce que les agents ont détecté en lisant les journaux d'audit natifs du poste et en diffant l'état entre deux check-ins (compte créé, élévation de privilèges, persistance, processus suspect, altération d'audit…) — l'agent constate, il n'exécute et n'écrit jamais rien sur le poste. Réservée aux comptes admin, masquée s'il n'y a rien à afficher. Le badge « N à traiter » (rouge) et le compteur du menu Inventaire ne comptent que ce qui est réellement prioritaire, cf. étape suivante." },
      { title: "Prioriser plutôt que tout traiter", body: "Ouvrir la section affiche d'abord uniquement les évènements CRITIQUE/AVERTISSEMENT non acquittés (« à traiter »), regroupés par catégorie (compte créé, persistance, processus suspect…) — à l'échelle d'une centaine d'agents, une liste plate reste trop longue à dépouiller. Chaque catégorie affiche déjà les noms des actifs concernés (tronqués si nombreux, survolez pour la liste complète) sans avoir besoin de déplier. Cliquez une catégorie pour voir le détail évènement par évènement, ou « Acquitter le groupe » pour fermer en une fois tout le bruit homogène qu'elle porte (ex. une rafale de persistance détectée au 1er rollout d'un poste). Le reste — niveau INFO et tout ce qui est déjà acquitté, souvent l'essentiel du volume — part directement dans un « Historique » replié en dessous : un journal de référence pour la piste d'audit NIS 2, pas une file à vider. « Acquitter tout » (en-tête) ferme en une fois tout ce qui reste non acquitté, y compris l'historique." },
      { title: "Comprendre le résumé de conformité", body: "Chaque ligne montre un « Résumé » sous forme de badges : ✓ (checks conformes), ⚠ (avertissements, à corriger), — (indéterminés, non évaluables). « Aucun check collecté » indique qu'aucun scan de durcissement n'existe encore pour cet actif." },
      { title: "Filtrer les actifs", body: "Utilisez « Rechercher un actif… », les menus « Tous les OS » et « Toutes les catégories », le bouton « ⚠ Avec avertissements uniquement » pour n'afficher que les non-conformités, et « Actifs configurés uniquement » pour exclure réseau, sites web et hôtes ESXi (garder les actifs avec compte de service ou agent)." },
      { title: "Trier le tableau", body: "Cliquez les en-têtes « Résumé » ou « Dernier scan » pour trier (flèche ↑/↓ sur la colonne active). « Résumé » classe d'abord par nombre d'avertissements, le signal le plus actionnable. Les colonnes OS et Catégorie se filtrent par menu plutôt que par tri." },
      { title: "Déplier le détail d'un actif", body: "Cliquez une ligne pour la déplier : la liste des checks apparaît sous la ligne (une seule dépliée à la fois). Chaque check détaille l'état, l'explication et, quand il y a lieu, la solution et la commande recommandées. Depuis la page Actifs, le lien de durcissement d'un actif déplie directement sa ligne ici." },
      { title: "Lire les solutions sans jamais exécuter de commande", body: "Les commandes affichées dans le détail sont une aide à la remédiation : Allsafe ne les exécute jamais lui-même. C'est à l'analyste de les relire, de les tester puis de les appliquer manuellement sur le serveur concerné." },
      { title: "Surveiller la fraîcheur des agents", body: "Sur un actif collecté par agent, une icône d'alerte jaune à côté de « Dernier scan » signale un check-in trop ancien au regard de la fréquence attendue (quotidienne ou hebdomadaire selon la criticité) : vérifiez que l'agent tourne et joint bien le serveur Allsafe." },
      { title: "Lancer le scan web (admin)", body: "Le bouton « Lancer le scan web » exécute des checks 100% passifs (en-têtes de sécurité HTTP, protocole TLS) sur tous les actifs de type « Site web », sans aucune tentative d'injection. Le nombre de sites vérifiés et d'avertissements s'affiche à la fin." },
    ],
  },
  '/agents': {
    title: 'Guide — déployer et utiliser les agents',
    subtitle: "Collecte alternative en lecture seule pour les postes, en complément du compte de service AD/SSH.",
    steps: [
      { title: 'Choisir la méthode de collecte, par actif', body: "Sur la page Actifs, passez la « méthode de collecte » d'un poste de « Compte de service (SSH/WinRM) » à « Agent ». L'agent ne traite que les postes que vous lui confiez — il complète le scan centralisé pour ceux qu'il atteint mal (éteints, hors réseau, VPN), il ne le remplace jamais." },
      { title: 'Générer un jeton d’enrôlement (admin)', body: "Bouton « + Jeton d'enrôlement » en haut à droite. Valable 48 h par défaut. Usage unique (un seul poste) ou réutilisable pour un déploiement de parc avec un jeton partagé. Copiez le jeton affiché — il n'est montré qu'une seule fois." },
      {
        title: 'Télécharger le bon paquet, l’installer et enrôler',
        body: "Bouton « Télécharger l'agent », puis, sur le poste, l'installer et l'enrôler avec le jeton (remplacez <JETON> et l'URL du serveur). L'agent crée une identité propre au poste (façon TOFU) et s'enrôle :",
        packages: [
          { os: 'windows', label: 'Windows — .exe autonome', desc: 'Poste critique isolé — assistant graphique (installation / réparation / mise à jour)', cmds: ['.\\allsafe-agent.exe install --token <JETON> --server http://<hôte-allsafe>:3000'] },
          { os: 'windows', label: 'Windows — .msi (GPO / parc)', desc: 'Déploiement de parc par GPO / script', cmds: ['msiexec /i allsafe-agent.msi /qn', 'allsafe-agent enroll --token <JETON> --server http://<hôte-allsafe>:3000'] },
          { os: 'linux', label: 'Linux — .deb', desc: 'Service systemd démarré automatiquement par le paquet', cmds: ['sudo dpkg -i allsafe-agent_<version>_amd64.deb', 'sudo allsafe-agent enroll --token <JETON> --server http://<hôte-allsafe>:3000'] },
        ],
      },
      { title: 'L’agent remonte tout seul', body: "Check-in automatique toutes les heures, plus un scan à la demande. À chaque contact, en lecture seule stricte, il remonte l'inventaire matériel (CPU/RAM/disques/applications), le durcissement CIS-like, et la détection d'évènements sensibles : compte créé, élévation de privilèges, réactivation de compte, nouvelle persistance (tâche planifiée, service, cron/systemd). Il constate — il n'exécute et n'écrit jamais rien sur le poste." },
      { title: 'Suivre le parc', body: "Le tableau liste statut, version et dernier contact de chaque agent. Cliquez une ligne pour l'historique des contacts d'un poste ; le badge « Historique » (près du titre) ouvre la vue globale, révoqués et supprimés inclus. Le bouton « Scanner maintenant » (par agent) force une collecte immédiate sans attendre le cycle horaire — prise en compte au prochain sondage (~60 s). Révoquez un agent avant de le supprimer." },
      {
        title: 'Mettre à jour l’agent',
        body: "Un poste dont la version remonte en retard sur celle publiée par le serveur porte un badge « Mise à jour dispo » (colonne « Version »). Allsafe ne se connecte jamais aux postes pour les mettre à jour lui-même (principe de non-intervention) — c'est toujours le poste qui vient chercher le paquet :",
        packages: [
          { os: 'windows', label: 'Windows — .exe autonome', desc: 'Relancez l’exécutable déjà installé : l’assistant détecte la version en place et propose « Mettre à jour » en un clic (aucune commande)' },
          { os: 'windows', label: 'Windows — .msi (GPO / parc)', desc: 'Réinstallation en place — même UpgradeCode, ne recrée pas une deuxième copie ni ne redemande le jeton', cmds: ['msiexec /i allsafe-agent.msi /qn'] },
          { os: 'linux', label: 'Linux — .deb', desc: 'Réinstallation du paquet — le service systemd redémarre seul, pas de ré-enrôlement', cmds: ['sudo dpkg -i allsafe-agent_<version>_amd64.deb'] },
        ],
      },
      { title: 'Automatiser la mise à jour', body: "Pour ne pas repasser poste par poste : les scripts `agent/deploy/update-agent.sh` (cron, quotidien) et `update-agent.ps1` (tâche planifiée GPO) comparent la version installée à celle publiée par le serveur (`GET /api/agents/latest/version`) et se réinstallent seuls si besoin — c'est votre infra (cron/GPO) qui les planifie, jamais Allsafe. Détail complet : `docs/AGENTS.md` § Mise à jour." },
    ],
  },

  // ─── Sécurité ────────────────────────────────────────────────────────────────
  '/audits': {
    title: 'Guide — Audits',
    subtitle: "Cadrer, autoriser, saisir les findings et contre-vérifier. Allsafe héberge et trace l'audit, il n'exécute jamais rien d'offensif.",
    steps: [
      { title: "Comprendre la page", body: "Le tableau liste tous les audits : « Titre », « Type », « Statut », « Période », « Conduit par » et « Findings » (pastilles de sévérité avec compte). Un audit terminé qui garde des findings clos jamais retestés porte un repère « ⚠ non retesté »." },
      { title: "Filtrer et rechercher", body: "En haut, trois filtres : « Tous statuts », « Tous types » et un champ « Rechercher… ». Combinez-les pour retrouver un audit. La liste se pagine par 25 (boutons « ← Préc. » / « Suiv. → » en bas quand il y a plusieurs pages)." },
      { title: "Créer un audit", body: "Cliquez sur « + Nouvel audit » (en haut à droite). Renseignez le titre, le type (architecture, configuration, code, pentest ou Red Team), la période et les actifs concernés. À la validation, vous arrivez directement sur la fiche de l'audit." },
      { title: "Poser l'autorisation écrite", body: "Sur la fiche, l'autorisation écrite est bloquante : aucun finding n'est saisissable tant qu'elle n'est pas posée. Une fois enregistrée, elle est immuable — c'est le garde-fou structurel de l'audit." },
      { title: "Saisir les findings à la main", body: "Les résultats sont rédigés manuellement (Allsafe n'exécute aucun outil offensif). Ajoutez chaque finding avec sa sévérité et sa description. Les pastilles du tableau se mettent à jour automatiquement." },
      { title: "Suivre les statuts et retester", body: "L'audit passe par les statuts « Cadrage », « Autorisé », « En cours », « Terminé », « Archivé ». Avant de clore, retestez les findings corrigés : un audit terminé avec des findings clos non retestés reste signalé « ⚠ non retesté » dans la liste." },
      { title: "Joindre les pièces", body: "Depuis la fiche, attachez le mandat d'audit et les preuves (PDF/PNG/JPEG). Ces pièces jointes gardent la trace complète et auditable de l'audit." },
    ],
  },
  '/bastion': {
    title: 'Guide — Bastion',
    subtitle: "Module à venir — accès jump host vers les serveurs critiques, pas encore implémenté.",
    steps: [
      { title: "Module en cours de développement", body: "Cette page est un espace réservé. Le bandeau « Module à venir » et l'encart « En cours de développement » indiquent qu'aucune fonctionnalité n'est active ici pour l'instant." },
      { title: "Ce qui est prévu", body: "Le module accueillera un accès bastion (jump host) vers les serveurs critiques, portée encore à définir. Point d'attention affiché : un bastion de connexion directe entre en tension avec la règle de non-intervention d'Allsafe (l'outil n'écrit ni n'exécute jamais rien sur un serveur) — à trancher avant toute implémentation." },
    ],
  },

  // ─── Gouvernance ─────────────────────────────────────────────────────────────
  '/documentation': {
    title: 'Guide — Documentation Entreprise',
    subtitle: "Centraliser les documents de gouvernance NIS 2 — PSSI, chartes, organigramme — avec historique des versions.",
    steps: [
      { title: "Comprendre la page", body: "Chaque carte correspond à un type de document (PSSI, Charte Administrateur…). La version la plus récente est mise en évidence ; les versions antérieures se replient sous « ▸ Historique »." },
      { title: "Ajouter un type de document", body: "Réservé aux admins : cliquez sur « + Ajouter un type de document » (en haut à droite) pour créer une nouvelle catégorie. Le registre de types est ouvert, sans passer par le code." },
      { title: "Téléverser un document", body: "Sur une carte, cliquez sur « + Téléverser », ou glissez-déposez le fichier directement sur la carte (« Déposez le fichier ici… ») pour ouvrir la modale pré-remplie. Formats acceptés : PDF, Word, Excel, PNG, JPEG (10 Mo max). Renseignez l'auteur et une note éventuelle." },
      { title: "L'historique est conservé", body: "Chaque téléversement crée une nouvelle version sans écraser les précédentes. Dépliez « Historique (n) » sur la carte pour consulter les versions antérieures, avec auteur et date." },
      { title: "Prévisualiser un document", body: "Cliquez sur le nom du fichier (📄) pour l'ouvrir : les PDF et images s'affichent directement dans le navigateur ; les fichiers Word/Excel se téléchargent." },
      { title: "Supprimer (admin)", body: "Le « ✕ » à côté d'une version supprime définitivement ce fichier de l'historique. Le bouton « Supprimer le type » n'apparaît que si le type ne contient plus aucun document. Ces suppressions sont irréversibles et demandent confirmation." },
    ],
  },
  '/notes': {
    title: 'Guide — Notes',
    subtitle: "Votre prise de notes personnelle — des fiches en Markdown organisées par thème puis par sujet.",
    steps: [
      { title: "Comprendre la page", body: "La colonne de gauche liste vos thèmes (icône emoji + nombre de sujets). Le panneau de droite affiche les sujets du thème sélectionné. Le premier thème est ouvert automatiquement au chargement." },
      { title: "Créer et gérer un thème", body: "Cliquez sur « Nouveau thème » en bas de la liste pour en ajouter un (nom, icône). Double-cliquez sur un thème pour le modifier. Le « ✕ » au survol le supprime — un thème contenant encore des sujets doit d'abord être vidé." },
      { title: "Ajouter un sujet", body: "Sélectionnez un thème, puis cliquez sur « Nouveau sujet » dans le panneau. Un sujet « Nouveau sujet » est créé et vous êtes redirigé vers son éditeur." },
      { title: "Rédiger le contenu", body: "Dans l'éditeur du sujet, saisissez votre contenu en Markdown (et images). Chaque sujet affiche sa date de dernière mise à jour dans la liste." },
      { title: "Supprimer un sujet", body: "Au survol d'une ligne de sujet, le « ✕ » supprime définitivement le sujet (après confirmation). Cette action est irréversible." },
    ],
  },

  // ─── Rapports ────────────────────────────────────────────────────────────────
  '/reports': {
    title: 'Guide — Rapport exécutif CVE',
    subtitle: "Résumé exécutif des vulnérabilités : export CSV du backlog et archives hebdomadaires figées.",
    steps: [
      { title: "Filtrer par actif", body: "En haut, la carte « Filtres » propose un sélecteur d'actifs. Laissez vide pour couvrir « tous les actifs », ou choisissez un ou plusieurs actifs. Le filtre s'applique à la fois à l'export CSV et aux archives hebdomadaires plus bas." },
      { title: "Exporter le backlog en CSV", body: "La carte « Export CSV — backlog courant » liste toutes les vulnérabilités non corrigées (ouvertes, en attente de correctif, faux positifs) sur les actifs choisis. Cliquez « Exporter CSV » : le fichier est généré côté serveur et téléchargé. Ce backlog ignore la période — c'est l'état courant." },
      { title: "Comprendre les rapports hebdomadaires figés", body: "Le bloc du bas archive un rapport par semaine (ex. « S30/2026 »), généré automatiquement chaque lundi à 7h sur la semaine écoulée. Colonnes « Corrigées », « En attente », « Faux positifs ». Les chiffres d'une semaine archivée ne changent plus — c'est ce qui en fait une preuve." },
      { title: "Décliner un rapport hebdo par actif", body: "Ces rapports existent pour le parc entier et pour chaque actif. Sélectionnez un actif dans les « Filtres » du haut pour n'afficher que ses semaines archivées." },
      { title: "Exporter une semaine en PDF ou CSV", body: "Chaque archive hebdomadaire offre son propre export. Attention : le CSV est généré côté serveur ; le bouton « Exporter PDF » est une impression du navigateur, pas un fichier produit par le serveur — autorisez les fenêtres pop-up si rien ne s'ouvre." },
    ],
  },
  '/rapport-veille': {
    title: 'Guide — Rapport Veille',
    subtitle: "Registre de veille NIS 2 : export CSV auditable et rapports hebdomadaires figés.",
    steps: [
      { title: "Comprendre l'objectif", body: "Cette page centralise la traçabilité de la veille technologique pour un auditeur NIS 2 : la liste complète des items traités et les rapports hebdomadaires figés qui prouvent le traitement sur la durée." },
      { title: "Filtrer l'export par thème", body: "Dans la carte « Export CSV — registre de veille », des puces de thèmes (« Ransomware », « Vulnérabilité », « Réglementation »…) permettent de restreindre l'export. Cliquez une puce pour l'activer/désactiver ; sans sélection, tous les thèmes sont inclus." },
      { title: "Exporter le registre en CSV", body: "Cliquez « Exporter CSV » : le fichier serveur reprend chaque item (source, sévérité, thèmes, statut, analyste, décision) — le document à présenter pour prouver le traitement à un auditeur." },
      { title: "Lire les rapports hebdomadaires figés", body: "Le bloc du bas archive un rapport par semaine (ex. « S30/2026 »), généré chaque lundi à 7h : volume « Collectés », « Traités », « Critiques ouverts », plus le respect du SLA 48h sur les critiques. Les chiffres d'une semaine archivée ne bougent plus." },
      { title: "Exporter une semaine", body: "Chaque archive a son export. Le CSV est produit côté serveur ; « Exporter PDF » est une impression navigateur côté client, pas un fichier généré par le serveur." },
    ],
  },
  '/rapport-surveillance': {
    title: 'Guide — Rapport Surveillance',
    subtitle: "Preuve hebdomadaire figée de la surveillance continue des identités (NIS 2).",
    steps: [
      { title: "Comprendre l'objectif", body: "Cette page archive les rapports hebdomadaires de la Surveillance Identités : elle prouve que le périmètre surveillé a bien été contrôlé sur chaque période, y compris quand aucune correspondance n'est trouvée." },
      { title: "Lire un rapport de semaine", body: "Chaque ligne est une semaine figée (ex. « S30/2026 »), générée automatiquement le lundi à 7h. Colonnes « Identités surveillées », « Fuites correspondantes », « IP blocklistées »." },
      { title: "Interpréter une semaine sans correspondance", body: "Un rapport vide a de la valeur : il atteste que le périmètre a été surveillé sur la période — ce qu'une absence de rapport ne prouverait pas." },
      { title: "Ouvrir le détail d'une semaine", body: "Dépliez une semaine pour voir le périmètre surveillé, les publications de fuite analysées et les adresses IP figurant sur une liste de blocage." },
      { title: "Exporter une semaine", body: "L'export CSV d'une archive est généré côté serveur ; le bouton « Exporter PDF » est une impression du navigateur, pas un fichier produit par le serveur — autorisez les pop-up au besoin." },
    ],
  },
  '/rapport-incidents': {
    title: 'Guide — Rapport Incidents',
    subtitle: "Un rapport détaillé par incident, généré à la demande — jamais figé par semaine.",
    steps: [
      { title: "Comprendre le principe", body: "Un incident est rare et jamais multiple la même semaine : son rapport se génère à l'unité et à la demande, pas en archive hebdomadaire. Il reflète l'état actuel de l'incident au moment où vous l'ouvrez." },
      { title: "Repérer un incident dans le registre", body: "La carte « Registre des incidents » liste chaque incident : « Titre », « Catégorie », « Sévérité », « Statut » (Déclaré, En cours, Contenu, Résolu, Clôturé), badges « NIS 2 » et date « Déclaré le »." },
      { title: "Consulter le rapport d'un incident", body: "Cliquez « 👁 Consulter le rapport » sur une ligne. Un panneau s'ouvre en bas avec la qualification NIS 2, le contenu des jalons envoyés, les pièces jointes du rapport final et la chronologie complète. Le bouton devient « Fermer »." },
      { title: "Exporter le rapport d'un incident en PDF", body: "Dans le panneau ouvert, « Exporter PDF » lance une impression du navigateur (pas un fichier serveur) — si rien ne s'ouvre, autorisez les fenêtres pop-up pour ce site puis réessayez." },
      { title: "Exporter le registre complet en CSV", body: "Le bouton « Exporter CSV (registre complet) », en haut à droite, télécharge tout le registre des incidents dans un fichier généré côté serveur. Il est distinct du rapport par incident et n'en dépend pas." },
    ],
  },

  // ─── Incidents ───────────────────────────────────────────────────────────────
  '/incidents': {
    title: 'Guide — Registre incidents',
    subtitle: "Déclarez et suivez les incidents avec la traçabilité des délais légaux NIS 2 (Art. 23). Allsafe trace qui a fait quoi et quand — il ne notifie jamais l'ANSSI à votre place.",
    steps: [
      { title: "Parcourir et filtrer le registre", body: "Le tableau liste les incidents : « Titre », « Catégorie », « Sévérité », « Statut », « Prise de connaissance », « Actifs » et « NIS 2 ». Filtrez par « Tous statuts », « Toutes sévérités », « Toutes catégories », ou activez « À notifier NIS 2 » et « Échéance dépassée ». Le champ « Rechercher… » filtre par texte. Cliquez une ligne pour ouvrir son détail." },
      { title: "Déclarer un incident", body: "Cliquez « + Déclarer un incident ». Renseignez « Titre », « Description », « Catégorie », « Sévérité », « Prise de connaissance » (point de départ légal des délais NIS 2) et « Déclaré par ». Ajoutez les « Actifs concernés ». Titre, déclarant et date de prise de connaissance sont obligatoires. Validez avec « Créer l'incident » — le détail s'ouvre aussitôt sur la roadmap." },
      { title: "Préremplissage depuis un autre module", body: "Un incident peut arriver prérempli depuis Sécurité, Vulnérabilités ou Veille (bouton « Déclarer un incident » de ces pages). Un bandeau « Préempli depuis… » s'affiche. Rien n'est créé tant que vous ne validez pas : vérifiez chaque champ avant de cliquer « Créer l'incident »." },
      { title: "Qualifier « à notifier » (toujours manuel)", body: "Dans le détail, bloc « Notification NIS 2 », cliquez « Qualifier à notifier ». Justifiez pourquoi l'incident relève de l'obligation NIS 2 et indiquez le validateur. Cette qualification est TOUJOURS un acte humain — jamais automatique. Une fois qualifié, les trois échéances sont calculées depuis la prise de connaissance. « Déqualifier » permet de revenir en arrière avec justification." },
      { title: "Suivre les 3 échéances (Art. 23)", body: "Après qualification, le bloc affiche « Alerte précoce » (24h), « Notification d'incident » (72h) et « Rapport final » (1 mois), avec leur date limite et un statut coloré (à venir / dépassé). La frise du haut résume l'avancement global de l'incident." },
      { title: "Marquer un jalon envoyé", body: "Quand vous avez réellement transmis une notification hors application (ex. au CERT-FR/ANSSI), cliquez « Marquer envoyé » sur le jalon concerné. Renseignez référence/canal (optionnel) et validateur. Allsafe n'envoie rien lui-même : il enregistre seulement que l'envoi a eu lieu. Un jalon envoyé est figé — bouton « Consulter » pour revoir contenu, date et auteur." },
      { title: "Roadmap : plan d'action et contacts", body: "Le bloc « Roadmap » propose un « Plan d'action » chronologique par catégorie (étapes internes/externes). Choisissez « Réalisé par » avant de cocher — chaque étape cochée porte qui l'a faite et quand. « Qui contacter » liste les organismes (cochez « Des données personnelles sont concernées » pour ajouter la CNIL) et les « Postes internes à contacter ». « + Ajouter un contact » enrichit l'annuaire. Cocher ici n'envoie et n'atteste rien." },
      { title: "Rapport final, historique et export", body: "Une fois le « Rapport final » marqué envoyé, joignez vos preuves via « + Joindre un PDF » (5 Mo max, sélectionnez d'abord « Ajouté par… »). Le bloc « Historique » trace toute la chronologie ; « + Ajouter une note » consigne une note libre. « Escalader en crise » ouvre une cellule de crise. « Exporter CSV » (en-tête) télécharge le registre. La suppression est réservée aux admins." },
    ],
  },
  '/crises': {
    title: 'Guide — Gestion de crise',
    subtitle: "Escaladez un ou plusieurs incidents en crise : cellule de crise, décisions et communications tracées. Allsafe journalise tout — il n'envoie jamais aucune communication réelle.",
    steps: [
      { title: "Parcourir les crises", body: "Le tableau liste les crises : « Titre », « Statut » (Active / Désactivée), « Activée par », « Incidents liés » et « Cellule de crise ». Filtrez par « Tous statuts » (Active / Désactivée) ou via « Rechercher… ». Une crise est un évènement rare : pas de pagination. Cliquez une ligne pour ouvrir son détail." },
      { title: "Activer une crise", body: "Cliquez « + Activer une crise ». Renseignez « Titre », « Description » (optionnel) et « Activée par ». La création EST l'activation — toujours un acte humain explicite. Validez avec « Activer la crise » ; le détail s'ouvre. Une crise peut aussi naître d'un incident via son bouton « Escalader en crise »." },
      { title: "Constituer la cellule de crise", body: "Dans le bloc « Cellule de crise » (crise active), cliquez « + Assigner un rôle » : indiquez le rôle, la personne et par qui. Chaque rôle est traçable ; la croix « ✕ » retire un rôle (une confirmation demande par qui)." },
      { title: "Rattacher des incidents", body: "Dans le bloc « Incidents liés », choisissez un incident dans « Rattacher un incident… », précisez « Par… » puis cliquez « Rattacher ». « ✕ » détache un incident (par qui demandé). Détacher ou supprimer une crise ne supprime jamais les incidents rattachés." },
      { title: "Journaliser décisions et communications", body: "Dans le bloc « Journal » (crise active), « + Décision » consigne une décision et son auteur ; « + Communication » consigne un message avec son audience (interne/externe) et son auteur. Allsafe n'émet AUCUNE communication réelle : il ne fait qu'enregistrer ce qui a été décidé/communiqué en dehors de l'outil." },
      { title: "Suivre la roadmap", body: "Le bloc « Roadmap » propose un plan d'action et un annuaire de contacts (mêmes composants que côté incident), pour guider la conduite de crise. Aucune action n'y déclenche d'envoi." },
      { title: "Désactiver la crise et clôturer", body: "Quand la crise est terminée, cliquez « Désactiver la crise » et justifiez (par qui). La crise passe « Désactivée » : la frise et l'en-tête indiquent qui l'a désactivée et quand ; le journal reste consultable. La suppression définitive est réservée aux admins." },
    ],
  },

  // ─── Administration (Paramètres > Sécurité) ─────────────────────────────────
  '/settings/administration': {
    title: 'Guide — Administration',
    subtitle: "Console réservée aux administrateurs : sécurité base de données, connexions, comptes et registres.",
    steps: [
      { title: "Naviguer entre les onglets", body: "Menu de gauche à sept entrées : « Base de données », « Connexions IP », « Utilisateurs », « Analystes », « Services », « Rôles », « Correspondances Windows ». La flèche « Réduire » en haut replie le menu en icônes seules." },
      { title: "Surveiller la base (déception)", body: "L'onglet « Base de données » affiche les alertes de leurres : tout accès à un objet-piège (fausses tables, comptes-pièges) ou toute commande DDL bloquée y remonte. Cliquez un objet pour la modale de détail expliquée en clair, puis « Acquitter » (ou « Acquitter tout »). Chaque ligne peut aussi être déclarée en incident." },
      { title: "Consulter les connexions IP", body: "L'onglet « Connexions IP » fusionne accès à l'app et évènements d'authentification (Connexion, Échec, Déconnexion, Mot de passe changé, Accès). Filtrez par e-mail/IP, par type, et par plage de dates « Du »/« au » ; « Réinitialiser » efface les filtres." },
      { title: "Gérer les comptes utilisateurs", body: "L'onglet « Utilisateurs » liste les comptes (rôle Administrateur/Analyste, désactivé, accès restreint). « + Ajouter un compte » pour créer, « Modifier », « Supprimer », et « Déconnecter partout » pour invalider les sessions. Les demandes « mot de passe oublié » en attente s'affichent en haut (« Traiter » / « Rejeter ») et un badge chiffré signale leur nombre sur l'onglet." },
      { title: "Tenir le registre des analystes", body: "L'onglet « Analystes » gère les noms proposés dans les menus déroulants d'attribution (validé par, déclaré par…). C'est distinct des comptes de connexion. « + Ajouter un analyste », puis « Modifier » / « Supprimer »." },
      { title: "Organiser services et rôles", body: "L'onglet « Services » regroupe les départements (RH, DSI…) avec code couleur et liste les postes rattachés (« Voir l'organigramme »). L'onglet « Rôles » définit qui tient quel poste (RSSI, DPO…), avec e-mail et lien hiérarchique — repris par les Incidents et la Gestion de crise. Le rattachement poste → service se fait côté Rôles." },
      { title: "Régler les correspondances Windows", body: "L'onglet « Correspondances Windows » associe un nom d'application Windows à un produit CPE pour alimenter le croisement avec les CVE. « + Ajouter une correspondance », à enrichir au fil des applications réellement rencontrées sur le parc." },
    ],
  },
}

// Résolution du guide pour une route : correspondance exacte d'abord, sinon le préfixe le plus
// long suivi de « / » (pour les pages de détail : /audits/:id → /audits). Le « / » évite qu'un
// préfixe morde sur une autre route (ex. /notes ne doit PAS matcher /notes-de-version).
export function guideForPath(pathname) {
  if (PAGE_GUIDES[pathname]) return PAGE_GUIDES[pathname]
  const match = Object.keys(PAGE_GUIDES)
    .filter(k => pathname.startsWith(k + '/'))
    .sort((a, b) => b.length - a.length)[0]
  return match ? PAGE_GUIDES[match] : null
}
