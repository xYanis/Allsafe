# Module OSINT — détection de fuites

Je veux ajouter à mon application une fonctionnalité OSINT orientée **détection de fuites de données** pour entreprises et personnes.

## Objectif
Le module doit permettre de rechercher si un email, un domaine, un nom d’entreprise, un pseudo ou une personne apparaît dans des fuites, des bases de credentials compromis, des archives publiques ou des sources OSINT.

## Cas d’usage
- Vérifier si un email perso est exposé.
- Vérifier si un domaine d’entreprise apparaît dans des breaches.
- Trouver des indices d’exposition de comptes, identifiants ou données publiques.
- Corréler les résultats entre plusieurs sources.

## Sources prioritaires
- XposedOrNot
- Have I Been Pwned
- IntelX
- Hunter.io
- Shodan
- Censys
- SecurityTrails
- crt.sh
- GitHub API
- Reddit API
- Wayback Machine

## Fonctionnement attendu
- Détection automatique du type d’entrée : email, domaine, pseudo, entreprise, IP.
- Lancement des connecteurs pertinents selon l’entrée.
- Normalisation des résultats.
- Déduplication.
- Score de confiance / pertinence.
- Vue synthétique des fuites potentielles.

## Contraintes
- Le module doit être une fonctionnalité additionnelle dans l’application existante.
- Utiliser des variables d’environnement pour les clés API.
- Gérer les quotas et les erreurs.
- Prévoir un cache.
- Prévoir l’ajout facile de nouveaux connecteurs.

## Sortie attendue
Pour chaque recherche, afficher :
- l’entrée analysée,
- les sources interrogées,
- les résultats bruts,
- les résultats normalisés,
- les correspondances détectées,
- un résumé final des fuites potentielles.