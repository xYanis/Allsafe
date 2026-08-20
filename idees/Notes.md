# 📝 Spécifications : Outil de Prise de Notes et d'Apprentissage

## 🎯 Objectif du Projet
Développer une application de prise de notes optimisée pour l'apprentissage technique. L'outil permet d'organiser les connaissances par thématiques, de rédiger des cours en Markdown avec un support natif des images, et d'évaluer la compréhension via des QCM générés automatiquement à partir du contenu des notes.

## 🗂️ 1. Thèmes et Architecture
L'application doit inclure par défaut 4 thèmes principaux. Chaque thème doit être illustré par une icône (UI/UX) pour faciliter la navigation :

*   **Cybersécurité** : 🛡️ (Bouclier / Cadenas)
*   **Réseau** : 🌐 (Réseau de nœuds / Globe)
*   **Système** : 💻 (Terminal / Serveur)
*   **IA (Intelligence Artificielle)** : 🧠 (Cerveau / Circuit)

*Note pour l'UI : Utiliser une bibliothèque d'icônes moderne (comme Lucide, Phosphor ou FontAwesome) pour représenter ces thèmes dans l'interface de navigation.*

## ✍️ 2. Gestion des Sujets et Éditeur Markdown
Dans chaque thème, l'utilisateur doit pouvoir créer, modifier et supprimer des "Sujets" (qui correspondent à des fiches de cours).

*   **Édition en Markdown :** L'écriture des notes se fait entièrement en format `.md` avec un rendu visuel en temps réel (ou mode lecture/écriture).
*   **Gestion des images :** 
    *   L'utilisateur doit pouvoir ajouter des images facilement (par glisser-déposer, upload ou URL).
    *   Les images doivent s'insérer automatiquement dans le texte via la syntaxe Markdown standard : `![Texte alternatif](chemin_de_l_image)`.
    *   Le système doit gérer le stockage local ou cloud de ces images de manière transparente.

## 🤖 3. Génération Automatique de QCM
C'est la fonctionnalité clé de l'outil pour l'apprentissage actif.

*   **Bouton d'action :** Chaque sujet dispose d'une option "Créer un QCM d'entraînement".
*   **Analyse du contenu :** Le système doit récupérer le texte brut du sujet (le Markdown) et s'en servir comme contexte pour un modèle d'Intelligence Artificielle (via un prompt système adapté).
*   **Génération :** L'IA doit extraire les concepts clés du sujet et générer des questions à choix multiples pertinentes (avec 1 bonne réponse et plusieurs distracteurs).
*   **Interface QCM :** Créer une interface interactive permettant à l'utilisateur de répondre au QCM, de valider, et de voir son score ainsi que la correction pour chaque question.

## 🛠️ 4. Directives pour l'implémentation (Tâches pour l'assistant code)
1.  **Stack technique :** Proposer une stack adaptée (Front-end, Back-end/BaaS) permettant de gérer facilement le Markdown, le stockage de fichiers (images) et les appels API.
2.  **Base de données :** Modéliser la base de données (Thèmes -> Sujets -> QCM liés).
3.  **Prompt IA :** Rédiger la structure du prompt qui sera envoyé à l'API LLM pour garantir que le QCM reste strictement fidèle aux notes du sujet.
4.  **UI/UX :** Construire une interface moderne, avec une sidebar pour les thèmes/sujets, une zone d'édition large, et un mode "Focus/Révision" pour les QCM.