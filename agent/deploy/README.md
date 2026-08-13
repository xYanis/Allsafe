# Déploiement centralisé des mises à jour (13/08/2026)

⚠️ **Ces scripts ne sont jamais exécutés par Allsafe.** Le backend ne se connecte, n'exécute et
n'écrit jamais rien sur les postes — c'est le principe de non-intervention (`CLAUDE.md` §1), qui
s'applique aussi bien aux 80 VM serveurs qu'aux postes équipés de l'agent. `update-agent.sh`/
`.ps1` sont des outils que **vous** déployez et planifiez avec votre propre infrastructure
(GPO côté AD, cron/config management côté Linux) — Allsafe se contente de servir passivement le
dernier paquet construit (`GET /api/agents/latest/*`, `routers/agents.py`), un peu comme un dépôt
de paquets qu'on interroge, jamais l'inverse.

Rôle précis depuis le 13/08/2026 (mode persistant, cf. `docs/AGENTS.md` § Mode persistant) : ces
scripts s'occupent uniquement de **mettre à jour le binaire** — le check-in lui-même est géré par
le service systemd/Windows installé avec le paquet (`allsafe-agent run`), pas par ce script (les
deux le détectent et se contentent d'un `systemctl restart`/redémarrage du service après une
installation réussie). Sans le service (mode cron/tâche planifiée nu, cf. `agent/README.md` §
Installation), ils font aussi le check-in eux-mêmes en repli. Planification plus lâche que le
check-in suffit ici (ex. quotidienne plutôt qu'horaire) — une mise à jour de version n'est pas
urgente au sens où un check-in l'est.

## Pré-requis

Le poste doit pouvoir joindre le serveur Allsafe sur le réseau (même URL que `--server` à
l'enrôlement, cf. `agent/README.md` § Usage — généralement le port du frontend, pas le backend
directement, cf. l'avertissement `--server` du même fichier).

Le serveur, lui, doit avoir les paquets à jour dans `agent/dist/` (monté en lecture seule dans le
conteneur backend, `AGENT_DIST_DIR=/app/agent-dist`) et `CURRENT_AGENT_VERSION`
(`routers/agents.py`) à jour — cf. `agent/README.md` § Mise à jour pour le workflow de release
complet (bump `Cargo.toml` + `CURRENT_AGENT_VERSION` + rebuild + copie dans `agent/dist/`).

## Linux — cron

Copier `update-agent.sh` sur le poste (ex. `/usr/local/sbin/allsafe-agent-update.sh`), puis :

```bash
chmod +x /usr/local/sbin/allsafe-agent-update.sh
echo "0 6 * * * root /usr/local/sbin/allsafe-agent-update.sh http://<hôte-allsafe>:3000" \
  | sudo tee /etc/cron.d/allsafe-agent
```

(quotidien à 6h — le check-in lui-même est du ressort du service systemd `allsafe-agent`
installé avec le `.deb`, pas de ce script ; ajuster librement, rien d'imposé côté Allsafe)

Log : `/var/log/allsafe-agent-update.log`.

Pour le pousser sur plusieurs machines d'un coup, votre config management habituel (Ansible,
scripts SSH internes...) fait l'affaire — pas d'outil dédié fourni ici, ce n'est plus du ressort
d'Allsafe une fois le script écrit.

## Windows — GPO

Deux briques indépendantes, toutes deux natives à Active Directory (aucune n'implique Allsafe) :

**1. Installation initiale du `.msi`** — GPO Software Installation classique
(`Computer Configuration > Policies > Software Settings > Software installation`), package
assigné pointant vers `\\serveur\partage\allsafe-agent.msi`. Gère l'installation sur toute une OU
au prochain redémarrage. N'automatise pas l'enrôlement en soi — ça reste `update-agent.ps1
-EnrollToken ...` (§ ci-dessous) ou un `enroll --token ...` manuel par poste, cf.
`docs/AGENTS.md`.

**2. Mise à jour périodique du binaire** — tâche planifiée déployée par GPO Preferences
(`Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks`), qui lance
`update-agent.ps1` (quotidien suffit, le check-in lui-même est du ressort du service Windows
`AllsafeAgent` installé avec le `.msi`, cf. § ci-dessus). Étapes :

1. Déposer `update-agent.ps1` dans SYSVOL (ex.
   `\\domaine\SYSVOL\domaine\scripts\update-agent.ps1`) — répliqué automatiquement sur tous les DC.
2. Créer la tâche planifiée via GPO Preferences : action `powershell.exe`, arguments
   `-ExecutionPolicy Bypass -File "\\domaine\SYSVOL\domaine\scripts\update-agent.ps1" -Server http://<hôte-allsafe>:3000`,
   exécutée en tant que `SYSTEM` (accès registre HKLM sans session interactive, même raison que le
   `schtasks /ru SYSTEM` documenté dans `agent/README.md`), déclencheur horaire.
3. Lier la GPO à l'OU des postes concernés.

Log : `%ProgramData%\allsafe-agent\update.log`.

## Déploiement de parc — jeton réutilisable (13/08/2026)

Pour enrôler beaucoup de postes sans générer un jeton par machine à la main : Sécurité > Agents >
Nouveau jeton > "Réutilisable (parc)", nombre de postes max + durée de validité adaptée à la durée
du déploiement (ex. 7 jours plutôt que les 48h par défaut d'un jeton usage unique). Un jeton
réutilisable ne se lie jamais à un actif précis — chaque enrôlement crée son propre actif, comme un
jeton "libre" à usage unique.

Embarquer ce jeton dans le script de démarrage/tâche planifiée déjà en place plutôt que d'en
distribuer un par poste :

```bash
# Linux — dans /etc/cron.d/allsafe-agent ou le script de provisioning
/usr/local/sbin/allsafe-agent-update.sh http://<hôte-allsafe>:3000 <JETON_BULK>
```

```powershell
# Windows — arguments de la tâche planifiée GPO
-ExecutionPolicy Bypass -File "\\domaine\SYSVOL\domaine\scripts\update-agent.ps1" -Server http://<hôte-allsafe>:3000 -EnrollToken <JETON_BULK>
```

Chaque script vérifie d'abord s'il est déjà enrôlé (`agent.json` présent) — un poste déjà enrôlé
ignore le jeton, l'auto-enrôlement ne se déclenche qu'une fois, au premier passage. Le jeton reste
lisible en clair dans le script/la GPO qui le porte (SYSVOL, cron) — acceptable pour un
déploiement borné dans le temps (le jeton expire), mais à révoquer (Sécurité > Agents) une fois le
parc enrôlé plutôt que de le laisser traîner indéfiniment.

## Pourquoi pas de "push" direct depuis Allsafe

Ça reviendrait à ce que le backend se connecte aux postes pour y exécuter une commande —
exactement ce que le principe de non-intervention interdit (`CLAUDE.md` §1), y compris pour du
lecture-seule/maintenance de l'agent lui-même. Le modèle reste strictement "pull" : chaque poste
vient chercher ce dont il a besoin, sur son propre calendrier, avec ses propres droits locaux.
