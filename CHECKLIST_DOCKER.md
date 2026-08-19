# Checklist sécurité Docker — Allsafe

> État constaté le 24/07/2026 sur `docker-compose.yml` / `backend/Dockerfile` / `frontend/Dockerfile`.
> Revue et mise à jour le 13/08/2026 — plusieurs points listés comme ouverts étaient en fait déjà
> corrigés dans le code (jamais recoché depuis), d'autres traités ce jour-là. Ce qui reste ouvert
> aujourd'hui est soit **bloqué sur le serveur cible de déploiement** (pas encore accessible), soit
> un choix assumé à reprendre plus tard.

---

## 🔴 Critique

- [x] **Aucune `restart:` policy** — `restart: unless-stopped` posé sur les 10 services (7 dev +
      `backend-prod`/`worker-prod`/`beat-prod`, 13/08/2026). Vérifié via `docker inspect` (champ
      `RestartPolicy`) sur plusieurs services.
- [x] **Tous les conteneurs tournent en `root`** — `USER app` (`backend/Dockerfile`, 10/08/2026),
      `USER node`/`USER nginx` (`frontend/Dockerfile`, stages dev/prod). `worker`/`beat` réutilisent
      l'image `backend`, donc déjà couverts.
- [x] **Frontend en mode dev en "prod"** — `frontend-prod` (27/07/2026, `target: prod`, build Vite
      minifié servi par nginx) existe déjà comme alternative dédiée sous le profil Compose "prod" ;
      `frontend` (dev, `npm run dev`) reste volontairement le service par défaut pour le
      développement quotidien. Pas un oubli : le choix du service à démarrer (`frontend` vs
      `frontend-prod`) reste à faire explicitement au déploiement.
- [x] **Backend avec `--reload`** (13/08/2026) — retiré du `CMD` de `backend/Dockerfile` (l'image
      reste "prod-safe" par défaut), réintroduit uniquement via `command:` sur le service dev
      `backend`. `backend-prod` (aucun override) en hérite l'absence.
- [x] **Bind mounts du code source en prod** (13/08/2026) — `backend-prod`/`worker-prod`/`beat-prod`
      créés sous le profil "prod" (même modèle que `frontend-prod`) : aucun bind mount `./backend:/app`,
      uniquement les volumes de données runtime (clé SSH, pièces jointes, sauvegardes...). Vérifié
      via `docker inspect --format '{{.Mounts}}'` sur `backend-prod` : aucun mount vers `/app`.

## 🟠 Élevé

- [x] **Ports publiés sur toutes les interfaces** — `backend`/`backend-prod` restreints à
      `127.0.0.1:8000:8000` (03/08/2026, audit sécurité). `frontend`/`frontend-prod` restent
      volontairement sur `0.0.0.0:3000` : c'est l'interface utilisateur elle-même, elle doit être
      joignable depuis le réseau — pas un oubli.
- [ ] **Pas de reverse proxy / TLS devant l'app** → **bloqué sur le serveur cible** (domaine et
      certificat pas encore connus, l'utilisateur n'a pas accès au serveur de déploiement à ce
      stade). nginx/traefik/caddy en frontal avec HTTPS, à poser une fois le serveur disponible.
- [ ] **Images non pin-nées par digest** — laissé ouvert par choix (13/08/2026) : le projet évolue
      encore vite (sessions quasi quotidiennes), un digest figé demanderait une mise à jour manuelle
      à chaque bump pour un gain surtout pertinent une fois en prod stable. À reconsidérer à ce
      moment-là.
- [x] **Aucun scan de vulnérabilités des images** (13/08/2026, Trivy, exécuté ponctuellement — pas
      intégré en continu) :
      - `cybervuln-backend` : 118 CVE HIGH/CRITICAL quasi toutes sur des paquets Debian de l'image de
        base (dont 17 CRITICAL sur `perl`/`libperl5.40`, sans correctif Debian publié à ce jour —
        Perl n'est jamais utilisé par l'app Python, dépendance de l'image de base uniquement).
        1 CVE actionnable trouvée et corrigée : `cryptography` 49.0.0 → **50.0.0**
        (`backend/requirements.txt`), revérifié fonctionnel (chiffrement Fernet des mots de passe
        SSH, `services/crypto.py`).
      - `cybervuln-frontend-prod` : 35 CVE HIGH/CRITICAL (dont 2 CRITICAL `libssl3`/`libcrypto3`,
        `CVE-2026-31789`) — toutes corrigées en ajoutant `RUN apk update && apk upgrade --no-cache`
        au stage `prod` (`frontend/Dockerfile`) : récupère les derniers paquets Alpine patchés au
        build plutôt que d'attendre une nouvelle image `nginx:1.27-alpine`. Rescanné : **0 HIGH/CRITICAL**.
- [ ] **Secrets via variables d'environnement en clair** (`.env` via `env_file`) — laissé ouvert,
      lourd : une vraie solution (Docker secrets, Vault, SOPS) sortirait du périmètre docker-compose
      pur vers Swarm/K8s ou un outillage supplémentaire. Décision à reprendre plus tard, pas dans
      cette passe.
- [x] **`BOOTSTRAP_ADMIN_PASSWORD`** (30/07/2026, authentification ; retiré 10/08/2026) — le
      bootstrap ne s'était de toute façon jamais déclenché (un vrai compte admin,
      `yhortholary@eurofeu.fr`, existait déjà en base depuis le 30/07), retrait donc sans risque.
      `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` supprimés de `.env`, `backend`/`worker`/
      `beat` redémarrés pour que les valeurs disparaissent aussi de l'environnement des conteneurs
      en cours (pas seulement du fichier) — vérifié absentes via `docker compose exec backend env`.
- [ ] **`COOKIE_SECURE=false`** → **bloqué sur le serveur cible**, dépend directement du reverse-proxy/
      TLS ci-dessus (le cookie `Secure` n'a de sens qu'une fois une vraie connexion HTTPS en place).

## 🟡 Moyen

- [x] **Aucun `.dockerignore`** (13/08/2026) — `backend/.dockerignore` (`__pycache__/`, `venv/`,
      `.pytest_cache/`) et `frontend/.dockerignore` (`node_modules/`, `dist/`) créés. Pas de
      `.dockerignore` racine : aucun service ne build depuis le contexte racine (`backend`/
      `frontend` ont chacun leur propre contexte), donc rien à y exclure.
- [x] **Aucune limite de ressources** — `mem_limit`/`cpus` déjà en place sur les 7 services d'origine
      (constaté en relisant `docker-compose.yml` à jour), étendu aux 3 nouveaux services prod
      (13/08/2026).
- [x] **Aucun `cap_drop` / `security_opt: no-new-privileges`** — déjà en place sur les 7 services
      d'origine (`cap_drop: [ALL]` partout sauf `db`, exception documentée : l'entrypoint Postgres a
      besoin de root au démarrage pour chown le volume de données), étendu aux 3 nouveaux services
      prod.
- [x] **Un seul réseau Docker** (13/08/2026) — segmenté en `backend_net` (db/redis/backend/worker/
      beat + variantes prod) et `frontend_net` (frontend/frontend-prod + backend/backend-prod, seuls
      services sur les deux). Vérifié en conditions réelles : `frontend` ne résout même plus les
      noms `db`/`redis` (DNS Docker limité aux services du même réseau), `backend` continue de
      joindre `db` normalement.
- [x] **Pas de rotation des logs** — déjà en place (`json-file`, 10m × 5 fichiers) sur les 7 services
      d'origine, étendu aux 3 nouveaux services prod.
- [x] **Pas de `HEALTHCHECK`** — déjà en place sur les 7 services d'origine (y compris `backend`/
      `worker`/`beat`/`frontend`, contrairement à ce que cette ligne affirmait), étendu à
      `backend-prod`/`worker-prod`/`beat-prod`.

## 🟢 Faible / bonnes pratiques

- [ ] **Volume `postgres_data`** — sauvegarde déjà en place (`services/backup.py`, `pg_dump`
      quotidien + rétention `BACKUP_RETENTION_DAYS`) ; le chiffrement au repos reste →
      **bloqué sur le serveur cible** (LUKS ou équivalent au niveau disque hôte, hors périmètre
      Docker).
- [ ] **Docker rootless / daemon durci** → **bloqué sur le serveur cible** (config du daemon Docker
      hôte, pas quelque chose que le repo peut poser).
- [x] **Alignement avec `audit/AUDIT_SECURITE.md`** (13/08/2026) — `git init` + `.gitignore` couvrant
      `.env`/`keys/id_ed25519`/`cookies.txt` (secrets réels trouvés et exclus avant le premier
      commit), cohérent avec les exclusions `.dockerignore` ci-dessus.

---

**Conforme / non concerné** : pas de `docker.sock` monté dans un conteneur applicatif (bon — pas de
risque d'évasion via l'API Docker) ; les images officielles `postgres`/`redis` tournent déjà en
interne sous un user non-root pour leur propre processus.

**Reste ouvert, tout bloqué sur le serveur cible ou un choix assumé** : reverse-proxy/TLS +
`COOKIE_SECURE`, rootless/durcissement du daemon, chiffrement au repos, épinglage par digest,
secrets en clair via env vars. Rien de ces points ne nécessite de nouvelle décision de code — à
reprendre dès que le serveur de déploiement est accessible (les trois premiers) ou lors d'une
session dédiée (les deux derniers).
