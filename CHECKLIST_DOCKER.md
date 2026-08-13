# Checklist sécurité Docker — Allsafe

> État constaté le 24/07/2026 sur `docker-compose.yml` / `backend/Dockerfile` / `frontend/Dockerfile`.
> Rien n'est corrigé ici, juste la liste. À traiter avant déploiement en prod.

---

## 🔴 Critique

- [ ] **Aucune `restart:` policy** sur aucun service — un reboot du serveur hôte ne relance rien
      (ni l'app, ni la déception DB) tant que quelqu'un ne relance pas `docker compose up` à la main.
      → `restart: unless-stopped` sur tous les services.
- [ ] **Tous les conteneurs tournent en `root`** — aucune directive `USER` dans `backend/Dockerfile` ni
      `frontend/Dockerfile`. Une RCE dans l'app donne du root *dans le conteneur* d'office.
      → créer un user non-root (`USER appuser`) dans les deux Dockerfiles.
- [ ] **Frontend en mode dev en "prod"** (`npm run dev`, serveur Vite) — pas un build de production,
      surface d'attaque plus large (dev server), pas de headers de sécurité (CSP, X-Frame-Options…).
      → `vite build` + servir les fichiers statiques via nginx/caddy en prod.
- [ ] **Backend avec `--reload`** (uvicorn) — flag de dev (watcher de fichiers), pas destiné à tourner
      en prod (perf + surface d'attaque). → retirer `--reload` en prod, ou séparer une commande prod
      dédiée dans un `docker-compose.prod.yml`.
- [ ] **Bind mounts du code source** (`./backend:/app`, `./frontend:/app`) en plus de l'image buildée —
      pratique en dev (hot reload), mais en prod ça expose le code source hôte dans le conteneur et
      inversement. → ne pas monter le code en prod, se fier uniquement à l'image buildée (COPY).

## 🟠 Élevé

- [ ] **Ports publiés sur toutes les interfaces** (`8000:8000`, `3000:3000` = `0.0.0.0` implicite) —
      accessibles depuis n'importe quelle IP pouvant atteindre l'hôte, pas seulement en local.
      → binder explicitement (`127.0.0.1:8000:8000`) si un reverse proxy fait la façade, ou pare-feu hôte.
- [ ] **Pas de reverse proxy / TLS devant l'app** — le trafic backend/frontend est en clair aujourd'hui
      (dev). → nginx/traefik/caddy en frontal avec HTTPS avant tout accès réseau réel.
- [ ] **Images non pin-nées par digest** (`postgres:16-alpine`, `redis:7-alpine`, `python:3.12-slim`,
      `node:20-alpine`) — un tag peut changer de contenu (`docker pull` futur ≠ image testée).
      → pin par digest (`@sha256:...`) pour les déploiements reproductibles, ou au moins figer les tags
      mineurs et auditer avant chaque bump.
- [ ] **Aucun scan de vulnérabilités des images** (Trivy / Grype / Docker Scout) — inconnu si les images
      de base ou les dépendances (`requirements.txt`, `package.json`) embarquent des CVE connues.
      → intégrer un scan dans le pipeline (même manuel/ponctuel avant déploiement).
- [ ] **Secrets via variables d'environnement en clair** (`.env` chargé par `env_file`) — visibles via
      `docker inspect`/`/proc/<pid>/environ` par quiconque a accès au host/socket Docker.
      → Docker secrets, ou un coffre (Vault/SOPS), au moins pour `DB_PASSWORD`, `SECRET_KEY`,
      `APP_DB_PASSWORD`, `AD_PASSWORD`, `WINRM_PASSWORD`, `ANTHROPIC_API_KEY`, `NVD_API_KEY`.
- [x] **`BOOTSTRAP_ADMIN_PASSWORD`** (30/07/2026, authentification ; retiré 10/08/2026) — le
      bootstrap ne s'était de toute façon jamais déclenché (un vrai compte admin,
      `yhortholary@eurofeu.fr`, existait déjà en base depuis le 30/07), retrait donc sans risque.
      `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` supprimés de `.env`, `backend`/`worker`/
      `beat` redémarrés pour que les valeurs disparaissent aussi de l'environnement des conteneurs
      en cours (pas seulement du fichier) — vérifié absentes via `docker compose exec backend env`.
- [ ] **`COOKIE_SECURE=false`** (30/07/2026, authentification) — le cookie de session HttpOnly n'a
      pas l'attribut `Secure` tant qu'aucun TLS n'est devant l'app (cohérent avec l'absence de
      reverse-proxy/TLS ci-dessus). → passer à `true` dès qu'un reverse-proxy TLS est mis en place,
      sinon le cookie de session voyage en clair sur le réseau.

## 🟡 Moyen

- [ ] **Aucun `.dockerignore`** (racine, backend/, frontend/) — le contexte de build peut embarquer
      `.env`, `keys/`, `.git/`, `node_modules/` dans les layers d'image sans qu'on le voie.
      → créer les `.dockerignore` (mêmes exclusions que le `.gitignore` déjà prévu dans `AUDIT_SECURITE.md`).
- [ ] **Aucune limite de ressources** (`mem_limit`/`cpus` ou `deploy.resources.limits`) — un conteneur
      compromis ou buggé peut épuiser la RAM/CPU de l'hôte (DoS involontaire ou provoqué).
      → plafonner mémoire/CPU par service, au minimum sur `backend`/`worker`/`db`.
- [ ] **Aucun `cap_drop` / `security_opt: no-new-privileges`** — les conteneurs gardent toutes les
      capacités Linux par défaut. → `cap_drop: [ALL]` + réajouter au cas par cas, `no-new-privileges:true`
      partout.
- [ ] **Un seul réseau Docker** (bridge par défaut) — `frontend` peut atteindre `db`/`redis` réseau-
      niveau alors qu'il n'en a jamais besoin (c'est un SPA, il ne parle qu'au backend via le navigateur).
      → segmenter en réseaux internes (`db`/`redis`/`backend`/`worker`/`beat` isolés, `frontend` à part)
      pour réduire le rayon d'action en cas de conteneur compromis.
- [ ] **Pas de rotation des logs** (`logging.driver`/`options.max-size`) — logs illimités peuvent remplir
      le disque hôte (DoS lent). → configurer `json-file` avec `max-size`/`max-file`, ou driver externe.
- [ ] **Pas de `HEALTHCHECK`** sur `backend`/`worker`/`beat`/`frontend` (seuls `db`/`redis` en ont) —
      un service planté silencieusement n'est pas détecté/relancé automatiquement.
      → ajouter des healthchecks (ex. `GET /api/health` pour le backend).

## 🟢 Faible / bonnes pratiques

- [ ] **Volume `postgres_data`** — pas de stratégie de sauvegarde/chiffrement au repos documentée pour
      la prod (hors périmètre Docker pur, mais à cadrer avant déploiement).
- [ ] **Docker rootless / daemon durci** — évaluer si le daemon Docker de l'hôte de prod tourne en mode
      rootless, ou au moins avec les options de durcissement standard (`userns-remap`, etc.).
- [ ] **Alignement avec `AUDIT_SECURITE.md`** — le `.gitignore` à créer avant tout `git init` doit aussi
      couvrir ce que les `.dockerignore` excluent (`.env`, `keys/`), pour rester cohérent.

---

**Conforme / non concerné** : pas de `docker.sock` monté dans un conteneur (bon — pas de risque
d'évasion via l'API Docker) ; les images officielles `postgres`/`redis` tournent déjà en interne sous un
user non-root pour leur propre processus (le point 🔴 root ci-dessus concerne uniquement les images
custom `backend`/`frontend`).
