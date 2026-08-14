# ─── Stage "dev" (défaut, docker-compose.yml § service `frontend`) ───────────
# Vite dev server avec HMR, sources montées en direct (`rw`) — c'est le mode
# utilisé pendant tout le développement de ce projet. `target: dev` est fixé
# explicitement dans docker-compose.yml : sans lui, Docker construit le
# DERNIER stage du fichier par défaut (`prod` ci-dessous), ce qui basculerait
# silencieusement l'environnement de dev vers un build figé, sans HMR.
FROM node:20-alpine AS dev
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
# Non-root (10/08/2026, cf. AUDIT_SECURITE.md) : `node` déjà présent dans l'image
# officielle (UID 1000, cohérent avec la propriété des bind mounts ./frontend, 1000:1000
# côté hôte WSL2/drvfs). `npm install` reste avant, en root — mais `node_modules` est un
# volume anonyme (docker-compose.yml), recréé root:root à chaque recréation du conteneur
# si on ne le réapproprie pas ici ; sans ce chown, `node` ne peut plus écrire son cache
# (`node_modules/.vite`) → EACCES en boucle et page blanche côté navigateur (14/08/2026).
RUN chown -R node:node /app
USER node
CMD ["npm", "run", "dev"]

# ─── Stage "build" (intermédiaire, jamais lancé directement) ─────────────────
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# ─── Stage "prod" (docker-compose.yml § service `frontend-prod`, profil "prod")
# Build Vite optimisé (minifié, sans tooling de dev) servi par nginx. Le
# `nginx.conf` reproduit le proxy /api → backend et le forwarding d'IP réelle
# (X-Forwarded-For/X-Real-IP) du `vite.config.js` dev — nécessaire pour que
# `routers/connections.py` continue de journaliser la vraie IP cliente et pas
# celle du conteneur frontend.
FROM nginx:1.27-alpine AS prod
# apk upgrade (13/08/2026, scan Trivy — CVE-2026-31789 CRITICAL sur libssl3/libcrypto3, correctif
# déjà publié par Alpine mais pas encore dans le tag figé nginx:1.27-alpine) : récupère les derniers
# paquets patchés du dépôt Alpine au moment du build, sans attendre une nouvelle image de base.
RUN apk update && apk upgrade --no-cache
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
# Non-root (10/08/2026, cf. AUDIT_SECURITE.md) : utilisateur `nginx` déjà présent dans
# l'image officielle. Master process non-root => la directive `user nginx;` du
# nginx.conf de base est ignorée (simple warning au démarrage, pas fatal — elle ne sert
# qu'à faire tomber les privilèges d'un master root vers les workers, inutile si le
# master n'est déjà pas root). Chemins que nginx doit pouvoir écrire (cache, pid, logs)
# réappropriés ; pid déplacé sous /tmp (accessible en écriture par tout utilisateur par
# défaut) plutôt que /var/run (root only) — modifié dans nginx.conf lui-même (pas via
# `-g` en ligne de commande sur CMD : les deux coexistent mal, "pid" directive is
# duplicate, testé en direct).
RUN chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /etc/nginx/conf.d /var/log/nginx \
    && sed -i 's#pid[[:space:]]*[^;]*;#pid /tmp/nginx.pid;#' /etc/nginx/nginx.conf
USER nginx
EXPOSE 3000
