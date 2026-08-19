# Multi-stage (18/08/2026, cf. audit/AUDIT_SECURITE.md #32) — avant ce correctif, `gcc`/
# `libldap2-dev`/`libsasl2-dev` (nécessaires seulement pour l'étape `pip install`, jamais
# à l'exécution) restaient dans l'image finale (confirmé en direct : `which gcc` présent,
# `gcc-14` complet installé). Une RCE applicative future (dépendance compromise, faille
# métier) donnait accès à un compilateur C complet dans le conteneur — facilite la
# fabrication d'un exploit sur place plutôt que d'avoir à en apporter un depuis l'extérieur.
# `ldap3` (requirements.txt) est pur Python, sans extension compilée : aucun `.so` runtime
# de libldap/libsasl à recopier dans le stage final pour lui (contrairement à `python-ldap`,
# non utilisé ici) — seul le paquet lui-même (copié via `pip install --user`) est nécessaire.
FROM python:3.12-slim AS build

WORKDIR /app

# postgresql-client-16 construit ici uniquement pour que le dépôt PGDG soit configuré une
# fois — le binaire lui-même est réinstallé dans le stage final (ci-dessous), pas copié
# depuis ce stage (ses propres dépendances partagées doivent être résolues dans l'image
# finale, pas seulement le binaire).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libldap2-dev libsasl2-dev gcc curl gnupg lsb-release \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail \
       https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends postgresql-client-16 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


FROM python:3.12-slim

WORKDIR /app

# curl : healthcheck backend (GET /api/health) + téléchargement de la clé PGDG ci-dessous.
# procps (pgrep) : healthcheck beat, qui n'a pas d'endpoint HTTP à interroger.
# postgresql-client-16 (pas le paquet Debian générique, qui donne la v15 sur bookworm) :
# pg_dump doit être de version >= au serveur (postgres:16-alpine dans docker-compose.yml).
# gnupg/lsb-release ne servent qu'à ajouter le dépôt PGDG — retirés juste après, inutiles
# à l'exécution.
RUN apt-get update && apt-get install -y --no-install-recommends curl gnupg lsb-release procps \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail \
       https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends postgresql-client-16 \
    && apt-get purge -y --auto-remove gnupg lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Utilisateur non-root (10/08/2026, cf. audit/AUDIT_SECURITE.md — durcissement avant passage en
# prod) : une RCE future (dépendance compromise, faille applicative) ne donne plus root
# dans le conteneur. UID 1000 choisi pour matcher la propriété déjà en place sur les bind
# mounts (./backend, ./keys — 1000:1000 côté hôte WSL2/drvfs, permissifs 777) ; les volumes
# nommés (backups/documents/incident_attachments/audit_attachments), eux root:root par
# défaut et déjà peuplés en usage réel, ont dû être réappropriés séparément
# (`docker run --rm -v <volume>:/data alpine chown -R 1000:1000 /data`) — un simple chown
# ici ne les couvre pas, ils sont montés PAR-DESSUS au démarrage du conteneur, écrasant
# tout ce que l'image pose à ces chemins.
RUN useradd -m -u 1000 -s /bin/bash app

# --chown inline (pas de `chown -R app:app /app` séparé après coup, ni sur les paquets
# installés) : une seule passe par COPY plutôt qu'un second parcours récursif de l'arbre.
COPY --from=build --chown=app:app /root/.local /home/app/.local
COPY --chown=app:app . .

USER app
ENV PATH=/home/app/.local/bin:$PATH

# Pas de --reload ici (13/08/2026, cf. CHECKLIST_DOCKER.md) : l'image doit rester "prod-safe" par
# défaut (utilisée telle quelle par backend-prod/worker-prod/beat-prod, docker-compose.yml) — le
# rechargement à chaud reste disponible, posé explicitement via `command:` sur le seul service dev
# `backend`.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
