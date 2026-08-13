FROM python:3.12-slim

WORKDIR /app

# postgresql-client-16 (pas le paquet Debian générique, qui donne la v15 sur
# bookworm) : pg_dump doit être de version >= au serveur (postgres:16-alpine
# dans docker-compose.yml) — un client plus ancien que le serveur n'est pas
# supporté par PostgreSQL. Dépôt officiel PGDG requis pour la v16 exacte.
# curl : healthcheck backend (GET /api/health) + téléchargement de la clé PGDG.
# procps (pgrep) : healthcheck beat, qui n'a pas d'endpoint HTTP à interroger.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libldap2-dev libsasl2-dev gcc curl gnupg lsb-release procps \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail \
       https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends postgresql-client-16 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Utilisateur non-root (10/08/2026, cf. AUDIT_SECURITE.md — durcissement avant passage en
# prod) : une RCE future (dépendance compromise, faille applicative) ne donne plus root
# dans le conteneur. UID 1000 choisi pour matcher la propriété déjà en place sur les bind
# mounts (./backend, ./keys — 1000:1000 côté hôte WSL2/drvfs, permissifs 777) ; les volumes
# nommés (backups/documents/incident_attachments/audit_attachments), eux root:root par
# défaut et déjà peuplés en usage réel, ont dû être réappropriés séparément
# (`docker run --rm -v <volume>:/data alpine chown -R 1000:1000 /data`) — un simple chown
# ici ne les couvre pas, ils sont montés PAR-DESSUS au démarrage du conteneur, écrasant
# tout ce que l'image pose à ces chemins.
RUN useradd -m -u 1000 -s /bin/bash app && chown -R app:app /app
USER app

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
