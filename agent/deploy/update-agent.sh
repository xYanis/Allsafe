#!/bin/bash
# Met à jour allsafe-agent depuis le serveur Allsafe puis pousse un check-in — à
# planifier en remplacement du simple `allsafe-agent checkin` documenté dans
# agent/README.md § Installation. Jamais lancé par Allsafe lui-même (respect du
# principe de non-intervention, cf. CLAUDE.md §1) : c'est le poste qui vient chercher
# sa mise à jour, Allsafe ne se connecte/n'exécute jamais rien dessus.
#
# N'enrôle un poste tout seul QUE si un jeton lui est explicitement fourni en 2e argument
# (typiquement un jeton réutilisable "parc", cf. docs/AGENTS.md § Enrôlement à l'échelle,
# embarqué dans ce même script de démarrage GPO/config management) — sans ce jeton, un
# poste non enrôlé reste signalé dans le log, jamais enrôlé silencieusement.
#
# 17/08/2026 — aussi la commande recommandée pour un premier poste isolé (au lieu de
# `dpkg -i` + `allsafe-agent enroll` manuels documentés dans agent/README.md § Installation) :
# une seule commande, erreurs visibles à l'écran (cf. équivalent Windows, même session,
# incident poste aos12).
#
# Usage : update-agent.sh URL_SERVEUR_ALLSAFE [JETON_ENROLEMENT_BULK]
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit tourner en root (dpkg/systemctl) — relance-le avec sudo." >&2
    exit 1
fi

SERVER="${1:-http://192.168.105.84:3000}"
ENROLL_TOKEN="${2:-}"
BIN=/usr/bin/allsafe-agent
CONFIG=/etc/allsafe-agent/agent.json
LOG=/var/log/allsafe-agent-update.log

# Miroir console (17/08/2026) — même raison que le script Windows équivalent : en usage
# manuel/interactif, un échec resté uniquement dans le fichier de log est invisible.
log() { local msg="$(date -Is)  $1"; echo "$msg" >> "$LOG"; echo "$msg"; }

latest_version=$(curl -sf "$SERVER/api/agents/latest/version" | grep -oP '"version"\s*:\s*"\K[^"]+') || {
    log "Échec de récupération de la version côté serveur ($SERVER)"
    exit 1
}

installed_version=""
[ -x "$BIN" ] && installed_version=$("$BIN" --version | awk '{print $2}')

if [ "$installed_version" != "$latest_version" ]; then
    log "Mise à jour : ${installed_version:-aucune} -> $latest_version"
    tmp=$(mktemp --suffix=.deb)
    if ! curl -sf "$SERVER/api/agents/latest/linux" -o "$tmp"; then
        log "Échec du téléchargement du .deb"
        rm -f "$tmp"
        exit 1
    fi
    if ! dpkg -i "$tmp" 2>&1 | tee -a "$LOG"; then
        rm -f "$tmp"
        log "Échec de l'installation dpkg — voir ci-dessus / $LOG (dépendances manquantes ? essayer 'apt-get install -f')"
        exit 1
    fi
    rm -f "$tmp"
    log "Installation terminée."
    # dpkg remplace le binaire sur disque, mais un service déjà actif garde l'ancien code
    # en mémoire tant qu'il n'est pas relancé — le postinst du paquet (`enable --now`) ne
    # redémarre pas un service déjà démarré, juste "start" (no-op si déjà actif).
    if systemctl is-enabled allsafe-agent >/dev/null 2>&1; then
        systemctl restart allsafe-agent
        log "Service redémarré."
    fi
else
    log "Déjà à jour ($installed_version)."
fi

if [ ! -f "$CONFIG" ]; then
    if [ -n "$ENROLL_TOKEN" ]; then
        log "Agent non enrôlé — enrôlement avec le jeton fourni…"
        if "$BIN" enroll --token "$ENROLL_TOKEN" --server "$SERVER" 2>&1 | tee -a "$LOG"; then
            log "Enrôlement réussi."
            systemctl restart allsafe-agent 2>/dev/null || true
        else
            log "Échec de l'enrôlement — jeton invalide/expiré/déjà à son quota d'usages ?"
        fi
    else
        log "Agent non enrôlé (pas de $CONFIG) — générez un jeton dans Allsafe > Sécurité > Agents (ou passez un jeton réutilisable en 2e argument pour un enrôlement automatique)."
    fi
fi

if systemctl is-active allsafe-agent >/dev/null 2>&1; then
    log "Service systemd actif — check-in géré par la boucle persistante, pas ce script."
elif [ -f "$CONFIG" ]; then
    "$BIN" checkin
    log "Check-in envoyé."
fi
