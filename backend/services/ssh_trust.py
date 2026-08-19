"""
services/ssh_trust.py
TOFU (trust-on-first-use) pour les connexions SSH sortantes (asyncssh),
partagé par asset_scanner.py et patch_checker.py.

cf. audit/AUDIT_SECURITE.md #2 : `known_hosts=None` désactivait toute vérification
de l'identité du serveur SSH. Un attaquant en MITM sur le VLAN (ARP spoofing,
VLAN partagé) pouvait se faire passer pour l'actif scanné : vol du mot de
passe SSH si l'actif s'authentifie par mot de passe, ou injection de faux
relevés de paquets sinon (fausse détection de patch) — contredit le modèle
« lecture seule fiable » sur lequel repose l'auto-bascule des vulns.

Le premier contact avec un hôte reste, par nature, non vérifié (TOFU) : la
clé présentée est acceptée et pinnée. Tout contact suivant avec une clé
différente est rejeté sans apprentissage silencieux — un changement de clé
légitime (réinstallation du serveur) doit être traité par un humain, pas
absorbé automatiquement.
"""

import logging
import os

import asyncssh

from config import settings

logger = logging.getLogger(__name__)


def _known_hosts_path() -> str:
    # /app/ssh-state (10/08/2026, cf. audit/AUDIT_SECURITE.md § Docker) : volume nommé séparé de
    # /app/keys, monté :ro depuis ce correctif — known_hosts est le seul des deux fichiers
    # qui a besoin d'écriture (apprentissage TOFU), la clé privée id_ed25519, elle, n'a
    # jamais besoin que d'être lue.
    path = settings.SSH_KNOWN_HOSTS or "/app/ssh-state/known_hosts"
    if not os.path.exists(path):
        open(path, "a").close()
    return path


def _append_entry(path: str, host: str, key: asyncssh.SSHKey) -> None:
    line = key.export_public_key("openssh").decode().strip()
    with open(path, "a") as f:
        f.write(f"{host} {line}\n")


async def connect_trusted(host: str, **connect_kwargs) -> asyncssh.SSHClientConnection:
    """Équivalent de asyncssh.connect(host, ..., known_hosts=<fichier pinné>),
    avec apprentissage de la clé hôte au premier contact seulement."""
    path = _known_hosts_path()

    try:
        return await asyncssh.connect(host, known_hosts=path, **connect_kwargs)
    except asyncssh.HostKeyNotVerifiable:
        known = asyncssh.read_known_hosts(path) if os.path.getsize(path) else None
        already_pinned = bool(known and known.match(host, host, None)[0])
        if already_pinned:
            # Une clé DIFFÉRENTE est déjà pinnée pour cet hôte : ne jamais
            # apprendre silencieusement par-dessus — ça reviendrait à annuler
            # la protection (c'est exactement le scénario MITM/clé-changée
            # qu'on cherche à détecter).
            raise

        logger.warning("SSH TOFU : premier contact avec %s, apprentissage de la clé hôte", host)
        conn = await asyncssh.connect(host, known_hosts=None, **connect_kwargs)
        server_key = conn.get_server_host_key()
        if server_key is not None:
            _append_entry(path, host, server_key)
        return conn
