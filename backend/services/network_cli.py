"""
services/network_cli.py
Driver SSH interactif générique (13/08/2026, durcissement switches Cisco IOS/IOS-XE, cf.
services/switch_hardening.py) — aucune syntaxe Cisco ici, uniquement la mécanique du canal.

Nécessaire parce que Cisco IOS/IOS-XE ne supporte pas de façon fiable l'exec non-interactif à
la `conn.run(cmd)` utilisé pour Linux (cf. asset_scanner.py::_scan_linux) : il faut un vrai
canal shell avec pty, envoyer les commandes au clavier et lire jusqu'au prompt suivant, comme
le ferait un terminal.

Réutilise services/ssh_trust.py::connect_trusted (même TOFU déjà éprouvé pour le SSH Linux) —
aucun nouveau modèle de confiance/credentials. Lecture seule strictement : ce module n'envoie
jamais que des commandes `show` (choisies côté switch_hardening.py), jamais de mode config
(cf. CLAUDE.md § non-intervention).
"""

import asyncio
import logging
import re
from typing import Iterable

from services.ssh_trust import connect_trusted

logger = logging.getLogger(__name__)

# Prompt Cisco IOS/IOS-XE typique : "switch>", "switch#", "switch(config)#"... toujours en fin
# de ligne, précédé d'un retour à la ligne une fois la sortie de commande terminée. Heuristique
# best-effort — un vendor dont le prompt diverge significativement retombera sur un timeout,
# traduit en checks "unknown" par l'appelant, jamais une exception qui remonte brute.
_PROMPT_RE = re.compile(r'(?:^|[\r\n])[\w./-]+(?:\([\w-]+\))?[>#]\s*$')
_READ_CHUNK = 4096
_MAX_BUFFER = 65536  # garde-fou mémoire si un appareil ne présente jamais le prompt attendu


class InteractiveShellError(RuntimeError):
    """Connexion échouée, timeout d'attente du prompt, ou buffer jamais résolu — jamais une
    exception brute : services/switch_hardening.py convertit toujours ceci en checks
    "unknown" plutôt que de faire échouer tout le cycle pour un seul actif injoignable."""


async def _read_until_prompt(stdout, timeout: float) -> str:
    buffer = ""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise InteractiveShellError(f"Timeout en attente du prompt (fin de buffer : {buffer[-200:]!r})")
        try:
            chunk = await asyncio.wait_for(stdout.read(_READ_CHUNK), timeout=remaining)
        except asyncio.TimeoutError:
            raise InteractiveShellError(f"Timeout en attente du prompt (fin de buffer : {buffer[-200:]!r})")
        if not chunk:
            raise InteractiveShellError("Connexion fermée avant l'apparition du prompt")
        buffer += chunk
        if len(buffer) > _MAX_BUFFER:
            raise InteractiveShellError("Prompt jamais détecté (buffer maximal atteint — vendor non reconnu ?)")
        if _PROMPT_RE.search(buffer):
            return buffer


def _strip_echo_and_prompt(command: str, raw: str) -> str:
    """Retire l'écho de la commande envoyée (1re ligne, le terminal distant la renvoie) et la
    ligne de prompt finale — ne garde que la sortie utile de la commande."""
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines and command.strip() in lines[0]:
        lines = lines[1:]
    if lines and _PROMPT_RE.search("\n" + lines[-1]):
        lines = lines[:-1]
    return "\n".join(lines).strip()


async def run_commands(
    host: str,
    username: str,
    password: str,
    commands: Iterable[str],
    preamble: Iterable[str] = ("terminal length 0",),
    connect_timeout: float = 15.0,
    command_timeout: float = 10.0,
) -> dict[str, str]:
    """Ouvre UNE session SSH interactive, envoie le préambule (désactivation de la pagination
    par défaut) puis chaque commande l'une après l'autre, retourne {commande: sortie}. Une
    seule connexion pour toutes les commandes — pas une par commande, coût de handshake SSH
    sinon multiplié inutilement."""
    try:
        async with await connect_trusted(
            host, username=username, password=password, connect_timeout=connect_timeout,
        ) as conn:
            process = await conn.create_process(term_type="vt100", encoding="utf8")
            try:
                # Premier prompt avant tout envoi (bannière de connexion incluse dans le buffer,
                # ignorée — seul l'arrivée du prompt compte ici).
                await _read_until_prompt(process.stdout, connect_timeout)

                for cmd in preamble:
                    process.stdin.write(cmd + "\n")
                    await _read_until_prompt(process.stdout, command_timeout)

                results: dict[str, str] = {}
                for cmd in commands:
                    process.stdin.write(cmd + "\n")
                    raw = await _read_until_prompt(process.stdout, command_timeout)
                    results[cmd] = _strip_echo_and_prompt(cmd, raw)
                return results
            finally:
                try:
                    process.stdin.write("exit\n")
                    process.close()
                except Exception:
                    pass  # session déjà en train de se fermer, rien à faire de plus
    except InteractiveShellError:
        raise
    except Exception as exc:
        raise InteractiveShellError(f"Connexion SSH à {host} échouée : {exc}") from exc
