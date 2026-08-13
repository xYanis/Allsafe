"""
services/ip_watch.py
Surveillance Identités — vérification d'IP/plages IP publiques surveillées
contre des listes de blocage gratuites (menace/abus), sans clé API.

Contrairement au matching nom/domaine (recherche en sous-chaîne dans du texte
libre d'articles), une IP ne s'y trouve quasiment jamais — vérifié en base :
aucun des 1500+ items de veille déjà collectés ne contient une seule adresse
IP dans son titre/résumé, ces sources ne parlent jamais au niveau
infrastructure. Le signal utile pour une IP/plage surveillée est différent :
apparaît-elle dans une liste d'IP compromises/attaquantes publiée par un tiers
— signe qu'une machine du parc est probablement compromise (bot, scan,
bruteforce...), pas qu'un article de presse la cite.

Sources retenues (100% gratuites, sans inscription, fraîcheur vérifiée avant
intégration — cf. STATUS.md session 20/07/2026, un candidat github
(ransomwatch) avait été écarté pour la même raison : plus mis à jour depuis
juin 2025) :
- IPsum (stamparm/ipsum, GitHub) — agrégat de nombreuses blocklists publiques,
  mis à jour quotidiennement. `score` = nombre de listes sources l'ayant
  signalée.
- Blocklist.de — IP signalées par des fail2ban (bruteforce SSH, mail, web...),
  mise à jour en continu (`Last-Modified` vérifié à quelques heures).
- Feodo Tracker (abuse.ch) — infrastructure C2 de malwares connus (Emotet,
  QakBot...), liste volontairement petite (IP actuellement actives).

Cache en mémoire process (même précédent que `_cycle_running` dans
patch_checker.py) : ces listes (jusqu'à ~115k lignes pour IPsum) sont
re-téléchargées au plus toutes les `CACHE_TTL_SECONDS`, pas à chaque appel de
GET /api/identities/matches.
"""

import ipaddress
import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 1800  # 30 min — fraîcheur suffisante, évite de marteler ces services tiers gratuits

# IPsum score = nombre de blocklists indépendantes (parmi celles qu'IPsum agrège)
# ayant signalé l'IP. Distribution réelle constatée sur ~113k IP (session
# 20/07/2026) : score 1 = 78 355 IP (69% du total, une seule liste d'accord —
# bruit/faux positifs fréquents), score 2 = 16 396, score 3 = 11 049, score 4+
# = ~7 300 (haute confiance). Seuil à 2 : élimine le plus gros du bruit à
# source unique sans perdre les IP corroborées par au moins une 2e liste.
IPSUM_MIN_SCORE = 2

IPSUM_URL     = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
BLOCKLISTDE_URL = "https://lists.blocklist.de/lists/all.txt"
FEODO_URL     = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

_cache: dict = {"fetched_at": 0.0, "blocklists": {}}


def _parse_ipsum(text: str) -> list[dict]:
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        try:
            score = int(parts[1])
        except ValueError:
            continue
        if score < IPSUM_MIN_SCORE:
            continue
        entries.append({"ip": parts[0], "score": parts[1]})
    return entries


def _parse_blocklistde(text: str) -> list[dict]:
    return [{"ip": line.strip()} for line in text.splitlines() if line.strip() and not line.startswith("#")]


def _parse_feodo(data: list) -> list[dict]:
    return [
        {"ip": e["ip_address"], "malware": e.get("malware"), "last_online": e.get("last_online")}
        for e in data
        if e.get("ip_address")
    ]


async def _fetch_blocklists(force: bool = False) -> dict[str, list[dict]]:
    """Télécharge (ou sert depuis le cache process) les 3 listes. Un échec sur
    l'une d'elles n'empêche pas d'utiliser les autres — ce sont des services
    tiers gratuits sans SLA, pas question qu'une panne ponctuelle de l'un
    casse toute la vérification."""
    now = time.time()
    if not force and _cache["blocklists"] and (now - _cache["fetched_at"]) < CACHE_TTL_SECONDS:
        return _cache["blocklists"]

    blocklists: dict[str, list[dict]] = {}
    async with httpx.AsyncClient(timeout=15) as client:
        for name, url, parse in (
            ("IPsum (FireHOL)", IPSUM_URL, "text"),
            ("Blocklist.de", BLOCKLISTDE_URL, "text"),
            ("Feodo Tracker (abuse.ch)", FEODO_URL, "json"),
        ):
            try:
                r = await client.get(url)
                r.raise_for_status()
                if parse == "json":
                    blocklists[name] = _parse_feodo(r.json())
                elif name == "IPsum (FireHOL)":
                    blocklists[name] = _parse_ipsum(r.text)
                else:
                    blocklists[name] = _parse_blocklistde(r.text)
            except Exception as e:
                logger.warning("Blocklist IP %s indisponible : %s", name, e)
                # Conserve l'ancienne version en cache pour cette source plutôt
                # que de la faire disparaître à la moindre panne réseau ponctuelle.
                blocklists[name] = _cache["blocklists"].get(name, [])

    _cache["blocklists"] = blocklists
    _cache["fetched_at"] = now
    return blocklists


def _network_or_none(value: str, kind: str) -> Optional[ipaddress._BaseNetwork | ipaddress._BaseAddress]:
    try:
        if kind == "ip_range":
            return ipaddress.ip_network(value, strict=False)
        return ipaddress.ip_address(value)
    except ValueError:
        return None


async def find_ip_matches(identities: list) -> list[dict]:
    """`identities` : WatchedIdentity de kind "ip"/"ip_range" (enabled).
    Retourne une entrée par (identité, IP blocklistée) matchée — une plage
    peut matcher plusieurs IP d'une même liste, chacune remontée séparément
    pour que l'analyste voie l'ampleur réelle (ex: 3 IP de sa plage sur
    IPsum)."""
    ip_identities = [i for i in identities if i.kind in ("ip", "ip_range")]
    if not ip_identities:
        return []

    blocklists = await _fetch_blocklists()
    results = []
    for identity in ip_identities:
        net = _network_or_none(identity.value, identity.kind)
        if net is None:
            continue
        for source_label, entries in blocklists.items():
            for entry in entries:
                try:
                    candidate = ipaddress.ip_address(entry["ip"])
                except ValueError:
                    continue
                matched = (candidate == net) if identity.kind == "ip" else (candidate in net)
                if matched:
                    results.append({
                        "identity_value": identity.value,
                        "identity_kind": identity.kind,
                        "source_label": source_label,
                        "ip": entry["ip"],
                        "detail": entry.get("malware") or (f"score {entry['score']}" if "score" in entry else None),
                    })
    return results
