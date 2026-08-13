"""
services/leak_lookup.py
Surveillance Identités — deux vérifications en direct, complémentaires au
matching texte (routers/identities.py) et aux listes de blocage IP
(services/ip_watch.py). Extension demandée le 28/07/2026, restée délibérément
gratuite (cf. STATUS.md) après avoir écarté un premier brouillon à base d'API
payantes (HIBP, IntelX, Hunter.io, Shodan, Censys, SecurityTrails).

- **XposedOrNot** (api.xposedornot.com) — vérifie si un email surveillé
  (kind="email") apparaît dans une fuite connue. API publique, gratuite, sans
  clé — testé en réel le 28/07/2026 : `GET /v1/check-email/{email}` renvoie
  `{"breaches": [[...]], "status": "success"}` si trouvé, `{"Error": "Not
  found"}` (toujours HTTP 200, pas 404) sinon. C'est l'équivalent gratuit de
  HIBP, payant depuis 2023 et hors périmètre pour cette raison (cf.
  docs/VEILLE.md § 9bis).
- **GitHub code search** — cherche si un domaine surveillé (kind="domain")
  apparaît dans du code public à côté d'un mot-clé d'identifiant (password,
  secret, clé API...) : signe qu'une configuration a pu être committée par
  erreur. Gratuit mais nécessite un token personnel (`GITHUB_TOKEN`, sans
  scope requis) — vérifié en réel le 28/07/2026 : `GET /search/code` renvoie
  401 "Requires authentication" même pour du contenu public, contrairement aux
  autres endpoints de recherche GitHub. Désactivé silencieusement sans token
  configuré (même logique que `NVD_API_KEY`), pas une erreur.
  ⚠️ **Bug trouvé et corrigé le 28/07/2026 (token configuré, premier test réel)** :
  `GITHUB_LEAK_KEYWORDS` groupait les mots-clés entre parenthèses
  (`(password OR secret OR ...)`) — syntaxe que l'API code search "legacy"
  rejette systématiquement (`422 ERROR_TYPE_QUERY_PARSING_FATAL`), avalée par
  le `except` générique et indistinguable d'un "aucune fuite" légitime :
  **la fonctionnalité n'avait donc jamais produit un seul résultat depuis sa
  création**, sans jamais le signaler. Parenthèses retirées (`OR` seul entre
  les mots-clés, sans groupement), confirmé en réel avec un vrai `200` et des
  résultats non vides. **Rate limit strict de l'endpoint search** : 10
  requêtes/minute par token (`x-ratelimit-resource: code_search`), distinct du
  quota API général — sans rapport avec le cache 6h en usage normal, mais à
  garder en tête si on teste plusieurs domaines à la suite en debug.

Cache en mémoire process **par valeur d'identité**, pas un téléchargement en
masse comme les blocklists IP (`ip_watch.py`) : ce sont des API interrogées
par valeur, pas des listes qu'on peut télécharger une fois pour toutes. TTL
volontairement plus long que les listes IP (6h contre 30 min, cf.
CACHE_TTL_SECONDS) : une fuite de données ou un secret committé ne change pas
d'une minute à l'autre, et ça ménage le quota gratuit de ces deux services.
"""

import logging
import time
from typing import Optional

import httpx

from config import settings

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 6 * 3600

XPOSEDORNOT_URL = "https://api.xposedornot.com/v1/check-email/{email}"
GITHUB_CODE_SEARCH_URL = "https://api.github.com/search/code"
# Mots-clés co-recherchés avec le domaine : sans eux, une simple mention du
# domaine (site vitrine, documentation, README d'un client...) noierait le
# signal utile sous du bruit — même principe "pas de CVE sans rapport" que
# services/cpe_matcher.py.
GITHUB_LEAK_KEYWORDS = "password OR secret OR apikey OR api_key OR credentials"

# (source, valeur d'identité) -> {"fetched_at": float, "result": dict|None}
_cache: dict[tuple[str, str], dict] = {}


def _cache_lookup(source: str, value: str) -> tuple[bool, Optional[dict]]:
    """`(hit, result)` plutôt que `result` seul : un match "aucune fuite" se
    met en cache comme `None`, indistinguable d'un cache absent si on ne
    renvoyait que la valeur — le booléen lève l'ambiguïté."""
    entry = _cache.get((source, value))
    if entry and (time.time() - entry["fetched_at"]) < CACHE_TTL_SECONDS:
        return True, entry["result"]
    return False, None


def _store(source: str, value: str, result: Optional[dict]) -> None:
    _cache[(source, value)] = {"fetched_at": time.time(), "result": result}


async def _check_xposedornot(client: httpx.AsyncClient, email: str) -> Optional[dict]:
    hit, cached = _cache_lookup("xposedornot", email)
    if hit:
        return cached

    try:
        r = await client.get(XPOSEDORNOT_URL.format(email=email))
        r.raise_for_status()
        data = r.json()
        # Trouvé : {"breaches": [["Nom1", "Nom2", ...]], "status": "success"}
        # Absent : {"Error": "Not found", "email": None} — toujours HTTP 200,
        # jamais 404 (vérifié en réel, cf. docstring du module).
        breaches = (data.get("breaches") or [[]])[0]
        result = {"breaches": breaches} if breaches else None
    except Exception as e:
        logger.warning("XposedOrNot indisponible pour cette adresse : %s", e)
        result = None

    _store("xposedornot", email, result)
    return result


async def _check_github_leak(client: httpx.AsyncClient, domain: str, token: str) -> Optional[dict]:
    hit, cached = _cache_lookup("github", domain)
    if hit:
        return cached

    try:
        r = await client.get(
            GITHUB_CODE_SEARCH_URL,
            params={"q": f'"{domain}" {GITHUB_LEAK_KEYWORDS}', "per_page": 5},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        r.raise_for_status()
        data = r.json()
        total = data.get("total_count", 0)
        items = data.get("items") or []
        result = {"total": total, "url": items[0]["html_url"]} if total and items else None
    except Exception as e:
        logger.warning("GitHub code search indisponible pour ce domaine : %s", e)
        result = None

    _store("github", domain, result)
    return result


async def find_osint_matches(identities: list) -> list[dict]:
    """`identities` : `WatchedIdentity` actives, tous `kind` confondus — filtre
    lui-même sur "email" (XposedOrNot, toujours actif) et "domain" (GitHub,
    seulement si `GITHUB_TOKEN` est configuré). Retourne une entrée par match,
    même forme que `ip_watch.find_ip_matches` pour un affichage frontend
    uniforme (`identity_value`, `identity_kind`, `source_label`, `detail`) —
    `url` en plus, absent côté IP (une IP blocklistée n'a pas de page à ouvrir).

    Une panne d'un des deux services ne bloque jamais l'autre ni le reste de
    la page (même principe que ip_watch.py face à des services tiers sans SLA).
    """
    emails  = [i for i in identities if i.kind == "email"]
    domains = [i for i in identities if i.kind == "domain"] if settings.GITHUB_TOKEN else []
    if not emails and not domains:
        return []

    results = []
    async with httpx.AsyncClient(timeout=15) as client:
        for identity in emails:
            match = await _check_xposedornot(client, identity.value)
            if match:
                names = match["breaches"]
                shown = ", ".join(names[:5]) + (f" (+{len(names) - 5})" if len(names) > 5 else "")
                results.append({
                    "identity_value": identity.value,
                    "identity_kind": "email",
                    "source_label": "XposedOrNot",
                    "detail": f"{len(names)} fuite(s) connue(s) : {shown}",
                    "url": None,
                })
        for identity in domains:
            match = await _check_github_leak(client, identity.value, settings.GITHUB_TOKEN)
            if match:
                results.append({
                    "identity_value": identity.value,
                    "identity_kind": "domain",
                    "source_label": "GitHub (code public)",
                    "detail": f"{match['total']} résultat(s) associant ce domaine à un identifiant potentiel",
                    "url": match["url"],
                })
    return results
