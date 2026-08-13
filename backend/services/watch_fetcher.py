"""
watch_fetcher.py
Agrégateur de veille cyber — conforme NIS 2.

Sources : officielles françaises, médias spécialisés, trackers de fuites, éditeurs de sécurité.
Chaque item est auto-catégorisé par thème (Cyber, Admin, Réseau, Hardware, Software,
Données, Réglementation, Ransomware, APT, Vulnérabilité, IA).

Séparation stricte HTTP / DB (contrainte asyncpg).
"""

import hashlib
import httpx
import logging
import re
import xml.etree.ElementTree as ET  # nosec B405 - Element/ParseError refs only ; parsing réel via defusedxml ci-dessous
from defusedxml.ElementTree import fromstring as ET_fromstring
from datetime import datetime, timezone, timedelta
from typing import Optional
from email.utils import parsedate_to_datetime
from sqlalchemy import select

from models import WatchItem, SyncState
from database import SessionLocal

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# ─── Sources ──────────────────────────────────────────────────────────────────

WATCH_FEEDS = [
    # Officielles françaises
    # CERT-FR Avis/Alertes : l'URL avait les segments inversés (le vrai chemin
    # est /avis/feed/ et /alerte/feed/, pas /feed/avis/ ni /feed/alerte/ —
    # confirmé via les liens <link rel="alternate"> de la page d'accueil), et
    # le flux réel est du RSS 2.0, pas de l'Atom.
    {"name": "CERT-FR Avis",       "url": "https://www.cert.ssi.gouv.fr/avis/feed/",         "source": "cert-fr-avis",        "type": "rss"},
    {"name": "CERT-FR Alertes",    "url": "https://www.cert.ssi.gouv.fr/alerte/feed/",       "source": "cert-fr-alerte",      "type": "rss"},
    {"name": "CERT-FR Bulletins",  "url": "https://www.cert.ssi.gouv.fr/actualite/feed/",    "source": "cert-fr-bulletin",    "type": "rss"},
    # ANSSI : ssi.gouv.fr redirige désormais vers cyber.gouv.fr (nouveau nom de
    # domaine), et /feed/ n'existe plus — le flux vit sous /actualites/rss/.
    {"name": "ANSSI",              "url": "https://www.ssi.gouv.fr/actualites/rss/",         "source": "anssi",               "type": "rss"},
    # CNIL : /fr/flux-rss-actualites n'a jamais existé sous cette forme sur le
    # site actuel — le vrai flux est /fr/rss.xml.
    {"name": "CNIL",               "url": "https://www.cnil.fr/fr/rss.xml",                  "source": "cnil",                "type": "rss"},
    # Cybermalveillance : /feed/ (générique) n'existe plus, le site expose
    # plusieurs flux Atom nommés (actualités, alertes, fiches réflexes...) — on
    # garde celui des actualités générales, le plus proche de l'intention
    # d'origine. Format réellement Atom, pas RSS malgré l'ancienne config.
    {"name": "Cybermalveillance",  "url": "https://www.cybermalveillance.gouv.fr/feed/atom-flux-actualites", "source": "cybermalveillance", "type": "atom"},
    # Médias IT & sécurité
    {"name": "IT Connect",         "url": "https://www.it-connect.fr/feed/",                 "source": "it-connect",          "type": "rss"},
    {"name": "ZATAZ",              "url": "https://www.zataz.com/feed/",                     "source": "zataz",               "type": "rss"},
    # Global Security Mag : /rss.xml n'existe pas sur ce SPIP — le flux "tout
    # le site" est exposé via /spip.php?page=backend.
    {"name": "Global Security Mag","url": "https://www.globalsecuritymag.fr/spip.php?page=backend", "source": "global-security-mag", "type": "rss"},
    # Trackers fuites de données
    # "fuitesinfos.fr" : /feed/ renvoie 404 depuis une refonte du site — le vrai
    # flux est en /feed.xml (retrouvé via <link rel="alternate" type="application/
    # rss+xml"> sur la page d'accueil). "Bonjour la fuite" a été retiré (site
    # dédié, retrait demandé) — cf. git history si besoin de le réintégrer.
    {"name": "fuitesinfos.fr",     "url": "https://fuitesinfos.fr/feed.xml",                 "source": "fuitesinfos",         "type": "rss"},
    # DataBreaches.net : référence historique du journalisme de fuites de
    # données (US, mais couverture internationale) — flux RSS 2.0 standard.
    {"name": "DataBreaches.net",   "url": "https://databreaches.net/feed/",                  "source": "databreaches-net",    "type": "rss"},
    # Éditeurs de sécurité français
    # Sekoia : blog.sekoia.io redirige maintenant vers www.sekoia.com/blog (site
    # refondu sous Webflow, ancien domaine .io abandonné) — /feed/ n'existe plus
    # du tout sur ce nouveau site (redirige vers la page HTML du blog, que le
    # parseur XML rejetait avec une erreur "not well-formed"). Vrai flux :
    # /blog/rss.xml.
    {"name": "Sekoia Blog",        "url": "https://www.sekoia.com/blog/rss.xml",             "source": "sekoia",              "type": "rss"},
    # HarfangLab : protégé par un vrai challenge JS Cloudflare ("Just a
    # moment..."), pas un simple filtre sur le User-Agent — infranchissable
    # avec un client HTTP classique (httpx), quel que soit l'en-tête envoyé.
    # Contourner ça demanderait un navigateur headless (Playwright) rien que
    # pour un flux RSS, disproportionné pour cette source unique — laissé tel
    # quel, source qui échouera systématiquement (erreur loggée, pas bloquante
    # pour les 15 autres flux, cf. gestion d'erreur par flux ci-dessous).
    {"name": "HarfangLab Blog",    "url": "https://harfanglab.io/feed/",                     "source": "harfanglab",          "type": "rss"},
    # Synacktiv : /feed.rss n'existe pas — le vrai flux est /feed/lastblog.xml.
    {"name": "Synacktiv Blog",     "url": "https://www.synacktiv.com/feed/lastblog.xml",     "source": "synacktiv",           "type": "rss"},
    {"name": "Intrinsec Blog",     "url": "https://www.intrinsec.com/feed/",                 "source": "intrinsec",           "type": "rss"},
    {"name": "No Limit Secu",      "url": "https://www.nolimitsecu.fr/feed/",                "source": "nolimitsecu",         "type": "rss"},
]

# ─── Sévérité par source ──────────────────────────────────────────────────────

SOURCE_DEFAULT_SEVERITY = {
    "cert-fr-alerte":      "critical",
    "cert-fr-avis":        "important",
    "cert-fr-bulletin":    "important",
    "anssi":               "important",
    "cnil":                "important",
    "cybermalveillance":   "important",
    "it-connect":          "informational",
    "zataz":               "important",
    "global-security-mag": "informational",
    "fuitesinfos":         "important",
    "sekoia":              "informational",
    "harfanglab":          "informational",
    "synacktiv":           "informational",
    "intrinsec":           "informational",
    "nolimitsecu":         "informational",
    "ransomware-live":     "important",
    "databreaches-net":    "important",
    "hibp":                "important",
}

# Pays par défaut des trackers dédiés "fuite de données" français (ces flux
# RSS n'ont pas de champ pays dans leur contenu) — permet d'afficher un
# drapeau cohérent dans l'onglet Fuite de données. ransomware.live fournit son
# propre champ `country` par victime (cf. _fetch_ransomware_live), donc absent
# de cette table. Les sources personnalisées (WatchSource) portent leur pays
# par défaut directement en base, pas ici.
SOURCE_DEFAULT_COUNTRY: dict[str, str] = {
    "zataz":       "FR",
    "fuitesinfos": "FR",
}

# Sources "fuite de données" natives (hors sources personnalisées ajoutées par
# l'utilisateur, cf. WatchSource) — exposées via GET /api/watch/leak-sources
# pour que le frontend sache lesquelles exclure de Veille technologique et
# inclure par défaut dans l'onglet Fuite de données.
BUILTIN_LEAK_SOURCES: list[str] = ["zataz", "fuitesinfos", "ransomware-live", "databreaches-net", "hibp"]

CRITICAL_KEYWORDS = {
    "critique", "critical", "urgence", "emergency",
    "0-day", "zero-day", "zero day", "0day",
    "ransomware", "remote code execution",
}
# Mots-clés courts et ambigus : nécessitent une correspondance de mot entier (\b),
# sinon ils matchent en sous-chaîne dans des mots courants sans rapport ("rce" dans
# "source"/"resource", "apt" dans "capteur"/"adaptation") et classaient à tort des
# articles informatifs en critique (ex: "Docky... gratuit et open source" → faux
# positif sur "rce").
CRITICAL_KEYWORDS_STRICT = {"apt", "rce"}

IMPORTANT_KEYWORDS = {
    "important", "alerte", "alert", "vulnérabilité",
    "vulnerability", "patch", "correctif", "mise à jour de sécurité",
}


def _contains_keyword(text: str, keywords: set[str], strict_keywords: set[str] = frozenset()) -> bool:
    """Sous-chaîne pour les mots-clés longs/spécifiques (tolère pluriels/conjugaisons :
    "vulnérabilité" matche "vulnérabilités"), correspondance de mot entier (\\b) pour
    les mots-clés courts et ambigus fournis dans strict_keywords."""
    if any(kw in text for kw in keywords):
        return True
    return any(re.search(rf"\b{re.escape(kw)}\b", text) for kw in strict_keywords)

# ─── Thèmes ───────────────────────────────────────────────────────────────────

SOURCE_DEFAULT_THEMES: dict[str, list[str]] = {
    "cert-fr-avis":        ["Cyber", "Vulnérabilité"],
    "cert-fr-alerte":      ["Cyber"],
    "cert-fr-bulletin":    ["Cyber"],
    "anssi":               ["Cyber", "Réglementation"],
    "cnil":                ["Données", "Réglementation"],
    "cybermalveillance":   ["Cyber"],
    "it-connect":          ["Admin", "Software"],
    "zataz":               ["Données", "Cyber", "Fuite de données"],
    "global-security-mag": ["Cyber"],
    "fuitesinfos":         ["Données", "Fuite de données"],
    "sekoia":              ["Cyber", "APT"],
    "harfanglab":          ["Cyber"],
    "synacktiv":           ["Cyber", "Vulnérabilité"],
    "intrinsec":           ["Cyber"],
    "nolimitsecu":         ["Cyber"],
    "ransomware-live":     ["Données", "Fuite de données", "Ransomware"],
    "databreaches-net":    ["Données", "Fuite de données"],
    "hibp":                ["Données", "Fuite de données"],
}

THEME_KEYWORDS: dict[str, list[str]] = {
    "Admin":             ["active directory", "windows server", "group policy", "powershell", "sysadmin", "annuaire ldap", "kerberos"],
    "APT":               ["threat actor", "apt-", "espionnage numérique", "acteur étatique", "nation state", "campagne ciblée", "groupe malveillant"],
    "Cyber":             ["cyberattaque", "cybermenace", "incident de sécurité", "compromission", "malware", "phishing", "hameçonnage", "botnet"],
    "Données":           ["rgpd", "gdpr", "données personnelles", "violation de données", "protection des données", "traitement de données"],
    "Fuite de données":  ["fuite de données", "data leak", "data breach", "données volées", "données dérobées", "exfiltration", "base de données volée", "dump sql", "données compromises"],
    "Hardware":          ["firmware", "bios", "uefi", " iot", "bmc", "ipmi", "microprocesseur", "circuit intégré", "puce"],
    # Pas de token court type "ia"/" ia " seul : trop ambigu en substring (matche
    # "diagnostic", "sociale", "financiaire"...) — uniquement des expressions
    # multi-mots ou marques suffisamment spécifiques pour ne pas faire de bruit.
    "IA":                ["intelligence artificielle", "ia générative", "chatgpt", "genai",
                          "large language model", "modèle de langage", "deepfake", "hypertrucage",
                          "machine learning", "deep learning", "prompt injection", "ai act", "règlement ia"],
    "Ransomware":        ["ransomware", "rançongiciel", "rançon", "cryptolocker"],
    "Réglementation":    ["nis2", "nis 2", "directive ue", "réglementation", "conformité", "homologation", "certification sécurité"],
    "Réseau":            ["firewall", "pare-feu", " vpn", "routeur", " dns ", "protocole réseau", "bgp", "tcp/ip", "proxy"],
    "Software":          ["mise à jour logiciel", "patch tuesday", "navigateur web", "office 365", "microsoft 365", "librairie", "framework", "dépendance"],
    "Vulnérabilité":     ["cve-20", "vulnérabilité critique", "0-day", "zero-day", "exploit", "preuve de concept", "poc "],
}


def _themes_for_item(source: str, title: str, summary: str) -> list[str]:
    """Catégorise un item par thèmes : source par défaut + détection mots-clés."""
    themes = set(SOURCE_DEFAULT_THEMES.get(source, ["Cyber"]))
    text = f"{title} {summary}".lower()
    for theme, keywords in THEME_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            themes.add(theme)
    return sorted(themes)


async def recompute_all_themes() -> dict:
    """Recalcule `themes` pour tous les items déjà en base à partir des règles
    actuelles (`_themes_for_item`) — fonction pure de source/titre/résumé, donc
    sans risque d'écraser une donnée saisie par un analyste (les thèmes ne sont
    jamais édités manuellement). Nécessaire quand un thème/mot-clé est ajouté
    après coup (ex: thème "IA", session 20/07/2026) : la classification ne
    tourne qu'à la collecte, un item déjà importé ne se reclasse jamais tout
    seul, aussi bien à l'ajout d'un thème qu'à l'affinement d'une liste de
    mots-clés existante."""
    db = SessionLocal()
    try:
        items = (await db.execute(select(WatchItem))).scalars().all()
        updated = 0
        for item in items:
            new_themes = _themes_for_item(item.source, item.title, item.summary or "")
            if sorted(item.themes or []) != new_themes:
                item.themes = new_themes
                updated += 1
        await db.commit()
        return {"total": len(items), "updated": updated}
    finally:
        await db.close()


# ─── Parsing ──────────────────────────────────────────────────────────────────

NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "dc":   "http://purl.org/dc/elements/1.1/",
}


def _text(el: Optional[ET.Element], default: str = "") -> str:
    if el is None:
        return default
    return (el.text or "").strip()


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).astimezone(timezone.utc)
    except Exception:
        pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def _extract_cve_ids(text: str) -> list[str]:
    return list({m.upper() for m in CVE_PATTERN.findall(text)})


def _severity(source: str, title: str) -> str:
    base = SOURCE_DEFAULT_SEVERITY.get(source, "informational")
    title_lower = title.lower()
    if _contains_keyword(title_lower, CRITICAL_KEYWORDS, CRITICAL_KEYWORDS_STRICT):
        return "critical"
    if base == "informational" and _contains_keyword(title_lower, IMPORTANT_KEYWORDS):
        return "important"
    return base


def _stable_url(url: str, source: str, title: str, published: Optional[datetime]) -> str:
    if url:
        return url
    raw = f"{source}|{title}|{published}"
    return f"urn:cybervuln:{hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()}"


def _find(entry: ET.Element, tag: str) -> Optional[ET.Element]:
    # `entry.find(a, NS) or entry.find(b)` est un piège classique d'ElementTree :
    # un Element sans enfants (ex. <title>texte</title>, une feuille) a
    # __len__() == 0, donc Python l'évalue comme "falsy" côté `or` même s'il a
    # bien du texte — le fallback "entry.find(b)" écrasait alors silencieusement
    # un élément pourtant valide (title/summary/link vides sur tous les items
    # Cybermalveillance malgré un flux Atom bien formé). Il faut vérifier
    # `is not None` explicitement, jamais la véracité de l'Element lui-même.
    el = entry.find(f"atom:{tag}", NS)
    return el if el is not None else entry.find(tag)


def _parse_atom(root: ET.Element, source: str, source_label: str, country: Optional[str] = None) -> list[dict]:
    items = []
    entries = root.findall("atom:entry", NS) or root.findall("entry")
    for entry in entries:
        title_el     = _find(entry, "title")
        summary_el   = _find(entry, "summary")
        content_el   = _find(entry, "content")
        link_el      = _find(entry, "link")
        updated_el   = _find(entry, "updated")
        published_el = _find(entry, "published")

        title   = _text(title_el)
        summary = _text(content_el) or _text(summary_el)
        url     = (link_el.get("href") if link_el is not None else None) or ""
        pub     = _parse_date(_text(published_el) or _text(updated_el))
        cves    = _extract_cve_ids(f"{title} {summary} {url}")

        items.append({
            "source": source, "source_label": source_label,
            "title": title,
            "url": _stable_url(url, source, title, pub),
            "summary": summary[:3000],
            "published_at": pub,
            "severity": _severity(source, title),
            "cve_ids_found": cves,
            "themes": _themes_for_item(source, title, summary),
            "country": country or SOURCE_DEFAULT_COUNTRY.get(source),
        })
    return items


def _parse_rss(root: ET.Element, source: str, source_label: str, country: Optional[str] = None) -> list[dict]:
    items = []
    channel = root.find("channel")
    if channel is None:
        return items
    for item in channel.findall("item"):
        title   = _text(item.find("title"))
        summary = _text(item.find("description"))
        url     = _text(item.find("link"))
        pub     = _parse_date(_text(item.find("pubDate")))
        cves    = _extract_cve_ids(f"{title} {summary}")

        items.append({
            "source": source, "source_label": source_label,
            "title": title,
            "url": _stable_url(url, source, title, pub),
            "summary": summary[:3000],
            "published_at": pub,
            "severity": _severity(source, title),
            "cve_ids_found": cves,
            "themes": _themes_for_item(source, title, summary),
            "country": country or SOURCE_DEFAULT_COUNTRY.get(source),
        })
    return items


# ─── ransomware.live (API JSON, pas de RSS) ───────────────────────────────────

RANSOMWARE_LIVE_URL = "https://api.ransomware.live/v2/recentvictims"


async def _fetch_ransomware_live() -> list[dict]:
    """Victimes de ransomware récentes, via l'API publique ransomware.live (sans
    authentification). On utilise uniquement /v2/recentvictims — l'endpoint
    /v2/countryvictims/{code} existe aussi mais renvoie un schéma de champs
    différent (post_title/post_url/group_name au lieu de victim/url/group, et
    surtout pas de champ `url` public : seulement `post_url`, un lien .onion),
    donc filtrer par pays côté client sur /recentvictims évite de composer deux
    schémas différents. Le champ `claim_url` (lien .onion vers le site de fuite
    du groupe) n'est jamais exposé — seul `url` (page publique ransomware.live)
    est utilisé comme lien sortant."""
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.get(RANSOMWARE_LIVE_URL)
            resp.raise_for_status()
        victims = resp.json()
    except Exception as e:
        logger.error("Erreur veille ransomware.live : %s", e)
        return []

    items = []
    for v in victims:
        victim  = (v.get("victim") or "").strip()
        group   = (v.get("group") or "").strip()
        activity = (v.get("activity") or "").strip()
        if not victim:
            continue
        title = f"{victim} — {group}" if group else victim
        if activity:
            title += f" ({activity})"
        summary = (v.get("description") or "").strip()
        url     = (v.get("url") or "").strip()
        pub     = _parse_date(v.get("attackdate") or v.get("discovered"))
        country = (v.get("country") or "").strip().upper() or None

        items.append({
            "source": "ransomware-live", "source_label": "Ransomware.live",
            "title": title,
            "url": _stable_url(url, "ransomware-live", title, pub),
            "summary": summary[:3000],
            "published_at": pub,
            "severity": _severity("ransomware-live", title),
            "cve_ids_found": [],
            "themes": _themes_for_item("ransomware-live", title, summary),
            "country": country,
        })
    logger.info("Veille Ransomware.live : %d entrées", len(items))
    return items


# ─── Have I Been Pwned (API JSON, pas de RSS) ─────────────────────────────────

HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
# L'API renvoie tout l'historique connu (1000+ brèches depuis 2007) sans
# paramètre de filtrage par date côté serveur — sans fenêtre de récence, la
# toute première synchro insérerait d'un coup des centaines d'entrées
# historiques sans rapport avec une "veille". On ne garde que les brèches
# ajoutées récemment au registre HIBP (AddedDate), au même esprit que
# ransomware.live/recentvictims qui ne renvoie déjà que du récent nativement.
HIBP_LOOKBACK_DAYS = 120


async def _fetch_hibp() -> list[dict]:
    """Brèches récemment ajoutées au registre public Have I Been Pwned (API sans
    authentification, réservée aux clients "grand public" — endpoint /breaches,
    pas /breachedaccount qui nécessite une clé API payante et interroge des
    emails précis, hors de propos ici)."""
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.get(HIBP_BREACHES_URL, headers={"User-Agent": "CyberVuln-Veille"})
            resp.raise_for_status()
        breaches = resp.json()
    except Exception as e:
        logger.error("Erreur veille HIBP : %s", e)
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=HIBP_LOOKBACK_DAYS)
    items = []
    for b in breaches:
        added = _parse_date(b.get("AddedDate"))
        if not added or added < cutoff:
            continue
        name   = (b.get("Title") or b.get("Name") or "").strip()
        domain = (b.get("Domain") or "").strip()
        if not name:
            continue
        title = f"{name} ({domain})" if domain else name
        pwn_count = b.get("PwnCount") or 0
        classes = ", ".join(b.get("DataClasses") or [])
        summary = f"{pwn_count:,} comptes concernés. Données : {classes}.".replace(",", " ")
        url = f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name', '')}"

        items.append({
            "source": "hibp", "source_label": "Have I Been Pwned",
            "title": title,
            "url": _stable_url(url, "hibp", title, added),
            "summary": summary[:3000],
            "published_at": added,
            "severity": _severity("hibp", title),
            "cve_ids_found": [],
            "themes": _themes_for_item("hibp", title, summary),
            "country": None,
        })
    logger.info("Veille HIBP : %d entrées récentes", len(items))
    return items


# ─── Collecte HTTP ────────────────────────────────────────────────────────────

async def _fetch_feed(feed: dict) -> list[dict]:
    try:
        from services.net_guard import validate_public_url
        validate_public_url(feed["url"])

        async with httpx.AsyncClient(
            timeout=30,
            # SSRF (AUDIT_SECURITE.md #1) : follow_redirects=True suivait
            # aveuglément une redirection vers l'interne (127.0.0.1, VLAN
            # privé...) même si l'URL d'origine était publique. Chaque hop est
            # maintenant re-validé à la main ci-dessous.
            follow_redirects=False,
            # Un User-Agent identifiant l'outil ("CyberVuln-Veille/1.0") se fait
            # bloquer par certains sites en anti-bot basique (ex: Sekoia,
            # confirmé en direct : 403 avec l'ancien UA, 200 avec un UA
            # navigateur standard). Reste un GET public sur un flux RSS/Atom
            # public, aucune donnée du parc n'est envoyée — même profil réseau
            # que la sync NVD/Debian Security Tracker.
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Accept": "application/atom+xml, application/rss+xml, application/xml, text/xml, */*",
            },
        ) as client:
            resp = await client.get(feed["url"])
            hops = 0
            while resp.is_redirect and hops < 5:
                next_url = str(resp.next_request.url)
                validate_public_url(next_url)
                resp = await client.get(next_url)
                hops += 1
            resp.raise_for_status()

        root = ET_fromstring(resp.content)
        if feed["type"] == "atom":
            items = _parse_atom(root, feed["source"], feed["name"], feed.get("country"))
        else:
            items = _parse_rss(root, feed["source"], feed["name"], feed.get("country"))

        logger.info("Veille %s : %d entrées", feed["name"], len(items))
        return items

    except Exception as e:
        logger.error("Erreur veille %s : %s", feed["name"], e)
        return []


async def _load_custom_feeds() -> list[dict]:
    """Flux RSS/Atom ajoutés dynamiquement par l'utilisateur (table
    WatchSource, gérée via GET/POST/PATCH/DELETE /api/watch/sources) — lus
    avant la collecte HTTP, au même esprit que la séparation HTTP/DB déjà en
    place (une lecture DB courte, indépendante de la session Phase 2)."""
    from models import WatchSource

    db = SessionLocal()
    try:
        result = await db.execute(select(WatchSource).where(WatchSource.enabled.is_(True)))
        rows = result.scalars().all()
        return [
            {"name": s.name, "url": s.url, "source": s.slug, "type": s.feed_type, "country": s.country}
            for s in rows
        ]
    finally:
        await db.close()


# ─── Sync principale ──────────────────────────────────────────────────────────

async def _touch_sync_state(now: datetime) -> None:
    """Enregistre l'horodatage de la dernière collecte (clé "watch" de la
    table générique SyncState), lu par GET /watch/sync-status pour afficher
    la date de dernière synchronisation dès le chargement de page — sans
    dépendre d'un clic manuel dans la session en cours (le cycle Celery
    horaire appelle aussi run_watch_sync)."""
    db = SessionLocal()
    try:
        state = await db.get(SyncState, "watch")
        if state is None:
            state = SyncState(key="watch")
            db.add(state)
        state.last_synced_at = now
        await db.commit()
    finally:
        await db.close()


async def run_watch_sync(feeds: Optional[list[dict]] = None) -> dict:
    """
    Synchronise tous les flux de veille et insère les nouveaux items en base.

    Phase 1 : collecte HTTP (aucune DB ouverte).
    Phase 2 : insertion avec déduplication par URL (SessionLocal, pas get_session).
    """
    if feeds is None:
        feeds = WATCH_FEEDS

    feeds = feeds + await _load_custom_feeds()

    stats = {"feeds": 0, "fetched": 0, "inserted": 0, "skipped": 0, "errors": 0}

    # Phase 1 — HTTP uniquement
    batches: list[list[dict]] = []
    for feed in feeds:
        items = await _fetch_feed(feed)
        batches.append(items)
        stats["feeds"] += 1
        stats["fetched"] += len(items)

    ransomware_items = await _fetch_ransomware_live()
    batches.append(ransomware_items)
    stats["feeds"] += 1
    stats["fetched"] += len(ransomware_items)

    hibp_items = await _fetch_hibp()
    batches.append(hibp_items)
    stats["feeds"] += 1
    stats["fetched"] += len(hibp_items)

    all_items = [item for batch in batches for item in batch]
    now = datetime.now(timezone.utc)
    # Horodatage mis à jour même sans nouvel item : une sync qui ne trouve rien
    # de neuf reste une sync effectuée, pas une sync manquante (cf. affichage
    # de la date de dernière synchronisation dans FuiteDeDonnees.jsx).
    await _touch_sync_state(now)
    stats["synced_at"] = now.isoformat()
    if not all_items:
        return stats

    # Phase 2 — DB
    db = SessionLocal()
    try:
        result = await db.execute(select(WatchItem.url))
        existing_urls: set[str] = {row[0] for row in result.fetchall()}

        for item in all_items:
            if not item.get("title"):
                continue
            if item["url"] in existing_urls:
                stats["skipped"] += 1
                continue

            db.add(WatchItem(
                source=item["source"],
                source_label=item["source_label"],
                title=item["title"],
                url=item["url"],
                summary=item["summary"],
                published_at=item["published_at"],
                received_at=now,
                severity=item["severity"],
                cve_ids_found=item["cve_ids_found"],
                themes=item["themes"],
                country=item.get("country"),
                status="new",
            ))
            existing_urls.add(item["url"])
            stats["inserted"] += 1

        await db.commit()

    except Exception as e:
        await db.rollback()
        logger.error("Erreur insertion veille : %s", e)
        stats["errors"] += 1
        raise
    finally:
        await db.close()

    logger.info(
        "Sync veille : %d insérés, %d doublons ignorés, %d erreurs",
        stats["inserted"], stats["skipped"], stats["errors"],
    )
    return stats
