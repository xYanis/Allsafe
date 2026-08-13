"""
rss_fetcher.py
Collecte des alertes de sécurité via flux RSS.

Sources supportées :
  - CERT-FR Avis      : https://www.cert.ssi.gouv.fr/feed/avis/
  - CERT-FR Alertes   : https://www.cert.ssi.gouv.fr/feed/alerte/
  - Exploit-DB        : https://www.exploit-db.com/rss.xml
  - GitHub Security   : https://github.com/advisories.atom
"""

import httpx
import logging
import re
import xml.etree.ElementTree as ET  # nosec B405 - Element/ParseError refs only ; parsing réel via defusedxml ci-dessous
from defusedxml.ElementTree import fromstring as _defused_fromstring
from datetime import datetime, timezone
from typing import Optional
from email.utils import parsedate_to_datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import CVE, Feed
from database import SessionLocal

logger = logging.getLogger(__name__)

# CVE ID pattern : CVE-YYYY-NNNNN
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

FEEDS = [
    {
        "name": "CERT-FR Avis",
        "url": "https://www.cert.ssi.gouv.fr/feed/avis/",
        "source": "cert-fr",
        "type": "atom",
    },
    {
        "name": "CERT-FR Alertes",
        "url": "https://www.cert.ssi.gouv.fr/feed/alerte/",
        "source": "cert-fr-alerte",
        "type": "atom",
    },
    {
        "name": "Exploit-DB",
        "url": "https://www.exploit-db.com/rss.xml",
        "source": "exploit-db",
        "type": "rss",
    },
    {
        "name": "GitHub Security Advisories",
        "url": "https://github.com/advisories.atom",
        "source": "github",
        "type": "atom",
    },
]

# Namespaces XML courants dans les flux Atom/RSS
NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "dc": "http://purl.org/dc/elements/1.1/",
    "content": "http://purl.org/rss/1.0/modules/content/",
}


# ─── Parsing ──────────────────────────────────────────────────────────────────

def _text(el: Optional[ET.Element], default: str = "") -> str:
    if el is None:
        return default
    return (el.text or "").strip()


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    # Format RFC 2822 (RSS) : "Mon, 10 Jun 2025 12:00:00 +0000"
    try:
        return parsedate_to_datetime(value).astimezone(timezone.utc)
    except Exception:
        pass
    # Format ISO 8601 (Atom) : "2025-06-10T12:00:00Z"
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def _extract_cve_ids(text: str) -> list[str]:
    """Extrait tous les CVE ID mentionnés dans un texte."""
    return list({m.upper() for m in CVE_PATTERN.findall(text)})


def _severity_from_title(title: str) -> str:
    """Infère une sévérité à partir du titre de l'alerte CERT-FR."""
    title_lower = title.lower()
    if any(w in title_lower for w in ("critique", "critical", "urgence", "emergency")):
        return "CRITICAL"
    if any(w in title_lower for w in ("élevé", "high", "important")):
        return "HIGH"
    if any(w in title_lower for w in ("moyen", "medium", "modéré")):
        return "MEDIUM"
    return "LOW"


def _parse_atom_feed(root: ET.Element, source: str) -> list[dict]:
    """Parse un flux Atom (CERT-FR, GitHub)."""
    items = []

    entries = root.findall("atom:entry", NS)
    if not entries:
        # Essai sans namespace
        entries = root.findall("entry")

    for entry in entries:
        title_el = entry.find("atom:title", NS) or entry.find("title")
        summary_el = entry.find("atom:summary", NS) or entry.find("summary")
        content_el = entry.find("atom:content", NS) or entry.find("content")
        link_el = entry.find("atom:link", NS) or entry.find("link")
        updated_el = entry.find("atom:updated", NS) or entry.find("updated")
        published_el = entry.find("atom:published", NS) or entry.find("published")

        title = _text(title_el)
        description = _text(content_el) or _text(summary_el)
        url = (link_el.get("href") if link_el is not None else None) or ""
        published = _parse_date(_text(published_el) or _text(updated_el))

        # Extraction des CVE depuis le titre + description
        cve_ids = _extract_cve_ids(f"{title} {description} {url}")

        items.append({
            "title": title,
            "description": description[:2000],
            "url": url,
            "published": published,
            "cve_ids": cve_ids,
            "source": source,
            "severity": _severity_from_title(title),
        })

    return items


def _parse_rss_feed(root: ET.Element, source: str) -> list[dict]:
    """Parse un flux RSS 2.0 (Exploit-DB)."""
    items = []
    channel = root.find("channel")
    if channel is None:
        return items

    for item in channel.findall("item"):
        title = _text(item.find("title"))
        description = _text(item.find("description"))
        link = _text(item.find("link"))
        pub_date = _text(item.find("pubDate"))

        # Exploit-DB met les CVE dans le titre : "EDB-ID:51234 CVE-2025-12345"
        cve_ids = _extract_cve_ids(f"{title} {description}")

        items.append({
            "title": title,
            "description": description[:2000],
            "url": link,
            "published": _parse_date(pub_date),
            "cve_ids": cve_ids,
            "source": source,
            "severity": _severity_from_title(title),
        })

    return items


def _parse_feed_xml(content: bytes, source: str, feed_type: str) -> list[dict]:
    """Parse le contenu XML d'un flux RSS ou Atom."""
    try:
        root = _defused_fromstring(content)
    except ET.ParseError as e:
        logger.error(f"Erreur parse XML {source}: {e}")
        return []

    if feed_type == "atom":
        return _parse_atom_feed(root, source)
    return _parse_rss_feed(root, source)


# ─── Enrichissement NVD ───────────────────────────────────────────────────────

async def _enrich_from_db(
    session: AsyncSession,
    cve_id: str,
    rss_item: dict,
) -> Optional[CVE]:
    """
    Si la CVE est déjà en base (collectée via NVD), enrichit son champ
    references avec l'URL de l'alerte CERT-FR / Exploit-DB.
    Retourne la CVE mise à jour, ou None si pas trouvée.
    """
    result = await session.execute(select(CVE).where(CVE.cve_id == cve_id))
    cve = result.scalar_one_or_none()

    if cve:
        refs = list(cve.references or [])
        if rss_item["url"] and rss_item["url"] not in refs:
            refs.append(rss_item["url"])
            cve.references = refs
        # Remonte la sévérité si l'alerte CERT-FR la juge critique
        if (
            rss_item["severity"] == "CRITICAL"
            and cve.severity not in ("CRITICAL",)
        ):
            logger.info(f"{cve_id} reclassé CRITICAL suite à alerte CERT-FR")
            cve.severity = "CRITICAL"

    return cve


# ─── Collecte ─────────────────────────────────────────────────────────────────

async def fetch_rss_feed(feed_config: dict) -> list[dict]:
    """Télécharge et parse un flux RSS/Atom. Retourne la liste des items."""
    url = feed_config["url"]
    source = feed_config["source"]
    feed_type = feed_config["type"]

    try:
        async with httpx.AsyncClient(
            timeout=30,
            follow_redirects=True,
            headers={
                "User-Agent": "CyberVuln-Scanner/1.0",
                "Accept": "application/atom+xml, application/rss+xml, application/xml, text/xml, */*",
            },
        ) as client:
            response = await client.get(url)
            response.raise_for_status()

        items = _parse_feed_xml(response.content, source, feed_type)
        logger.info(f"Flux {feed_config['name']} : {len(items)} entrées")
        return items

    except Exception as e:
        logger.error(f"Erreur collecte {feed_config['name']}: {e}")
        return []


async def run_rss_sync(feeds: Optional[list[dict]] = None) -> dict:
    """
    Synchronisation de tous les flux RSS/Atom configurés.
    Appelé par la tâche Celery toutes les heures.

    Pour chaque item RSS :
      1. Extrait les CVE IDs mentionnés
      2. Enrichit les CVE existantes en base (ajout référence, reclassification)
      3. Met à jour la date de dernière collecte du flux (table feeds)

    Retourne un rapport de synchronisation.
    """
    if feeds is None:
        feeds = FEEDS

    stats = {
        "feeds_processed": 0,
        "items_parsed": 0,
        "cves_enriched": 0,
        "cves_not_found": 0,
        "errors": 0,
    }

    # Phase 1 : collecte HTTP complète AVANT d'ouvrir la session DB.
    # asyncpg interdit toute autre opération pendant qu'une transaction est ouverte,
    # donc on ne mélange jamais I/O réseau et requêtes SQL sur la même session.
    fetched: list[tuple[dict, list[dict]]] = []
    for feed_config in feeds:
        items = await fetch_rss_feed(feed_config)
        fetched.append((feed_config, items))
        stats["feeds_processed"] += 1
        stats["items_parsed"] += len(items)

    # Phase 2 : opérations DB sur une session dédiée (SessionLocal, pas get_session).
    # get_session() est un générateur FastAPI et ne fonctionne pas bien depuis Celery
    # (boucle asyncio différente, autoflush qui déclenche des commits implicites).
    db = SessionLocal()
    try:
        for feed_config, items in fetched:
            for item in items:
                for cve_id in item["cve_ids"]:
                    try:
                        cve = await _enrich_from_db(db, cve_id, item)
                        if cve:
                            stats["cves_enriched"] += 1
                        else:
                            stats["cves_not_found"] += 1
                            logger.debug(
                                f"{cve_id} mentionné dans {feed_config['name']} "
                                f"mais absent de la base NVD"
                            )
                    except Exception as e:
                        logger.error(f"Erreur enrichissement {cve_id}: {e}")
                        await db.rollback()
                        stats["errors"] += 1

            # Flush les CVE dirty AVANT le SELECT sur feeds pour éviter l'autoflush
            # implicite qui provoquerait "another operation is in progress" sous asyncpg.
            await db.flush()

            # Mise à jour last_fetch dans la table feeds
            result = await db.execute(
                select(Feed).where(Feed.url == feed_config["url"])
            )
            feed_row = result.scalar_one_or_none()
            if feed_row:
                feed_row.last_fetch = datetime.now(timezone.utc)

            # Commit par flux pour limiter la taille des transactions
            await db.commit()

    except Exception as e:
        await db.rollback()
        logger.error(f"Erreur sync RSS: {e}")
        stats["errors"] += 1
        raise
    finally:
        await db.close()

    logger.info(
        f"Sync RSS terminée : {stats['items_parsed']} items, "
        f"{stats['cves_enriched']} CVE enrichies, "
        f"{stats['errors']} erreurs"
    )

    return stats
