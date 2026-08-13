"""
kb_build.py
Résout un numéro de KB Microsoft en numéro(s) de build OS, depuis le titre de
l'article support.microsoft.com.

Pourquoi cette source (session 21/07/2026) : pour les CVE Windows anciennes,
**aucune** des sources déjà utilisées ne fournit de seuil de build exploitable —
vérifié en conditions réelles :
  - NVD : `configurations` réduit à `{"vulnerable": true}` sans
    `versionEndExcluding` pour les CVE 2019-2021 (cf. docs/MATCHING.md § signal 2)
  - MSRC sug v2 (`affectedProduct`) : `affectedBinaries` vide
  - MSRC CVRF v3 : `AffectedFiles` vide
  - Registre CBS de la machine : les vieux KB sont purgés par le nettoyage
    Windows, et les entrées restantes n'ont pas d'horodatage exploitable
Le titre de l'article KB, lui, porte systématiquement le build :
    "March 12, 2019—KB4489899 (OS Build 17763.379) | Microsoft Support"

Ce que ça permet : trancher **avec certitude** (et non plus par heuristique de
date) si une CVE ancienne est corrigée — les CU Windows étant strictement
cumulatives, un build installé supérieur au build du correctif contient
forcément ce correctif.

Contrainte opérationnelle : support.microsoft.com rate-limite agressivement
(réponses "Service unavailable" après une rafale — constaté en test). D'où le
cache en base permanent (`KbBuild`, couple KB→build immuable) + un verrou
sérialisant les appels réseau avec délai. Une CVE peut porter 14 KB et un actif
des milliers de CVE : sans cache, inutilisable.

Aucune donnée du parc n'est transmise — juste un numéro de KB (identifiant
public), même profil réseau que les appels MSRC/NVD déjà en place.
"""

import re
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy import select

from database import SessionLocal
from models import KbBuild

logger = logging.getLogger(__name__)

KB_ARTICLE_URL = "https://support.microsoft.com/help/{kb}"

# Délai entre deux requêtes réseau vers support.microsoft.com. Volontairement
# généreux : le cache absorbe le coût sur la durée (chaque KB n'est récupéré
# qu'une fois dans la vie de l'installation), alors qu'une rafale se fait
# rate-limiter et renvoie "Service unavailable" pour tout le monde.
_FETCH_DELAY_SECONDS = 3.0

# Sérialise les appels réseau : le cycle de patch check traite les CVE en
# séquence, mais un check manuel peut arriver en parallèle.
_fetch_lock = asyncio.Lock()
_last_fetch_at: float = 0.0

# "March 12, 2019—KB4489899 (OS Build 17763.379)"
# "September 21, 2021—KB5005611 (OS Builds 19041.1266, 19042.1266, and 19043.1266)"
_BUILD_RE = re.compile(r"OS Builds?\s+([\d.,\s]+?(?:and\s+[\d.]+)?)\s*\)", re.IGNORECASE)
_BUILD_NUM_RE = re.compile(r"\d+\.\d+")
_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.S | re.IGNORECASE)


def _parse_builds(title: str) -> list[str]:
    """Extrait les builds depuis le titre d'article. Retourne [] si absent
    (certains KB n'exposent pas de build : mises à jour .NET, Defender…)."""
    m = _BUILD_RE.search(title)
    if not m:
        return []
    return _BUILD_NUM_RE.findall(m.group(1))


async def _fetch_kb_title(kb: str) -> Optional[str]:
    """Récupère le titre de l'article KB (throttlé). None si indisponible."""
    global _last_fetch_at
    async with _fetch_lock:
        loop = asyncio.get_event_loop()
        elapsed = loop.time() - _last_fetch_at
        if elapsed < _FETCH_DELAY_SECONDS:
            await asyncio.sleep(_FETCH_DELAY_SECONDS - elapsed)
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=25) as client:
                r = await client.get(
                    KB_ARTICLE_URL.format(kb=kb),
                    headers={"User-Agent": "Mozilla/5.0 (compatible; Allsafe-patch-check)"},
                )
            _last_fetch_at = loop.time()
            if r.status_code != 200:
                return None
            m = _TITLE_RE.search(r.text)
            title = m.group(1).strip() if m else None
            # Page de rate-limit : titre générique, pas une vraie réponse —
            # ne surtout pas la mettre en cache comme un "pas de build".
            if not title or "service unavailable" in title.lower():
                return None
            return title
        except Exception as e:
            logger.warning(f"KB{kb} : récupération du build impossible ({type(e).__name__})")
            _last_fetch_at = loop.time()
            return None


async def get_kb_builds(kb: str) -> list[str]:
    """
    Builds OS produits par ce KB, avec cache permanent en base.
    Retourne [] si inconnu/indisponible (l'appelant retombe sur ses autres signaux).
    """
    kb = str(kb).upper().replace("KB", "").strip()
    if not kb.isdigit():
        return []

    session = SessionLocal()
    try:
        cached = await session.get(KbBuild, kb)
        if cached is not None:
            return list(cached.builds or [])

        title = await _fetch_kb_title(kb)
        if title is None:
            # Échec réseau/rate-limit : **pas** mis en cache, on retentera plus
            # tard (contrairement à un article réellement sans build).
            return []

        builds = _parse_builds(title)
        session.add(KbBuild(
            kb=kb,
            builds=builds,
            title=title[:500],
            found=bool(builds),
            fetched_at=datetime.now(timezone.utc),
        ))
        await session.commit()
        if builds:
            logger.info(f"KB{kb} → build(s) {builds}")
        return builds
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


def _build_branch(build: str) -> str:
    """Branche d'un build ("17763.379" → "17763") — identifie la version d'OS."""
    return build.split(".")[0]


def _build_key(build: str) -> tuple[int, ...]:
    return tuple(int(n) for n in build.split("."))


async def resolve_fixed_build(kb_numbers: list[str], installed_build: str) -> Optional[dict]:
    """
    Cherche, parmi les KB d'une CVE, celui qui cible la **même branche d'OS** que
    le build installé, et retourne le seuil corrigé correspondant.

    Le filtrage par branche est essentiel : une CVE Windows liste un KB par
    version d'OS (ex: CVE-2019-0697 → KB4489868 pour Windows 10 1803 / branche
    17134, KB4489899 pour Windows Server 2019 / branche 17763). Comparer le build
    installé au mauvais KB donnerait un verdict faux.

    `installed_build` : "10.0.17763.9020" ou "17763.9020".
    Retourne None si aucun KB de la même branche n'est résolvable (l'appelant
    garde alors ses signaux existants).
    """
    if not installed_build or not kb_numbers:
        return None

    parts = installed_build.split(".")
    # "10.0.17763.9020" → branche 17763 ; "17763.9020" → 17763
    inst = ".".join(parts[2:]) if len(parts) == 4 and parts[0] == "10" else installed_build
    if "." not in inst:
        return None
    branch = _build_branch(inst)

    for kb in kb_numbers:
        builds = await get_kb_builds(kb)
        for b in builds:
            if _build_branch(b) != branch:
                continue
            return {
                "kb": f"KB{str(kb).replace('KB', '')}",
                "fixed_build": b,
                "installed_build": inst,
                "patched": _build_key(inst) >= _build_key(b),
            }
    return None
