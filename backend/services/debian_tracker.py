"""
debian_tracker.py
Interroge le Debian Security Tracker (données publiques) pour connaître la
version *Debian* d'un paquet qui corrige une CVE donnée, par release.

Pourquoi : NVD publie les versions corrigées AMONT (ex: kernel.org 6.1.170),
alors que Debian backporte les correctifs dans ses propres paquets sans changer
le numéro amont — comparer la version installée aux plages NVD ne détecte donc
jamais un correctif Debian. Le tracker donne la version du paquet Debian qui
contient le fix (ex: CVE-2026-31431 → linux 6.1.170-1 pour bookworm), comparable
directement à la sortie de dpkg-query.

Anonymisation : le téléchargement du JSON complet n'envoie aucune donnée sur le
parc (même profil réseau que la sync NVD). Aucun hostname/IP ne sort.
"""

import gzip
import json
import time
import asyncio
import logging
import re
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
# Cache disque éphémère dans le conteneur — retéléchargé après restart, acceptable
# pour un fichier de 11 Mo compressé qui change plusieurs fois par jour.
# Sous /app/cache (pas /tmp, cf. audit/AUDIT_SECURITE.md bandit B108) : /tmp est un
# répertoire partagé où un chemin fixe est sujet aux attaques par symlink
# (write_bytes suit un lien existant) ; /app/cache n'appartient qu'à cette appli.
CACHE_PATH = Path("/app/cache/debian_security_tracker.json.gz")
CACHE_TTL_SECONDS = 24 * 3600

# Version Debian (composant CPE / VERSION_ID os-release) → nom de release tracker
RELEASE_BY_VERSION = {
    "11": "bullseye",
    "12": "bookworm",
    "13": "trixie",
    "14": "forky",
}

# Index en mémoire : {cve_id: {release: {"package", "status", "fixed_version"}}}
# construit uniquement pour les CVE demandées (pas les ~150k du tracker).
_index: dict[str, dict] = {}
_index_built_at: float = 0.0
_lock = asyncio.Lock()


def debian_release_for_asset(asset) -> Optional[str]:
    """
    Déduit la release Debian ("bookworm"...) d'un actif depuis son cpe_list
    (cpe:2.3:o:debian:debian_linux:12:... → bookworm) ou son os_version.
    None si l'actif n'est pas identifiable comme Debian.
    """
    for cpe in (asset.cpe_list or []):
        parts = cpe.split(":")
        if len(parts) >= 6 and parts[3] == "debian":
            major = parts[5].split(".")[0]
            return RELEASE_BY_VERSION.get(major)
    if "debian" in (asset.os or "").lower():
        major = (asset.os_version or "").split(".")[0].strip()
        return RELEASE_BY_VERSION.get(major)
    return None


def _download_tracker() -> bytes:
    """Télécharge le JSON du tracker (déjà décompressé par httpx) — bloquant."""
    with httpx.Client(timeout=120) as client:
        resp = client.get(TRACKER_URL)
        resp.raise_for_status()
        return resp.content


def _ensure_cache_file() -> Optional[bytes]:
    """
    Retourne le JSON brut du tracker, depuis le cache disque s'il a moins de
    CACHE_TTL_SECONDS, sinon après retéléchargement. None si indisponible
    (réseau coupé et pas de cache) — l'appelant retombe alors sur la voie NVD.
    """
    if CACHE_PATH.exists() and (time.time() - CACHE_PATH.stat().st_mtime) < CACHE_TTL_SECONDS:
        try:
            return gzip.decompress(CACHE_PATH.read_bytes())
        except OSError:
            pass  # cache corrompu → retélécharger

    try:
        raw = _download_tracker()
    except Exception as e:
        logger.warning(f"Debian Security Tracker inaccessible : {e}")
        if CACHE_PATH.exists():
            try:
                logger.info("Utilisation du cache tracker périmé (réseau indisponible)")
                return gzip.decompress(CACHE_PATH.read_bytes())
            except OSError:
                pass
        return None

    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_bytes(gzip.compress(raw, compresslevel=1))
    except OSError as e:
        logger.warning(f"Écriture cache tracker impossible : {e}")
    return raw


def _build_index(raw: bytes, wanted: set[str]) -> dict[str, dict]:
    """
    Parse le JSON complet ({paquet_source: {CVE: {releases: ...}}}) et ne
    conserve que les CVE demandées — l'index complet (~150k CVE) gonflerait la
    mémoire du process backend pour rien. Une CVE peut toucher plusieurs paquets
    source (copies embarquées) → liste d'entrées par release.
    """
    data = json.loads(raw)
    index: dict[str, dict] = {}
    for package, cves in data.items():
        for cve_id, info in cves.items():
            if cve_id not in wanted:
                continue
            for release, rel_info in (info.get("releases") or {}).items():
                index.setdefault(cve_id, {}).setdefault(release, []).append({
                    "package": package,
                    "status": rel_info.get("status"),
                    "fixed_version": rel_info.get("fixed_version"),
                })
    return index


async def get_debian_fix_info(cve_id: str, release: str) -> Optional[list[dict]]:
    """
    Retourne la liste des {"package", "status", "fixed_version"} pour une CVE et
    une release Debian, ou None si le tracker ne connaît pas cette CVE/release
    (ou est injoignable) — l'appelant retombe alors sur la comparaison NVD.
    """
    global _index, _index_built_at

    async with _lock:
        fresh = (time.time() - _index_built_at) < CACHE_TTL_SECONDS
        if not fresh or cve_id not in _index:
            raw = await asyncio.get_event_loop().run_in_executor(None, _ensure_cache_file)
            if raw is None:
                return _index.get(cve_id, {}).get(release) if _index else None
            # Reconstruire en gardant les CVE déjà indexées (autres vulns du cycle)
            wanted = set(_index.keys()) | {cve_id}
            _index = await asyncio.get_event_loop().run_in_executor(
                None, _build_index, raw, wanted
            )
            # Marquer la CVE comme résolue même absente du tracker, pour ne pas
            # reparser 77 Mo à chaque check de cette CVE.
            _index.setdefault(cve_id, {})
            _index_built_at = time.time()

    return _index.get(cve_id, {}).get(release)


async def is_cve_tracked(cve_id: str) -> Optional[bool]:
    """
    Cette CVE figure-t-elle **quelque part** dans le Debian Security Tracker
    (n'importe quel paquet source, n'importe quelle release) ?

    Distinction que `get_debian_fix_info` ne permet pas : celle-ci renvoie None
    aussi bien pour une CVE inconnue que pour une CVE connue sans entrée dans la
    release demandée.

    Utilité (session 21/07/2026) : le tracker référence **toute** CVE touchant un
    paquet Debian, y compris celles marquées "non affecté" pour une release
    donnée. Une CVE totalement absente ne concerne donc aucun paquet Debian —
    signal fort de non-applicabilité sur un actif Debian. Vérifié dans les deux
    sens : les CVE affectant réellement le parc (CVE-2011-1400, CVE-2013-6474,
    CVE-2026-41988) sont toutes présentes ; les non résolues (CVE-2013-2617,
    CVE-2010-4226, plugins Jenkins…) toutes absentes.

    Retourne None si le tracker est injoignable — l'appelant ne doit alors rien
    conclure.
    """
    global _index, _index_built_at

    async with _lock:
        fresh = (time.time() - _index_built_at) < CACHE_TTL_SECONDS
        if not fresh or cve_id not in _index:
            raw = await asyncio.get_event_loop().run_in_executor(None, _ensure_cache_file)
            if raw is None:
                return None   # tracker indisponible : surtout ne pas conclure
            wanted = set(_index.keys()) | {cve_id}
            _index = await asyncio.get_event_loop().run_in_executor(
                None, _build_index, raw, wanted
            )
            _index.setdefault(cve_id, {})
            _index_built_at = time.time()

    # dict non vide = au moins une release référencée pour cette CVE
    return bool(_index.get(cve_id))


# ─── Comparaison de versions au format dpkg (Debian Policy §5.6.12) ───────────
# Implémentée localement pour ne pas exécuter de commande distante supplémentaire
# (dpkg --compare-versions marcherait mais multiplie les allers-retours SSH).

def _char_order(c: str) -> int:
    if c == "~":
        return -1
    if c == "":
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_nondigits(a: str, b: str) -> int:
    length = max(len(a), len(b))
    for i in range(length):
        oa = _char_order(a[i] if i < len(a) else "")
        ob = _char_order(b[i] if i < len(b) else "")
        if oa != ob:
            return (oa > ob) - (oa < ob)
    return 0


def _cmp_part(a: str, b: str) -> int:
    """Compare upstream_version ou debian_revision selon l'algorithme dpkg."""
    while a or b:
        ma = re.match(r"[^0-9]*", a)
        mb = re.match(r"[^0-9]*", b)
        r = _cmp_nondigits(ma.group(), mb.group())
        if r:
            return r
        a, b = a[ma.end():], b[mb.end():]

        ma = re.match(r"[0-9]*", a)
        mb = re.match(r"[0-9]*", b)
        na = int(ma.group() or 0)
        nb = int(mb.group() or 0)
        if na != nb:
            return (na > nb) - (na < nb)
        a, b = a[ma.end():], b[mb.end():]
    return 0


def _split_deb_version(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        head, v = v.split(":", 1)
        if head.isdigit():
            epoch = int(head)
    if "-" in v:
        upstream, revision = v.rsplit("-", 1)
    else:
        upstream, revision = v, ""
    return epoch, upstream, revision


def deb_version_compare(a: str, b: str) -> int:
    """-1 / 0 / 1 selon que a < / == / > b, sémantique dpkg (epoch, ~, révision)."""
    ea, ua, ra = _split_deb_version(a)
    eb, ub, rb = _split_deb_version(b)
    if ea != eb:
        return (ea > eb) - (ea < eb)
    r = _cmp_part(ua, ub)
    if r:
        return r
    return _cmp_part(ra, rb)
