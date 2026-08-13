"""
services/prtg_client.py
Client de lecture seule pour l'API cœur PRTG Network Monitor (04/08/2026, supervision
réseau) — pas PRTG Multiboard, qui sert à agréger des widgets visuels entre instances,
pas à interroger le statut d'un device par hostname.

Deuxième sonde après Meraki (cf. services/meraki_client.py, même schéma) : source
supplémentaire de la table `network_status`, jamais nommée en dur côté modèle. Aucun
appel de ce module n'écrit ni n'agit sur un objet PRTG (seuls des GET sont utilisés),
cohérent avec la règle de non-intervention (CLAUDE.md § Règles absolues) — CBR héberge
et affiche l'état constaté, il ne configure jamais rien côté PRTG.

Auth : token API envoyé en paramètre de requête `apitoken` (alternative moderne à
username/passhash, supportée nativement par l'API PRTG) — pas d'en-tête dédié
contrairement à Meraki.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from config import settings

logger = logging.getLogger(__name__)

USER_AGENT = "Allsafe-CyberVuln/1.0"

# Colonnes demandées à content=devices : "host" est la valeur DNS/IP réellement
# configurée pour la surveillance côté PRTG (utilisée pour le rapprochement),
# "device" le nom d'affichage (repli si host ne matche rien). "status_raw" est le
# code numérique stable (3=Up, 5=Down...) normalisé par prtg_matcher.py — "status"
# (libellé texte) n'est PAS fiable pour cette normalisation : constaté en conditions
# réelles (04/08/2026) qu'il est renvoyé **localisé selon la langue de l'interface
# PRTG** ("OK" au lieu de "Up", "En pause (...)" au lieu de "Paused" sur ce serveur
# configuré en français) — gardé uniquement à titre informatif dans `metrics`.
DEVICE_COLUMNS = "objid,device,host,status,status_raw,group,probe"


# Indices de vendor par type de capteur PRTG (colonne "type_raw", stable — pas
# "type", localisé selon la langue de l'interface, même piège que "status" côté
# devices). Tenue à la main sur la base des cas réellement observés (04/08/2026,
# module Veille technologique : "Firewall / Équipements réseau" et "Matériel /
# Constructeurs" proposent des suggestions issues de l'inventaire, cf.
# services/watch_profile.py) — pas une tentative de couvrir tous les vendors PRTG
# possibles, un autre cas observé s'ajoute ici au cas par cas.
VENDOR_SENSOR_TYPE_HINTS = {
    "snmpsynology": "Synology",
}


class PrtgConfigError(RuntimeError):
    """Levée si PRTG_URL / PRTG_API_TOKEN ne sont pas configurés."""


def is_configured() -> bool:
    return bool(settings.PRTG_URL and settings.PRTG_API_TOKEN)


def _base_url() -> str:
    return (settings.PRTG_URL or "").rstrip("/")


async def get_device_statuses() -> list[dict]:
    """État de tous les devices PRTG (content=devices, une ligne par device — pas par
    capteur individuel, l'état "actif" recherché ici est celui de la machine).

    Chaque entrée contient notamment : objid, device (nom d'affichage), host
    (DNS/IP de surveillance), status (libellé texte PRTG), group, probe. Lecture
    seule — ne modifie rien côté PRTG.

    `count=50000` : l'API PRTG limite par défaut à 500 lignes par requête ; ce
    paramètre demande tout en un seul appel, largement suffisant pour un parc de
    cette taille (pas de pagination nécessaire, contrairement à Meraki)."""
    if not is_configured():
        raise PrtgConfigError("PRTG_URL / PRTG_API_TOKEN non configurés dans .env")

    params = {
        "content": "devices",
        "columns": DEVICE_COLUMNS,
        "count": 50000,
        "apitoken": settings.PRTG_API_TOKEN,
    }
    if not settings.PRTG_VERIFY_TLS:
        logger.warning(
            "PRTG_VERIFY_TLS=false — vérification du certificat TLS désactivée pour %s "
            "(CA interne non approuvée par le conteneur, cf. config.py)", _base_url(),
        )
    async with httpx.AsyncClient(
        timeout=20, headers={"User-Agent": USER_AGENT}, verify=settings.PRTG_VERIFY_TLS,
    ) as client:
        response = await client.get(f"{_base_url()}/api/table.json", params=params)
        response.raise_for_status()
        data = response.json()
        return data.get("devices", [])


_OLE_AUTOMATION_EPOCH = datetime(1899, 12, 30, tzinfo=timezone.utc)


def parse_prtg_date(value) -> Optional[datetime]:
    """Convertit une colonne date brute PRTG (`_raw`, ex. lastup_raw/lastdown_raw) —
    nombre de jours depuis le 30/12/1899 UTC (date "Automation"/OLE, même format
    que les dates Excel) — en datetime UTC. Confirmé en conditions réelles
    (07/08/2026) : `46241.2753588542` ↔ `07/08/2026 08:36:31` heure locale (CEST,
    UTC+2), soit `2026-08-07 06:36:31 UTC` — conversion exacte. PRTG renvoie une
    chaîne vide pour "jamais" (ex. capteur qui n'est jamais tombé depuis sa
    création) — pas un flottant, donc pas de `<= 0` à filtrer en pratique, gardé
    par robustesse."""
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    return _OLE_AUTOMATION_EPOCH + timedelta(days=value)


# Capteur PRTG à utiliser pour "depuis quand le device répond-il" (colonne
# "type_raw", stable) — pas n'importe quel capteur : un device en porte plusieurs
# (état système, espace disque, trafic...), prendre le premier venu donnerait un
# "depuis quand" trompeur (ex. lié à une alerte disque plutôt qu'à la
# joignabilité réelle). Constaté en conditions réelles (07/08/2026) que
# `content=devices` ne porte pas `lastup_raw`/`lastdown_raw` (toujours vide) —
# uniquement disponible via `content=sensors`. "ping" est le capteur de
# joignabilité le plus courant (ICMP direct) ; "snmpuptime"/"wmiuptime" en repli
# pour les devices sans capteur Ping actif (ex. équipements réseau supervisés en
# SNMP uniquement, cf. aos12/aos13.aer.loc observés en test). Liste tenue à la
# main au cas par cas, comme VENDOR_SENSOR_TYPE_HINTS ci-dessus.
CONNECTIVITY_SENSOR_TYPE_PRIORITY = ("ping", "snmpuptime", "wmiuptime")


# Type de capteur PRTG pour un certificat SSL surveillé (colonne "type_raw",
# stable). `lastvalue_raw` de ce type de capteur est directement le nombre de
# jours restants avant expiration — pas besoin de parser le libellé texte
# localisé ("60 #"), même précaution que pour le statut des devices.
SSL_CERTIFICATE_TYPE_RAW = "sslcertificate"

SENSOR_COLUMNS = "objid,parentid,device,sensor,type_raw,lastvalue_raw,status_raw,lastup_raw,lastdown_raw"


async def get_sensors() -> list[dict]:
    """Tous les capteurs PRTG, une seule requête — source commune à
    `vendor_hints_from_sensors()` et `ssl_certificates_from_sensors()` plutôt que
    deux appels `content=sensors` séparés pour la même donnée. `parentid` est
    l'objid du device parent du capteur (cf. content=devices), relie chaque
    capteur à son device sans dépendre du nom affiché."""
    if not is_configured():
        raise PrtgConfigError("PRTG_URL / PRTG_API_TOKEN non configurés dans .env")

    params = {
        "content": "sensors",
        "columns": SENSOR_COLUMNS,
        "count": 50000,
        "apitoken": settings.PRTG_API_TOKEN,
    }
    async with httpx.AsyncClient(
        timeout=20, headers={"User-Agent": USER_AGENT}, verify=settings.PRTG_VERIFY_TLS,
    ) as client:
        response = await client.get(f"{_base_url()}/api/table.json", params=params)
        response.raise_for_status()
        return response.json().get("sensors", [])


def vendor_hints_from_sensors(sensors: list[dict]) -> dict[int, str]:
    """{device objid: vendor} pour les devices dont au moins un capteur révèle le
    vendor réel (cf. VENDOR_SENSOR_TYPE_HINTS) — la table `devices` elle-même ne
    porte aucune colonne vendor/modèle exploitable (constaté en conditions réelles,
    04/08/2026)."""
    hints: dict[int, str] = {}
    for sensor in sensors:
        parentid = sensor.get("parentid")
        type_raw = (sensor.get("type_raw") or "").lower()
        if parentid is None or parentid in hints:
            continue
        for prefix, vendor in VENDOR_SENSOR_TYPE_HINTS.items():
            if type_raw.startswith(prefix):
                hints[parentid] = vendor
                break
    return hints


def connectivity_timestamps_from_sensors(sensors: list[dict]) -> dict[int, dict]:
    """{device objid: {"lastup_raw": ..., "lastdown_raw": ...}} à partir du capteur
    de joignabilité le plus fiable disponible sur ce device (cf.
    CONNECTIVITY_SENSOR_TYPE_PRIORITY) — un device sans aucun de ces types de
    capteur (ex. capteurs personnalisés uniquement) n'apparaît pas dans le
    résultat plutôt que de retomber sur un capteur non pertinent."""
    best: dict[int, tuple[int, dict]] = {}
    for sensor in sensors:
        parentid = sensor.get("parentid")
        type_raw = (sensor.get("type_raw") or "").lower()
        if parentid is None or type_raw not in CONNECTIVITY_SENSOR_TYPE_PRIORITY:
            continue
        priority = CONNECTIVITY_SENSOR_TYPE_PRIORITY.index(type_raw)
        current = best.get(parentid)
        if current is None or priority < current[0]:
            best[parentid] = (priority, {
                "lastup_raw": sensor.get("lastup_raw"),
                "lastdown_raw": sensor.get("lastdown_raw"),
            })
    return {objid: timestamps for objid, (_, timestamps) in best.items()}


def ssl_certificates_from_sensors(sensors: list[dict]) -> dict[int, list[dict]]:
    """{device objid: [{sensor, days_remaining, status_raw}, ...]} — un device peut
    porter plusieurs certificats (ex. plusieurs sites hébergés sur un même VPS).
    Un capteur en pause (`lastvalue_raw` vide, cf. STATUS_RAW_MAP côté matcher)
    n'a pas de valeur numérique exploitable, écarté plutôt que planté sur un
    `round()` de chaîne vide."""
    certs: dict[int, list[dict]] = {}
    for sensor in sensors:
        if (sensor.get("type_raw") or "").lower() != SSL_CERTIFICATE_TYPE_RAW:
            continue
        parentid = sensor.get("parentid")
        days_remaining = sensor.get("lastvalue_raw")
        if parentid is None or not isinstance(days_remaining, (int, float)):
            continue
        certs.setdefault(parentid, []).append({
            "sensor": sensor.get("sensor"),
            "days_remaining": round(days_remaining),
            "status_raw": sensor.get("status_raw"),
        })
    return certs
