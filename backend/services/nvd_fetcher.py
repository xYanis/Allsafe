"""
nvd_fetcher.py
Collecte des CVE depuis l'API NVD/NIST v2.

Documentation officielle : https://nvd.nist.gov/developers/vulnerabilities
Rate limits :
  - Sans clé API : 5 requêtes / 30 secondes
  - Avec clé API  : 50 requêtes / 30 secondes (recommandé, gratuit sur nvd.nist.gov)
"""

import httpx
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import CVE, SyncState
from database import SessionLocal

logger = logging.getLogger(__name__)

# Marge de recouvrement appliquée au curseur incrémental persisté — filet de
# sécurité contre toute perte partielle passée inaperçue (cf. incident
# CVE-2022-30190/juin 2026 : une sync interrompue en cours de page laissait
# perdre silencieusement ce qui n'avait pas encore été commité, sans que le
# curseur ne recule jamais dessus). Chaque run redemande donc un peu de
# terrain déjà couvert par le précédent plutôt que de faire une confiance
# aveugle au succès complet du run précédent.
INCREMENTAL_OVERLAP = timedelta(days=3)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000          # Maximum autorisé par l'API NVD
DELAY_NO_KEY = 6.5       # secondes entre requêtes sans clé API
DELAY_WITH_KEY = 0.7     # secondes entre requêtes avec clé API


# ─── Parsing ──────────────────────────────────────────────────────────────────

def _parse_cvss_v3(metrics: dict) -> tuple[Optional[float], Optional[str], Optional[str]]:
    """Extrait score, vecteur et sévérité CVSS v3.1 ou v3.0."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return (
                data.get("baseScore"),
                data.get("vectorString"),
                data.get("baseSeverity"),
            )
    return None, None, None


def _parse_cve_item(item: dict) -> Optional[dict]:
    """
    Transforme un item brut de l'API NVD en dict prêt pour la base.
    Retourne None si l'item est incomplet ou rejeté (status REJECTED).
    """
    cve = item.get("cve", {})

    if cve.get("vulnStatus", "") == "Rejected":
        return None

    cve_id = cve.get("id")
    if not cve_id:
        return None

    # Description en anglais en priorité
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        None,
    )
    if not description:
        return None

    metrics = cve.get("metrics", {})
    cvss_score, cvss_vector, severity = _parse_cvss_v3(metrics)

    # Fallback CVSS v2 si pas de v3
    if cvss_score is None:
        v2 = metrics.get("cvssMetricV2", [])
        if v2:
            cvss_score = v2[0].get("cvssData", {}).get("baseScore")
            cvss_vector = v2[0].get("cvssData", {}).get("vectorString")
            base_severity = v2[0].get("baseSeverity", "")
            severity = base_severity if base_severity else _score_to_severity(cvss_score)

    if severity is None and cvss_score is not None:
        severity = _score_to_severity(cvss_score)

    references = [
        r.get("url") for r in cve.get("references", []) if r.get("url")
    ]

    cpe_list = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpe_list.append(match.get("criteria"))

    published_str = cve.get("published")
    modified_str = cve.get("lastModified")

    return {
        "cve_id": cve_id,
        "description": description,
        "published": _parse_dt(published_str),
        "modified": _parse_dt(modified_str),
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "references": references,
        "cpe": [c for c in cpe_list if c],
        "source": "nvd",
        "raw_data": item,
    }


def _score_to_severity(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# ─── Fetcher ──────────────────────────────────────────────────────────────────

class NVDFetcher:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.delay = DELAY_WITH_KEY if api_key else DELAY_NO_KEY
        self.headers = {"apiKey": api_key} if api_key else {}

    async def _get_page(
        self,
        client: httpx.AsyncClient,
        params: dict,
    ) -> dict:
        """Effectue une requête paginée avec retry sur erreur 503."""
        for attempt in range(3):
            try:
                response = await client.get(
                    NVD_API_BASE,
                    params=params,
                    headers=self.headers,
                    timeout=60,
                )
                if response.status_code == 503:
                    wait = 30 * (attempt + 1)
                    logger.warning(f"NVD API 503, attente {wait}s (tentative {attempt+1}/3)")
                    await asyncio.sleep(wait)
                    continue
                response.raise_for_status()
                return response.json()
            except httpx.TimeoutException:
                logger.warning(f"Timeout NVD (tentative {attempt+1}/3)")
                await asyncio.sleep(10)
        raise RuntimeError("NVD API indisponible après 3 tentatives")

    async def fetch_recent(
        self,
        days: int = 1,
        since: Optional[datetime] = None,
    ) -> AsyncGenerator[dict, None]:
        """
        Génère les CVE publiées ou modifiées dans les N derniers jours.
        Utilisé par la tâche Celery planifiée (toutes les 4h).

        Si `since` est fourni (déjà des CVE en base), interroge NVD par date de
        MODIFICATION depuis ce point plutôt que par date de PUBLICATION sur toute
        la fenêtre `days` — évite de re-télécharger ce qui est déjà en mémoire à
        chaque resynchro manuelle. `days` sert uniquement de secours si la base
        est vide (premier import).
        """
        now = datetime.now(timezone.utc)

        if since:
            params_base = {
                "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": PAGE_SIZE,
            }
        else:
            start = now - timedelta(days=days)
            params_base = {
                "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": PAGE_SIZE,
            }

        async for item in self._paginate(params_base):
            yield item

    async def fetch_by_severity(
        self,
        severity: str,
        days: int = 30,
    ) -> AsyncGenerator[dict, None]:
        """
        Génère les CVE d'une sévérité donnée sur les N derniers jours.
        severity: CRITICAL | HIGH | MEDIUM | LOW
        """
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=days)

        params_base = {
            "cvssV3Severity": severity.upper(),
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": PAGE_SIZE,
        }

        async for item in self._paginate(params_base):
            yield item

    async def fetch_by_cpe(
        self,
        cpe_name: str,
    ) -> AsyncGenerator[dict, None]:
        """
        Génère les CVE affectant un CPE spécifique.
        Ex: cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*
        (11 composants après "cpe:2.3" — un composant en trop renvoie un 404
        NVD, cf. bug corrigé dans services/asset_importer.py `_build_cpe`)
        """
        params_base = {
            "cpeName": cpe_name,
            "resultsPerPage": PAGE_SIZE,
        }

        async for item in self._paginate(params_base):
            yield item

    async def fetch_by_id(self, cve_id: str) -> Optional[dict]:
        """
        Récupère une CVE précise par son identifiant (ex: "CVE-2022-30190").

        Sert de filet de rattrapage : la sync incrémentale (`fetch_recent`)
        interroge NVD par `lastModStartDate` depuis `max(CVE.modified)` en
        base — une CVE dont la dernière modification NVD réelle est déjà
        antérieure à ce curseur au moment où elle aurait dû être récupérée
        reste invisible pour toujours, la sync ne revenant jamais en arrière
        (cf. docs/ARCHITECTURE.md, incident CVE-2022-30190 manquante pour
        Windows Server 2019 malgré une base CVE par ailleurs à jour).
        """
        async with httpx.AsyncClient() as client:
            data = await self._get_page(client, {"cveId": cve_id})
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        return _parse_cve_item(vulnerabilities[0])

    async def _paginate(self, params_base: dict) -> AsyncGenerator[dict, None]:
        """Gère la pagination automatique sur tous les résultats NVD."""
        start_index = 0

        async with httpx.AsyncClient() as client:
            while True:
                params = {**params_base, "startIndex": start_index}
                data = await self._get_page(client, params)

                total = data.get("totalResults", 0)
                vulnerabilities = data.get("vulnerabilities", [])

                logger.info(
                    f"NVD page {start_index // PAGE_SIZE + 1} : "
                    f"{len(vulnerabilities)} CVE (total: {total})"
                )

                for item in vulnerabilities:
                    parsed = _parse_cve_item(item)
                    if parsed:
                        yield parsed

                start_index += PAGE_SIZE
                if start_index >= total:
                    break

                await asyncio.sleep(self.delay)


# ─── Upsert en base ───────────────────────────────────────────────────────────

async def upsert_cve(session: AsyncSession, data: dict) -> tuple[CVE, bool]:
    """
    Insère ou met à jour une CVE en base.
    Retourne (cve, created) où created=True si nouvelle entrée.
    """
    result = await session.execute(
        select(CVE).where(CVE.cve_id == data["cve_id"])
    )
    existing = result.scalar_one_or_none()

    if existing:
        # Mise à jour uniquement si la date de modification est plus récente
        if data["modified"] and existing.modified:
            new_mod = data["modified"].replace(tzinfo=None) if data["modified"].tzinfo else data["modified"]
            ex_mod  = existing.modified.replace(tzinfo=None) if existing.modified.tzinfo else existing.modified
            if new_mod <= ex_mod:
                return existing, False

        for field, value in data.items():
            if field != "raw_data":  # raw_data seulement à la création
                setattr(existing, field, value)
        return existing, False
    else:
        cve = CVE(**data)
        session.add(cve)
        return cve, True


# ─── Point d'entrée principal ─────────────────────────────────────────────────

async def run_nvd_sync(
    api_key: Optional[str] = None,
    days: int = 1,
    severity_filter: Optional[list[str]] = None,
    incremental: bool = True,
    since_override: Optional[datetime] = None,
) -> dict:
    """
    Synchronisation complète NVD → base de données.
    Appelé par la tâche Celery scheduled_tasks.py.

    `incremental=True` (par défaut) : interroge NVD uniquement sur ce qui a été
    modifié depuis le curseur persisté (table `sync_state`, clé "nvd") plutôt
    que de retélécharger toute la fenêtre `days` à chaque appel. `days` ne sert
    alors que de secours si la base est vide (aucun curseur enregistré).

    Le curseur n'est **avancé que si le run se termine sans erreur**, avec une
    marge de recouvrement (`INCREMENTAL_OVERLAP`) sur l'ancien curseur — sans
    ça, un run interrompu en cours de pagination (timeout, 503 NVD après 3
    tentatives...) committait déjà ce qu'il avait réussi à traiter, et le
    prochain run repartait de `max(CVE.modified)` **recalculé sur ce résultat
    partiel** : tout ce qui restait à traiter dans la fenêtre interrompue était
    perdu pour toujours, sans jamais réapparaître dans une sync future (incident
    constaté : ~4750 CVE manquantes pour Windows Server 2019 seul, cf.
    docs/ARCHITECTURE.md § Sync NVD).

    `since_override` : balaie NVD par date de modification depuis ce point précis,
    en court-circuitant le curseur persisté (ne le lit ni ne l'avance). Sert au
    filet de sécurité quotidien (`sync_nvd_critical`) — un balayage large et
    redondant (ex: 45 jours) indépendant du curseur canonique, pour rester une
    vraie 2e chance en cas de trou dans la sync incrémentale plutôt qu'un doublon
    silencieux de la même fenêtre.

    Retourne un rapport de synchronisation :
    {
        "fetched": 142,
        "created": 38,
        "updated": 104,
        "skipped": 0,
        "errors": 0,
        "duration_seconds": 47.3,
    }
    """
    start_time = datetime.now(timezone.utc)
    fetcher = NVDFetcher(api_key=api_key)

    stats = {"fetched": 0, "created": 0, "updated": 0, "skipped": 0, "errors": 0}

    # SessionLocal() directement — get_session() est un générateur FastAPI qui peut
    # se comporter différemment depuis le contexte asyncio.run() des workers Celery.
    session = SessionLocal()
    try:
        since = None
        if since_override is not None:
            since = since_override
            logger.info(f"Sync NVD — balayage redondant depuis {since.isoformat()} (curseur canonique ignoré)")
        elif incremental:
            state = await session.get(SyncState, "nvd")
            if state and state.last_synced_at:
                since = state.last_synced_at - INCREMENTAL_OVERLAP
                logger.info(
                    f"Sync NVD incrémentale depuis {since.isoformat()} "
                    f"(curseur {state.last_synced_at.isoformat()} - {INCREMENTAL_OVERLAP.days}j de recouvrement)"
                )

        async for cve_data in fetcher.fetch_recent(days=days, since=since):
            stats["fetched"] += 1

            if severity_filter and cve_data.get("severity") not in severity_filter:
                stats["skipped"] += 1
                continue

            try:
                _, created = await upsert_cve(session, cve_data)
                if created:
                    stats["created"] += 1
                else:
                    stats["updated"] += 1
            except Exception as e:
                logger.error(f"Erreur upsert {cve_data.get('cve_id')}: {e}")
                stats["errors"] += 1
                await session.rollback()
                continue

            # Commit par lot de 100 pour éviter les transactions trop longues
            if (stats["created"] + stats["updated"]) % 100 == 0:
                await session.commit()

        # Curseur avancé uniquement ici — la boucle complète s'est terminée sans
        # exception, donc NVD a bien été interrogé jusqu'à `start_time` inclus.
        # Jamais touché lors d'un balayage redondant (`since_override`) : ce
        # n'est pas la source de vérité canonique, juste une 2e chance en plus.
        if incremental and since_override is None:
            state = await session.get(SyncState, "nvd")
            if state is None:
                state = SyncState(key="nvd")
                session.add(state)
            state.last_synced_at = start_time

        await session.commit()

    except RuntimeError as e:
        # NVD API indisponible après retries — on conserve ce qui a déjà été
        # commité mais on N'AVANCE PAS le curseur : le prochain run reprendra
        # exactement depuis le même point (avec le recouvrement en plus), donc
        # ce qui n'a pas pu être traité cette fois sera retenté, pas perdu.
        await session.commit()
        logger.warning(f"Sync NVD interrompue (API NVD): {e} — {stats['created']} CVE sauvegardées, curseur non avancé")
        stats["errors"] += 1
    except Exception as e:
        await session.rollback()
        logger.error(f"Erreur sync NVD: {e}")
        raise
    finally:
        await session.close()

    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    stats["duration_seconds"] = round(duration, 1)

    logger.info(
        f"Sync NVD terminée : {stats['created']} créées, "
        f"{stats['updated']} mises à jour, "
        f"{stats['errors']} erreurs ({duration:.1f}s)"
    )

    return stats


async def run_nvd_sync_by_id(cve_id: str, api_key: Optional[str] = None) -> dict:
    """
    Récupère et importe une CVE précise par ID — filet de rattrapage pour une
    CVE passée à travers le trou de la sync incrémentale (cf. `fetch_by_id`).
    Ignore entièrement le curseur incrémental, donc récupère la CVE quelle que
    soit sa date de dernière modification NVD réelle.
    """
    fetcher = NVDFetcher(api_key=api_key)
    parsed = await fetcher.fetch_by_id(cve_id)
    if not parsed:
        return {"found": False, "cve_id": cve_id}

    session = SessionLocal()
    try:
        _, created = await upsert_cve(session, parsed)
        await session.commit()
        return {"found": True, "created": created, "cve_id": parsed["cve_id"], "severity": parsed["severity"]}
    finally:
        await session.close()


async def run_nvd_backfill_by_cpe(cpe_name: str, api_key: Optional[str] = None) -> dict:
    """
    Importe TOUTES les CVE que NVD considère applicables à un CPE donné,
    quelle que soit leur date de publication/modification — rattrapage complet
    pour un produit du parc, indépendant du curseur incrémental (cf.
    `run_nvd_sync`).

    Nécessaire en plus du fix du curseur incrémental : celui-ci empêche les
    *futures* pertes silencieuses mais ne comble pas le retard déjà accumulé
    (incident du 20/07/2026 : ~4750 CVE manquantes pour
    windows_server_2019 seul, cf. docs/ARCHITECTURE.md § Sync NVD). Utilise
    `fetch_by_cpe` (jusqu'ici jamais appelée dans le code) plutôt qu'un import
    NVD complet — cible précisément ce qui concerne le parc réel, pas les
    ~300k CVE de NVD dans leur ensemble, la plupart hors sujet.
    """
    fetcher = NVDFetcher(api_key=api_key)
    stats = {"cpe": cpe_name, "fetched": 0, "created": 0, "updated": 0, "errors": 0}

    session = SessionLocal()
    try:
        async for cve_data in fetcher.fetch_by_cpe(cpe_name):
            stats["fetched"] += 1
            try:
                _, created = await upsert_cve(session, cve_data)
                stats["created" if created else "updated"] += 1
            except Exception as e:
                logger.error(f"Erreur upsert {cve_data.get('cve_id')} (backfill {cpe_name}): {e}")
                stats["errors"] += 1
                await session.rollback()
                continue

            if (stats["created"] + stats["updated"]) % 100 == 0:
                await session.commit()

        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()

    logger.info(
        f"Backfill CPE {cpe_name} terminé : {stats['created']} créées, "
        f"{stats['updated']} mises à jour, {stats['errors']} erreurs"
    )
    return stats
