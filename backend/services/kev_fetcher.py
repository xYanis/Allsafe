"""
services/kev_fetcher.py
CISA KEV (Known Exploited Vulnerabilities Catalog) — CVE dont l'exploitation active dans la
nature est confirmée (pas une prédiction comme EPSS : un fait constaté). Source publique
gratuite, sans clé : https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Même principe que epss_fetcher.py : export JSON complet régénéré au fil de l'eau (pas d'API
incrémentale), met à jour uniquement les CVE déjà en base (`cves.cve_id`), n'en crée jamais —
NVD reste l'unique source de vérité pour la CVE elle-même.

Deux passes bulk UPDATE plutôt qu'une : la CISA retire parfois une entrée du catalogue (rare
mais déjà arrivé), donc les CVE marquées kev=true qui ne sont plus dans le feed doivent être
réinitialisées, pas seulement celles du feed mises à jour — sinon un retrait resterait affiché
indéfiniment.

`kev` alimente aussi la métrique temporelle E (Exploit Code Maturity) du score CVSS-BTE
(services/cvss_bte.py) — même raisonnement qu'epss_fetcher.py : un `recalculate_all_scores()`
en fin de sync corrige les `cvss_bte` déjà en base pour refléter le catalogue à jour.
"""

import logging
from datetime import date, datetime, timezone

import httpx
from sqlalchemy import bindparam, update

from database import SessionLocal
from models import CVE, SyncState
from services.scoring import recalculate_all_scores

logger = logging.getLogger(__name__)

KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_UPDATE_BATCH_SIZE = 2000
SYNC_STATE_KEY = "kev"


async def run_kev_sync(rescore: bool = True) -> dict:
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(KEV_JSON_URL, follow_redirects=True)
        response.raise_for_status()
        payload = response.json()

    entries = payload.get("vulnerabilities", [])
    feed_rows = []
    for entry in entries:
        cve_id = entry.get("cveID")
        if not cve_id:
            continue
        raw_date = entry.get("dateAdded")  # "YYYY-MM-DD"
        try:
            date_added = date.fromisoformat(raw_date) if raw_date else None
        except ValueError:
            date_added = None
        ransomware = entry.get("knownRansomwareCampaignUse") == "Known"
        feed_rows.append({"_cve_id": cve_id, "_date_added": date_added, "_ransomware": ransomware})

    if not feed_rows:
        # Catalogue CISA jamais vide en pratique (1665+ entrées au 17/08/2026) — un feed vide
        # signale plus probablement un souci de parsing/format en amont qu'un vrai catalogue
        # vidé. Ne touche rien plutôt que de réinitialiser silencieusement tout le monde.
        logger.warning("Sync KEV : feed vide ou illisible, aucune écriture effectuée")
        return {"kev_total": 0, "skipped": "empty_feed"}

    feed_ids = {r["_cve_id"] for r in feed_rows}

    session = SessionLocal()
    try:
        # Passe 1 : réinitialise les CVE marquées kev=true qui ne sont plus dans le feed
        # (retrait CISA, rare mais possible) — exécutée AVANT la passe 2, sur les seules
        # lignes déjà kev=true (index partiel idx_cves_kev, coût négligeable même sur 191k CVE).
        conn = await session.connection()
        reset_stmt = update(CVE).where(CVE.kev.is_(True), CVE.cve_id.notin_(feed_ids)).values(
            kev=False, kev_date_added=None, kev_ransomware=False,
        )
        await conn.execute(reset_stmt)

        # Passe 2 : applique le feed courant, par lot.
        stmt = (
            update(CVE)
            .where(CVE.cve_id == bindparam("_cve_id"))
            .values(kev=True, kev_date_added=bindparam("_date_added"), kev_ransomware=bindparam("_ransomware"))
        )
        for i in range(0, len(feed_rows), _UPDATE_BATCH_SIZE):
            batch = feed_rows[i:i + _UPDATE_BATCH_SIZE]
            conn = await session.connection()
            await conn.execute(stmt, batch)
            await session.commit()

        state = await session.get(SyncState, SYNC_STATE_KEY)
        if state is None:
            state = SyncState(key=SYNC_STATE_KEY)
            session.add(state)
        state.last_synced_at = datetime.now(timezone.utc)
        await session.commit()

        logger.info("Sync KEV : %d entrées dans le catalogue CISA", len(feed_rows))
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()

    stats = {"kev_total": len(feed_rows)}
    if rescore:
        stats["rescore"] = await recalculate_all_scores()
    return stats
