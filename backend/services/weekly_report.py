"""
weekly_report.py
Génération des rapports hebdomadaires **figés** du module Rapports.

Un rapport porte sur une **semaine ISO complète** (lundi 00:00 → lundi suivant
00:00, exclu) et n'est jamais recalculé après coup : cf. docstring du modèle
`Report` (models.py).

Les trois contenus sont branchés : `cve` (rapport exécutif, `routers/reports.py`),
`veille` (registre NIS 2, `services/watch_report.py`) et `surveillance`
(identités, `services/identity_report.py`). La mécanique (semaine ISO, bornes,
upsert, archives, export) reste indépendante du type — un 4e rapport ne demande
qu'un `build_*_payload()` et une branche ci-dessous (cf. principe "penser
scalable", CLAUDE.md).

Les Incidents n'en font PAS partie : un incident est rare, jamais plusieurs la
même semaine — son rapport se fait à l'unité, généré à la demande, jamais figé
(cf. `services/incident_report.py`, `routers/incidents.py::get_incident_report`).
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Report, Asset

logger = logging.getLogger(__name__)

KINDS = ("cve", "veille", "surveillance")

# Types de rapport déclinables **par actif**. La veille (registre NIS 2) et la
# surveillance d'identités ne sont pas rattachées au parc : les décliner par
# actif produirait N copies identiques du même rapport.
ASSET_SCOPED_KINDS = ("cve",)

AUTO_GENERATED_BY = "Auto (hebdomadaire)"


# ─── Semaine ISO ──────────────────────────────────────────────────────────────

def week_label(iso_year: int, iso_week: int) -> str:
    """"S30/2026" — format demandé par l'utilisateur (semaine puis année)."""
    return f"S{iso_week:02d}/{iso_year}"


def week_bounds(iso_year: int, iso_week: int) -> tuple[datetime, datetime]:
    """
    Bornes UTC d'une semaine ISO : lundi 00:00 inclus → lundi suivant 00:00 exclu.

    `fromisocalendar` fait le travail exact — surtout aux frontières d'année, où
    un calcul naïf depuis le 1er janvier se trompe d'une semaine une année sur
    cinq environ (le 2029-12-31 appartient à la semaine 1 de 2030).
    """
    start = datetime.fromisocalendar(iso_year, iso_week, 1).replace(tzinfo=timezone.utc)
    return start, start + timedelta(days=7)


def current_week(now: datetime | None = None) -> tuple[int, int]:
    """Semaine ISO en cours — (année ISO, numéro de semaine)."""
    now = now or datetime.now(timezone.utc)
    y, w, _ = now.isocalendar()
    return y, w


def last_complete_week(now: datetime | None = None) -> tuple[int, int]:
    """
    Dernière semaine ISO **terminée**.

    C'est la semaine que le rapport automatique couvre : générer S30 pendant la
    semaine 30 produirait un rapport tronqué (« 2 corrections cette semaine »
    un mardi matin), archivé comme s'il était complet. On attend donc que la
    semaine soit close — d'où le déclenchement le lundi.
    """
    now = now or datetime.now(timezone.utc)
    y, w, _ = (now - timedelta(days=7)).isocalendar()
    return y, w


# ─── Génération ───────────────────────────────────────────────────────────────

def _period_label(iso_year: int, iso_week: int, start: datetime, end: datetime) -> str:
    """"semaine S30/2026 (20/07 au 26/07/2026)" — libellé lisible commun aux rapports."""
    return (
        f"semaine {week_label(iso_year, iso_week)} "
        f"({start.strftime('%d/%m')} au {(end - timedelta(days=1)).strftime('%d/%m/%Y')})"
    )

async def build_cve_report(
    session: AsyncSession, iso_year: int, iso_week: int, start: datetime, end: datetime,
    asset_id: str | None = None,
) -> dict:
    """
    Contenu du rapport exécutif CVE pour la fenêtre [start, end[.

    Réutilise exactement les briques du rapport à la demande
    (`routers/reports.py`) — il ne doit pas exister deux façons de calculer un
    même chiffre, sinon le rapport figé et l'écran divergent silencieusement.
    """
    # Import local : routers/reports.py importe déjà ce module pour les endpoints
    # d'archives — un import de module à module en tête de fichier créerait un
    # cycle à l'import de l'app.
    from routers.reports import build_summary_payload

    label = _period_label(iso_year, iso_week, start, end)
    return await build_summary_payload(
        session, asset_ids=[asset_id] if asset_id else None,
        since=start, until=end, period_label=label,
    )


async def generate_report(
    session: AsyncSession,
    kind: str,
    iso_year: int,
    iso_week: int,
    generated_by: str = AUTO_GENERATED_BY,
    force: bool = False,
    asset_id: str | None = None,
) -> tuple[Report, bool]:
    """
    Génère (ou régénère) le rapport `kind` de la semaine ISO donnée.

    Retourne `(rapport, créé)` — `créé=False` quand un rapport figé existait
    déjà et que `force` est faux : on ne réécrit pas silencieusement un
    instantané archivé, c'est toute sa raison d'être. La régénération reste
    possible explicitement (bouton dédié / `force=true`), par exemple après
    correction d'un bug de calcul.
    """
    if kind not in KINDS:
        raise ValueError(f"Type de rapport inconnu : {kind}")
    if asset_id and kind not in ASSET_SCOPED_KINDS:
        raise ValueError(f"Le rapport '{kind}' ne se décline pas par actif")

    existing = (await session.execute(
        select(Report).where(
            Report.kind == kind,
            Report.iso_year == iso_year,
            Report.iso_week == iso_week,
            Report.asset_id == asset_id if asset_id else Report.asset_id.is_(None),
        )
    )).scalar_one_or_none()

    start, end = week_bounds(iso_year, iso_week)

    if existing and not force:
        # Exception au gel : un rapport produit **avant la fin de la semaine**
        # qu'il couvre est incomplet par construction (généré manuellement en
        # cours de semaine). Sans cette règle, il resterait figé tel quel pour
        # toujours — la tâche du lundi le sauterait, voyant qu'un rapport S30
        # existe déjà, et l'archive garderait une semaine tronquée.
        # Une fois la semaine close, le rapport devient définitif : seul `force`
        # peut encore le réécrire.
        if existing.generated_at and existing.generated_at >= end:
            return existing, False

    if kind == "cve":
        payload = await build_cve_report(session, iso_year, iso_week, start, end, asset_id=asset_id)
    elif kind == "veille":
        from services.watch_report import build_veille_payload
        payload = await build_veille_payload(session, start, end, _period_label(iso_year, iso_week, start, end))
    elif kind == "surveillance":
        from services.identity_report import build_surveillance_payload
        payload = await build_surveillance_payload(session, start, end, _period_label(iso_year, iso_week, start, end))
    else:
        raise NotImplementedError(f"Contenu du rapport '{kind}' pas encore implémenté")

    report = existing or Report(
        kind=kind, iso_year=iso_year, iso_week=iso_week, asset_id=asset_id,
    )
    if asset_id:
        asset = await session.get(Asset, asset_id)
        report.asset_label = asset.name if asset else None
    report.label        = week_label(iso_year, iso_week)
    report.period_start = start
    report.period_end   = end
    report.generated_at = datetime.now(timezone.utc)
    report.generated_by = generated_by
    report.summary      = payload["summary"]
    report.stats        = payload["stats"]
    report.activity     = payload["activity"]

    if existing is None:
        session.add(report)
    await session.commit()
    await session.refresh(report)

    logger.info(
        "Rapport %s %s %s (%s)",
        kind, report.label, "régénéré" if existing else "généré", generated_by,
    )
    return report, True


async def generate_weekly_reports(session: AsyncSession, force: bool = False) -> list[dict]:
    """
    Point d'entrée de la tâche planifiée — génère, pour la dernière semaine
    complète et chaque type de rapport disposant d'un contenu :
      - le rapport **global** (tout le parc, `asset_id = NULL`) ;
      - un rapport **par actif**.

    Pourquoi générer tous les actifs d'avance plutôt qu'à la demande : un
    rapport par actif produit après coup n'est pas fidèle. La requête d'activité
    s'appuie sur les horodatages de clôture, et rouvrir une vulnérabilité efface
    le sien (`update_vulnerability`) — elle disparaît alors du rapport de la
    semaine où elle avait été clôturée. Seule une génération à temps capture la
    semaine telle qu'elle était. Coût mesuré : ~0,25 s par rapport, soit ~20 s
    par semaine pour 80 actifs.

    Les types non encore implémentés sont ignorés sans faire échouer la tâche :
    l'ajout du contenu `veille`/`surveillance` ne demandera aucune modification
    ici ni dans le planning Celery.
    """
    iso_year, iso_week = last_complete_week()
    label = week_label(iso_year, iso_week)

    asset_ids = [str(a) for a in (await session.execute(select(Asset.id))).scalars().all()]

    out = []
    for kind in KINDS:
        # `None` en premier = rapport global, puis un par actif quand le type
        # se décline ainsi (cf. ASSET_SCOPED_KINDS).
        scopes: list[str | None] = [None, *asset_ids] if kind in ASSET_SCOPED_KINDS else [None]
        for asset_id in scopes:
            try:
                report, created = await generate_report(
                    session, kind, iso_year, iso_week, force=force, asset_id=asset_id,
                )
                out.append({
                    "kind": kind, "label": report.label,
                    "scope": report.asset_label or "parc", "created": created,
                })
            except NotImplementedError:
                break  # type non implémenté : inutile de boucler sur les actifs
            except Exception as exc:  # un rapport en échec ne doit pas bloquer les autres
                logger.error("Échec génération rapport %s %s (actif=%s) : %s", kind, label, asset_id, exc)
                out.append({"kind": kind, "label": label, "scope": asset_id, "error": str(exc)})
    return out
