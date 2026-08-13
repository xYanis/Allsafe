"""
watch_report.py
Contenu du rapport hebdomadaire de **veille** (registre NIS 2).

La mécanique hebdomadaire (semaine ISO, gel, archives, export) est commune aux
trois rapports et vit dans `services/weekly_report.py` — ce module ne produit que
le contenu propre à la veille, pour la fenêtre [start, end[.

Périmètre : **Veille technologique uniquement**. Les sources dédiées "fuite de
données" (ransomware.live, ZATAZ…) sont exclues, exactement comme dans l'écran
Veille technologique (cf. `GET /api/watch/leak-sources`) — elles ont leur propre
onglet et ne relèvent pas du registre de veille auditable.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from models import WatchItem, WatchSource, Asset
from services.watch_fetcher import BUILTIN_LEAK_SOURCES

logger = logging.getLogger(__name__)

# Même valeur que routers/watch.py — SLA NIS 2 sur les alertes critiques.
SLA_HOURS = 48

SEVERITY_LABELS = {"critical": "Critique", "important": "Important", "informational": "Informationnel"}
STATUS_LABELS = {"new": "Nouveau", "in_review": "En cours", "treated": "Traité", "not_applicable": "Non concerné"}


async def _leak_sources(session: AsyncSession) -> list[str]:
    rows = (await session.execute(
        select(WatchSource.slug).where(WatchSource.enabled.is_(True), WatchSource.category == "leak")
    )).scalars().all()
    return BUILTIN_LEAK_SOURCES + list(rows)


def _item_row(w: WatchItem, asset_names: dict[str, str] | None = None) -> dict:
    names = asset_names or {}
    return {
        "assets": [names[a] for a in (w.asset_ids or []) if a in names],
        "title": w.title,
        "source_label": w.source_label or w.source,
        "severity": w.severity,
        "status": w.status,
        "url": w.url,
        "themes": w.themes or [],
        "received_at": w.received_at.isoformat() if w.received_at else None,
        "reviewed_at": w.reviewed_at.isoformat() if w.reviewed_at else None,
        "reviewed_by": w.reviewed_by,
        "decision": w.decision,
    }


async def build_veille_payload(
    session: AsyncSession, start: datetime, end: datetime, period_label: str
) -> dict:
    """
    Rapport de veille pour la semaine [start, end[ : `summary` (markdown figé),
    `stats` (compteurs) et `activity` (les éléments eux-mêmes, pour l'export CSV).

    Deux fenêtres distinctes, à ne pas confondre :
    - **reçus** dans la semaine (`received_at`) — le volume de veille à traiter ;
    - **traités** dans la semaine (`reviewed_at`) — le travail réellement fait,
      qui peut porter sur des éléments reçus les semaines précédentes.
    Les confondre donnerait un taux de traitement faux dès qu'un élément est
    traité en différé, ce qui est le cas courant.
    """
    leak = await _leak_sources(session)
    asset_names = {str(i): n for i, n in (await session.execute(select(Asset.id, Asset.name))).all()}

    def _scope(q):
        return q.where(WatchItem.source.notin_(leak)) if leak else q

    received = (await session.execute(
        _scope(select(WatchItem))
        .where(WatchItem.received_at >= start, WatchItem.received_at < end)
        .order_by(WatchItem.severity, WatchItem.received_at.desc())
    )).scalars().all()

    treated = (await session.execute(
        _scope(select(WatchItem))
        .where(WatchItem.reviewed_at >= start, WatchItem.reviewed_at < end)
        .where(WatchItem.status.in_(["treated", "not_applicable"]))
        .order_by(WatchItem.reviewed_at.desc())
    )).scalars().all()

    # Éléments critiques reçus dans la semaine et toujours non traités à la
    # génération : c'est le manquement que cherche un auditeur NIS 2.
    critical_pending = [
        w for w in received
        if w.severity == "critical" and w.status in ("new", "in_review")
    ]

    by_severity: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_theme: dict[str, int] = {}
    for w in received:
        by_severity[w.severity] = by_severity.get(w.severity, 0) + 1
        label = w.source_label or w.source
        by_source[label] = by_source.get(label, 0) + 1
        for t in (w.themes or []):
            by_theme[t] = by_theme.get(t, 0) + 1

    # Délai moyen de traitement, sur les éléments traités dans la semaine.
    delays = [
        (w.reviewed_at - w.received_at).total_seconds() / 3600
        for w in treated if w.reviewed_at and w.received_at
    ]
    avg_delay_h = round(sum(delays) / len(delays), 1) if delays else None

    # SLA : critiques reçus dans la semaine, non traités, et dont le délai
    # dépasse déjà 48 h à la clôture de la semaine.
    sla_exceeded = [
        w for w in critical_pending
        if w.received_at and (end - w.received_at).total_seconds() > SLA_HOURS * 3600
    ]

    # Le stock global (toutes semaines confondues) encore ouvert — un rapport
    # hebdomadaire qui ne montrerait que sa propre semaine masquerait une dette
    # qui s'accumule.
    backlog_total = await session.scalar(
        _scope(select(func.count(WatchItem.id))).where(WatchItem.status.in_(["new", "in_review"]))
    )
    backlog_critical = await session.scalar(
        _scope(select(func.count(WatchItem.id)))
        .where(WatchItem.status.in_(["new", "in_review"]), WatchItem.severity == "critical")
    )

    stats = {
        "received": len(received),
        "treated": len(treated),
        "by_severity": by_severity,
        "by_source": by_source,
        "by_theme": by_theme,
        "critical_received": by_severity.get("critical", 0),
        "critical_pending": len(critical_pending),
        "sla_hours": SLA_HOURS,
        "sla_exceeded": len(sla_exceeded),
        "avg_treatment_delay_hours": avg_delay_h,
        "backlog_total": backlog_total or 0,
        "backlog_critical": backlog_critical or 0,
    }

    activity = {
        "received": [_item_row(w, asset_names) for w in received],
        "treated": [_item_row(w, asset_names) for w in treated],
        "critical_pending": [_item_row(w, asset_names) for w in critical_pending],
    }

    return {
        "summary": _render_summary(stats, activity, period_label),
        "stats": stats,
        "activity": activity,
    }


def _render_summary(stats: dict, activity: dict, period_label: str) -> str:
    """
    Markdown du rapport — même grammaire que le rapport exécutif CVE (titres,
    tableaux, gras) pour être rendu par le même composant `ReportMarkdown.jsx`.
    Les mots de sévérité sont écrits en toutes lettres et en majuscules
    (CRITIQUE…) car ce composant les colore automatiquement.
    """
    L: list[str] = []
    L.append("# Rapport de veille — registre NIS 2")
    L.append("")
    L.append(f"Veille technologique · Période : {period_label}")
    L.append("")

    if stats["sla_exceeded"]:
        niveau = "CRITIQUE"
    elif stats["critical_pending"]:
        niveau = "ÉLEVÉ"
    elif stats["backlog_critical"]:
        niveau = "MODÉRÉ"
    else:
        niveau = "FAIBLE"
    L.append(f"**Niveau de vigilance : {niveau}**")
    L.append("")

    L.append(f"## Ce qui a été fait — {period_label}")
    if not stats["received"] and not stats["treated"]:
        L.append("Aucune activité de veille sur la période.")
    else:
        L.append(f"- **{stats['received']}** élément(s) collecté(s), dont **{stats['critical_received']}** de sévérité CRITIQUE")
        L.append(f"- **{stats['treated']}** élément(s) traité(s) par un analyste")
        if stats["avg_treatment_delay_hours"] is not None:
            L.append(f"- Délai moyen de traitement : **{stats['avg_treatment_delay_hours']} h**")
    L.append("")

    L.append(f"## Respect du SLA ({stats['sla_hours']} h sur les critiques)")
    if stats["sla_exceeded"]:
        L.append(f"**{stats['sla_exceeded']} élément(s) CRITIQUE(S) non traité(s) au-delà de {stats['sla_hours']} h.**")
    elif stats["critical_received"]:
        L.append(f"Aucun dépassement — les {stats['critical_received']} élément(s) critique(s) de la semaine sont dans les délais.")
    else:
        L.append("Aucun élément critique reçu sur la période.")
    L.append("")

    if stats["by_severity"]:
        L.append("## Répartition par sévérité")
        L.append("| Sévérité | Éléments reçus |")
        L.append("|---|---|")
        for key in ("critical", "important", "informational"):
            if stats["by_severity"].get(key):
                L.append(f"| {SEVERITY_LABELS[key]} | {stats['by_severity'][key]} |")
        L.append("")

    if stats["by_source"]:
        L.append("## Sources les plus actives")
        L.append("| Source | Éléments |")
        L.append("|---|---|")
        for label, n in sorted(stats["by_source"].items(), key=lambda kv: -kv[1])[:8]:
            L.append(f"| {label} | {n} |")
        L.append("")

    if stats["by_theme"]:
        L.append("## Thèmes dominants")
        top = sorted(stats["by_theme"].items(), key=lambda kv: -kv[1])[:8]
        L.append(", ".join(f"**{t}** ({n})" for t, n in top))
        L.append("")

    pending = activity.get("critical_pending") or []
    if pending:
        L.append("## Éléments critiques encore à traiter")
        L.append("| Élément | Source | Reçu le | Statut |")
        L.append("|---|---|---|---|")
        for w in pending[:10]:
            recu = (w["received_at"] or "")[:10]
            titre = (w["title"] or "")[:80].replace("|", "-")
            L.append(f"| {titre} | {w['source_label']} | {recu} | {STATUS_LABELS.get(w['status'], w['status'])} |")
        if len(pending) > 10:
            L.append(f"| *… et {len(pending) - 10} de plus* | | | |")
        L.append("")

    L.append("## Stock restant (toutes semaines confondues)")
    L.append(f"- **{stats['backlog_total']}** élément(s) non traité(s) au total, dont **{stats['backlog_critical']}** CRITIQUE(S)")
    L.append("")

    treated_rows = activity.get("treated") or []
    if treated_rows:
        L.append("## Décisions consignées cette semaine")
        L.append("| Élément | Actifs concernés | Analyste | Décision |")
        L.append("|---|---|---|---|")
        for w in treated_rows[:15]:
            titre = (w["title"] or "")[:60].replace("|", "-")
            decision = (w["decision"] or STATUS_LABELS.get(w["status"], ""))[:80].replace("|", "-").replace("\n", " ")
            actifs = ", ".join(w.get("assets") or []) or "—"
            L.append(f"| {titre} | {actifs} | {w['reviewed_by'] or '—'} | {decision} |")
        if len(treated_rows) > 15:
            L.append(f"| *… et {len(treated_rows) - 15} de plus* | | | |")
        L.append("")

    return "\n".join(L)
