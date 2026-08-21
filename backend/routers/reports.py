import csv
import codecs
import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from database import get_session
from models import Vulnerability, CVE, Asset, Report
from services.claude_analyzer import generate_executive_summary
from services.stats import compute_stats
from services.csv_safety import csv_safe
from services.inventory_export import build_inventory_pdf
from config import settings

router = APIRouter()


def _parse_asset_ids(asset_id: str | None) -> list[str] | None:
    return [v.strip() for v in asset_id.split(",") if v.strip()] if asset_id else None


@router.get("/csv")
async def export_csv(asset_id: str | None = None, session: AsyncSession = Depends(get_session)):
    """
    Backlog courant (tout ce qui n'est pas `patched`) — document de travail à
    remettre à l'équipe sécurité. `asset_id` (CSV d'UUID, optionnel) restreint
    à un/plusieurs actifs, cohérent avec le filtre "Actifs" du reste de la page.
    """
    asset_ids = _parse_asset_ids(asset_id)

    q = (
        select(Vulnerability, CVE, Asset)
        .join(CVE, Vulnerability.cve_id == CVE.id)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .where(Vulnerability.status != "patched")
        .order_by(CVE.cvss_score.desc())
    )
    if asset_ids:
        q = q.where(Vulnerability.asset_id.in_(asset_ids))

    rows = (await session.execute(q)).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["CVE ID", "Sévérité", "Score CVSS", "Actif", "OS", "Type", "Statut", "Détecté le", "Validé par", "Annotation"])
    for v, c, a in rows:
        writer.writerow([
            c.cve_id, c.severity, c.cvss_score,
            # `a.name`/`os`/`os_version`/`asset_type` passés par csv_safe (11/08/2026,
            # bug réel corrigé — cf. audit/AUDIT_SECURITE.md #7/STATUS.md) : ce sont des champs
            # texte libre modifiables par tout compte `analyst` via PUT /api/assets, pas
            # seulement admin — la protection anti-injection de formule était déjà posée
            # sur validated_by/notes plus bas mais oubliée sur le nom/l'OS de l'actif.
            csv_safe(a.name or ""), csv_safe(f"{a.os} {a.os_version}"), csv_safe(a.asset_type or ""),
            v.status,
            v.detected_at.strftime("%Y-%m-%d") if v.detected_at else "",
            csv_safe(v.validated_by or ""),
            csv_safe(v.notes or ""),
        ])

    # Le BOM UTF-8 est nécessaire pour qu'Excel (notamment en locale FR) détecte
    # l'encodage correctement — sans lui, les caractères accentués s'affichent
    # comme des caractères mojibake ("Ã©" au lieu de "é"), cf. même correction
    # déjà appliquée à l'export veille (routers/watch.py).
    csv_bytes = codecs.BOM_UTF8 + output.getvalue().encode("utf-8")
    return StreamingResponse(
        iter([csv_bytes]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=vulnerabilites.csv"},
    )


@router.get("/inventory/pdf")
async def export_inventory_pdf(session: AsyncSession = Depends(get_session)):
    """
    Export PDF du module Inventaire (patrimoine IT) — lecture seule, aucune
    écriture sur les serveurs. Tableau récapitulatif (CPU/architecture/cœurs/
    RAM/disques/nb d'apps) suivi du détail des applications installées par
    actif (cf. services/inventory_export.py).
    """
    assets = (await session.execute(select(Asset).order_by(Asset.name))).scalars().all()
    pdf_bytes = build_inventory_pdf(assets)
    filename = f"cbr-inventaire-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.pdf"
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


class SummaryRequest(BaseModel):
    # None (défaut) = pas de fenêtre temporelle, résumé = état actuel uniquement
    # (comportement historique). 7/30 = ajoute une section "Ce qui a été fait"
    # sur la période, pensée pour un envoi hebdomadaire à l'équipe sécurité.
    period_days: int | None = None
    asset_id: str | None = None


@router.post("/executive-summary")
async def executive_summary(data: SummaryRequest = SummaryRequest(), session: AsyncSession = Depends(get_session)):
    asset_ids = _parse_asset_ids(data.asset_id)
    since = None
    period_label = None
    if data.period_days:
        since = datetime.now(timezone.utc) - timedelta(days=data.period_days)
        period_label = f"{data.period_days} derniers jours"

    payload = await build_summary_payload(
        session, asset_ids=asset_ids, since=since, period_label=period_label
    )
    return {"summary": payload["summary"]}


async def build_summary_payload(
    session: AsyncSession,
    asset_ids: list[str] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    period_label: str | None = None,
) -> dict:
    """
    Construit le rapport exécutif : texte markdown + chiffres + activité.

    Partagé par le rapport à la demande (`POST /executive-summary`) et par le
    rapport hebdomadaire figé (`services/weekly_report.py`) — il ne doit exister
    qu'une seule façon de calculer ces chiffres, sinon l'archive S30 et l'écran
    finissent par se contredire sur les mêmes données.

    `since`/`until` délimitent la section "Ce qui a été fait" : `since` seul =
    fenêtre glissante (« 7 derniers jours »), les deux = semaine ISO close.
    """
    stats = await compute_stats(session, asset_ids=asset_ids)

    # CVE encore réellement à traiter (ni `patched`, ni `false_positive`) sur le
    # parc ou la sélection d'actifs — sert au "Top CVE" et au comptage "encore à
    # traiter" par sévérité ci-dessous. Deux bugs réels corrigés par ce filtre :
    # 1. Sans restriction au parc du tout, "Tous les actifs" remontait n'importe
    #    quelle CVE CRITICAL jamais importée depuis NVD, y compris sans aucun
    #    rapport avec les actifs suivis (ex: CVE-2026-48286, Adobe Campaign
    #    Classic — jamais matchée à aucun actif).
    # 2. Sans le filtre de statut, une CVE déjà corrigée sur tous les actifs où
    #    elle a été détectée pouvait quand même apparaître en tête de "Top CVE
    #    critiques à traiter en priorité" simplement parce qu'elle a le CVSS le
    #    plus élevé — constaté en réel : les 5 CVE remontées étaient toutes
    #    déjà `patched`. Une CVE matchée à plusieurs actifs avec des statuts
    #    différents reste listée tant qu'au moins un actif ne l'a pas corrigée.
    unresolved = select(Vulnerability.cve_id).where(
        Vulnerability.status.in_(["open", "in_progress", "accepted_risk", "awaiting_fix", "awaiting_fix_partial"])
    ).distinct()
    if asset_ids:
        unresolved = unresolved.where(Vulnerability.asset_id.in_(asset_ids))

    top_cves_all = (await session.execute(
        select(CVE)
        .where(CVE.severity == "CRITICAL", CVE.id.in_(unresolved))
        .order_by(CVE.cvss_score.desc())
    )).scalars().all()
    top_cves = top_cves_all[:5]
    critical_unresolved = len(top_cves_all)

    # Annotation "en attente de correctif" pour les CVE du Top 5 — montre que la
    # CVE est bien suivie (pas ignorée) même si son statut reste techniquement
    # "à traiter" tant que le correctif éditeur/distro n'est pas sorti. Une CVE
    # matchée à plusieurs actifs peut avoir plusieurs lignes `awaiting_fix` avec
    # des annotations différentes — on garde la plus récente (`awaiting_fix_at`
    # desc), un résumé exécutif n'a pas besoin de toutes les lister.
    awaiting_fix_notes: dict = {}
    if top_cves:
        awaiting_q = (
            select(Vulnerability.cve_id, Vulnerability.notes)
            .where(
                Vulnerability.cve_id.in_([c.id for c in top_cves]),
                Vulnerability.status.in_(["awaiting_fix", "awaiting_fix_partial"]),
            )
            .order_by(Vulnerability.awaiting_fix_at.desc())
        )
        if asset_ids:
            awaiting_q = awaiting_q.where(Vulnerability.asset_id.in_(asset_ids))
        for cve_id, notes in (await session.execute(awaiting_q)).all():
            awaiting_fix_notes.setdefault(cve_id, notes)
    high_unresolved = await session.scalar(
        select(func.count(func.distinct(CVE.id))).where(CVE.severity == "HIGH", CVE.id.in_(unresolved))
    )

    activity = None
    if since:
        activity = await _activity_during_period(session, asset_ids, since, until)

    asset_label = await _asset_label(session, asset_ids)

    summary = await generate_executive_summary(
        stats, top_cves, activity=activity, period_label=period_label,
        asset_label=asset_label, critical_unresolved=critical_unresolved,
        high_unresolved=high_unresolved, awaiting_fix_notes=awaiting_fix_notes,
        api_key=settings.ANTHROPIC_API_KEY,
    )
    return {"summary": summary, "stats": stats, "activity": activity or {}}


async def _asset_label(session: AsyncSession, asset_ids: list[str] | None) -> str:
    if not asset_ids:
        return "Tous les actifs"
    if len(asset_ids) == 1:
        asset = await session.get(Asset, asset_ids[0])
        return asset.name if asset else "1 actif"
    return f"{len(asset_ids)} actifs sélectionnés"


# Plafond des listes d'activité (03/08/2026, cf. STATUS.md § passage à
# l'échelle) : `detected` n'est pas borné par un rythme humain comme
# patched/awaiting_fix/false_positive, elle inclut toute création de
# Vulnerability sur la fenêtre — un run de matching massif (ex: élargissement
# AD du 28/07/2026, 264 949 lignes créées le même jour) tombant dans la
# semaine du rapport charge tout ça en objets Python en une requête et a fait
# planter le worker (OOM, exit 137). Même convention que
# `identity_report.py` (leak_matches/ip_matches) et `_activity_table`
# (affichage markdown, déjà plafonné à 15 côté rendu) : les N plus critiques
# en détail + un `total` réel toujours exact, jamais silencieusement
# tronqué sans le dire (cf. `openTruncated` côté Dashboard.jsx, même principe).
ACTIVITY_ROW_CAP = 15


async def _activity_during_period(
    session: AsyncSession,
    asset_ids: list[str] | None,
    since: datetime,
    until: datetime | None = None,
) -> dict:
    """
    Vulnérabilités dont le statut a changé (ou qui ont été détectées) sur la
    fenêtre [since, until[, pour la section "Ce qui a été fait" du résumé — le
    contenu qu'on veut pouvoir envoyer tel quel à l'équipe sécurité.

    `until` (optionnel) borne la fenêtre à droite. Indispensable au rapport
    hebdomadaire : sans lui, le rapport de la semaine 30 régénéré en semaine 32
    inclurait tout ce qui s'est passé depuis, sous une étiquette S30.

    Chaque section vaut `{"items": [...], "total": N}` — `items` plafonné à
    `ACTIVITY_ROW_CAP`, `total` toujours le vrai compte (requête d'agrégation
    séparée, pas `len(items)`).
    """
    base = (
        select(Vulnerability, CVE, Asset)
        .join(CVE, Vulnerability.cve_id == CVE.id)
        .join(Asset, Vulnerability.asset_id == Asset.id)
    )
    if asset_ids:
        base = base.where(Vulnerability.asset_id.in_(asset_ids))

    async def _rows(column, extra_where=None):
        where = column >= since
        if until is not None:
            where = where & (column < until)
        if extra_where is not None:
            where = where & extra_where
        filtered = base.where(where)
        total = await session.scalar(select(func.count()).select_from(filtered.subquery()))
        rows = (await session.execute(
            filtered.order_by(CVE.cvss_score.desc()).limit(ACTIVITY_ROW_CAP)
        )).all()
        items = [
            {
                "cve_id": c.cve_id, "severity": c.severity, "asset_name": a.name,
                "validated_by": v.validated_by, "notes": v.notes,
            }
            for v, c, a in rows
        ]
        return {"items": items, "total": total or 0}

    patched   = await _rows(Vulnerability.patched_at,        Vulnerability.status == "patched")
    awaiting  = await _rows(Vulnerability.awaiting_fix_at,   Vulnerability.status == "awaiting_fix")
    false_pos = await _rows(Vulnerability.false_positive_at, Vulnerability.status == "false_positive")
    detected  = await _rows(Vulnerability.detected_at)

    return {"patched": patched, "awaiting_fix": awaiting, "false_positive": false_pos, "detected": detected}


# ─── Rapports hebdomadaires figés ─────────────────────────────────────────────
# Cf. services/weekly_report.py pour la logique de semaine ISO et de génération,
# et la docstring du modèle `Report` pour la raison du gel.

def _report_row(r: Report, full: bool = False) -> dict:
    out = {
        "id": str(r.id),
        "kind": r.kind,
        "label": r.label,
        "iso_year": r.iso_year,
        "iso_week": r.iso_week,
        "period_start": r.period_start.isoformat() if r.period_start else None,
        "period_end": r.period_end.isoformat() if r.period_end else None,
        "generated_at": r.generated_at.isoformat() if r.generated_at else None,
        "generated_by": r.generated_by,
        "asset_id": str(r.asset_id) if r.asset_id else None,
        "asset_label": r.asset_label,          # None = tout le parc
        # `complete=False` = rapport d'une semaine encore en cours au moment de
        # sa génération : chiffres partiels, il sera régénéré automatiquement une
        # fois la semaine close (cf. services/weekly_report.py). L'UI le signale,
        # pour qu'un rapport tronqué ne soit jamais lu comme définitif.
        "complete": bool(
            r.generated_at and r.period_end and r.generated_at >= r.period_end
        ),
    }
    activity = r.activity or {}
    # Compteurs toujours renvoyés : la liste d'archives les affiche sans avoir à
    # télécharger le contenu complet de chaque rapport. Dérivés des clés
    # réellement présentes plutôt que d'une liste figée — les sections diffèrent
    # selon le type (`patched`/`awaiting_fix`… pour cve, `received`/`treated`…
    # pour veille), et un nouveau type ne doit rien imposer ici.
    # Deux formes possibles par section (03/08/2026) : une liste brute (veille/
    # surveillance, jamais assez volumineux pour poser problème) ou
    # `{"items": [...], "total": N}` (cve, plafonné — cf. `ACTIVITY_ROW_CAP`
    # dans `_activity_during_period`) — `total` prime toujours sur `len(items)`
    # pour rester le vrai chiffre même quand la liste détaillée est tronquée.
    out["counts"] = {
        k: (v.get("total", 0) if isinstance(v, dict) else len(v))
        for k, v in activity.items() if isinstance(v, (list, dict))
    }
    if full:
        out["summary"] = r.summary
        out["stats"] = r.stats or {}
        out["activity"] = activity
    return out


@router.get("/weekly")
async def list_weekly_reports(
    kind: str | None = Query(None, description="cve | veille | surveillance"),
    asset_id: str | None = Query(None, description="UUID(s) d'actif séparés par des virgules ; absent = parc entier"),
    session: AsyncSession = Depends(get_session),
):
    """
    Archives, de la semaine la plus récente à la plus ancienne.

    Sans `asset_id`, ne renvoie que les rapports **globaux** (parc entier) — et
    non tous les rapports confondus, sinon chaque semaine apparaîtrait autant de
    fois qu'il y a d'actifs. Avec plusieurs actifs, une ligne par (semaine,
    actif), même format de paramètre que le reste de l'app (CSV d'UUID).
    """
    asset_ids = _parse_asset_ids(asset_id)
    q = select(Report).order_by(Report.iso_year.desc(), Report.iso_week.desc(), Report.asset_label)
    q = q.where(Report.asset_id.in_(asset_ids)) if asset_ids else q.where(Report.asset_id.is_(None))
    if kind:
        q = q.where(Report.kind == kind)
    rows = (await session.execute(q)).scalars().all()
    return {"items": [_report_row(r) for r in rows]}


@router.post("/weekly/generate")
async def generate_weekly_report(
    kind: str = Query("cve"),
    iso_year: int | None = Query(None),
    iso_week: int | None = Query(None, ge=1, le=53),
    asset_id: str | None = Query(None, description="Limite le rapport à un actif ; absent = tout le parc"),
    force: bool = Query(False, description="Régénère un rapport déjà archivé"),
    generated_by: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
):
    """
    Génère un rapport à la demande. Sans `iso_year`/`iso_week`, cible la
    **dernière semaine complète** — la même que la tâche planifiée, pour que le
    bouton manuel et l'automatisme ne produisent jamais deux rapports différents.

    Un rapport déjà archivé n'est jamais réécrit sans `force=true` (`created`
    vaut alors `false`) : un instantané figé qui change tout seul ne vaut rien
    pour un audit.
    """
    from services.weekly_report import generate_report, last_complete_week

    if iso_year is None or iso_week is None:
        iso_year, iso_week = last_complete_week()

    try:
        report, created = await generate_report(
            session, kind, iso_year, iso_week,
            generated_by=generated_by or "Manuel", force=force, asset_id=asset_id,
        )
    except NotImplementedError:
        raise HTTPException(501, f"Le contenu du rapport '{kind}' n'est pas encore implémenté")
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return {"created": created, "report": _report_row(report, full=True)}


@router.get("/weekly/{report_id}")
async def get_weekly_report(report_id: str, session: AsyncSession = Depends(get_session)):
    report = await session.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Rapport introuvable")
    return _report_row(report, full=True)


@router.get("/weekly/{report_id}/csv")
async def export_weekly_report_csv(report_id: str, session: AsyncSession = Depends(get_session)):
    """
    Export CSV de l'activité **figée** du rapport — reconstruit depuis le
    snapshot, jamais depuis l'état courant de la base (sinon le CSV de S30
    téléchargé aujourd'hui ne correspondrait plus au rapport S30 affiché).
    """
    report = await session.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Rapport introuvable")

    activity = report.activity or {}
    output = io.StringIO()
    writer = csv.writer(output)

    # Colonnes propres à chaque type de rapport : les sections d'un registre de
    # veille (reçus / traités) n'ont rien à voir avec celles d'un rapport CVE
    # (corrigées / en attente…). Ajouter un type = une branche ici.
    if report.kind == "veille":
        writer.writerow(["Semaine", "Événement", "Élément", "Source", "Sévérité", "Statut", "Reçu le", "Analyste", "Actifs concernés", "Décision", "Lien"])
        for label, key in [("Reçu", "received"), ("Traité", "treated"), ("Critique en attente", "critical_pending")]:
            for row in activity.get(key) or []:
                writer.writerow([
                    report.label, label,
                    csv_safe(row.get("title", "")), csv_safe(row.get("source_label", "")), row.get("severity", ""),
                    row.get("status", ""), (row.get("received_at") or "")[:10],
                    row.get("reviewed_by") or "", ", ".join(row.get("assets") or []),
                    csv_safe((row.get("decision") or "").replace("\n", " ")),
                    csv_safe(row.get("url") or ""),
                ])
    elif report.kind == "surveillance":
        writer.writerow(["Semaine", "Événement", "Identité", "Type / Source", "Détail", "Reçu le", "Lien"])
        for row in activity.get("identities") or []:
            writer.writerow([report.label, "Périmètre surveillé", csv_safe(row.get("value", "")), row.get("kind", ""), "", "", ""])
        for row in activity.get("leak_matches") or []:
            writer.writerow([
                report.label, "Fuite correspondante", csv_safe(", ".join(row.get("matched_identities") or [])),
                csv_safe(row.get("source_label", "")), csv_safe(row.get("title", "")),
                (row.get("received_at") or "")[:10], csv_safe(row.get("url") or ""),
            ])
        for row in activity.get("ip_matches") or []:
            writer.writerow([
                report.label, "IP sur liste de blocage", csv_safe(row.get("identity_value", "")),
                csv_safe(row.get("source_label", "")), csv_safe(f"{row.get('ip', '')} — {row.get('detail') or ''}".strip(" —")), "", "",
            ])
    else:
        writer.writerow(["Semaine", "Événement", "CVE ID", "Sévérité", "Actif", "Validé par", "Annotation"])
        for label, key in [
            ("Corrigée", "patched"), ("En attente de correctif", "awaiting_fix"),
            ("Faux positif", "false_positive"), ("Détectée", "detected"),
        ]:
            section = activity.get(key) or {}
            items = section.get("items", []) if isinstance(section, dict) else section
            total = section.get("total", len(items)) if isinstance(section, dict) else len(items)
            for row in items:
                writer.writerow([
                    report.label, label,
                    row.get("cve_id", ""), row.get("severity", ""), csv_safe(row.get("asset_name", "")),
                    csv_safe(row.get("validated_by") or ""), csv_safe(row.get("notes") or ""),
                ])
            # Liste plafonnée à ACTIVITY_ROW_CAP côté génération (cf.
            # routers/reports.py::_activity_during_period) — jamais présenter un
            # CSV tronqué comme complet sans le dire (même principe que
            # `openTruncated` côté Dashboard.jsx).
            if total > len(items):
                writer.writerow([report.label, label, "", "", "", "", f"… et {total - len(items)} de plus (total réel : {total}, liste plafonnée à {len(items)})"])

    # BOM UTF-8 pour Excel FR, même raison que l'export CSV du backlog ci-dessus.
    csv_bytes = codecs.BOM_UTF8 + output.getvalue().encode("utf-8")
    scope = f"-{report.asset_label}" if report.asset_label else ""
    filename = f"cybervuln-rapport-{report.kind}{scope}-S{report.iso_week:02d}-{report.iso_year}.csv"
    return StreamingResponse(
        iter([csv_bytes]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
