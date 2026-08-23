"""
routers/watch.py
API de veille cyber — registre auditable NIS 2.

Filtres multi-valeurs (source, severity, themes) : passer des valeurs séparées par virgule.
Exemple : GET /api/watch?themes=Cyber,Ransomware&severity=critical,important
"""

import codecs
import csv
import io
import json as _json
import re
import unicodedata
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, func, cast, String, or_
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from models import WatchItem, WatchSource, SyncState, Asset, WatchProfileItem
from services.watch_fetcher import BUILTIN_LEAK_SOURCES, WATCH_FEEDS
from services.csv_safety import csv_safe

router = APIRouter()

SLA_HOURS = 48

# Libellés FR utilisés dans l'export CSV — la valeur enum stockée en base (colonne
# de gauche) ne change pas, seul l'affichage change ("Non applicable" → "Non concerné").
STATUS_LABELS_FR = {
    "new": "Nouveau",
    "in_review": "En cours",
    "treated": "Traité",
    "not_applicable": "Non concerné",
}


# ─── Schémas ──────────────────────────────────────────────────────────────────

class WatchUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    reviewed_by: Optional[str] = None
    decision: Optional[str] = None
    linked_cve_id: Optional[str] = None
    # Actifs concernés, désignés par l'analyste (liste d'UUID). `[]` efface la
    # sélection ; `None` (champ absent) la laisse inchangée — d'où l'Optional
    # plutôt qu'un défaut à liste vide, qui écraserait à chaque PATCH partiel.
    asset_ids: Optional[list[str]] = None


class WatchProfileEntry(BaseModel):
    kind: str            # os | software
    value: str
    origin: str = "manual"


class WatchProfileReplace(BaseModel):
    items: list[WatchProfileEntry]


class WatchSourceCreate(BaseModel):
    name: str
    url: str
    feed_type: str = "rss"  # rss | atom
    category: str = "general"  # general (Veille technologique) | leak (Fuite de données)
    country: Optional[str] = None  # ISO alpha-2, optionnel


class WatchSourceUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    feed_type: Optional[str] = None
    country: Optional[str] = None
    enabled: Optional[bool] = None


# ─── Sérialisation ────────────────────────────────────────────────────────────

def _profile_matches(w: WatchItem, terms: list[str] | None) -> list[str]:
    from services.watch_profile import matched_terms
    return matched_terms(terms or [], w.title, w.summary)

async def _asset_names(session: AsyncSession) -> dict[str, str]:
    """{uuid: nom} de tout le parc — une seule requête, plutôt qu'un aller-retour
    par item de veille (la liste en renvoie 50 à 200 d'un coup)."""
    rows = (await session.execute(select(Asset.id, Asset.name))).all()
    return {str(i): n for i, n in rows}

def _item_dict(w: WatchItem, asset_names: dict[str, str] | None = None,
               profile_terms: list[str] | None = None) -> dict:
    delay_h = None
    if w.reviewed_at and w.received_at:
        delay_h = round((w.reviewed_at - w.received_at).total_seconds() / 3600, 1)

    sla_exceeded = (
        w.severity == "critical"
        and w.status == "new"
        and w.received_at is not None
        and (datetime.now(timezone.utc) - w.received_at).total_seconds() > SLA_HOURS * 3600
    )

    return {
        "id": str(w.id),
        "source": w.source,
        "source_label": w.source_label,
        "title": w.title,
        "url": w.url,
        "summary": w.summary,
        "published_at": w.published_at.isoformat() if w.published_at else None,
        "received_at": w.received_at.isoformat() if w.received_at else None,
        "severity": w.severity,
        "status": w.status,
        "reviewed_by": w.reviewed_by,
        "reviewed_at": w.reviewed_at.isoformat() if w.reviewed_at else None,
        "decision": w.decision,
        "linked_cve_id": w.linked_cve_id,
        "cve_ids_found": w.cve_ids_found or [],
        "themes": w.themes or [],
        "country": w.country,
        "image_url": w.image_url,
        "is_verified": w.is_verified,
        # Correspondance au profil de veille, calculée à la volée (jamais
        # stockée : le profil évolue, un indicateur figé deviendrait faux).
        # Marque seulement — ne retire jamais l'élément du registre.
        "profile_matches": _profile_matches(w, profile_terms),
        "asset_ids": w.asset_ids or [],
        # Noms résolus à la lecture (jamais stockés) : un actif renommé l'est
        # partout, et un actif supprimé disparaît simplement de la liste.
        "assets": [
            {"id": aid, "name": asset_names[aid]}
            for aid in (w.asset_ids or []) if asset_names and aid in asset_names
        ] if asset_names is not None else [],
        "delay_hours": delay_h,
        "sla_exceeded": sla_exceeded,
    }


# ─── Regroupement des doublons (affichage seulement) ──────────────────────────
# La même actualité arrive souvent par plusieurs sources (un avis CERT-FR
# republié tel quel par Global Security Mag) ou à deux URLs sur une même source
# (variante avec/sans identifiant numérique) : titres identiques, URLs
# différentes, donc le dédoublonnage à l'insertion (URL exacte) ne les voit pas.
# On les regroupe **à l'affichage** — rien n'est supprimé en base, le registre
# NIS 2 reste complet et auditable (toggle `group_duplicates=false` pour tout voir).

# Ordre de « traitement » d'un statut : un groupe dont au moins un membre est
# traité/non concerné est considéré traité (l'actu a été qualifiée une fois).
_STATUS_RANK = {"new": 0, "in_review": 1, "treated": 2, "not_applicable": 2}


def _norm_title_key(title: Optional[str]) -> str:
    """Clé de regroupement : titre en minuscules, espaces normalisés."""
    return " ".join((title or "").lower().split())


def _group_rows_by_title(rows: list[WatchItem]) -> list[list[WatchItem]]:
    """Regroupe les items de titre identique, groupes triés par première entrée
    dans le registre (received_at le plus ancien du groupe) décroissante — la
    veille reste ordonnée du plus récent au plus ancien."""
    buckets: dict[str, list[WatchItem]] = {}
    for w in rows:
        buckets.setdefault(_norm_title_key(w.title), []).append(w)

    def _min_received(g: list[WatchItem]) -> datetime:
        dates = [w.received_at for w in g if w.received_at]
        return min(dates) if dates else datetime.min.replace(tzinfo=timezone.utc)

    return sorted(buckets.values(), key=_min_received, reverse=True)


def _group_dict(group: list[WatchItem], asset_names: dict[str, str] | None,
                terms: list[str] | None) -> dict:
    """Un item représentatif du groupe, enrichi des sources/CVE/thèmes de tous ses
    membres. Le représentant porte le statut le plus avancé (pour qu'un groupe
    déjà qualifié s'affiche comme tel), à défaut le plus ancien reçu."""
    rep = sorted(
        group,
        key=lambda w: (-_STATUS_RANK.get(w.status, 0),
                       w.received_at or datetime.max.replace(tzinfo=timezone.utc)),
    )[0]

    d = _item_dict(rep, asset_names, terms)

    # Union des champs informatifs sur l'ensemble du groupe
    d["cve_ids_found"]   = sorted({c for w in group for c in (w.cve_ids_found or [])})
    d["themes"]          = sorted({t for w in group for t in (w.themes or [])})
    d["profile_matches"] = sorted({m for w in group for m in _profile_matches(w, terms)})

    received = min((w.received_at for w in group if w.received_at), default=rep.received_at)
    d["received_at"] = received.isoformat() if received else None

    # Sources distinctes (badges), et tous les ids pour le traitement en cascade
    sources, seen = [], set()
    for w in group:
        if w.source not in seen:
            seen.add(w.source)
            sources.append({"source": w.source, "source_label": w.source_label, "url": w.url})
    d["group_size"]     = len(group)
    d["group_sources"]  = sources
    d["group_item_ids"] = [str(w.id) for w in group]
    return d


def _source_dict(s: WatchSource) -> dict:
    return {
        "id": str(s.id),
        "name": s.name,
        "slug": s.slug,
        "url": s.url,
        "feed_type": s.feed_type,
        "category": s.category,
        "country": s.country,
        "enabled": s.enabled,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


def _slugify(name: str) -> str:
    # NFKD décompose les caractères accentués en (lettre de base + diacritique
    # combinant) — on jette ensuite les diacritiques (catégorie Unicode "Mn")
    # pour arriver à de l'ASCII pur ("Générale" -> "Generale") avant le regex
    # [^a-z0-9]+. Sans cette étape, chaque caractère accentué (fréquent dans
    # des noms de source en français) produisait son propre tiret ("Générale"
    # -> "g-n-rale" au lieu de "generale").
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    s = re.sub(r"[^a-z0-9]+", "-", ascii_name.strip().lower()).strip("-")
    return s or "source"


# Clés déjà utilisées par une source codée en dur (WATCH_FEEDS + ransomware-live/
# hibp) — un slug généré à partir du nom d'une source personnalisée ne doit
# jamais entrer en collision avec l'une d'elles (écraserait silencieusement ses
# items lors du filtrage par source).
def _reserved_source_keys() -> set[str]:
    return {f["source"] for f in WATCH_FEEDS} | {"ransomware-live", "hibp"}


def _apply_multi(q, column, raw: Optional[str]):
    """Applique un filtre IN sur une colonne à partir d'une valeur CSV."""
    if not raw:
        return q
    values = [v.strip() for v in raw.split(",") if v.strip()]
    if values:
        q = q.where(column.in_(values))
    return q


def _apply_multi_exclude(q, column, raw: Optional[str]):
    """Repli NOT IN de `_apply_multi` — exclut les lignes dont la colonne est
    dans la liste CSV. Utilisé pour exclure les sources "fuite de données"
    (cf. GET /watch/leak-sources) de Veille technologique, désormais leur
    propre onglet (cf. FuiteDeDonnees.jsx)."""
    if not raw:
        return q
    values = [v.strip() for v in raw.split(",") if v.strip()]
    if values:
        q = q.where(column.notin_(values))
    return q


def _apply_themes(q, raw: Optional[str]):
    """Filtre OR sur un tableau JSON : au moins un des thèmes demandés doit être présent.

    PostgreSQL stocke les caractères non-ASCII en JSON sous forme d'échappements
    unicode (Données → Données). Dans un pattern LIKE, le backslash est un
    caractère d'échappement, donc il faut le doubler pour matcher un backslash
    littéral : 'Donn\\u00e9es' dans le pattern = 'Données' stocké.
    """
    if not raw:
        return q
    themes = [t.strip() for t in raw.split(",") if t.strip()]
    if not themes:
        return q
    conditions = []
    for t in themes:
        # json.dumps génère la forme unicode-échappée (Données → Données)
        # [1:-1] supprime les guillemets JSON encadrants
        json_encoded = _json.dumps(t)[1:-1]
        # Dans un pattern LIKE PostgreSQL, \ est le caractère d'échappement :
        # il faut doubler chaque backslash pour qu'il soit interprété littéralement.
        like_safe = json_encoded.replace("\\", "\\\\")
        conditions.append(cast(WatchItem.themes, String).like(f'%"{like_safe}"%'))
        # Forme UTF-8 littérale au cas où le stockage ne serait pas échappé
        if json_encoded != t:
            conditions.append(cast(WatchItem.themes, String).like(f'%"{t}"%'))
    q = q.where(or_(*conditions))
    return q


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("/stats")
async def watch_stats(
    days: int = Query(30, ge=1, le=365),
    source: Optional[str] = None,
    exclude_source: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
):
    """KPIs de veille pour tableau de bord et rapport auditeur NIS 2.

    `source`/`exclude_source` (optionnels, mutuellement exclusifs en pratique) :
    restreint tous les compteurs à un sous-ensemble de sources — utilisé par
    l'onglet "Fuite de données" (`source=<résultat de /watch/leak-sources>`) et
    par Veille technologique qui exclut ces mêmes sources dédiées
    (`exclude_source=<idem>`).
    """
    since         = datetime.now(timezone.utc) - timedelta(days=days)
    sla_threshold = datetime.now(timezone.utc) - timedelta(hours=SLA_HOURS)

    def _scope(q):
        q = _apply_multi(q, WatchItem.source, source)
        q = _apply_multi_exclude(q, WatchItem.source, exclude_source)
        return q

    total = await session.scalar(_scope(select(func.count(WatchItem.id))))

    status_rows = (await session.execute(
        _scope(select(WatchItem.status, func.count(WatchItem.id))).group_by(WatchItem.status)
    )).all()
    by_status = {r[0]: r[1] for r in status_rows}

    sla_exceeded = await session.scalar(
        _scope(select(func.count(WatchItem.id)))
        .where(WatchItem.severity == "critical")
        .where(WatchItem.status == "new")
        .where(WatchItem.received_at <= sla_threshold)
    )

    sev_rows = (await session.execute(
        _scope(select(WatchItem.severity, func.count(WatchItem.id))).group_by(WatchItem.severity)
    )).all()
    by_severity = {r[0]: r[1] for r in sev_rows}

    src_rows = (await session.execute(
        _scope(select(WatchItem.source_label, func.count(WatchItem.id))).group_by(WatchItem.source_label)
    )).all()
    by_source = {r[0]: r[1] for r in src_rows}

    treated_rows = (await session.execute(
        _scope(select(WatchItem.received_at, WatchItem.reviewed_at))
        .where(WatchItem.status.in_(["treated", "not_applicable"]))
        .where(WatchItem.reviewed_at >= since)
        .where(WatchItem.received_at.is_not(None))
        .where(WatchItem.reviewed_at.is_not(None))
    )).all()

    avg_delay_h = None
    if treated_rows:
        delays = [(r[1] - r[0]).total_seconds() / 3600 for r in treated_rows if r[1] and r[0]]
        avg_delay_h = round(sum(delays) / len(delays), 1) if delays else None

    period_total = await session.scalar(
        _scope(select(func.count(WatchItem.id))).where(WatchItem.received_at >= since)
    )
    period_treated = await session.scalar(
        _scope(select(func.count(WatchItem.id)))
        .where(WatchItem.received_at >= since)
        .where(WatchItem.status.in_(["treated", "not_applicable"]))
    )
    treatment_rate = round(period_treated / period_total * 100, 1) if period_total else 0.0

    critical_untreated = await session.scalar(
        _scope(select(func.count(WatchItem.id)))
        .where(WatchItem.severity == "critical")
        .where(WatchItem.status.in_(["new", "in_review"]))
    )

    return {
        "total": total,
        "by_status": by_status,
        "sla_exceeded": sla_exceeded,
        "sla_hours": SLA_HOURS,
        "by_severity": by_severity,
        "by_source": by_source,
        "avg_treatment_delay_hours": avg_delay_h,
        "period_days": days,
        "period_total": period_total,
        "period_treated": period_treated,
        "treatment_rate_pct": treatment_rate,
        "critical_untreated": critical_untreated,
    }


@router.get("/export")
async def export_watch_items(
    date_from: Optional[str] = None,
    date_to:   Optional[str] = None,
    status:    Optional[str] = None,
    themes:    Optional[str] = None,
    session: AsyncSession = Depends(get_session),
):
    """
    Export CSV du registre de veille — destiné au rapport auditeur NIS 2.

    Restreint aux items severity=critical : ce sont les seuls soumis au SLA 48h
    (cf. `sla_exceeded`) et donc les seuls dont l'auditeur a besoin de voir la
    traçabilité complète du traitement. Colonnes réduites à l'essentiel (la
    sévérité n'est plus affichée, elle vaut toujours "critique" ; les CVE
    auto-détectées bruyantes sont retirées au profit de la CVE liée, validée
    par l'analyste).
    """
    q = select(WatchItem).where(WatchItem.severity == "critical").order_by(WatchItem.received_at.asc())
    if date_from:
        q = q.where(WatchItem.received_at >= datetime.fromisoformat(date_from))
    if date_to:
        q = q.where(WatchItem.received_at <= datetime.fromisoformat(date_to))
    q = _apply_multi(q, WatchItem.status, status)
    q = _apply_themes(q, themes)

    rows = (await session.execute(q)).scalars().all()
    names = await _asset_names(session)

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";", quoting=csv.QUOTE_ALL)
    writer.writerow([
        "Date réception", "Source", "Titre", "URL", "Thèmes",
        "Statut", "Analyste", "Date traitement", "Délai traitement (h)",
        "Décision", "CVE liée", "Actifs concernés",
    ])
    for w in rows:
        delay_h = ""
        if w.reviewed_at and w.received_at:
            delay_h = str(round((w.reviewed_at - w.received_at).total_seconds() / 3600, 1))
        writer.writerow([
            w.received_at.strftime("%Y-%m-%d %H:%M") if w.received_at else "",
            csv_safe(w.source_label or w.source),
            csv_safe(w.title),
            csv_safe(w.url or ""),
            csv_safe(", ".join(w.themes or [])),
            STATUS_LABELS_FR.get(w.status, w.status),
            w.reviewed_by or "",
            w.reviewed_at.strftime("%Y-%m-%d %H:%M") if w.reviewed_at else "",
            delay_h,
            csv_safe(w.decision or ""),
            w.linked_cve_id or "",
            csv_safe(", ".join(names[a] for a in (w.asset_ids or []) if a in names)),
        ])

    # Le BOM UTF-8 est nécessaire pour qu'Excel (notamment en locale FR) détecte
    # l'encodage correctement — sans lui, les caractères accentués s'affichent
    # comme des caractères mojibake ("Ã©" au lieu de "é").
    csv_bytes = codecs.BOM_UTF8 + output.getvalue().encode("utf-8")
    filename = f"cybervuln-veille-critique-{datetime.now().strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        iter([csv_bytes]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.post("/sync")
async def trigger_watch_sync():
    """Déclenche manuellement la collecte de veille (toutes les sources)."""
    from services.watch_fetcher import run_watch_sync
    stats = await run_watch_sync()
    return stats


@router.post("/recompute-themes")
async def recompute_watch_themes():
    """Recalcule les thèmes de tous les items déjà en base avec les règles
    actuelles — à lancer après l'ajout d'un thème ou d'un mot-clé (ex: thème
    "IA", session 20/07/2026), la classification ne tournant qu'à la collecte
    (cf. services/watch_fetcher.py `recompute_all_themes`)."""
    from services.watch_fetcher import recompute_all_themes
    stats = await recompute_all_themes()
    return stats


@router.get("/sync-status")
async def watch_sync_status(session: AsyncSession = Depends(get_session)):
    """Date de la dernière collecte de veille (manuelle ou cycle Celery
    horaire) — lu au chargement de page pour afficher la date de dernière
    synchronisation sans attendre un clic manuel (cf. FuiteDeDonnees.jsx)."""
    state = await session.get(SyncState, "watch")
    return {"last_synced_at": state.last_synced_at.isoformat() if state and state.last_synced_at else None}


# ─── Sources personnalisées (flux RSS/Atom ajoutés par l'utilisateur) ─────────
# Ajoutables depuis deux endroits : Fuite de données (category="leak", inclus
# par défaut dans cet onglet, exclu de Veille technologique) et Veille
# technologique (category="general", inclus normalement dans son registre,
# jamais dans Fuite de données) — cf. /leak-sources pour le routage.

@router.get("/leak-sources")
async def leak_sources(session: AsyncSession = Depends(get_session)):
    """Liste des clés de source à traiter comme "fuite de données" — sources
    codées en dur (BUILTIN_LEAK_SOURCES) + sources personnalisées actives de
    category="leak" (les sources "general" ajoutées depuis Veille
    technologique n'en font pas partie). Utilisé par le frontend (Veille
    technologique pour exclure, Fuite de données pour inclure par défaut)
    afin de ne pas dupliquer cette liste côté client à chaque ajout de
    source."""
    rows = (await session.execute(
        select(WatchSource.slug).where(WatchSource.enabled.is_(True), WatchSource.category == "leak")
    )).scalars().all()
    return {"sources": BUILTIN_LEAK_SOURCES + list(rows)}


_COUNTRY_RANGE_DELTAS = {
    "day": timedelta(days=1), "week": timedelta(weeks=1),
    "month": timedelta(days=30), "year": timedelta(days=365),
}


@router.get("/leak-dashboard")
async def leak_dashboard(
    source: Optional[str] = None,
    country_range: str = Query("all", pattern="^(day|week|month|year|all)$"),
    session: AsyncSession = Depends(get_session),
):
    """Dashboard mondial de Fuite de données (23/08/2026, demande explicite) — total, répartition
    par pays/source, tendance hebdo/mensuelle sur 12 périodes. `source` (CSV) restreint aux
    sources dédiées "fuite" comme /watch/stats — le frontend passe systématiquement
    `leakSources.join(',')` (résultat de /leak-sources), jamais appelé sans filtre en pratique
    (sinon inclurait CERT-FR/ANSSI, hors sujet ici). Tout scope confondu par défaut (pas de
    fenêtre `days` comme /stats) : c'est un total/historique, pas un indicateur "activité
    récente" — SAUF le classement pays, seul à prendre `country_range` (23/08/2026, demande
    explicite d'une vue jour/semaine/mois/année/tout) : total/tendance/répartition source
    restent volontairement sur tout l'historique, périmètre non demandé pour eux."""
    def _scope(q):
        return _apply_multi(q, WatchItem.source, source)

    # Date RÉELLE de la fuite (23/08/2026, retour utilisateur — "moyen de remonter plus loin
    # dans les dates ?") : `received_at` (date d'IMPORT chez Allsafe) était utilisé partout
    # dans cet endpoint jusqu'ici, alors qu'une instance qui vient de commencer à synchroniser
    # n'a que quelques jours d'import quelle que soit l'ancienneté réelle des fuites — vérifié
    # en conditions réelles : `published_at` remonte à 2023 sur cette base, `received_at` à
    # l'avant-veille seulement. `coalesce` : ~20% des items n'ont pas de `published_at` fiable
    # (flux sans date de publication exploitable), repli sur `received_at` plutôt que de les
    # exclure du classement/de la tendance.
    real_date = func.coalesce(WatchItem.published_at, WatchItem.received_at)

    total = await session.scalar(_scope(select(func.count(WatchItem.id))))

    country_q = _scope(select(WatchItem.country, func.count(WatchItem.id))).where(WatchItem.country.is_not(None))
    if country_range != "all":
        country_q = country_q.where(real_date >= datetime.now(timezone.utc) - _COUNTRY_RANGE_DELTAS[country_range])
    country_rows = (await session.execute(
        country_q.group_by(WatchItem.country).order_by(func.count(WatchItem.id).desc())
    )).all()
    by_country = [{"country": r[0], "count": r[1]} for r in country_rows]

    source_rows = (await session.execute(
        _scope(select(WatchItem.source, WatchItem.source_label, func.count(WatchItem.id)))
        .group_by(WatchItem.source, WatchItem.source_label)
        .order_by(func.count(WatchItem.id).desc())
    )).all()
    by_source = [{"source": r[0], "source_label": r[1], "count": r[2]} for r in source_rows]

    # 12 dernières semaines/mois glissants — `date_trunc` groupe par période calendaire
    # (semaine ISO démarrant lundi, mois civil), pas une fenêtre de 7/30 jours glissante.
    # Expression construite UNE FOIS et réutilisée dans select/group_by/order_by (pas un
    # `func.date_trunc('week', ...)` réécrit à chaque endroit) : le 1er argument littéral se
    # bind en paramètre PostgreSQL ($1/$2/$3 distincts sinon), et Postgres refuse alors le
    # GROUP BY — il ne sait pas au moment de PREPARE que ces paramètres porteront la même
    # valeur à l'exécution ("column must appear in GROUP BY", constaté en conditions réelles).
    # Réutiliser le même objet Python fait que SQLAlchemy compile un seul bind partagé.
    now = datetime.now(timezone.utc)
    week_trunc = func.date_trunc('week', real_date)
    week_rows = (await session.execute(
        _scope(select(week_trunc, func.count(WatchItem.id)))
        .where(real_date >= now - timedelta(weeks=12))
        .group_by(week_trunc)
        .order_by(week_trunc)
    )).all()
    trend_weekly = [{"period": r[0].isoformat(), "count": r[1]} for r in week_rows if r[0]]

    month_trunc = func.date_trunc('month', real_date)
    month_rows = (await session.execute(
        _scope(select(month_trunc, func.count(WatchItem.id)))
        .where(real_date >= now - timedelta(days=366))
        .group_by(month_trunc)
        .order_by(month_trunc)
    )).all()
    trend_monthly = [{"period": r[0].isoformat(), "count": r[1]} for r in month_rows if r[0]]

    return {
        "total": total,
        "by_country": by_country,
        "by_source": by_source,
        "trend_weekly": trend_weekly,
        "trend_monthly": trend_monthly,
    }


@router.get("/sources")
async def list_watch_sources(category: Optional[str] = None, session: AsyncSession = Depends(get_session)):
    """Sources personnalisées (table WatchSource) — les sources codées en dur
    ne sont pas gérables ici, seulement listées à titre indicatif. `category`
    (optionnel) filtre sur general|leak — Veille technologique et Fuite de
    données n'ont chacune besoin que de gérer les leurs."""
    q = select(WatchSource).order_by(WatchSource.created_at.asc())
    if category:
        q = q.where(WatchSource.category == category)
    rows = (await session.execute(q)).scalars().all()
    return {"builtin": BUILTIN_LEAK_SOURCES, "custom": [_source_dict(s) for s in rows]}


@router.post("/sources", status_code=201)
async def create_watch_source(data: WatchSourceCreate, session: AsyncSession = Depends(get_session)):
    if data.feed_type not in ("rss", "atom"):
        raise HTTPException(400, "feed_type invalide — valeurs : rss, atom")
    if data.category not in ("general", "leak"):
        raise HTTPException(400, "category invalide — valeurs : general, leak")
    if not data.name.strip() or not data.url.strip():
        raise HTTPException(400, "Nom et URL requis")

    from services.net_guard import validate_public_url
    try:
        validate_public_url(data.url.strip())
    except ValueError as e:
        raise HTTPException(400, f"URL refusée : {e}")

    slug = _slugify(data.name)
    if slug in _reserved_source_keys():
        raise HTTPException(409, f"« {data.name} » entre en conflit avec une source existante — choisissez un nom différent")
    existing = await session.scalar(select(WatchSource).where(WatchSource.slug == slug))
    if existing:
        raise HTTPException(409, f"Une source nommée « {data.name} » existe déjà")

    source = WatchSource(
        name=data.name.strip(),
        slug=slug,
        url=data.url.strip(),
        feed_type=data.feed_type,
        category=data.category,
        country=(data.country.upper() if data.country else None),
        enabled=True,
        created_at=datetime.now(timezone.utc),
    )
    session.add(source)
    await session.commit()
    await session.refresh(source)
    return _source_dict(source)


@router.patch("/sources/{source_id}")
async def update_watch_source(source_id: str, data: WatchSourceUpdate, session: AsyncSession = Depends(get_session)):
    source = await session.get(WatchSource, source_id)
    if not source:
        raise HTTPException(404, "Source introuvable")

    if data.name is not None and data.name.strip():
        source.name = data.name.strip()
    if data.url is not None and data.url.strip():
        from services.net_guard import validate_public_url
        try:
            validate_public_url(data.url.strip())
        except ValueError as e:
            raise HTTPException(400, f"URL refusée : {e}")
        source.url = data.url.strip()
    if data.feed_type is not None:
        if data.feed_type not in ("rss", "atom"):
            raise HTTPException(400, "feed_type invalide — valeurs : rss, atom")
        source.feed_type = data.feed_type
    if data.country is not None:
        source.country = data.country.upper() or None
    if data.enabled is not None:
        source.enabled = data.enabled

    await session.commit()
    await session.refresh(source)
    return _source_dict(source)


@router.delete("/sources/{source_id}", status_code=204)
async def delete_watch_source(source_id: str, session: AsyncSession = Depends(get_session)):
    """Retire la source de la liste de collecte — les items déjà importés
    restent en base (leur source_label est figé sur l'item), seule la
    collecte future s'arrête."""
    source = await session.get(WatchSource, source_id)
    if not source:
        raise HTTPException(404, "Source introuvable")
    await session.delete(source)
    await session.commit()


@router.get("")
async def list_watch_items(
    source:    Optional[str] = None,   # une ou plusieurs valeurs séparées par virgule
    exclude_source: Optional[str] = None,  # idem — repli NOT, cf. Veille technologique
    severity:  Optional[str] = None,   # idem
    themes:    Optional[str] = None,   # idem
    country:   Optional[str] = None,   # idem (ISO alpha-2, ex "FR,DE") — vide = tous pays, cf. Fuite de données
    status:    Optional[str] = None,   # idem (utilisé par l'export, pas le filtre UI)
    reviewed_by: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to:   Optional[str] = None,
    sla_only:  bool = Query(False),
    profile_only: bool = Query(False, description="Ne garder que les éléments correspondant au profil de veille"),
    group_duplicates: bool = Query(True, description="Regrouper à l'affichage les items de titre identique (même actu multi-sources). Rien n'est supprimé — false pour la vue d'audit complète."),
    page:      int  = Query(1, ge=1),
    per_page:  int  = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
):
    q = select(WatchItem).order_by(WatchItem.received_at.desc())

    q = _apply_multi(q, WatchItem.source,   source)
    q = _apply_multi_exclude(q, WatchItem.source, exclude_source)
    q = _apply_multi(q, WatchItem.severity, severity)
    q = _apply_multi(q, WatchItem.status,   status)
    q = _apply_multi(q, WatchItem.country,  country)
    q = _apply_themes(q, themes)

    if reviewed_by:
        q = q.where(WatchItem.reviewed_by == reviewed_by)
    if date_from:
        q = q.where(WatchItem.received_at >= datetime.fromisoformat(date_from))
    if date_to:
        q = q.where(WatchItem.received_at <= datetime.fromisoformat(date_to))
    if sla_only:
        sla_threshold = datetime.now(timezone.utc) - timedelta(hours=SLA_HOURS)
        q = (
            q.where(WatchItem.severity == "critical")
            .where(WatchItem.status == "new")
            .where(WatchItem.received_at <= sla_threshold)
        )

    from services.watch_profile import load_profile_terms
    names = await _asset_names(session)
    terms = await load_profile_terms(session)

    profile_active = profile_only and terms

    # Le marquage profil (correspondance texte, mot entier sur titre + résumé) et
    # le regroupement des doublons (titre normalisé) ne s'expriment pas en SQL de
    # façon fiable : dans ces deux cas on rapatrie l'ensemble filtré et on pagine
    # en Python. Volume réel : ~2000 éléments, coût négligeable — à revoir si le
    # registre explose. Sinon, pagination SQL classique (chemin rapide).
    if group_duplicates or profile_active:
        all_rows = (await session.execute(q)).scalars().all()
        if profile_active:
            all_rows = [w for w in all_rows if _profile_matches(w, terms)]

        if group_duplicates:
            groups = _group_rows_by_title(all_rows)
            total = len(groups)
            page_groups = groups[(page - 1) * per_page: page * per_page]
            items = [_group_dict(g, names, terms) for g in page_groups]
        else:
            total = len(all_rows)
            page_rows = all_rows[(page - 1) * per_page: page * per_page]
            items = [_item_dict(w, names, terms) for w in page_rows]
    else:
        total = await session.scalar(select(func.count()).select_from(q.subquery()))
        items_db = (await session.execute(q.offset((page - 1) * per_page).limit(per_page))).scalars().all()
        items = [_item_dict(w, names, terms) for w in items_db]

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "profile_terms": terms,
        "items": items,
    }


@router.patch("/{item_id}")
async def update_watch_item(
    item_id: str,
    data: WatchUpdate,
    session: AsyncSession = Depends(get_session),
):
    item = await session.get(WatchItem, item_id)
    if not item:
        raise HTTPException(404, "Item de veille introuvable")

    if data.status is not None:
        if data.status not in ("new", "in_review", "treated", "not_applicable"):
            raise HTTPException(400, "Statut invalide — valeurs : new, in_review, treated, not_applicable")
        item.status = data.status
        if data.status in ("treated", "not_applicable") and item.reviewed_at is None:
            item.reviewed_at = datetime.now(timezone.utc)

    if data.severity is not None:
        if data.severity not in ("critical", "important", "informational"):
            raise HTTPException(400, "Sévérité invalide — valeurs : critical, important, informational")
        item.severity = data.severity

    if data.reviewed_by is not None:
        item.reviewed_by = data.reviewed_by or None
    if data.decision is not None:
        item.decision = data.decision or None
    if data.linked_cve_id is not None:
        item.linked_cve_id = data.linked_cve_id.upper() if data.linked_cve_id else None

    if data.asset_ids is not None:
        # Ne conserve que des actifs réellement existants : un id inventé ou
        # supprimé entre l'ouverture de la modale et l'enregistrement ne doit
        # pas être écrit en base.
        valid = set()
        if data.asset_ids:
            rows = (await session.execute(
                select(Asset.id).where(Asset.id.in_(data.asset_ids))
            )).scalars().all()
            valid = {str(a) for a in rows}
        item.asset_ids = [a for a in data.asset_ids if a in valid]

    await session.commit()
    await session.refresh(item)
    from services.watch_profile import load_profile_terms
    return _item_dict(item, await _asset_names(session), await load_profile_terms(session))


# ─── Profil de veille ─────────────────────────────────────────────────────────
# Ce que le parc utilise réellement (OS, logiciels), pour **mettre en avant** les
# éléments de veille qui le concernent. Ne filtre jamais la collecte ni le
# registre : cf. docstring du modèle WatchProfileItem.

@router.get("/profile")
async def get_watch_profile(session: AsyncSession = Depends(get_session)):
    """
    Profil enregistré + suggestions issues de l'inventaire réel.

    Les suggestions portent la liste des actifs où le terme a été vu (l'analyste
    doit savoir *pourquoi* on lui propose un terme) et un `selected` indiquant
    s'il fait déjà partie du profil — le frontend n'a rien à recouper lui-même.

    `categories` décrit les 5 sections possibles (label + `from_inventory`,
    cf. `services/watch_profile.PROFILE_CATEGORIES`) : le frontend s'en sert
    pour savoir lesquelles proposent des chips d'inventaire (OS/Logiciels) et
    lesquelles n'affichent que les termes déjà ajoutés à la main (Firewall/
    SaaS/Matériel), sans dupliquer cette liste côté client.
    """
    from services.watch_profile import suggestions_from_inventory, PROFILE_CATEGORIES

    rows = (await session.execute(
        select(WatchProfileItem).order_by(WatchProfileItem.kind, WatchProfileItem.value)
    )).scalars().all()
    selected = {(r.kind, r.value.lower()) for r in rows}

    suggestions = await suggestions_from_inventory(session)
    for kind, entries in suggestions.items():
        for e in entries:
            e["selected"] = (kind, e["value"].lower()) in selected

    return {
        "categories": [{"kind": k, **v} for k, v in PROFILE_CATEGORIES.items()],
        "items": [
            {"id": str(r.id), "kind": r.kind, "value": r.value,
             "origin": r.origin, "enabled": r.enabled}
            for r in rows
        ],
        "suggestions": suggestions,
    }


@router.put("/profile")
async def replace_watch_profile(
    data: WatchProfileReplace,
    session: AsyncSession = Depends(get_session),
):
    """
    Remplace le profil complet — la modale envoie l'état final des cases cochées,
    pas un diff. Plus simple à raisonner qu'une succession d'ajouts/suppressions,
    et sans risque d'état intermédiaire incohérent si l'utilisateur ferme en
    cours de route.
    """
    from services.watch_profile import PROFILE_CATEGORIES

    seen: set[tuple[str, str]] = set()
    clean: list[WatchProfileEntry] = []
    for e in data.items:
        kind = (e.kind or "").strip().lower()
        value = (e.value or "").strip()
        if kind not in PROFILE_CATEGORIES or not value:
            continue
        key = (kind, value.lower())
        if key in seen:          # doublons silencieux (même terme coché deux fois)
            continue
        seen.add(key)
        clean.append(WatchProfileEntry(kind=kind, value=value, origin=e.origin or "manual"))

    existing = (await session.execute(select(WatchProfileItem))).scalars().all()
    for row in existing:
        await session.delete(row)
    await session.flush()

    now = datetime.now(timezone.utc)
    for e in clean:
        session.add(WatchProfileItem(
            kind=e.kind, value=e.value, origin=e.origin, enabled=True, created_at=now,
        ))
    await session.commit()
    return {"count": len(clean)}


@router.get("/profile/preview-term")
async def preview_profile_term(
    term: str = Query(..., min_length=1, max_length=200),
    session: AsyncSession = Depends(get_session),
):
    """
    Confirmation en direct pendant la saisie d'un terme (modale "Profil de
    veille", session 22/07/2026) — combien d'éléments du registre le
    contiennent déjà en mot entier. Purement informatif, cf.
    `services.watch_profile.count_term_matches` : `0` ne bloque jamais l'ajout,
    ça dit juste "rien pour l'instant", pas "terme invalide".
    """
    from services.watch_profile import count_term_matches
    term = term.strip()
    return {"term": term, "count": await count_term_matches(session, term) if term else 0}
