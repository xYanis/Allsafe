"""
identity_report.py
Contenu du rapport hebdomadaire de **Surveillance Identités**.

La mécanique hebdomadaire (semaine ISO, gel, archives, export) est commune aux
trois rapports et vit dans `services/weekly_report.py` — ce module ne produit que
le contenu propre à la surveillance, pour la fenêtre [start, end[.

Ce que ce rapport prouve, y compris (et surtout) quand il ne trouve rien : que le
périmètre déclaré a bien été surveillé sur la période. Pour un audit NIS 2,
« aucune correspondance sur 214 fuites analysées » est un résultat, pas un vide —
alors qu'une absence de rapport ne prouve rien du tout.
"""

import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import WatchItem, WatchedIdentity

logger = logging.getLogger(__name__)

KIND_LABELS = {"name": "Nom", "domain": "Domaine", "ip": "Adresse IP", "ip_range": "Plage IP"}


async def build_surveillance_payload(
    session: AsyncSession, start: datetime, end: datetime, period_label: str
) -> dict:
    """
    Rapport de surveillance pour la semaine [start, end[.

    Réutilise le moteur de correspondance de `routers/identities.py` (import
    local, même schéma que le rapport CVE avec `build_summary_payload`) plutôt
    que de le réimplémenter : deux logiques de matching finiraient par diverger,
    et l'écran Surveillance Identités et le rapport se contrediraient.

    ⚠️ Deux natures de résultat, volontairement séparées dans le rendu :
    - **fuites** : historisées, restreintes aux items reçus dans la semaine — le
      résultat est donc bien celui de la période couverte ;
    - **IP blocklistées** : les listes de blocage publiques (IPsum, Blocklist.de,
      Feodo Tracker) ne donnent que leur **état courant**, sans historique. Ce
      volet reflète donc l'instant de la génération, pas la semaine écoulée.
      Le figer reste utile (on sait ce qui était vrai ce lundi-là), mais le
      rapport doit le dire pour ne pas laisser croire à un relevé rétroactif.
    """
    from routers.identities import _leak_source_keys, _name_matches
    from services.ip_watch import find_ip_matches

    identities = (await session.execute(
        select(WatchedIdentity).where(WatchedIdentity.enabled.is_(True))
    )).scalars().all()

    leak_sources = await _leak_source_keys(session)

    # Items de fuite **reçus dans la semaine** — c'est le volume réellement
    # analysé sur la période, et ce qu'on peut affirmer avoir couvert.
    items = (await session.execute(
        select(WatchItem)
        .where(WatchItem.source.in_(leak_sources))
        .where(WatchItem.received_at >= start, WatchItem.received_at < end)
        .order_by(WatchItem.received_at.desc())
    )).scalars().all()

    names   = [i.value for i in identities if i.kind == "name"]
    domains = [i.value for i in identities if i.kind == "domain"]

    leak_matches = []
    for w in items:
        text = f"{w.title} {w.summary or ''}".lower()
        company = w.title.split(" — ", 1)[0].lower() if w.source == "ransomware-live" else None
        matched = [n for n in names if _name_matches(n, text) or (company and _name_matches(n, company))]
        matched += [d for d in domains if d in text]
        if matched:
            leak_matches.append({
                "title": w.title,
                "source_label": w.source_label or w.source,
                "url": w.url,
                "country": w.country,
                "received_at": w.received_at.isoformat() if w.received_at else None,
                "matched_identities": matched,
            })

    ip_matches = await find_ip_matches(identities) if identities else []

    by_kind: dict[str, int] = {}
    for i in identities:
        by_kind[i.kind] = by_kind.get(i.kind, 0) + 1

    stats = {
        "identities_monitored": len(identities),
        "identities_by_kind": by_kind,
        "leaks_analysed": len(items),
        "leak_matches": len(leak_matches),
        "ip_matches": len(ip_matches),
    }

    activity = {
        "identities": [{"value": i.value, "kind": i.kind} for i in identities],
        "leak_matches": leak_matches,
        "ip_matches": ip_matches,
    }

    return {
        "summary": _render_summary(stats, activity, period_label),
        "stats": stats,
        "activity": activity,
    }


def _render_summary(stats: dict, activity: dict, period_label: str) -> str:
    """
    Markdown du rapport — même grammaire que les deux autres rapports (titres,
    tableaux, gras), rendu par `ReportMarkdown.jsx`. Les niveaux sont écrits en
    majuscules (CRITIQUE / ÉLEVÉ / …) car ce composant les colore automatiquement.
    """
    L: list[str] = []
    L.append("# Rapport de surveillance — identités")
    L.append("")
    L.append(f"Surveillance Identités · Période : {period_label}")
    L.append("")

    if stats["leak_matches"]:
        niveau = "CRITIQUE"
    elif stats["ip_matches"]:
        niveau = "ÉLEVÉ"
    elif not stats["identities_monitored"]:
        # Aucune identité surveillée : ce n'est pas « rien à signaler », c'est
        # une surveillance non configurée — l'inverse d'un bon résultat.
        niveau = "MODÉRÉ"
    else:
        niveau = "FAIBLE"
    L.append(f"**Niveau d'exposition : {niveau}**")
    L.append("")

    L.append(f"## Ce qui a été surveillé — {period_label}")
    if not stats["identities_monitored"]:
        L.append("**Aucune identité surveillée n'est configurée** — la surveillance n'a rien pu couvrir "
                 "sur la période. Ajoutez au moins un nom, domaine ou plage IP dans "
                 "CyberVeille > Surveillance Identités.")
    else:
        perimetre = ", ".join(
            f"{n} {KIND_LABELS.get(k, k).lower()}{'s' if n > 1 else ''}"
            for k, n in sorted(stats["identities_by_kind"].items())
        )
        L.append(f"- **{stats['identities_monitored']}** identité(s) surveillée(s) : {perimetre}")
        L.append(f"- **{stats['leaks_analysed']}** publication(s) de fuite analysée(s) sur la période")
        L.append(f"- **{stats['leak_matches']}** correspondance(s) trouvée(s)")
    L.append("")

    L.append("## Fuites de données concernant le périmètre")
    if not stats["identities_monitored"]:
        L.append("Sans identité surveillée, aucun croisement n'a pu être fait.")
    elif not stats["leak_matches"]:
        L.append(f"**Aucune correspondance** sur les {stats['leaks_analysed']} publication(s) analysée(s) "
                 "cette semaine. Le périmètre déclaré n'apparaît dans aucune fuite publiquement rapportée.")
    else:
        L.append("| Identité | Publication | Source | Reçue le |")
        L.append("|---|---|---|---|")
        for m in activity["leak_matches"][:15]:
            titre = (m["title"] or "")[:70].replace("|", "-")
            L.append(f"| {', '.join(m['matched_identities'])} | {titre} | {m['source_label']} | {(m['received_at'] or '')[:10]} |")
        if len(activity["leak_matches"]) > 15:
            L.append(f"| *… et {len(activity['leak_matches']) - 15} de plus* | | | |")
    L.append("")

    L.append("## Adresses IP sur listes de blocage")
    L.append("*Relevé à la date de génération : les listes publiques (IPsum, Blocklist.de, Feodo "
             "Tracker) ne publient que leur état courant, sans historique — ce volet ne peut donc pas "
             "être rétroactif, contrairement au reste du rapport.*")
    L.append("")
    ip_ids = stats["identities_by_kind"].get("ip", 0) + stats["identities_by_kind"].get("ip_range", 0)
    if not ip_ids:
        L.append("Aucune adresse ni plage IP surveillée.")
    elif not stats["ip_matches"]:
        L.append("**Aucune adresse du périmètre ne figure sur les listes de blocage consultées.**")
    else:
        L.append("| Identité | Adresse IP | Liste | Détail |")
        L.append("|---|---|---|---|")
        for m in activity["ip_matches"][:15]:
            L.append(f"| {m['identity_value']} | {m['ip']} | {m['source_label']} | {m.get('detail') or '—'} |")
        if len(activity["ip_matches"]) > 15:
            L.append(f"| *… et {len(activity['ip_matches']) - 15} de plus* | | | |")
    L.append("")

    if activity["identities"]:
        L.append("## Périmètre surveillé (détail)")
        L.append("| Identité | Type |")
        L.append("|---|---|")
        for i in activity["identities"]:
            L.append(f"| {i['value']} | {KIND_LABELS.get(i['kind'], i['kind'])} |")
        L.append("")

    return "\n".join(L)
