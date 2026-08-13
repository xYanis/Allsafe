"""
services/stats.py
Calcul des KPI (dashboard + rapports) — extrait de routers/stats.py pour être
appelable directement par d'autres routers (ex: reports.py) sans passer par le
handler FastAPI lui-même : `Depends(get_session)` n'est résolu que dans le
pipeline HTTP, l'appeler comme une fonction Python normale casse dès que la
signature change (bug rencontré : routers/reports.py appelait
`get_stats(session)` positionnellement, cassé par l'ajout du paramètre
`asset_id` en tête de signature).
"""

from datetime import date, datetime, timezone
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from models import CVE, Asset, Vulnerability


async def get_configured_asset_ids(session: AsyncSession) -> list[str]:
    """Actifs "entièrement configurés" : au moins un scan SSH/WinRM réussi avec de
    vraies données de paquets (`installed_packages` non vide) — pas un actif
    réseau (asset_type="network", Meraki/PRTG), qui n'a jamais de paquets
    installés donc déjà exclu par construction (condition asset_type gardée
    explicite quand même pour ne pas dépendre implicitement de cette seule
    corrélation). Extrait le 07/08/2026 (routers/vulnerabilities.py en a besoin
    en plus de compute_stats ci-dessous, cf. `configured_only` sur
    `GET /api/vulnerabilities`) pour ne jamais faire diverger la définition."""
    ids = (await session.execute(
        select(Asset.id).where(
            Asset.asset_type != "network",
            func.json_array_length(Asset.installed_packages) > 0,
        )
    )).scalars().all()
    return [str(i) for i in ids]


async def compute_stats(
    session: AsyncSession, asset_ids: list[str] | None = None, default_configured_only: bool = False,
) -> dict:
    """
    `asset_ids` (optionnel) : restreint tous les compteurs à ce sous-ensemble du
    parc (filtre "Actifs" du dashboard/rapports, un/plusieurs/tous) — une sélection
    explicite de l'utilisateur n'est jamais recalculée à sa place, y compris pour
    inclure des actifs réseau.

    `default_configured_only` (07/08/2026, demande explicite, dashboard
    uniquement — cf. `routers/stats.py`) : sans sélection explicite, restreint le
    périmètre par défaut aux actifs "entièrement configurés" (au moins un scan
    SSH/WinRM réussi avec de vraies données de paquets, `installed_packages` non
    vide) plutôt qu'au parc entier. Sur le parc réel au moment de la demande :
    3 actifs configurés sur 72 serveurs/postes (gitlab.aer.loc, DEPLOYAPP,
    CRAFTER), 69 jamais scannés avec succès — sans ce filtre, ces 69 gonflaient
    quand même les compteurs via leur seul CPE niveau OS (dérivé à l'import,
    indépendant du scan), des chiffres non vérifiés puisque jamais confirmés par
    un scan réel. Un actif réseau (asset_type="network", Meraki/PRTG) n'a jamais
    de paquets installés donc déjà exclu par construction — condition asset_type
    gardée explicite quand même pour ne pas dépendre implicitement de cette seule
    corrélation.

    ⚠️ Défaut `False` volontaire : `routers/reports.py::build_summary_payload`
    (rapports hebdomadaires/exécutifs, traçabilité NIS 2) appelle cette fonction
    sans le préciser — un rapport de conformité ne doit jamais rétrécir
    silencieusement son périmètre à 3 actifs sur 72 parce que le dashboard a
    changé de comportement. Seul `routers/stats.py` (dashboard) le passe à `True`.
    """
    explicit_selection = bool(asset_ids)
    assets_to_configure = None
    if not explicit_selection and default_configured_only:
        asset_ids = await get_configured_asset_ids(session)
        total_non_network = await session.scalar(
            select(func.count(Asset.id)).where(Asset.asset_type != "network")
        )
        assets_to_configure = total_non_network - len(asset_ids)

    def scoped(q):
        return q.where(Vulnerability.asset_id.in_(asset_ids)) if asset_ids else q

    # Sous-requête : CVE liées à au moins un actif du parc (ou de la sélection)
    matched_cve_ids = scoped(select(Vulnerability.cve_id).distinct()).subquery()

    today_start = datetime.combine(date.today(), datetime.min.time()).replace(tzinfo=timezone.utc)

    # "sur X actifs" reflète le périmètre effectif : sélection explicite, ou
    # périmètre "configurés" par défaut ci-dessus (dashboard) — sinon (reports.py,
    # default_configured_only=False) le parc entier hors actifs réseau, comme
    # avant l'introduction de ce paramètre.
    total_assets = len(asset_ids) if asset_ids is not None else await session.scalar(
        select(func.count(Asset.id)).where(Asset.asset_type != "network")
    )
    total_cves     = await session.scalar(select(func.count(CVE.id)).where(CVE.id.in_(matched_cve_ids)))
    critical_cves  = await session.scalar(select(func.count(CVE.id)).where(CVE.severity == "CRITICAL").where(CVE.id.in_(matched_cve_ids)))
    high_cves      = await session.scalar(select(func.count(CVE.id)).where(CVE.severity == "HIGH").where(CVE.id.in_(matched_cve_ids)))
    open_vulns     = await session.scalar(scoped(select(func.count(Vulnerability.id)).where(Vulnerability.status == "open")))
    patched_vulns  = await session.scalar(scoped(select(func.count(Vulnerability.id)).where(Vulnerability.status == "patched")))
    awaiting_vulns = await session.scalar(scoped(select(func.count(Vulnerability.id)).where(Vulnerability.status.in_(["awaiting_fix", "awaiting_fix_partial"]))))
    patched_today  = await session.scalar(scoped(
        select(func.count(Vulnerability.id))
        .where(Vulnerability.status == "patched")
        .where(Vulnerability.patched_at >= today_start)
    ))
    total_vulns    = await session.scalar(scoped(select(func.count(Vulnerability.id))))

    patch_rate = round((patched_vulns / total_vulns * 100) if total_vulns else 0, 1)
    # Même base que patch_rate (total_vulns, tous statuts confondus) pour rester
    # directement comparable côte à côte sur le dashboard.
    awaiting_rate = round((awaiting_vulns / total_vulns * 100) if total_vulns else 0, 1)

    exposed = await session.scalar(scoped(
        select(func.count(func.distinct(Vulnerability.asset_id)))
        .where(Vulnerability.status == "open")
    ))

    sev_rates = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        total_sev = await session.scalar(scoped(
            select(func.count(Vulnerability.id))
            .join(CVE, Vulnerability.cve_id == CVE.id)
            .where(CVE.severity == sev)
        ))
        patched_sev = await session.scalar(scoped(
            select(func.count(Vulnerability.id))
            .join(CVE, Vulnerability.cve_id == CVE.id)
            .where(CVE.severity == sev)
            .where(Vulnerability.status == "patched")
        ))
        sev_rates[sev.lower()] = {
            "total": total_sev or 0,
            "patched": patched_sev or 0,
            "rate": round((patched_sev / total_sev * 100) if total_sev else 0, 1),
        }

    return {
        "total_assets": total_assets,
        "exposed_assets": exposed,
        "total_cves": total_cves,
        "critical_cves": critical_cves,
        "high_cves": high_cves,
        "open_vulnerabilities": open_vulns,
        "patched_vulnerabilities": patched_vulns,
        "awaiting_fix_vulnerabilities": awaiting_vulns,
        "patched_today": patched_today,
        "patch_rate_percent": patch_rate,
        "awaiting_fix_rate_percent": awaiting_rate,
        "severity_rates": sev_rates,
        # Reflète une sélection *explicite* de l'utilisateur (filtre "Actifs" du
        # dashboard) — pas le filtrage automatique "configurés" par défaut
        # ci-dessus, qui n'est pas un choix actif de l'utilisateur.
        "asset_filter_active": explicit_selection,
        # Nombre d'actifs non-réseau jamais scannés avec succès (donc pas comptés
        # dans total_assets/les KPI ci-dessus) — None si une sélection explicite
        # est active (le concept "à configurer" ne s'applique qu'au périmètre par
        # défaut). Cf. docstring pour le détail.
        "assets_to_configure": assets_to_configure,
    }
