from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete as sa_delete
from sqlalchemy.exc import IntegrityError
from typing import Optional
from database import get_session
from models import Asset, Vulnerability, NetworkStatus, CVE
from services.asset_scanner import scan_asset, apply_scan_result
from services.asset_importer import _build_cpe
from services.crypto import encrypt_password, decrypt_password
from services.scoring import recalculate_scores_for_asset
from services.cpe_matcher import get_installed_package_vulnerabilities
from services.network_protocol_check import check_all_network_assets
from services.switch_hardening import run_switch_hardening_checks
from tasks.scheduled_tasks import run_cpe_matching_for_asset_task

router = APIRouter()

# Statuts encore "à traiter" pour une vulnérabilité — mêmes que le calcul de
# `arCandidates` côté Vulnerabilities.jsx (risque accepté groupé) : patched/
# false_positive/accepted_risk ne comptent plus comme une mise à jour en
# attente (07/08/2026, cf. § pending_updates de list_assets ci-dessous).
PENDING_UPDATE_STATUSES = ("open", "in_progress", "awaiting_fix", "awaiting_fix_partial")


async def _packages_with_vulns(asset: Asset, packages: list, session: AsyncSession) -> list:
    """Annote chaque paquet installé avec les CVE déjà matchées et non résolues
    pour cet actif (`vuln_count`/`severity`/`cve_ids`) — cf.
    services/cpe_matcher.py § get_installed_package_vulnerabilities."""
    badges = await get_installed_package_vulnerabilities(asset, session)
    out = []
    for pkg in packages:
        name = pkg.get("name") if isinstance(pkg, dict) else None
        badge = badges.get(name) if name else None
        out.append({**pkg, **({
            "vuln_count": badge["count"], "severity": badge["severity"], "cve_ids": badge["cve_ids"],
        } if badge else {})})
    return out


class AssetCreate(BaseModel):
    name: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    asset_type: str = "server"
    tags: dict = {}
    cpe_list: list = []
    # Méthode de collecte active (12/08/2026, module Agents) — service_account (compte de
    # service SSH/WinRM partagé, inchangé) ou agent (poste enrôlé, cf. routers/agents.py).
    # Distinct de `source` (comment l'actif a été DÉCOUVERT), cf. models.py::Asset.
    collection_method: str = "service_account"
    # Identifiants SSH par machine — phase de test (cf. models.py). scan_username
    # n'est pas sensible (renvoyé par l'API pour préremplir le formulaire d'édition) ;
    # scan_password est write-only, jamais renvoyé, laissé vide = ne pas changer.
    scan_username: Optional[str] = None
    scan_password: Optional[str] = None


class ScanCredentials(BaseModel):
    # Identifiants ponctuels pour un scan unique, prioritaires sur les identifiants
    # stockés sur l'actif et sur la clé SSH partagée du parc — jamais stockés ni
    # journalisés. Existe pour dépanner un test one-shot sans toucher l'actif.
    username: Optional[str] = None
    password: Optional[str] = None


@router.get("")
async def list_assets(session: AsyncSession = Depends(get_session)):
    assets = (await session.execute(select(Asset).order_by(Asset.name))).scalars().all()
    counts = dict((await session.execute(
        select(Vulnerability.asset_id, func.count()).group_by(Vulnerability.asset_id)
    )).all())
    # `open_vuln_count` (11/08/2026) : même principe qu'au-dessus, filtré sur le statut
    # "open" strict — même définition que le bucket "ouvertes" du Dashboard (pas
    # in_progress/awaiting_fix, qui ont leur propre affichage ailleurs dans l'app).
    open_counts = dict((await session.execute(
        select(Vulnerability.asset_id, func.count())
        .where(Vulnerability.status == "open")
        .group_by(Vulnerability.asset_id)
    )).all())
    # Mises à jour en attente, système vs applicative (07/08/2026, cf.
    # models.py::Vulnerability § component_type) — une seule requête groupée pour
    # toute la liste, même principe que `counts` ci-dessus. Statuts "encore à
    # traiter" seulement (mêmes que la sélection risque accepté groupé côté
    # frontend) : patched/false_positive/accepted_risk ne sont plus des mises à
    # jour "en attente". `component_type` NULL (WithSecure, création manuelle,
    # ou pas encore backfillé) n'est compté dans aucun des deux — reste visible
    # via `vuln_count` global, juste pas ventilé système/application.
    pending_rows = (await session.execute(
        select(Vulnerability.asset_id, Vulnerability.component_type, func.count())
        .where(Vulnerability.status.in_(PENDING_UPDATE_STATUSES))
        .group_by(Vulnerability.asset_id, Vulnerability.component_type)
    )).all()
    pending_by_asset: dict = {}
    for asset_id, component_type, cnt in pending_rows:
        entry = pending_by_asset.setdefault(asset_id, {"system": 0, "application": 0})
        if component_type in entry:
            entry[component_type] += cnt
    # État réseau (04/08/2026, cf. services/meraki_matcher.py + services/prtg_matcher.py,
    # deux sondes désormais possibles) — une seule requête pour toute la liste, jamais une
    # par actif. `network_status` reste `None` pour un actif jamais rapproché d'aucune sonde.
    # Un même actif peut avoir une ligne par source (UNIQUE asset_id+source) : on retient la
    # plus récemment mise à jour, pas une source figée en dur — reflète l'état le plus
    # fraîchement constaté quelle que soit la sonde qui l'a remonté.
    network_rows = (await session.execute(select(NetworkStatus))).scalars().all()
    network_by_asset: dict = {}
    for row in network_rows:
        current = network_by_asset.get(row.asset_id)
        if current is None or (row.updated_at or row.last_reported_at) > (current.updated_at or current.last_reported_at):
            network_by_asset[row.asset_id] = row
    return [
        _asset_dict(a, counts.get(a.id, 0), network_by_asset.get(a.id), pending_by_asset.get(a.id), open_counts.get(a.id, 0))
        for a in assets
    ]


@router.post("/network-protocol-check/run")
async def trigger_network_protocol_check():
    """Lance le test TCP passif (Telnet/HTTP) sur tous les actifs `asset_type=
    "network"` actifs (switches/pare-feux PRTG/Meraki) — cf.
    services/network_protocol_check.py. Écrit `Asset.network_compliance`, ne
    modifie ni ne contacte rien d'autre. Déclenchement manuel pour l'instant,
    pas encore planifié (cf. STATUS.md)."""
    return await check_all_network_assets()


@router.post("/switch-hardening/run")
async def trigger_switch_hardening_check():
    """Durcissement Cisco IOS/IOS-XE (SSH credentialed, lecture seule — cf.
    services/switch_hardening.py) sur les actifs `asset_type="network"` avec
    `scan_username` renseigné. Fusionne dans `Asset.network_compliance` (ne
    l'écrase pas — cohabite avec les checks de network-protocol-check/run
    ci-dessus) et met à jour `Asset.last_scan`. Déclenchement manuel, pas
    planifié (même précédent que Meraki/PRTG/GLPI)."""
    return await run_switch_hardening_checks()


@router.get("/{asset_id}/pending-updates")
async def asset_pending_updates(asset_id: str, session: AsyncSession = Depends(get_session)):
    """Détail des vulnérabilités en attente d'un actif, ventilé système/application
    (07/08/2026, cf. PENDING_UPDATE_STATUSES ci-dessus) — alimente la modale ouverte
    au clic sur une pastille de la colonne "Mises à jour" (PendingUpdatesBadge.jsx),
    qui n'affichait jusqu'ici que le compte sans le détail (demande explicite).
    `component_type IS NULL` exclu : rien à ventiler dans un groupe qu'on ne connaît
    pas (cf. cpe_matcher.py::backfill_component_types).

    Groupe "application" : `packages` liste le(s) nom(s) de logiciel installé
    concerné(s) (ex. "7-Zip 21.07") — sans ça une CVE seule ne dit pas *quelle*
    application mettre à jour (demande explicite, même jour). Réutilise
    `get_installed_package_vulnerabilities` (déjà la source de la colonne "Apps",
    cf. `_packages_with_vulns` ci-dessous) plutôt que de refaire le matching
    paquet↔CVE une deuxième fois — juste inversé (paquet→CVE devient CVE→paquets).
    Absent/vide pour "system" : une mise à jour système ne pointe pas vers un
    paquet de `installed_packages` mais vers l'OS lui-même."""
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Actif introuvable")

    rows = (await session.execute(
        select(Vulnerability, CVE)
        .join(CVE, Vulnerability.cve_id == CVE.id)
        .where(
            Vulnerability.asset_id == asset_id,
            Vulnerability.status.in_(PENDING_UPDATE_STATUSES),
            Vulnerability.component_type.isnot(None),
        )
        .order_by(CVE.cvss_score.desc().nullslast())
    )).all()

    packages_by_cve: dict = {}
    if any(vuln.component_type == "application" for vuln, _ in rows):
        package_vulns = await get_installed_package_vulnerabilities(asset, session)
        for pkg_name, info in package_vulns.items():
            for cve_id in info["cve_ids"]:
                packages_by_cve.setdefault(cve_id, []).append(pkg_name)

    result = {"system": [], "application": []}
    for vuln, cve in rows:
        item = {
            "vuln_id": str(vuln.id),
            "cve_id": cve.cve_id,
            "severity": cve.severity,
            "cvss_score": cve.cvss_score,
            "status": vuln.status,
        }
        if vuln.component_type == "application":
            item["packages"] = packages_by_cve.get(cve.cve_id, [])
        result[vuln.component_type].append(item)
    return result


@router.post("", status_code=201)
async def create_asset(data: AssetCreate, session: AsyncSession = Depends(get_session)):
    # Cet endpoint sert uniquement à l'ajout manuel depuis l'interface — l'import AD/SSH
    # construit ses propres Asset() directement dans asset_importer.py.
    payload = data.model_dump(exclude={"scan_password"})
    asset = Asset(**payload, source="manual")
    if data.scan_password:
        asset.scan_password_encrypted = encrypt_password(data.scan_password)
    # Sans CPE, un actif ajouté manuellement ne matche jamais aucune CVE (cf. cpe_matcher.py) —
    # l'import AD/SSH dérive déjà son CPE depuis l'OS via _build_cpe(), on fait pareil ici.
    if not asset.cpe_list and asset.os:
        cpe = _build_cpe(asset.os, asset.os_version or "")
        if cpe:
            asset.cpe_list = [cpe]
    session.add(asset)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(409, f"Un actif existe déjà avec le hostname '{data.hostname}'.")
    await session.refresh(asset)
    run_cpe_matching_for_asset_task.apply_async(args=[str(asset.id)], queue='default')
    return _asset_dict(asset)


@router.put("/{asset_id}")
async def update_asset(asset_id: str, data: AssetCreate, session: AsyncSession = Depends(get_session)):
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Actif introuvable")
    updates = data.model_dump(exclude_unset=True, exclude={"scan_password"})
    for k, v in updates.items():
        setattr(asset, k, v)
    # Champ write-only : laissé vide = on conserve le mot de passe déjà enregistré.
    if data.scan_password:
        asset.scan_password_encrypted = encrypt_password(data.scan_password)
    if not asset.cpe_list and asset.os:
        cpe = _build_cpe(asset.os, asset.os_version or "")
        if cpe:
            asset.cpe_list = [cpe]
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(409, f"Un actif existe déjà avec le hostname '{data.hostname}'.")
    run_cpe_matching_for_asset_task.apply_async(args=[str(asset.id)], queue='default')
    # Rejoue le scoring si la criticité a changé — sinon le nouveau multiplicateur
    # (cf. services/scoring.py) reste invisible jusqu'au prochain scan/sync NVD.
    if "tags" in updates:
        await recalculate_scores_for_asset(asset.id, session)
    return _asset_dict(asset)


@router.post("/{asset_id}/scan")
async def scan_asset_endpoint(
    asset_id: str,
    creds: ScanCredentials = ScanCredentials(),
    session: AsyncSession = Depends(get_session),
):
    """
    Scan read-only (WinRM/SSH) : vérifie la fiabilité des infos déclarées
    (hostname, OS, version) et collecte la liste des applications installées.
    Ne modifie jamais rien sur le serveur — met juste à jour l'actif en base.

    Priorité des identifiants : `creds` du corps de requête (dépannage ponctuel) >
    identifiants stockés sur l'actif (`scan_username`/`scan_password_encrypted`) >
    clé SSH partagée du parc (SSH_USER/SSH_KEY_PATH).
    """
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Actif introuvable")
    if asset.collection_method != "service_account":
        # Sans ce garde-fou, un clic sur un actif collecté autrement (agent, ou hôte ESXi
        # depuis la sync vSphere) ouvrirait une vraie session SSH/WinRM avec des commandes
        # pensées pour Debian/RHEL/Windows contre un shell qui n'a rien à voir (BusyBox
        # ESXi...), et apply_scan_result() écraserait silencieusement le hardware/cpe_list
        # posé par la méthode de collecte réelle (13/08/2026, intégration vSphere).
        raise HTTPException(400, "Cet actif n'est pas scanné par SSH/WinRM (collection_method != service_account)")

    username = creds.username or asset.scan_username
    password = creds.password
    if not password and asset.scan_password_encrypted:
        password = decrypt_password(asset.scan_password_encrypted)

    result = await scan_asset(asset, username=username, password=password)

    # apply_scan_result (12/08/2026, extrait pour être partagé avec le push agent —
    # cf. services/asset_scanner.py::apply_scan_result et routers/agents.py::checkin) :
    # persiste le résultat sur l'actif, corrige hostname/OS/CPE si le scan les révèle plus
    # fiables que le déclaré, déclenche matching CPE + cycle patch check.
    result = await apply_scan_result(asset, result, session)

    if result.get("reachable"):
        # Reflète les CVE déjà matchées avant CE scan — celles éventuellement révélées par
        # les paquets tout juste détectés n'apparaîtront qu'après la tâche de matching
        # déclenchée dans apply_scan_result (quelques secondes, pas instantané). Spécifique
        # à cet endpoint (réponse HTTP pour l'UI) : n'a pas sa place dans apply_scan_result,
        # que le push agent utilise aussi sans avoir besoin de cette annotation.
        result["packages"] = await _packages_with_vulns(asset, result.get("packages", []), session)

    return result


@router.get("/{asset_id}/packages")
async def get_asset_packages(asset_id: str, session: AsyncSession = Depends(get_session)):
    """Liste des applications/paquets installés, collectée lors du dernier scan."""
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Actif introuvable")
    packages = await _packages_with_vulns(asset, asset.installed_packages or [], session)
    return {
        "packages": packages,
        "hardware": asset.hardware or {},
        "last_scan": asset.last_scan.isoformat() if asset.last_scan else None,
        "last_scan_result": asset.last_scan_result,
    }


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(asset_id: str, session: AsyncSession = Depends(get_session)):
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Actif introuvable")
    # Pas de ON DELETE CASCADE sur la FK — on supprime explicitement les vulnérabilités
    # liées avant l'actif, sinon la contrainte bloque la suppression.
    await session.execute(sa_delete(Vulnerability).where(Vulnerability.asset_id == asset_id))
    await session.delete(asset)
    await session.commit()


def _asset_dict(
    a: Asset, vuln_count: int = 0, network_status: Optional[NetworkStatus] = None,
    pending_updates: Optional[dict] = None, open_vuln_count: int = 0,
) -> dict:
    return {
        "id": str(a.id),
        "name": a.name,
        "hostname": a.hostname,
        "ip_address": a.ip_address,
        "os": a.os,
        "os_version": a.os_version,
        "asset_type": a.asset_type,
        "tags": a.tags,
        "cpe_list": a.cpe_list,
        "status": a.status,
        "last_scan": a.last_scan.isoformat() if a.last_scan else None,
        "source": a.source,
        "collection_method": a.collection_method,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "vuln_count": vuln_count,
        # Distinct de `vuln_count` (tous statuts confondus — utilisé par exemple pour
        # prévenir avant suppression d'actif, "X vulnérabilités seront supprimées").
        # `open_vuln_count` (11/08/2026, bug réel corrigé) : uniquement `status="open"`,
        # même agrégat groupé server-side que `vuln_count` (une requête pour tout le
        # parc, pas une par actif) — la colonne "Vulnérabilités ouvertes" d'Assets.jsx
        # le recalculait auparavant côté client depuis une liste plafonnée à 200 lignes
        # triée par score sur *tout le parc*, donnant un compte juste seulement pour les
        # actifs dont les CVE figuraient dans ce top 200 global (cf. STATUS.md).
        "open_vuln_count": open_vuln_count,
        # Ventilation système/application des vulns encore ouvertes (07/08/2026,
        # cf. PENDING_UPDATE_STATUSES ci-dessus) — {"system": 0, "application": 0}
        # par défaut sur les endpoints qui ne calculent pas cet agrégat (create/update).
        "pending_updates": pending_updates or {"system": 0, "application": 0},
        "package_count": len(a.installed_packages or []),
        # Mises à jour disponibles **indépendamment d'une CVE connue** (10/08/2026,
        # partie B de la demande du 07/08 — la A est `component_type`/`pending_updates`
        # ci-dessus, qui ne compte que des vulns déjà matchées à une CVE). Dérivé de
        # `installed_packages[].available_version`, déjà collecté côté Linux par
        # `apt list --upgradable` (cf. services/asset_scanner.py::_scan_linux) mais
        # jamais agrégé nulle part avant ce champ — jusqu'ici visible seulement en
        # ouvrant le détail des paquets un par un. Pas de colonne dédiée : calculé à
        # la volée comme `package_count` juste au-dessus, `installed_packages` est
        # déjà chargé sur ce endpoint (pas un des 3 endpoints "candidats" en
        # `load_only(raiseload=True)`).
        # ⚠️ Windows structurellement absent (impasse vérifiée en conditions réelles,
        # cf. STATUS.md) : Microsoft.Update.Session (seule API lecture-seule
        # d'énumération des mises à jour disponibles côté Windows) exige des droits
        # COM que le compte de service WinRM read-only n'a pas (`UnauthorizedAccessException,
        # 0x80070005`) — même famille de restriction que Get-WmiObject/Get-SecureBootUEFI
        # déjà documentés. Élever ses droits est écarté (contraire au principe de
        # non-intervention, CLAUDE.md) : `available_version` ne sera donc jamais posé
        # sur un paquet Windows, ce compteur reste 0 sur ce parc quoi qu'il arrive.
        "available_updates_count": sum(1 for p in (a.installed_packages or []) if p.get("available_version")),
        "last_scan_result": a.last_scan_result,
        "hardware": a.hardware,
        # Test TCP passif Telnet/HTTP sur les actifs réseau uniquement (07/08/2026,
        # cf. services/network_protocol_check.py) — None tant qu'aucun run n'a été
        # lancé, ou pour un actif serveur (concept sans objet, il a déjà `compliance`
        # dans last_scan_result via son propre scan SSH/WinRM).
        "network_compliance": a.network_compliance,
        "scan_username": a.scan_username,
        "has_scan_password": bool(a.scan_password_encrypted),
        # État réseau (Meraki, cf. services/meraki_matcher.py) — None si l'actif n'a
        # jamais été rapproché d'un équipement Meraki (couverture partielle attendue).
        "network_status": {
            "status": network_status.status,
            "last_reported_at": network_status.last_reported_at.isoformat() if network_status.last_reported_at else None,
            "source": network_status.source,
            # Uniquement renseigné par la sonde PRTG (lastup_raw/lastdown_raw) pour
            # l'instant, None pour Meraki/dormant — cf. services/prtg_matcher.py.
            "status_since": (network_status.metrics or {}).get("status_since"),
        } if network_status else None,
    }
