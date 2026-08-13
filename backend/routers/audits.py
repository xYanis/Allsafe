"""
routers/audits.py
Module Audits (03/08/2026, cf. docs/AUDITS.md) — hub de suivi des audits techniques
(architecture/configuration/code/pentest/redteam). CBR héberge et trace l'audit, ne l'exécute
jamais : aucun scan, aucun outil offensif — seuls les résultats rédigés à la main entrent.

⚠️ Garde-fou central : aucun finding ne peut être saisi tant que `audit.status == "cadrage"`
(POST /audits/{id}/findings le refuse en 403). L'autorisation (`scope`/`rules_of_engagement`/
`authorized_by`/`authorized_at`) ne se pose qu'une fois, via POST /audits/{id}/authorize —
`AuditUpdate` n'expose volontairement pas ces 4 champs (même trick que
routers/incidents.py pour `requires_notification`) : absents du schéma Pydantic, un client qui
tenterait de les forcer dans un PATCH les verrait silencieusement ignorés.

⚠️ Ordre de déclaration des routes : /findings et /findings/open-unretested-count sont
déclarées AVANT /{audit_id} — même piège que /crises/contacts et /incidents/notification-
contacts (FastAPI matcherait sinon "findings" comme un audit_id).
"""

import os
import uuid as uuidlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_admin
from database import get_session
from models import Audit, AuditAsset, AuditAttachment, AuditFinding, AuditFindingHistory, Asset
from services import audit_finding_history, audit_report
from services.audit_attachments import validate_attachment, ensure_audit_dir, audit_dir

router = APIRouter()

AUDIT_TYPES      = ["architecture", "configuration", "code", "pentest", "redteam"]
METHODOLOGIES    = ["boite_noire", "boite_grise", "boite_blanche"]
AUDIT_STATUSES   = ["cadrage", "autorise", "en_cours", "termine", "archive"]
FINDING_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
FINDING_STATUSES   = ["ouvert", "remediation_planifiee", "corrige", "risque_accepte", "faux_positif"]
RETEST_RESULTS      = ["corrige", "partiellement_corrige", "non_corrige"]

CONTENT_TYPES = {".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}


# ─── Schémas ──────────────────────────────────────────────────────────────────

class AuditCreate(BaseModel):
    title: str
    type: str
    methodology: Optional[str] = None
    referential: Optional[str] = None
    conducted_by: Optional[str] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    asset_ids: list[str] = []


class AuditUpdate(BaseModel):
    title: Optional[str] = None
    type: Optional[str] = None
    methodology: Optional[str] = None
    referential: Optional[str] = None
    status: Optional[str] = None
    conducted_by: Optional[str] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    executive_summary: Optional[str] = None


class AuthorizePayload(BaseModel):
    scope: str
    rules_of_engagement: str
    authorized_by: str
    authorized_at: datetime


class FindingCreate(BaseModel):
    author: str   # qui saisit le finding — trace la 1re entrée d'audit_finding_history
    title: str
    description: Optional[str] = None
    severity: str
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    owasp_ref: Optional[str] = None
    affected_asset_id: Optional[str] = None
    affected_component: Optional[str] = None
    cve_id: Optional[str] = None
    proof_of_concept: Optional[str] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    status: str = "ouvert"
    mitre_techniques: list[str] = []
    discovered_at: Optional[datetime] = None


class FindingUpdate(BaseModel):
    author: Optional[str] = None   # requis si `status` change (traçabilité de la transition)
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    owasp_ref: Optional[str] = None
    affected_asset_id: Optional[str] = None
    affected_component: Optional[str] = None
    cve_id: Optional[str] = None
    proof_of_concept: Optional[str] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    status: Optional[str] = None
    mitre_techniques: Optional[list[str]] = None


class RetestPayload(BaseModel):
    retested_at: Optional[datetime] = None
    retest_result: str
    retested_by: str


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _get_audit_or_404(session: AsyncSession, audit_id: str) -> Audit:
    audit = await session.get(Audit, audit_id)
    if not audit:
        raise HTTPException(404, "Audit introuvable")
    return audit


async def _get_finding_or_404(session: AsyncSession, audit_id: str, finding_id: str) -> AuditFinding:
    finding = await session.get(AuditFinding, finding_id)
    if not finding or str(finding.audit_id) != audit_id:
        raise HTTPException(404, "Finding introuvable")
    return finding


async def _asset_names(session: AsyncSession) -> dict[str, str]:
    rows = (await session.execute(select(Asset.id, Asset.name))).all()
    return {str(r[0]): r[1] for r in rows}


async def _finding_summary(session: AsyncSession, audit_ids: list[str]) -> dict[str, dict]:
    """Compteurs de findings par audit — utilisés par la liste (§ badges par sévérité) et
    le signal "terminé sans retest". Une seule requête groupée plutôt qu'une par audit."""
    if not audit_ids:
        return {}
    rows = (await session.execute(
        select(AuditFinding.audit_id, AuditFinding.severity, AuditFinding.status, AuditFinding.retested_at)
        .where(AuditFinding.audit_id.in_(audit_ids))
    )).all()
    out: dict[str, dict] = {aid: {"total": 0, "by_severity": {}, "open": 0, "unretested_closed": 0} for aid in audit_ids}
    for audit_id, severity, status, retested_at in rows:
        s = out[str(audit_id)]
        s["total"] += 1
        s["by_severity"][severity] = s["by_severity"].get(severity, 0) + 1
        if status == "ouvert":
            s["open"] += 1
        if status in ("corrige", "risque_accepte") and not retested_at:
            s["unretested_closed"] += 1
    return out


def _audit_dict(a: Audit, asset_ids: list[str] | None = None, asset_names: dict[str, str] | None = None, summary: dict | None = None) -> dict:
    asset_ids = asset_ids or []
    asset_names = asset_names or {}
    summary = summary or {"total": 0, "by_severity": {}, "open": 0, "unretested_closed": 0}
    return {
        "id": str(a.id),
        "title": a.title,
        "type": a.type,
        "methodology": a.methodology,
        "referential": a.referential,
        "status": a.status,
        "scope": a.scope,
        "rules_of_engagement": a.rules_of_engagement,
        "authorized_by": a.authorized_by,
        "authorized_at": a.authorized_at.isoformat() if a.authorized_at else None,
        "conducted_by": a.conducted_by,
        "started_at": a.started_at.isoformat() if a.started_at else None,
        "ended_at": a.ended_at.isoformat() if a.ended_at else None,
        "executive_summary": a.executive_summary,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "asset_ids": asset_ids,
        "asset_names": [asset_names[i] for i in asset_ids if i in asset_names],
        "findings_total": summary["total"],
        "findings_by_severity": summary["by_severity"],
        "findings_open": summary["open"],
        "findings_unretested_closed": summary["unretested_closed"],
    }


def _finding_dict(f: AuditFinding, asset_names: dict[str, str] | None = None) -> dict:
    asset_names = asset_names or {}
    return {
        "id": str(f.id),
        "audit_id": str(f.audit_id),
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "cvss_vector": f.cvss_vector,
        "cvss_score": f.cvss_score,
        "cwe_id": f.cwe_id,
        "owasp_ref": f.owasp_ref,
        "affected_asset_id": str(f.affected_asset_id) if f.affected_asset_id else None,
        "affected_asset_name": asset_names.get(str(f.affected_asset_id)) if f.affected_asset_id else None,
        "affected_component": f.affected_component,
        "cve_id": f.cve_id,
        "proof_of_concept": f.proof_of_concept,
        "impact": f.impact,
        "recommendation": f.recommendation,
        "status": f.status,
        "mitre_techniques": f.mitre_techniques or [],
        "discovered_at": f.discovered_at.isoformat() if f.discovered_at else None,
        "retested_at": f.retested_at.isoformat() if f.retested_at else None,
        "retest_result": f.retest_result,
        "retested_by": f.retested_by,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


def _history_dict(h: AuditFindingHistory) -> dict:
    return {
        "id": str(h.id),
        "old_status": h.old_status,
        "new_status": h.new_status,
        "changed_at": h.changed_at.isoformat() if h.changed_at else None,
        "changed_by": h.changed_by,
        "notes": h.notes,
    }


def _attachment_dict(a: AuditAttachment) -> dict:
    return {
        "id": str(a.id),
        "audit_id": str(a.audit_id) if a.audit_id else None,
        "finding_id": str(a.finding_id) if a.finding_id else None,
        "kind": a.kind,
        "filename": a.filename,
        "size_bytes": a.size_bytes,
        "uploaded_by": a.uploaded_by,
        "uploaded_at": a.uploaded_at.isoformat() if a.uploaded_at else None,
    }


async def _upload_attachment(session, content: bytes, filename: str, uploaded_by: str, kind: str,
                              audit_id: str, finding_id: str | None) -> AuditAttachment:
    try:
        ext = validate_attachment(content, filename or "")
    except ValueError as e:
        raise HTTPException(400, str(e))

    stored_filename = f"{uuidlib.uuid4()}{ext}"
    dir_path = ensure_audit_dir(audit_id)
    with open(os.path.join(dir_path, stored_filename), "wb") as f:
        f.write(content)

    attachment = AuditAttachment(
        audit_id=audit_id if kind == "mandate" else None,
        finding_id=finding_id if kind == "evidence" else None,
        kind=kind, filename=filename, stored_filename=stored_filename,
        size_bytes=len(content), uploaded_by=uploaded_by,
    )
    session.add(attachment)
    await session.commit()
    await session.refresh(attachment)
    return attachment


# ─── Findings — requêtes transverses (déclarées avant /{audit_id}) ────────────

@router.get("/findings")
async def list_findings_cross_audit(
    asset_id: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
):
    """Findings d'audit liés à un actif — alimente la fiche Actif (ScanResultModal.jsx),
    à côté des vulnérabilités. Pas de pagination : volume par actif toujours faible."""
    if not asset_id:
        raise HTTPException(400, "asset_id requis")
    rows = (await session.execute(
        select(AuditFinding, Audit.title)
        .join(Audit, Audit.id == AuditFinding.audit_id)
        .where(AuditFinding.affected_asset_id == asset_id)
        .order_by(AuditFinding.discovered_at.desc())
    )).all()
    return {"items": [{**_finding_dict(f), "audit_title": title} for f, title in rows]}


@router.get("/findings/open-unretested-count")
async def open_unretested_findings_count(session: AsyncSession = Depends(get_session)):
    """Compteur léger pour le Dashboard — findings encore ouverts sur un audit déjà
    terminé, jamais retestés (retested_at NULL). Même mécanique que
    incidents.router::nis2_pending_count."""
    count = (await session.execute(
        select(func.count(AuditFinding.id))
        .join(Audit, Audit.id == AuditFinding.audit_id)
        .where(Audit.status == "termine", AuditFinding.status == "ouvert", AuditFinding.retested_at.is_(None))
    )).scalar_one()
    return {"count": count}


# ─── Audits — liste / détail / création / édition ─────────────────────────────

@router.get("")
async def list_audits(
    status: Optional[str] = None,
    type: Optional[str] = None,
    q: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
):
    query = select(Audit).order_by(Audit.created_at.desc())
    if status:
        query = query.where(Audit.status == status)
    if type:
        query = query.where(Audit.type == type)
    rows = (await session.execute(query)).scalars().all()
    if q:
        needle = q.lower()
        rows = [a for a in rows if needle in (a.title or "").lower()]

    total = len(rows)
    page_rows = rows[(page - 1) * per_page: page * per_page]
    audit_ids = [str(a.id) for a in page_rows]

    links = (await session.execute(
        select(AuditAsset.audit_id, AuditAsset.asset_id).where(AuditAsset.audit_id.in_(audit_ids))
    )).all() if audit_ids else []
    asset_ids_by_audit: dict[str, list[str]] = {}
    for aid, asid in links:
        asset_ids_by_audit.setdefault(str(aid), []).append(str(asid))

    asset_names = await _asset_names(session)
    summary = await _finding_summary(session, audit_ids)

    return {
        "total": total, "page": page, "per_page": per_page,
        "items": [_audit_dict(a, asset_ids_by_audit.get(str(a.id), []), asset_names, summary.get(str(a.id))) for a in page_rows],
    }


@router.post("", status_code=201)
async def create_audit(data: AuditCreate, session: AsyncSession = Depends(get_session)):
    if data.type not in AUDIT_TYPES:
        raise HTTPException(400, f"Type invalide — valeurs : {', '.join(AUDIT_TYPES)}")
    if data.methodology and data.methodology not in METHODOLOGIES:
        raise HTTPException(400, f"Méthodologie invalide — valeurs : {', '.join(METHODOLOGIES)}")

    valid_assets = set()
    if data.asset_ids:
        found = (await session.execute(select(Asset.id).where(Asset.id.in_(data.asset_ids)))).scalars().all()
        valid_assets = {str(a) for a in found}

    audit = Audit(
        title=data.title, type=data.type, methodology=data.methodology, referential=data.referential,
        conducted_by=data.conducted_by, started_at=data.started_at, ended_at=data.ended_at,
    )
    session.add(audit)
    await session.flush()

    linked_ids = [aid for aid in data.asset_ids if aid in valid_assets]
    for aid in linked_ids:
        session.add(AuditAsset(audit_id=audit.id, asset_id=aid))

    await session.commit()
    await session.refresh(audit)
    return _audit_dict(audit, linked_ids, await _asset_names(session))


@router.get("/{audit_id}")
async def get_audit(audit_id: str, session: AsyncSession = Depends(get_session)):
    audit = await _get_audit_or_404(session, audit_id)
    asset_ids = (await session.execute(
        select(AuditAsset.asset_id).where(AuditAsset.audit_id == audit_id)
    )).scalars().all()
    asset_ids = [str(a) for a in asset_ids]
    summary = (await _finding_summary(session, [audit_id])).get(audit_id)
    return _audit_dict(audit, asset_ids, await _asset_names(session), summary)


@router.patch("/{audit_id}")
async def update_audit(audit_id: str, data: AuditUpdate, session: AsyncSession = Depends(get_session)):
    audit = await _get_audit_or_404(session, audit_id)

    if data.type is not None and data.type not in AUDIT_TYPES:
        raise HTTPException(400, f"Type invalide — valeurs : {', '.join(AUDIT_TYPES)}")
    if data.methodology is not None and data.methodology not in METHODOLOGIES:
        raise HTTPException(400, f"Méthodologie invalide — valeurs : {', '.join(METHODOLOGIES)}")
    if data.status is not None:
        if data.status not in AUDIT_STATUSES:
            raise HTTPException(400, f"Statut invalide — valeurs : {', '.join(AUDIT_STATUSES)}")
        if data.status == "cadrage":
            raise HTTPException(400, "Retour à « cadrage » impossible")
        if data.status == "autorise":
            raise HTTPException(400, "Utiliser POST /audits/{id}/authorize (champs de mandat requis)")
        if audit.status == "cadrage":
            raise HTTPException(403, "Audit non autorisé — passer par POST /audits/{id}/authorize d'abord")
        audit.status = data.status

    if data.title is not None:
        audit.title = data.title
    if data.type is not None:
        audit.type = data.type
    if data.methodology is not None:
        audit.methodology = data.methodology
    if data.referential is not None:
        audit.referential = data.referential
    if data.conducted_by is not None:
        audit.conducted_by = data.conducted_by
    if data.started_at is not None:
        audit.started_at = data.started_at
    if data.ended_at is not None:
        audit.ended_at = data.ended_at
    if data.executive_summary is not None:
        audit.executive_summary = data.executive_summary

    await session.commit()
    await session.refresh(audit)
    asset_ids = [str(a) for a in (await session.execute(
        select(AuditAsset.asset_id).where(AuditAsset.audit_id == audit_id)
    )).scalars().all()]
    return _audit_dict(audit, asset_ids, await _asset_names(session))


@router.delete("/{audit_id}", status_code=204)
async def delete_audit(audit_id: str, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    """Réservé admin (03/08/2026, audit sécurité) : efface en cascade les findings et leur
    historique de statut, y compris sur un audit `termine`/`archive` — même raison que
    delete_incident."""
    audit = await _get_audit_or_404(session, audit_id)
    await session.delete(audit)
    await session.commit()


@router.post("/{audit_id}/authorize")
async def authorize_audit(audit_id: str, data: AuthorizePayload, session: AsyncSession = Depends(get_session)):
    audit = await _get_audit_or_404(session, audit_id)
    if audit.authorized_by or audit.authorized_at:
        raise HTTPException(409, "Audit déjà autorisé — ces champs sont immuables")
    if not data.scope.strip() or not data.rules_of_engagement.strip() or not data.authorized_by.strip():
        raise HTTPException(400, "Périmètre, règles d'engagement et mandataire sont requis")

    audit.scope = data.scope
    audit.rules_of_engagement = data.rules_of_engagement
    audit.authorized_by = data.authorized_by
    audit.authorized_at = data.authorized_at
    audit.status = "autorise"
    await session.commit()
    await session.refresh(audit)
    asset_ids = [str(a) for a in (await session.execute(
        select(AuditAsset.asset_id).where(AuditAsset.audit_id == audit_id)
    )).scalars().all()]
    return _audit_dict(audit, asset_ids, await _asset_names(session))


@router.post("/{audit_id}/assets/{asset_id}", status_code=201)
async def link_audit_asset(audit_id: str, asset_id: str, session: AsyncSession = Depends(get_session)):
    await _get_audit_or_404(session, audit_id)
    if not await session.get(Asset, asset_id):
        raise HTTPException(404, "Actif introuvable")
    existing = await session.get(AuditAsset, {"audit_id": audit_id, "asset_id": asset_id})
    if not existing:
        session.add(AuditAsset(audit_id=audit_id, asset_id=asset_id))
        await session.commit()
    return {"ok": True}


@router.delete("/{audit_id}/assets/{asset_id}", status_code=204)
async def unlink_audit_asset(audit_id: str, asset_id: str, session: AsyncSession = Depends(get_session)):
    link = await session.get(AuditAsset, {"audit_id": audit_id, "asset_id": asset_id})
    if link:
        await session.delete(link)
        await session.commit()


# ─── Findings ──────────────────────────────────────────────────────────────────

@router.get("/{audit_id}/findings")
async def list_audit_findings(audit_id: str, session: AsyncSession = Depends(get_session)):
    await _get_audit_or_404(session, audit_id)
    rows = (await session.execute(
        select(AuditFinding).where(AuditFinding.audit_id == audit_id).order_by(AuditFinding.discovered_at.asc())
    )).scalars().all()
    names = await _asset_names(session)  # une requête pour la liste, pas une par finding
    return {"items": [_finding_dict(f, names) for f in rows]}


@router.post("/{audit_id}/findings", status_code=201)
async def create_audit_finding(audit_id: str, data: FindingCreate, session: AsyncSession = Depends(get_session)):
    audit = await _get_audit_or_404(session, audit_id)
    if audit.status == "cadrage":
        raise HTTPException(403, "Audit non autorisé — aucun finding ne peut être saisi avant autorisation")
    if data.severity not in FINDING_SEVERITIES:
        raise HTTPException(400, f"Sévérité invalide — valeurs : {', '.join(FINDING_SEVERITIES)}")
    if data.status not in FINDING_STATUSES:
        raise HTTPException(400, f"Statut invalide — valeurs : {', '.join(FINDING_STATUSES)}")
    if data.affected_asset_id and not await session.get(Asset, data.affected_asset_id):
        raise HTTPException(404, "Actif affecté introuvable")

    finding = AuditFinding(
        audit_id=audit_id, title=data.title, description=data.description, severity=data.severity,
        cvss_vector=data.cvss_vector, cvss_score=data.cvss_score, cwe_id=data.cwe_id, owasp_ref=data.owasp_ref,
        affected_asset_id=data.affected_asset_id, affected_component=data.affected_component, cve_id=data.cve_id,
        proof_of_concept=data.proof_of_concept, impact=data.impact, recommendation=data.recommendation,
        status=data.status, mitre_techniques=data.mitre_techniques,
        discovered_at=data.discovered_at or datetime.now(timezone.utc),
    )
    session.add(finding)
    await session.flush()
    audit_finding_history.record(session, finding.id, None, data.status, data.author, notes="Finding créé")
    await session.commit()
    await session.refresh(finding)
    return _finding_dict(finding, await _asset_names(session))


@router.patch("/{audit_id}/findings/{finding_id}")
async def update_audit_finding(audit_id: str, finding_id: str, data: FindingUpdate, session: AsyncSession = Depends(get_session)):
    finding = await _get_finding_or_404(session, audit_id, finding_id)

    if data.severity is not None and data.severity not in FINDING_SEVERITIES:
        raise HTTPException(400, f"Sévérité invalide — valeurs : {', '.join(FINDING_SEVERITIES)}")
    if data.status is not None and data.status not in FINDING_STATUSES:
        raise HTTPException(400, f"Statut invalide — valeurs : {', '.join(FINDING_STATUSES)}")
    if data.affected_asset_id is not None and data.affected_asset_id and not await session.get(Asset, data.affected_asset_id):
        raise HTTPException(404, "Actif affecté introuvable")

    if data.status is not None and data.status != finding.status:
        if not data.author:
            raise HTTPException(400, "L'analyste à l'origine du changement de statut est requis")
        audit_finding_history.record(session, finding.id, finding.status, data.status, data.author)
        finding.status = data.status

    for field in ("title", "description", "severity", "cvss_vector", "cvss_score", "cwe_id", "owasp_ref",
                  "affected_component", "cve_id", "proof_of_concept", "impact", "recommendation", "mitre_techniques"):
        value = getattr(data, field)
        if value is not None:
            setattr(finding, field, value)
    if data.affected_asset_id is not None:
        finding.affected_asset_id = data.affected_asset_id or None

    await session.commit()
    await session.refresh(finding)
    return _finding_dict(finding, await _asset_names(session))


@router.delete("/{audit_id}/findings/{finding_id}", status_code=204)
async def delete_audit_finding(audit_id: str, finding_id: str, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    """Réservé admin (03/08/2026, audit sécurité) — efface aussi l'historique du finding
    (ON DELETE CASCADE)."""
    finding = await _get_finding_or_404(session, audit_id, finding_id)
    await session.delete(finding)
    await session.commit()


@router.post("/{audit_id}/findings/{finding_id}/retest")
async def retest_audit_finding(audit_id: str, finding_id: str, data: RetestPayload, session: AsyncSession = Depends(get_session)):
    finding = await _get_finding_or_404(session, audit_id, finding_id)
    if data.retest_result not in RETEST_RESULTS:
        raise HTTPException(400, f"Résultat invalide — valeurs : {', '.join(RETEST_RESULTS)}")

    finding.retested_at = data.retested_at or datetime.now(timezone.utc)
    finding.retest_result = data.retest_result
    finding.retested_by = data.retested_by
    await session.commit()
    await session.refresh(finding)
    return _finding_dict(finding, await _asset_names(session))


@router.get("/{audit_id}/findings/{finding_id}/history")
async def get_finding_history(audit_id: str, finding_id: str, session: AsyncSession = Depends(get_session)):
    await _get_finding_or_404(session, audit_id, finding_id)
    rows = (await session.execute(
        select(AuditFindingHistory).where(AuditFindingHistory.finding_id == finding_id)
        .order_by(AuditFindingHistory.changed_at.asc())
    )).scalars().all()
    return {"entries": [_history_dict(h) for h in rows]}


# ─── Pièces jointes (mandat sur l'audit, preuves sur un finding) ──────────────

@router.get("/{audit_id}/attachments")
async def list_audit_attachments(audit_id: str, session: AsyncSession = Depends(get_session)):
    await _get_audit_or_404(session, audit_id)
    rows = (await session.execute(
        select(AuditAttachment).where(AuditAttachment.audit_id == audit_id).order_by(AuditAttachment.uploaded_at.asc())
    )).scalars().all()
    return {"items": [_attachment_dict(a) for a in rows]}


@router.post("/{audit_id}/attachments", status_code=201)
async def upload_audit_attachment(
    audit_id: str, file: UploadFile = File(...), uploaded_by: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    await _get_audit_or_404(session, audit_id)
    content = await file.read()
    attachment = await _upload_attachment(session, content, file.filename or "", uploaded_by, "mandate", audit_id, None)
    return _attachment_dict(attachment)


@router.post("/{audit_id}/findings/{finding_id}/attachments", status_code=201)
async def upload_finding_attachment(
    audit_id: str, finding_id: str, file: UploadFile = File(...), uploaded_by: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    await _get_finding_or_404(session, audit_id, finding_id)
    content = await file.read()
    attachment = await _upload_attachment(session, content, file.filename or "", uploaded_by, "evidence", audit_id, finding_id)
    return _attachment_dict(attachment)


@router.get("/{audit_id}/findings/{finding_id}/attachments")
async def list_finding_attachments(audit_id: str, finding_id: str, session: AsyncSession = Depends(get_session)):
    await _get_finding_or_404(session, audit_id, finding_id)
    rows = (await session.execute(
        select(AuditAttachment).where(AuditAttachment.finding_id == finding_id).order_by(AuditAttachment.uploaded_at.asc())
    )).scalars().all()
    return {"items": [_attachment_dict(a) for a in rows]}


async def _attachment_belongs_to_audit(session: AsyncSession, attachment: AuditAttachment, audit_id: str) -> bool:
    """Une pièce jointe est soit le mandat de l'audit (audit_id posé), soit la preuve d'un
    de ses findings (finding_id posé) — les deux stockées sous le même audit_dir(audit_id)."""
    if attachment.audit_id and str(attachment.audit_id) == audit_id:
        return True
    if attachment.finding_id:
        finding = await session.get(AuditFinding, attachment.finding_id)
        return bool(finding and str(finding.audit_id) == audit_id)
    return False


@router.get("/{audit_id}/attachments/{attachment_id}/download")
async def download_audit_attachment(audit_id: str, attachment_id: str, session: AsyncSession = Depends(get_session)):
    attachment = await session.get(AuditAttachment, attachment_id)
    if not attachment or not await _attachment_belongs_to_audit(session, attachment, audit_id):
        raise HTTPException(404, "Pièce jointe introuvable")
    path = os.path.join(audit_dir(audit_id), attachment.stored_filename)
    if not os.path.isfile(path):
        raise HTTPException(404, "Fichier introuvable sur le disque")
    ext = os.path.splitext(attachment.stored_filename)[1]
    return FileResponse(path, media_type=CONTENT_TYPES.get(ext, "application/octet-stream"), filename=attachment.filename)


@router.delete("/{audit_id}/attachments/{attachment_id}", status_code=204)
async def delete_audit_attachment(audit_id: str, attachment_id: str, session: AsyncSession = Depends(get_session)):
    attachment = await session.get(AuditAttachment, attachment_id)
    if not attachment or not await _attachment_belongs_to_audit(session, attachment, audit_id):
        raise HTTPException(404, "Pièce jointe introuvable")
    path = os.path.join(audit_dir(audit_id), attachment.stored_filename)
    if os.path.isfile(path):
        os.remove(path)
    await session.delete(attachment)
    await session.commit()


# ─── Rapport ────────────────────────────────────────────────────────────────

@router.get("/{audit_id}/report")
async def get_audit_report(audit_id: str, session: AsyncSession = Depends(get_session)):
    audit = await _get_audit_or_404(session, audit_id)
    summary = await audit_report.build_audit_report(session, audit)
    return {"summary": summary}
