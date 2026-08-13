"""
routers/incidents.py
Registre d'incidents de sécurité + suivi des délais légaux de notification NIS 2
(Directive, Art. 23 — cf. docstring de services/nis2_deadlines.py pour le détail des
garde-fous). Endpoints minces : toute la logique de qualification/échéances vit dans
services/nis2_deadlines.py, ce routeur ne fait que valider l'entrée, appeler le service
et commiter.

⚠️ Aucun schéma Pydantic de création/édition n'expose `requires_notification` ni les
champs `*_sent_at`/`*_sent_by` : un client qui tenterait de les forcer dans le payload
de POST/PATCH les verrait silencieusement ignorés (absents du modèle = ignorés par
Pydantic). Seuls les endpoints dédiés (qualify/unqualify/mark-sent) peuvent les poser,
et toujours avec justification/validateur obligatoires.
"""

import codecs
import csv
import io
import os
import uuid as uuidlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_deps import require_admin
from database import get_session
from models import Incident, IncidentTimelineEntry, IncidentNotificationContact, IncidentAttachment, Asset, SecurityEvent, Vulnerability, CVE, WatchItem, Crisis, AuditFinding, Audit
from services import nis2_deadlines, incident_report
from services.incident_timeline import record as record_timeline
from services.csv_safety import csv_safe
from services.incident_attachments import validate_pdf, ensure_incident_dir, incident_dir

router = APIRouter()

CATEGORIES = nis2_deadlines.CATEGORIES
SEVERITIES = nis2_deadlines.SEVERITIES
STATUSES   = nis2_deadlines.STATUSES

CATEGORY_LABELS = {
    "ransomware": "Ransomware", "data_breach": "Fuite de données", "intrusion": "Intrusion",
    "dos": "Déni de service", "phishing": "Hameçonnage", "malware": "Logiciel malveillant",
    "misconfiguration": "Erreur de configuration", "other": "Autre",
}
SEVERITY_LABELS = {"critical": "Critique", "major": "Majeur", "minor": "Mineur"}
STATUS_LABELS   = {
    "declared": "Déclaré", "in_progress": "En cours", "contained": "Contenu",
    "resolved": "Résolu", "closed": "Clôturé",
}


# ─── Schémas ──────────────────────────────────────────────────────────────────

class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    category: str
    severity: str
    status: str = "declared"
    detected_at: Optional[datetime] = None
    aware_at: datetime
    reported_by: str
    affected_asset_ids: list[str] = []
    security_event_id: Optional[int] = None
    vulnerability_id: Optional[str] = None
    watch_item_id: Optional[str] = None
    audit_finding_id: Optional[str] = None


class ResponseStepCompletion(BaseModel):
    """Une étape cochée du Plan d'action — `index` dans RESPONSE_STEPS[category]
    (frontend/src/constants/incidentPlaybooks.js), `by` l'analyste qui l'a réalisée,
    `at` quand. Remplace l'ancienne forme list[int] (indices seuls, sans attribution,
    cf. schema_patches.sql 29/07/2026)."""
    index: int
    by: str
    at: Optional[datetime] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    detected_at: Optional[datetime] = None
    reported_by: Optional[str] = None
    affected_asset_ids: Optional[list[str]] = None
    completed_response_steps: Optional[list[ResponseStepCompletion]] = None


class NoteCreate(BaseModel):
    author: str
    notes: str


class QualifyPayload(BaseModel):
    analyst: str
    justification: str


class UnqualifyPayload(BaseModel):
    analyst: str
    reason: str


class AwareAtPayload(BaseModel):
    new_aware_at: datetime
    analyst: str
    recompute: bool = False


class MilestoneSentPayload(BaseModel):
    sent_by: str
    sent_at: Optional[datetime] = None
    note: Optional[str] = None


class ContactCreate(BaseModel):
    name: str
    role: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    website_url: Optional[str] = None
    categories: list[str] = []
    notes: Optional[str] = None


class ContactUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    website_url: Optional[str] = None
    categories: Optional[list[str]] = None
    notes: Optional[str] = None


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _guard(fn):
    """Traduit un ValueError de services/nis2_deadlines.py en HTTP — 409 pour un
    conflit d'état (déjà qualifié, déjà envoyé, verrouillé), 400 pour une entrée
    invalide (justification vide, jalon inconnu)."""
    try:
        fn()
    except ValueError as e:
        msg = str(e)
        code = 409 if ("déjà" in msg or "verrouillé" in msg) else 400
        raise HTTPException(code, msg)


async def _asset_names(session: AsyncSession) -> dict[str, str]:
    rows = (await session.execute(select(Asset.id, Asset.name))).all()
    return {str(r[0]): r[1] for r in rows}


async def _crisis_titles(session: AsyncSession) -> dict[str, str]:
    """Cf. routers/crises.py — jointure légère (nom seul) pour afficher le lien
    Incident -> Crisis sans requête séparée côté frontend."""
    rows = (await session.execute(select(Crisis.id, Crisis.title))).all()
    return {str(r[0]): r[1] for r in rows}


def _incident_dict(inc: Incident, names: dict[str, str] | None = None, crisis_titles: dict[str, str] | None = None) -> dict:
    names = names or {}
    crisis_titles = crisis_titles or {}
    return {
        "id": str(inc.id),
        "title": inc.title,
        "description": inc.description,
        "category": inc.category,
        "category_label": CATEGORY_LABELS.get(inc.category, inc.category),
        "severity": inc.severity,
        "severity_label": SEVERITY_LABELS.get(inc.severity, inc.severity),
        "status": inc.status,
        "status_label": STATUS_LABELS.get(inc.status, inc.status),
        "detected_at": inc.detected_at.isoformat() if inc.detected_at else None,
        "aware_at": inc.aware_at.isoformat() if inc.aware_at else None,
        "aware_at_locked": inc.aware_at_locked,
        "reported_by": inc.reported_by,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
        "requires_notification": inc.requires_notification,
        "notification_qualified_by": inc.notification_qualified_by,
        "notification_qualified_at": inc.notification_qualified_at.isoformat() if inc.notification_qualified_at else None,
        "notification_justification": inc.notification_justification,
        "early_warning_due_at": inc.early_warning_due_at.isoformat() if inc.early_warning_due_at else None,
        "early_warning_sent_at": inc.early_warning_sent_at.isoformat() if inc.early_warning_sent_at else None,
        "early_warning_sent_by": inc.early_warning_sent_by,
        "incident_notification_due_at": inc.incident_notification_due_at.isoformat() if inc.incident_notification_due_at else None,
        "incident_notification_sent_at": inc.incident_notification_sent_at.isoformat() if inc.incident_notification_sent_at else None,
        "incident_notification_sent_by": inc.incident_notification_sent_by,
        "final_report_due_at": inc.final_report_due_at.isoformat() if inc.final_report_due_at else None,
        "final_report_sent_at": inc.final_report_sent_at.isoformat() if inc.final_report_sent_at else None,
        "final_report_sent_by": inc.final_report_sent_by,
        "security_event_id": inc.security_event_id,
        "vulnerability_id": str(inc.vulnerability_id) if inc.vulnerability_id else None,
        "watch_item_id": str(inc.watch_item_id) if inc.watch_item_id else None,
        "audit_finding_id": str(inc.audit_finding_id) if inc.audit_finding_id else None,
        "affected_asset_ids": inc.affected_asset_ids or [],
        "affected_asset_names": [names[a] for a in (inc.affected_asset_ids or []) if a in names],
        "completed_response_steps": inc.completed_response_steps or [],
        "crisis_id": str(inc.crisis_id) if inc.crisis_id else None,
        "crisis_title": crisis_titles.get(str(inc.crisis_id)) if inc.crisis_id else None,
    }


def _contact_dict(c: IncidentNotificationContact) -> dict:
    return {
        "id": str(c.id),
        "name": c.name,
        "role": c.role,
        "email": c.email,
        "phone": c.phone,
        "website_url": c.website_url,
        "categories": c.categories or [],
        "notes": c.notes,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


def _timeline_dict(e: IncidentTimelineEntry) -> dict:
    return {
        "id": str(e.id),
        "event_type": e.event_type,
        "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
        "author": e.author,
        "old_value": e.old_value,
        "new_value": e.new_value,
        "notes": e.notes,
        "meta": e.meta,
    }


def _is_overdue(inc: Incident) -> bool:
    if not inc.requires_notification:
        return False
    now = datetime.now(timezone.utc)
    pairs = [
        (inc.early_warning_due_at, inc.early_warning_sent_at),
        (inc.incident_notification_due_at, inc.incident_notification_sent_at),
        (inc.final_report_due_at, inc.final_report_sent_at),
    ]
    return any(due and not sent and now > due for due, sent in pairs)


async def _get_or_404(session: AsyncSession, incident_id: str) -> Incident:
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "Incident introuvable")
    return inc


# ─── Liste / détail / création / édition ─────────────────────────────────────

@router.get("")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    requires_notification: Optional[bool] = None,
    overdue_only: bool = Query(False),
    asset_id: Optional[str] = None,
    q: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
):
    query = select(Incident).order_by(Incident.aware_at.desc())
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    if category:
        query = query.where(Incident.category == category)
    if requires_notification is not None:
        query = query.where(Incident.requires_notification == requires_notification)

    rows = (await session.execute(query)).scalars().all()

    if asset_id:
        rows = [i for i in rows if asset_id in (i.affected_asset_ids or [])]
    if overdue_only:
        rows = [i for i in rows if _is_overdue(i)]
    if q:
        needle = q.lower()
        rows = [i for i in rows if needle in (i.title or "").lower() or needle in (i.description or "").lower()]

    total = len(rows)
    page_rows = rows[(page - 1) * per_page: page * per_page]
    names = await _asset_names(session)
    crisis_titles = await _crisis_titles(session)
    return {
        "total": total, "page": page, "per_page": per_page,
        "items": [_incident_dict(i, names, crisis_titles) for i in page_rows],
    }


@router.get("/nis2/pending-count")
async def nis2_pending_count(session: AsyncSession = Depends(get_session)):
    """Compteur léger pour un badge nav — échéances NIS 2 non envoyées, dépassées ou
    imminentes (< 24h), même mécanique que securityEventsCount() dans Layout.jsx."""
    rows = (await session.execute(
        select(Incident).where(Incident.requires_notification.is_(True))
    )).scalars().all()

    now = datetime.now(timezone.utc)
    overdue = 0
    imminent = 0
    for inc in rows:
        pairs = [
            (inc.early_warning_due_at, inc.early_warning_sent_at),
            (inc.incident_notification_due_at, inc.incident_notification_sent_at),
            (inc.final_report_due_at, inc.final_report_sent_at),
        ]
        for due, sent in pairs:
            if not due or sent:
                continue
            delta_hours = (due - now).total_seconds() / 3600
            if delta_hours < 0:
                overdue += 1
            elif delta_hours < 24:
                imminent += 1

    return {"overdue": overdue, "imminent": imminent}


@router.get("/export")
async def export_incidents(session: AsyncSession = Depends(get_session)):
    """Export CSV auditeur — même pattern que GET /api/watch/export."""
    rows = (await session.execute(select(Incident).order_by(Incident.aware_at.asc()))).scalars().all()
    names = await _asset_names(session)

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";", quoting=csv.QUOTE_ALL)
    writer.writerow([
        "Titre", "Catégorie", "Sévérité", "Statut", "Prise de connaissance",
        "Déclaré par", "À notifier NIS 2", "Alerte précoce (échéance)", "Alerte précoce (envoyée)",
        "Notification (échéance)", "Notification (envoyée)", "Rapport final (échéance)",
        "Rapport final (envoyé)", "Actifs concernés",
    ])
    for inc in rows:
        writer.writerow([
            csv_safe(inc.title),
            CATEGORY_LABELS.get(inc.category, inc.category),
            SEVERITY_LABELS.get(inc.severity, inc.severity),
            STATUS_LABELS.get(inc.status, inc.status),
            inc.aware_at.strftime("%Y-%m-%d %H:%M") if inc.aware_at else "",
            csv_safe(inc.reported_by or ""),
            "Oui" if inc.requires_notification else "Non",
            inc.early_warning_due_at.strftime("%Y-%m-%d %H:%M") if inc.early_warning_due_at else "",
            inc.early_warning_sent_at.strftime("%Y-%m-%d %H:%M") if inc.early_warning_sent_at else "",
            inc.incident_notification_due_at.strftime("%Y-%m-%d %H:%M") if inc.incident_notification_due_at else "",
            inc.incident_notification_sent_at.strftime("%Y-%m-%d %H:%M") if inc.incident_notification_sent_at else "",
            inc.final_report_due_at.strftime("%Y-%m-%d %H:%M") if inc.final_report_due_at else "",
            inc.final_report_sent_at.strftime("%Y-%m-%d %H:%M") if inc.final_report_sent_at else "",
            # csv_safe (11/08/2026, bug réel corrigé — même oubli que routers/reports.py) :
            # les noms d'actifs sont du texte libre modifiable par tout compte `analyst`.
            csv_safe(", ".join(names[a] for a in (inc.affected_asset_ids or []) if a in names)),
        ])

    csv_bytes = codecs.BOM_UTF8 + output.getvalue().encode("utf-8")
    filename = f"cybervuln-incidents-{datetime.now().strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        iter([csv_bytes]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/prefill")
async def prefill_incident(
    source_type: str = Query(..., description="security_event | vulnerability | watch_item | audit_finding"),
    source_id: str = Query(...),
    session: AsyncSession = Depends(get_session),
):
    """Suggestions de champs pour la modale de création, à partir d'un signal existant
    — lecture seule, ne crée jamais rien. La création reste un POST /incidents
    explicite après confirmation de l'analyste (cf. CLAUDE.md, non-intervention/
    décision humaine — même esprit appliqué ici à la création d'incident)."""
    if source_type == "security_event":
        event = await session.get(SecurityEvent, int(source_id))
        if not event:
            raise HTTPException(404, "Événement de sécurité introuvable")
        return {
            "title": f"Alerte déception — {event.source} sur {event.object_name or 'objet leurre'}",
            "description": f"Opération `{event.operation}` par le rôle `{event.db_user}`"
                           + (f" depuis {event.client_addr}" if event.client_addr else "") + ".",
            "category": "intrusion",
            "severity": "major",
            "aware_at": (event.occurred_at or datetime.now(timezone.utc)).isoformat(),
            "affected_asset_ids": [],
            "security_event_id": event.id,
        }

    if source_type == "vulnerability":
        vuln = await session.get(Vulnerability, source_id)
        if not vuln:
            raise HTTPException(404, "Vulnérabilité introuvable")
        cve = await session.get(CVE, vuln.cve_id)
        asset = await session.get(Asset, vuln.asset_id)
        sev = (cve.severity if cve else "") or ""
        severity = "critical" if sev in ("CRITICAL", "HIGH") else "major" if sev == "MEDIUM" else "minor"
        return {
            "title": f"{cve.cve_id if cve else 'CVE inconnue'} sur {asset.name if asset else 'actif inconnu'}",
            "description": (cve.description if cve else "") or "",
            "category": "intrusion",
            "severity": severity,
            "aware_at": datetime.now(timezone.utc).isoformat(),
            "affected_asset_ids": [str(vuln.asset_id)] if vuln.asset_id else [],
            "vulnerability_id": str(vuln.id),
        }

    if source_type == "watch_item":
        item = await session.get(WatchItem, source_id)
        if not item:
            raise HTTPException(404, "Item de veille introuvable")
        severity = "critical" if item.severity == "critical" else "major" if item.severity == "important" else "minor"
        return {
            "title": item.title,
            "description": item.summary or "",
            "category": "other",
            "severity": severity,
            "aware_at": (item.received_at or datetime.now(timezone.utc)).isoformat(),
            "affected_asset_ids": item.asset_ids or [],
            "watch_item_id": str(item.id),
        }

    if source_type == "audit_finding":
        finding = await session.get(AuditFinding, source_id)
        if not finding:
            raise HTTPException(404, "Finding d'audit introuvable")
        audit = await session.get(Audit, finding.audit_id)
        severity = "critical" if finding.severity in ("CRITICAL", "HIGH") else "major" if finding.severity == "MEDIUM" else "minor"
        description = "\n\n".join(x for x in [
            finding.description,
            f"**Impact** : {finding.impact}" if finding.impact else None,
            f"**Preuve de concept** : {finding.proof_of_concept}" if finding.proof_of_concept else None,
        ] if x)
        return {
            "title": f"Finding audit — {finding.title}",
            "description": description,
            "category": "intrusion",
            "severity": severity,
            "aware_at": datetime.now(timezone.utc).isoformat(),
            "affected_asset_ids": [str(finding.affected_asset_id)] if finding.affected_asset_id else [],
            "audit_finding_id": str(finding.id),
            "_audit_title": audit.title if audit else None,
        }

    raise HTTPException(400, "source_type invalide — valeurs : security_event, vulnerability, watch_item, audit_finding")


# ─── Contacts personnalisés (roadmap) ─────────────────────────────────────────
# Routes littérales déclarées avant `/{incident_id}` : sinon FastAPI matcherait
# "notification-contacts" comme un incident_id (le premier pattern enregistré
# gagne) — même raison que /prefill, /export, /nis2/pending-count ci-dessus.

@router.get("/notification-contacts")
async def list_notification_contacts(session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(IncidentNotificationContact).order_by(IncidentNotificationContact.name)
    )).scalars().all()
    return {"items": [_contact_dict(c) for c in rows]}


@router.post("/notification-contacts", status_code=201)
async def create_notification_contact(data: ContactCreate, session: AsyncSession = Depends(get_session)):
    contact = IncidentNotificationContact(
        name=data.name, role=data.role, email=data.email, phone=data.phone,
        website_url=data.website_url, categories=data.categories, notes=data.notes,
    )
    session.add(contact)
    await session.commit()
    await session.refresh(contact)
    return _contact_dict(contact)


@router.patch("/notification-contacts/{contact_id}")
async def update_notification_contact(contact_id: str, data: ContactUpdate, session: AsyncSession = Depends(get_session)):
    contact = await session.get(IncidentNotificationContact, contact_id)
    if not contact:
        raise HTTPException(404, "Contact introuvable")
    if data.name is not None:
        contact.name = data.name
    if data.role is not None:
        contact.role = data.role
    if data.email is not None:
        contact.email = data.email
    if data.phone is not None:
        contact.phone = data.phone
    if data.website_url is not None:
        contact.website_url = data.website_url
    if data.categories is not None:
        contact.categories = data.categories
    if data.notes is not None:
        contact.notes = data.notes
    await session.commit()
    await session.refresh(contact)
    return _contact_dict(contact)


@router.delete("/notification-contacts/{contact_id}", status_code=204)
async def delete_notification_contact(contact_id: str, session: AsyncSession = Depends(get_session)):
    contact = await session.get(IncidentNotificationContact, contact_id)
    if not contact:
        raise HTTPException(404, "Contact introuvable")
    await session.delete(contact)
    await session.commit()


@router.get("/{incident_id}")
async def get_incident(incident_id: str, session: AsyncSession = Depends(get_session)):
    inc = await _get_or_404(session, incident_id)
    return _incident_dict(inc, await _asset_names(session), await _crisis_titles(session))


@router.delete("/{incident_id}", status_code=204)
async def delete_incident(incident_id: str, session: AsyncSession = Depends(get_session), _admin=Depends(require_admin)):
    """Suppression demandée explicitement par l'utilisateur (confirmation côté UI) — efface
    aussi la timeline (ON DELETE CASCADE). Contrairement à SecurityEvent (jamais supprimable,
    trace d'intrusion), un incident mal saisi ou de test doit pouvoir être retiré du registre ;
    la prudence porte sur la confirmation avant l'appel, pas sur l'absence de l'opération.
    Réservé admin (03/08/2026, audit sécurité) : la suppression efface aussi la timeline
    append-only, un compte analyst ne doit pas pouvoir la faire disparaître seul."""
    inc = await _get_or_404(session, incident_id)
    await session.delete(inc)
    await session.commit()


@router.post("", status_code=201)
async def create_incident(data: IncidentCreate, session: AsyncSession = Depends(get_session)):
    if data.category not in CATEGORIES:
        raise HTTPException(400, f"Catégorie invalide — valeurs : {', '.join(CATEGORIES)}")
    if data.severity not in SEVERITIES:
        raise HTTPException(400, f"Sévérité invalide — valeurs : {', '.join(SEVERITIES)}")
    if data.status not in STATUSES:
        raise HTTPException(400, f"Statut invalide — valeurs : {', '.join(STATUSES)}")

    valid_assets = set()
    if data.affected_asset_ids:
        found = (await session.execute(select(Asset.id).where(Asset.id.in_(data.affected_asset_ids)))).scalars().all()
        valid_assets = {str(a) for a in found}

    inc = Incident(
        title=data.title,
        description=data.description,
        category=data.category,
        severity=data.severity,
        status=data.status,
        detected_at=data.detected_at,
        aware_at=data.aware_at,
        reported_by=data.reported_by,
        affected_asset_ids=[a for a in data.affected_asset_ids if a in valid_assets],
        security_event_id=data.security_event_id,
        vulnerability_id=data.vulnerability_id,
        watch_item_id=data.watch_item_id,
        audit_finding_id=data.audit_finding_id,
    )
    session.add(inc)
    await session.flush()  # incident.id posé avant l'entrée de timeline (FK)
    record_timeline(session, inc.id, "created", data.reported_by, new_value=data.status)
    await session.commit()
    await session.refresh(inc)
    return _incident_dict(inc, await _asset_names(session))


@router.patch("/{incident_id}")
async def update_incident(incident_id: str, data: IncidentUpdate, session: AsyncSession = Depends(get_session)):
    inc = await _get_or_404(session, incident_id)

    if data.category is not None and data.category not in CATEGORIES:
        raise HTTPException(400, f"Catégorie invalide — valeurs : {', '.join(CATEGORIES)}")
    if data.severity is not None and data.severity not in SEVERITIES:
        raise HTTPException(400, f"Sévérité invalide — valeurs : {', '.join(SEVERITIES)}")
    if data.status is not None and data.status not in STATUSES:
        raise HTTPException(400, f"Statut invalide — valeurs : {', '.join(STATUSES)}")

    if data.status is not None and data.status != inc.status:
        record_timeline(session, inc.id, "status_change", data.reported_by or inc.reported_by,
                         old_value=inc.status, new_value=data.status)
        inc.status = data.status

    if data.title is not None:
        inc.title = data.title
    if data.description is not None:
        inc.description = data.description
    if data.category is not None:
        inc.category = data.category
    if data.severity is not None:
        inc.severity = data.severity
    if data.detected_at is not None:
        inc.detected_at = data.detected_at
    if data.reported_by is not None:
        inc.reported_by = data.reported_by
    if data.affected_asset_ids is not None:
        valid = set()
        if data.affected_asset_ids:
            found = (await session.execute(select(Asset.id).where(Asset.id.in_(data.affected_asset_ids)))).scalars().all()
            valid = {str(a) for a in found}
        inc.affected_asset_ids = [a for a in data.affected_asset_ids if a in valid]
    if data.completed_response_steps is not None:
        inc.completed_response_steps = [
            {"index": s.index, "by": s.by, "at": (s.at or datetime.now(timezone.utc)).isoformat()}
            for s in data.completed_response_steps
        ]

    inc.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(inc)
    return _incident_dict(inc, await _asset_names(session))


@router.get("/{incident_id}/timeline")
async def get_incident_timeline(incident_id: str, session: AsyncSession = Depends(get_session)):
    await _get_or_404(session, incident_id)
    rows = (await session.execute(
        select(IncidentTimelineEntry)
        .where(IncidentTimelineEntry.incident_id == incident_id)
        .order_by(IncidentTimelineEntry.occurred_at.asc())
    )).scalars().all()
    return {"entries": [_timeline_dict(e) for e in rows]}


@router.get("/{incident_id}/report")
async def get_incident_report(incident_id: str, session: AsyncSession = Depends(get_session)):
    inc = await _get_or_404(session, incident_id)
    summary = await incident_report.build_incident_report(session, inc)
    return {"summary": summary}


@router.post("/{incident_id}/notes")
async def add_incident_note(incident_id: str, data: NoteCreate, session: AsyncSession = Depends(get_session)):
    inc = await _get_or_404(session, incident_id)
    record_timeline(session, inc.id, "note", data.author, notes=data.notes)
    await session.commit()
    rows = (await session.execute(
        select(IncidentTimelineEntry)
        .where(IncidentTimelineEntry.incident_id == incident_id)
        .order_by(IncidentTimelineEntry.occurred_at.asc())
    )).scalars().all()
    return {"entries": [_timeline_dict(e) for e in rows]}


# ─── Qualification NIS 2 / échéances ──────────────────────────────────────────

@router.post("/{incident_id}/qualify-notification")
async def qualify_notification(incident_id: str, data: QualifyPayload, session: AsyncSession = Depends(get_session)):
    inc = await _get_or_404(session, incident_id)
    _guard(lambda: nis2_deadlines.qualify_for_notification(session, inc, data.analyst, data.justification))
    await session.commit()
    await session.refresh(inc)
    return _incident_dict(inc, await _asset_names(session))


@router.post("/{incident_id}/unqualify-notification")
async def unqualify_notification(incident_id: str, data: UnqualifyPayload, session: AsyncSession = Depends(get_session)):
    inc = await _get_or_404(session, incident_id)
    _guard(lambda: nis2_deadlines.unqualify_notification(session, inc, data.analyst, data.reason))
    await session.commit()
    await session.refresh(inc)
    return _incident_dict(inc, await _asset_names(session))


@router.post("/{incident_id}/aware-at")
async def set_aware_at(incident_id: str, data: AwareAtPayload, session: AsyncSession = Depends(get_session)):
    inc = await _get_or_404(session, incident_id)
    _guard(lambda: nis2_deadlines.change_aware_at(session, inc, data.new_aware_at, data.analyst, data.recompute))
    await session.commit()
    await session.refresh(inc)
    return _incident_dict(inc, await _asset_names(session))


@router.post("/{incident_id}/milestones/{milestone}/mark-sent")
async def mark_milestone_sent(
    incident_id: str, milestone: str, data: MilestoneSentPayload, session: AsyncSession = Depends(get_session),
):
    inc = await _get_or_404(session, incident_id)
    _guard(lambda: nis2_deadlines.mark_milestone_sent(
        session, inc, milestone, data.sent_by, sent_at=data.sent_at, note=data.note,
    ))
    await session.commit()
    await session.refresh(inc)
    return _incident_dict(inc, await _asset_names(session))


# ─── Pièces jointes PDF (rapport final) ───────────────────────────────────────

def _attachment_dict(a: IncidentAttachment) -> dict:
    return {
        "id": str(a.id),
        "milestone": a.milestone,
        "filename": a.filename,
        "size_bytes": a.size_bytes,
        "uploaded_by": a.uploaded_by,
        "uploaded_at": a.uploaded_at.isoformat() if a.uploaded_at else None,
    }


@router.get("/{incident_id}/attachments")
async def list_incident_attachments(incident_id: str, session: AsyncSession = Depends(get_session)):
    await _get_or_404(session, incident_id)
    rows = (await session.execute(
        select(IncidentAttachment).where(IncidentAttachment.incident_id == incident_id)
        .order_by(IncidentAttachment.uploaded_at.asc())
    )).scalars().all()
    return {"items": [_attachment_dict(a) for a in rows]}


@router.post("/{incident_id}/attachments", status_code=201)
async def upload_incident_attachment(
    incident_id: str,
    file: UploadFile = File(...),
    uploaded_by: str = Form(...),
    milestone: str = Form("final_report"),
    session: AsyncSession = Depends(get_session),
):
    await _get_or_404(session, incident_id)
    content = await file.read()
    try:
        validate_pdf(content, file.filename or "")
    except ValueError as e:
        raise HTTPException(400, str(e))

    stored_filename = f"{uuidlib.uuid4()}.pdf"
    dir_path = ensure_incident_dir(incident_id)
    with open(os.path.join(dir_path, stored_filename), "wb") as f:
        f.write(content)

    attachment = IncidentAttachment(
        incident_id=incident_id, milestone=milestone, filename=file.filename,
        stored_filename=stored_filename, size_bytes=len(content), uploaded_by=uploaded_by,
    )
    session.add(attachment)
    await session.commit()
    await session.refresh(attachment)
    return _attachment_dict(attachment)


@router.get("/{incident_id}/attachments/{attachment_id}/download")
async def download_incident_attachment(incident_id: str, attachment_id: str, session: AsyncSession = Depends(get_session)):
    attachment = await session.get(IncidentAttachment, attachment_id)
    if not attachment or str(attachment.incident_id) != incident_id:
        raise HTTPException(404, "Pièce jointe introuvable")
    path = os.path.join(incident_dir(incident_id), attachment.stored_filename)
    if not os.path.isfile(path):
        raise HTTPException(404, "Fichier introuvable sur le disque")
    return FileResponse(path, media_type="application/pdf", filename=attachment.filename)


@router.delete("/{incident_id}/attachments/{attachment_id}", status_code=204)
async def delete_incident_attachment(incident_id: str, attachment_id: str, session: AsyncSession = Depends(get_session)):
    attachment = await session.get(IncidentAttachment, attachment_id)
    if not attachment or str(attachment.incident_id) != incident_id:
        raise HTTPException(404, "Pièce jointe introuvable")
    path = os.path.join(incident_dir(incident_id), attachment.stored_filename)
    if os.path.isfile(path):
        os.remove(path)
    await session.delete(attachment)
    await session.commit()
