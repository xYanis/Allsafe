from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from database import get_session
from models import CVE, Vulnerability

router = APIRouter()


@router.get("")
async def list_cves(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    search: str | None = None,
    matched_only: bool = Query(True, description="Restreindre aux CVE affectant au moins un actif du parc"),
    days: int | None = Query(None, ge=1, le=365, description="Restreindre aux CVE publiées dans les N derniers jours"),
    kev: bool = Query(False, description="Restreindre aux CVE exploitées activement (CISA KEV)"),
    msf_module: bool = Query(False, description="Restreindre aux CVE avec un module Metasploit disponible"),
    session: AsyncSession = Depends(get_session),
):
    q = select(CVE).order_by(CVE.published.desc())

    if matched_only:
        # Seules les CVE liées à au moins une vulnérabilité détectée sur le parc
        q = q.where(CVE.id.in_(select(Vulnerability.cve_id).distinct()))

    if severity:
        q = q.where(CVE.severity == severity.upper())
    if search:
        q = q.where(or_(
            CVE.cve_id.ilike(f"%{search}%"),
            CVE.description.ilike(f"%{search}%"),
        ))
    if days:
        q = q.where(CVE.published >= datetime.now(timezone.utc) - timedelta(days=days))
    # KEV/maturité d'exploit (17/08/2026) : filtres booléens, s'appuient sur les index
    # partiels posés dans schema_patches.sql (idx_cves_kev/idx_cves_msf_module).
    if kev:
        q = q.where(CVE.kev.is_(True))
    if msf_module:
        q = q.where(CVE.msf_module.is_(True))

    total = await session.scalar(select(func.count()).select_from(q.subquery()))
    cves = (await session.execute(q.offset((page - 1) * per_page).limit(per_page))).scalars().all()
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "matched_only": matched_only,
        "items": [_cve_dict(c) for c in cves],
    }


@router.get("/{cve_id}")
async def get_cve(cve_id: str, session: AsyncSession = Depends(get_session)):
    from fastapi import HTTPException
    cve = (await session.execute(select(CVE).where(CVE.cve_id == cve_id.upper()))).scalar_one_or_none()
    if not cve:
        raise HTTPException(404, f"{cve_id} introuvable")
    return _cve_dict(cve, full=True)


def _cve_dict(c: CVE, full: bool = False) -> dict:
    d = {
        "id": str(c.id),
        "cve_id": c.cve_id,
        "description": c.description,
        "cvss_score": c.cvss_score,
        "severity": c.severity,
        "epss_score": c.epss_score,
        "published": c.published.isoformat() if c.published else None,
        "source": c.source,
        # KEV/maturité d'exploit (17/08/2026) — scalaires légers, dans le dict de base
        # (pas réservés à full=True) : nécessaires au badge en vue liste (CVEs.jsx).
        "kev": c.kev,
        "kev_ransomware": c.kev_ransomware,
        "msf_module": c.msf_module,
        "msf_best_rank": c.msf_best_rank,
    }
    if full:
        d.update({
            "cvss_vector": c.cvss_vector,
            "references": c.references,
            "cpe": c.cpe,
            "modified": c.modified.isoformat() if c.modified else None,
            "kev_date_added": c.kev_date_added.isoformat() if c.kev_date_added else None,
            "msf_module_count": c.msf_module_count,
        })
    return d
