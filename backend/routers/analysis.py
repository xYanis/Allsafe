from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database import get_session
from models import CVE, Asset, Vulnerability
from services.claude_analyzer import analyze_cve_for_asset
from config import settings

router = APIRouter()


@router.post("/cve")
async def analyze_cve(
    payload: dict,
    session: AsyncSession = Depends(get_session),
):
    cve_id = payload.get("cve_id")
    asset_id = payload.get("asset_id")

    if not cve_id or not asset_id:
        raise HTTPException(400, "cve_id et asset_id requis")

    cve = (await session.execute(select(CVE).where(CVE.cve_id == cve_id.upper()))).scalar_one_or_none()
    if not cve:
        raise HTTPException(404, f"CVE {cve_id} introuvable")

    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Actif introuvable")

    result = await analyze_cve_for_asset(cve, asset, api_key=settings.ANTHROPIC_API_KEY)

    vuln = (await session.execute(
        select(Vulnerability)
        .where(Vulnerability.asset_id == asset.id)
        .where(Vulnerability.cve_id == cve.id)
    )).scalar_one_or_none()

    if vuln:
        vuln.ai_analysis = result["analysis"]
        await session.commit()

    return result
