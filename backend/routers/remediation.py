import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_session
from services.remediation import get_recommendation, get_script

router = APIRouter()


@router.post("/recommend")
async def recommend(
    payload: dict,
    session: AsyncSession = Depends(get_session),
):
    vuln_id = payload.get("vuln_id")
    if not vuln_id:
        raise HTTPException(400, "vuln_id requis")
    return await get_recommendation(uuid.UUID(vuln_id), session)


@router.post("/script")
async def script(
    payload: dict,
    session: AsyncSession = Depends(get_session),
):
    vuln_id = payload.get("vuln_id")
    if not vuln_id:
        raise HTTPException(400, "vuln_id requis")
    return await get_script(uuid.UUID(vuln_id), session)
