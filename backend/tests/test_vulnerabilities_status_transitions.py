"""
tests/test_vulnerabilities_status_transitions.py
Régression directe de l'incident du 27/07/2026 (cf. STATUS.md) : le PATCH
unitaire (`update_vulnerability`) n'avait pas de branche dédiée pour le
nouveau statut `awaiting_fix_partial` et retombait dans le `else` prévu pour
open/in_progress, qui efface `validated_by`/`last_patch_check`/
`patch_check_result`. Trois lignes réelles ont perdu leur validateur avant
d'être réparées via l'API.

Test direct de la fonction de route (pas de serveur HTTP, pas de base de
données) : session mockée, `Vulnerability` en mémoire — on inspecte l'objet
muté après l'appel.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from models import Vulnerability
from routers.vulnerabilities import update_vulnerability, VulnUpdate


def _fake_session(vuln: Vulnerability) -> MagicMock:
    # `get`/`commit` sont asynchrones sur une vraie AsyncSession, `add` ne
    # l'est pas — un mock 100% async ferait planter le "jamais awaited" sur
    # `session.add()` (appelé sans await par record_status_change).
    session = MagicMock()
    session.get = AsyncMock(return_value=vuln)
    session.commit = AsyncMock()
    return session


async def test_awaiting_fix_partial_preserves_validated_by_and_patch_check_result():
    vuln = Vulnerability(
        status="awaiting_fix",
        validated_by="Yanis Hortholary",
        notes="analyse détaillée existante",
        last_patch_check=datetime.now(timezone.utc),
        patch_check_result={"partial_fix": True, "details": "..."},
    )
    session = _fake_session(vuln)

    await update_vulnerability("fake-id", VulnUpdate(status="awaiting_fix_partial"), session)

    assert vuln.status == "awaiting_fix_partial"
    assert vuln.validated_by == "Yanis Hortholary"       # ne doit jamais être effacé
    assert vuln.last_patch_check is not None              # idem
    assert vuln.patch_check_result is not None            # idem
    assert vuln.notes == "analyse détaillée existante"    # jamais touché par cette branche
    assert vuln.awaiting_fix_at is not None


async def test_awaiting_fix_preserves_validated_by_and_patch_check_result():
    # Même vérification sur le statut jumeau (awaiting_fix), qui avait déjà sa
    # branche dédiée — sert de garde-fou si quelqu'un simplifie le if/elif un jour.
    vuln = Vulnerability(
        status="open",
        last_patch_check=datetime.now(timezone.utc),
        patch_check_result={"no_fix_available": True},
    )
    session = _fake_session(vuln)

    await update_vulnerability(
        "fake-id",
        VulnUpdate(status="awaiting_fix", validated_by="Yanis Hortholary", notes="en attente"),
        session,
    )

    assert vuln.status == "awaiting_fix"
    assert vuln.last_patch_check is not None
    assert vuln.patch_check_result is not None


async def test_open_status_clears_previous_check_state():
    # Comportement intentionnel de la branche `else` (open/in_progress) : elle
    # doit continuer à tout effacer, sinon un rattrapage réutiliserait un
    # verdict périmé (cf. invariant `update_vulnerability`, STATUS.md).
    vuln = Vulnerability(
        status="patched",
        validated_by="Auto (patch check)",
        patched_at=datetime.now(timezone.utc),
        last_patch_check=datetime.now(timezone.utc),
        patch_check_result={"patch_detected": True},
    )
    session = _fake_session(vuln)

    await update_vulnerability("fake-id", VulnUpdate(status="open"), session)

    assert vuln.status == "open"
    assert vuln.validated_by is None
    assert vuln.last_patch_check is None
    assert vuln.patch_check_result is None


async def test_accepted_risk_requires_notes_validated_by_and_review_date():
    vuln = Vulnerability(status="open")
    session = _fake_session(vuln)

    with pytest.raises(HTTPException) as exc_info:
        await update_vulnerability("fake-id", VulnUpdate(status="accepted_risk"), session)
    assert exc_info.value.status_code == 400
