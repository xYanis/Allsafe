"""
tests/test_audits_guardrails.py
Garde-fous du module Audits (routers/audits.py, cf. docs/AUDITS.md) :
- aucun finding ne peut être saisi tant que l'audit n'est pas autorisé (statut "cadrage"),
- l'autorisation (scope/rules_of_engagement/authorized_by/authorized_at) ne se pose qu'une
  fois, immuable ensuite,
- le préremplissage d'incident depuis un finding d'audit mappe correctement la sévérité.

Tests unitaires purs, sans base de données ni serveur HTTP (mêmes conventions que
test_incidents_guardrails.py) : `session` mocké, modèles en mémoire.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from models import Audit, AuditFinding
from routers.audits import AuthorizePayload, FindingCreate, authorize_audit, create_audit_finding


def _make_session(get_return=None):
    session = MagicMock()
    session.get = AsyncMock(return_value=get_return)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.execute = AsyncMock()
    return session


def _empty_query_result():
    """Résultat vide compatible avec `.all()` (_asset_names) et `.scalars().all()`
    (liaisons AuditAsset) — les deux formes sont utilisées selon l'appelant."""
    result = MagicMock()
    result.all.return_value = []
    result.scalars.return_value.all.return_value = []
    return result


class TestFindingBlockedBeforeAuthorization:
    async def test_finding_rejected_on_cadrage_audit(self):
        audit = Audit(id="a1", title="t", type="code", status="cadrage")
        session = _make_session(get_return=audit)

        payload = FindingCreate(author="Yanis Hortholary", title="Finding", severity="HIGH")
        with pytest.raises(HTTPException) as exc_info:
            await create_audit_finding("a1", payload, session)

        assert exc_info.value.status_code == 403
        session.add.assert_not_called()
        session.commit.assert_not_called()

    async def test_finding_accepted_once_authorized(self):
        audit = Audit(id="a1", title="t", type="code", status="autorise")
        session = _make_session(get_return=audit)
        # session.get est aussi appelé pour l'actif affecté (None ici, pas de vérification)
        session.execute.return_value = _empty_query_result()

        payload = FindingCreate(author="Yanis Hortholary", title="Finding", severity="HIGH")
        await create_audit_finding("a1", payload, session)

        # 2 appels : le finding lui-même + l'entrée audit_finding_history de création
        assert session.add.call_count == 2
        session.commit.assert_called_once()


class TestAuthorizationImmutable:
    async def test_authorize_sets_fields_and_status(self):
        audit = Audit(id="a1", title="t", type="code", status="cadrage")
        session = _make_session(get_return=audit)
        session.execute.return_value = _empty_query_result()

        payload = AuthorizePayload(
            scope="Application CBR", rules_of_engagement="Boîte blanche",
            authorized_by="RSSI", authorized_at=datetime.now(timezone.utc),
        )
        await authorize_audit("a1", payload, session)

        assert audit.status == "autorise"
        assert audit.authorized_by == "RSSI"
        session.commit.assert_called_once()

    async def test_second_authorization_rejected_with_409(self):
        audit = Audit(
            id="a1", title="t", type="code", status="autorise",
            authorized_by="RSSI", authorized_at=datetime.now(timezone.utc),
        )
        session = _make_session(get_return=audit)

        payload = AuthorizePayload(
            scope="Autre périmètre", rules_of_engagement="Autres règles",
            authorized_by="Quelqu'un d'autre", authorized_at=datetime.now(timezone.utc),
        )
        with pytest.raises(HTTPException) as exc_info:
            await authorize_audit("a1", payload, session)

        assert exc_info.value.status_code == 409
        assert audit.authorized_by == "RSSI"   # inchangé
        session.commit.assert_not_called()

    async def test_authorize_rejects_blank_scope(self):
        audit = Audit(id="a1", title="t", type="code", status="cadrage")
        session = _make_session(get_return=audit)

        payload = AuthorizePayload(
            scope="   ", rules_of_engagement="Boîte blanche",
            authorized_by="RSSI", authorized_at=datetime.now(timezone.utc),
        )
        with pytest.raises(HTTPException) as exc_info:
            await authorize_audit("a1", payload, session)

        assert exc_info.value.status_code == 400
        assert audit.status == "cadrage"
        session.commit.assert_not_called()


class TestIncidentPrefillSeverityMapping:
    """routers/incidents.py::prefill_incident, branche source_type="audit_finding" —
    même échelle (critical/major/minor) que les autres sources (vulnerability, watch_item)."""

    async def _prefill(self, severity):
        from routers.incidents import prefill_incident

        finding = AuditFinding(
            id="f1", audit_id="a1", title="Finding", severity=severity,
            status="ouvert", discovered_at=datetime.now(timezone.utc),
        )
        audit = Audit(id="a1", title="Audit", type="code", status="autorise")

        session = MagicMock()
        session.get = AsyncMock(side_effect=[finding, audit])
        return await prefill_incident(source_type="audit_finding", source_id="f1", session=session)

    async def test_high_maps_to_critical(self):
        result = await self._prefill("HIGH")
        assert result["severity"] == "critical"
        assert result["audit_finding_id"] == "f1"

    async def test_critical_maps_to_critical(self):
        result = await self._prefill("CRITICAL")
        assert result["severity"] == "critical"

    async def test_medium_maps_to_major(self):
        result = await self._prefill("MEDIUM")
        assert result["severity"] == "major"

    async def test_low_maps_to_minor(self):
        result = await self._prefill("LOW")
        assert result["severity"] == "minor"
