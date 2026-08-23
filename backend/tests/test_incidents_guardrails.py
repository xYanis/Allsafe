"""
tests/test_incidents_guardrails.py
Garde-fous du module Incidents (routers/incidents.py) :
- la création ne peut jamais qualifier un incident "à notifier" via le payload
  (IncidentCreate ne déclare pas ces champs — Pydantic les ignore silencieusement),
- le préremplissage (/prefill) est strictement lecture seule, ne crée jamais rien,
- la qualification NIS 2 exige toujours une justification non vide.

Tests unitaires purs, sans base de données ni serveur HTTP (mêmes conventions que
test_vulnerabilities_status_transitions.py) : `session` mocké, modèles en mémoire.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from models import Incident, SecurityEvent
from routers.incidents import IncidentCreate, QualifyPayload, prefill_incident, qualify_notification


class TestCreatePayloadIgnoresNotificationFields:
    """Le schéma IncidentCreate ne déclare pas requires_notification / *_sent_at —
    Pydantic ignore silencieusement tout champ non déclaré (comportement par défaut),
    donc un client qui tenterait de les forcer dans le payload n'a aucun effet."""

    def test_requires_notification_not_settable_via_payload(self):
        data = IncidentCreate(
            title="Test", category="intrusion", severity="major",
            aware_at=datetime.now(timezone.utc), reported_by="Yanis Hortholary",
            **{"requires_notification": True, "early_warning_sent_at": "2026-01-01T00:00:00Z"},
        )
        assert not hasattr(data, "requires_notification")
        assert "requires_notification" not in data.model_dump()
        assert "early_warning_sent_at" not in data.model_dump()


class TestPrefillIsReadOnly:
    async def test_prefill_from_security_event_never_writes(self):
        event = SecurityEvent(
            id=1, source="trap_read", object_name="v_fake_customers",
            operation="SELECT", db_user="cbr_app", occurred_at=datetime.now(timezone.utc),
        )
        session = MagicMock()
        session.get = AsyncMock(return_value=event)

        result = await prefill_incident(source_type="security_event", source_id="1", session=session)

        session.add.assert_not_called()
        session.commit.assert_not_called()
        assert result["security_event_id"] == 1
        assert result["category"] == "intrusion"

    async def test_prefill_unknown_source_type_rejected(self):
        session = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await prefill_incident(source_type="bogus", source_id="1", session=session)
        assert exc_info.value.status_code == 400
        session.add.assert_not_called()

    async def test_prefill_missing_source_is_404(self):
        session = MagicMock()
        session.get = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc_info:
            await prefill_incident(source_type="security_event", source_id="999", session=session)
        assert exc_info.value.status_code == 404
        session.add.assert_not_called()


class TestQualifyRequiresJustification:
    async def test_empty_justification_rejected_with_400(self):
        inc = Incident(
            title="t", category="intrusion", severity="major", status="declared",
            aware_at=datetime.now(timezone.utc), reported_by="Yanis Hortholary",
            requires_notification=False,  # Column(default=...) ne s'applique qu'à l'INSERT
        )
        session = MagicMock()
        session.get = AsyncMock(return_value=inc)
        session.commit = AsyncMock()
        session.refresh = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await qualify_notification("fake-id", QualifyPayload(analyst="Yanis Hortholary", justification=""), session)
        assert exc_info.value.status_code == 400
        assert inc.requires_notification is False
        session.commit.assert_not_called()
