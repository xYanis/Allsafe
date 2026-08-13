"""
tests/test_crisis_guardrails.py
Gestion de crise (services/crisis.py) — garde-fous de désactivation (justification
obligatoire, jamais deux fois) et de rattachement d'incident (pas de double-rattachement
à une autre crise, rien sur une crise désactivée).

Tests unitaires purs : `Crisis`/`Incident` en mémoire (jamais persistés), `session`
mocké — ces fonctions ne font que muter l'objet et appeler `session.add()` (synchrone,
via crisis_timeline.record), aucune I/O réelle. Même convention que
test_nis2_deadlines.py.
"""

import uuid
from unittest.mock import MagicMock

import pytest

from models import Crisis, Incident
from services import crisis as cr


def _crisis(**kwargs) -> Crisis:
    # Column(default=...) ne s'applique qu'à l'INSERT — un objet construit en mémoire
    # (jamais persisté, comme ici) doit poser explicitement id/status/crisis_roles,
    # sinon ils valent None plutôt que leur défaut DB.
    defaults = dict(
        id=uuid.uuid4(), title="Crise test", status="active",
        activated_by="Yanis Hortholary", crisis_roles=[],
    )
    defaults.update(kwargs)
    return Crisis(**defaults)


def _incident(**kwargs) -> Incident:
    defaults = dict(
        id=uuid.uuid4(), title="Incident test", category="intrusion", severity="major",
        status="declared", reported_by="Yanis Hortholary",
        requires_notification=False, aware_at_locked=False, crisis_id=None,
    )
    defaults.update(kwargs)
    return Incident(**defaults)


class TestStandDownCrisis:
    def test_requires_non_empty_justification(self):
        c = _crisis()
        with pytest.raises(ValueError):
            cr.stand_down_crisis(MagicMock(), c, "Yanis Hortholary", "")
        assert c.status == "active"

    def test_refuses_double_stand_down(self):
        c = _crisis(status="stood_down")
        with pytest.raises(ValueError):
            cr.stand_down_crisis(MagicMock(), c, "Yanis Hortholary", "déjà fait")

    def test_stands_down_and_fills_fields(self):
        c = _crisis()
        cr.stand_down_crisis(MagicMock(), c, "Yanis Hortholary", "Menace écartée")
        assert c.status == "stood_down"
        assert c.stood_down_by == "Yanis Hortholary"
        assert c.stand_down_justification == "Menace écartée"
        assert c.stood_down_at is not None


class TestAssignRole:
    def test_requires_role(self):
        c = _crisis()
        with pytest.raises(ValueError):
            cr.assign_role(MagicMock(), c, "", "Yanis Hortholary", "admin")

    def test_requires_analyst_name(self):
        c = _crisis()
        with pytest.raises(ValueError):
            cr.assign_role(MagicMock(), c, "Décideur", "", "admin")

    def test_assigns_new_role(self):
        c = _crisis()
        cr.assign_role(MagicMock(), c, "Décideur", "Nicolas Szebesta", "admin")
        assert c.crisis_roles == [{"role": "Décideur", "analyst_name": "Nicolas Szebesta"}]

    def test_reassigning_same_role_replaces_not_duplicates(self):
        c = _crisis(crisis_roles=[{"role": "Décideur", "analyst_name": "Ancien"}])
        cr.assign_role(MagicMock(), c, "Décideur", "Nouveau", "admin")
        assert c.crisis_roles == [{"role": "Décideur", "analyst_name": "Nouveau"}]


class TestRemoveRole:
    def test_unknown_role_rejected(self):
        c = _crisis(crisis_roles=[{"role": "Décideur", "analyst_name": "X"}])
        with pytest.raises(ValueError):
            cr.remove_role(MagicMock(), c, "Communication", "admin")

    def test_removes_existing_role(self):
        c = _crisis(crisis_roles=[
            {"role": "Décideur", "analyst_name": "X"},
            {"role": "Communication", "analyst_name": "Y"},
        ])
        cr.remove_role(MagicMock(), c, "Décideur", "admin")
        assert c.crisis_roles == [{"role": "Communication", "analyst_name": "Y"}]


class TestLinkIncident:
    def test_refused_on_stood_down_crisis(self):
        c = _crisis(status="stood_down")
        inc = _incident()
        with pytest.raises(ValueError):
            cr.link_incident(MagicMock(), c, inc, "admin")
        assert inc.crisis_id is None

    def test_refused_if_already_linked_elsewhere(self):
        c = _crisis()
        inc = _incident(crisis_id=uuid.uuid4())
        with pytest.raises(ValueError):
            cr.link_incident(MagicMock(), c, inc, "admin")

    def test_links_unattached_incident(self):
        c = _crisis()
        inc = _incident()
        cr.link_incident(MagicMock(), c, inc, "admin")
        assert inc.crisis_id == c.id

    def test_relinking_same_crisis_is_a_noop_not_an_error(self):
        c = _crisis()
        inc = _incident(crisis_id=c.id)
        cr.link_incident(MagicMock(), c, inc, "admin")
        assert inc.crisis_id == c.id


class TestUnlinkIncident:
    def test_refused_if_not_linked_to_this_crisis(self):
        c = _crisis()
        inc = _incident(crisis_id=uuid.uuid4())
        with pytest.raises(ValueError):
            cr.unlink_incident(MagicMock(), c, inc, "admin")

    def test_refused_if_not_linked_at_all(self):
        c = _crisis()
        inc = _incident(crisis_id=None)
        with pytest.raises(ValueError):
            cr.unlink_incident(MagicMock(), c, inc, "admin")

    def test_unlinks_incident(self):
        c = _crisis()
        inc = _incident(crisis_id=c.id)
        cr.unlink_incident(MagicMock(), c, inc, "admin")
        assert inc.crisis_id is None


class TestRecordDecision:
    def test_requires_non_empty_content(self):
        c = _crisis()
        with pytest.raises(ValueError):
            cr.record_decision(MagicMock(), c, "admin", "   ")


class TestRecordCommunication:
    def test_requires_non_empty_content(self):
        c = _crisis()
        with pytest.raises(ValueError):
            cr.record_communication(MagicMock(), c, "admin", "", "interne")

    def test_rejects_invalid_audience(self):
        c = _crisis()
        with pytest.raises(ValueError):
            cr.record_communication(MagicMock(), c, "admin", "Message", "public")

    def test_accepts_interne_and_externe(self):
        c = _crisis()
        cr.record_communication(MagicMock(), c, "admin", "Message interne", "interne")
        cr.record_communication(MagicMock(), c, "admin", "Message externe", "externe")
