"""
tests/test_nis2_deadlines.py
Échéances légales NIS 2 (services/nis2_deadlines.py) — calcul du délai "1 mois" en
mois calendaire (pas 30 jours fixes) et garde-fous : aucune requalification,
déqualification ou recalcul ne doit pouvoir écraser un jalon déjà envoyé.

Tests unitaires purs : `Incident` en mémoire (jamais persisté), `session` mocké —
ces fonctions ne font que muter l'objet et appeler `session.add()` (synchrone, via
incident_timeline.record), aucune I/O réelle.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from models import Incident
from services import nis2_deadlines as nd


def _incident(**kwargs) -> Incident:
    # Column(default=...) ne s'applique qu'à l'INSERT — un Incident construit en
    # mémoire (jamais persisté, comme ici) doit poser explicitement requires_notification
    # et aware_at_locked, sinon ils valent None plutôt que leur défaut DB (False).
    defaults = dict(
        title="Test", category="intrusion", severity="major", status="declared",
        aware_at=datetime(2026, 7, 29, 10, 0, tzinfo=timezone.utc),
        reported_by="Yanis Hortholary",
        requires_notification=False, aware_at_locked=False,
    )
    defaults.update(kwargs)
    return Incident(**defaults)


class TestComputeDeadlines:
    def test_24h_and_72h(self):
        aware = datetime(2026, 7, 29, 10, 0, tzinfo=timezone.utc)
        d = nd.compute_deadlines(aware)
        assert d["early_warning_due_at"] == datetime(2026, 7, 30, 10, 0, tzinfo=timezone.utc)
        assert d["incident_notification_due_at"] == datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc)

    def test_final_report_is_calendar_month_not_30_days(self):
        aware = datetime(2026, 7, 29, 10, 0, tzinfo=timezone.utc)
        d = nd.compute_deadlines(aware)
        assert d["final_report_due_at"] == datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc)
        assert d["final_report_due_at"] != aware + timedelta(days=30)

    def test_calendar_month_edge_case_january_31(self):
        # 31 janvier + 1 mois calendaire -> 28 février (2027 n'est pas bissextile).
        aware = datetime(2027, 1, 31, 8, 0, tzinfo=timezone.utc)
        d = nd.compute_deadlines(aware)
        assert d["final_report_due_at"] == datetime(2027, 2, 28, 8, 0, tzinfo=timezone.utc)

    def test_calendar_month_crosses_year_boundary(self):
        aware = datetime(2026, 12, 15, 12, 0, tzinfo=timezone.utc)
        d = nd.compute_deadlines(aware)
        assert d["final_report_due_at"] == datetime(2027, 1, 15, 12, 0, tzinfo=timezone.utc)


class TestQualifyForNotification:
    def test_requires_non_empty_justification(self):
        inc = _incident()
        with pytest.raises(ValueError):
            nd.qualify_for_notification(MagicMock(), inc, "Yanis Hortholary", "")
        assert inc.requires_notification is False

    def test_qualifies_and_fixes_the_three_deadlines(self):
        inc = _incident()
        nd.qualify_for_notification(MagicMock(), inc, "Yanis Hortholary", "Fuite de données confirmée")
        assert inc.requires_notification is True
        assert inc.notification_qualified_by == "Yanis Hortholary"
        assert inc.notification_justification == "Fuite de données confirmée"
        assert inc.early_warning_due_at is not None
        assert inc.incident_notification_due_at is not None
        assert inc.final_report_due_at is not None

    def test_refuses_double_qualification(self):
        inc = _incident(requires_notification=True)
        with pytest.raises(ValueError):
            nd.qualify_for_notification(MagicMock(), inc, "Yanis Hortholary", "encore")


class TestUnqualifyNotification:
    def test_refused_if_a_milestone_already_sent(self):
        inc = _incident(requires_notification=True, early_warning_sent_at=datetime.now(timezone.utc))
        with pytest.raises(ValueError):
            nd.unqualify_notification(MagicMock(), inc, "Yanis Hortholary", "erreur")
        assert inc.requires_notification is True  # inchangé — jamais écrasé

    def test_succeeds_if_nothing_sent_yet(self):
        inc = _incident(requires_notification=True, notification_justification="x")
        nd.unqualify_notification(MagicMock(), inc, "Yanis Hortholary", "erreur de qualification")
        assert inc.requires_notification is False
        assert inc.notification_justification is None

    def test_requires_non_empty_reason(self):
        inc = _incident(requires_notification=True)
        with pytest.raises(ValueError):
            nd.unqualify_notification(MagicMock(), inc, "Yanis Hortholary", "")


class TestChangeAwareAt:
    def test_refused_when_locked(self):
        inc = _incident(aware_at_locked=True)
        old = inc.aware_at
        with pytest.raises(ValueError):
            nd.change_aware_at(MagicMock(), inc, datetime.now(timezone.utc), "Yanis Hortholary", True)
        assert inc.aware_at == old

    def test_recompute_skips_milestones_already_sent(self):
        inc = _incident(
            requires_notification=True,
            early_warning_due_at=datetime(2026, 7, 30, 10, 0, tzinfo=timezone.utc),
            early_warning_sent_at=datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc),
        )
        new_aware = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)
        nd.change_aware_at(MagicMock(), inc, new_aware, "Yanis Hortholary", True)

        # early_warning déjà envoyé : son échéance figée ne doit pas bouger.
        assert inc.early_warning_due_at == datetime(2026, 7, 30, 10, 0, tzinfo=timezone.utc)
        # incident_notification pas encore envoyé : recalculée depuis le nouveau aware_at.
        assert inc.incident_notification_due_at == new_aware + timedelta(hours=72)

    def test_no_recompute_leaves_due_dates_untouched(self):
        inc = _incident(
            requires_notification=True,
            incident_notification_due_at=datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc),
        )
        nd.change_aware_at(MagicMock(), inc, datetime(2026, 7, 1, 10, 0, tzinfo=timezone.utc), "Yanis Hortholary", False)
        assert inc.incident_notification_due_at == datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc)


class TestMarkMilestoneSent:
    def test_refused_if_not_qualified(self):
        inc = _incident(requires_notification=False)
        with pytest.raises(ValueError):
            nd.mark_milestone_sent(MagicMock(), inc, "early_warning", "Yanis Hortholary")

    def test_refused_on_double_call(self):
        inc = _incident(requires_notification=True, early_warning_sent_at=datetime.now(timezone.utc))
        with pytest.raises(ValueError):
            nd.mark_milestone_sent(MagicMock(), inc, "early_warning", "Yanis Hortholary")

    def test_locks_aware_at_on_first_milestone_sent(self):
        inc = _incident(requires_notification=True)
        assert inc.aware_at_locked is False
        nd.mark_milestone_sent(MagicMock(), inc, "incident_notification", "Yanis Hortholary")
        assert inc.aware_at_locked is True
        assert inc.incident_notification_sent_at is not None
        assert inc.incident_notification_sent_by == "Yanis Hortholary"

    def test_unknown_milestone_rejected(self):
        inc = _incident(requires_notification=True)
        with pytest.raises(ValueError):
            nd.mark_milestone_sent(MagicMock(), inc, "bogus", "Yanis Hortholary")
