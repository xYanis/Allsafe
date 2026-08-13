"""
services/audit_finding_history.py
Journal append-only des transitions de statut d'un finding d'audit — même pattern que
services/vuln_history.py::record_status_change (transitions de statut), pas
services/incident_timeline.py (journal d'événements libres) : décision de conception
délibérée de ne pas fusionner les trois journaux du projet, cf. docs/AUDITS.md §4.
"""

from datetime import datetime, timezone

from models import AuditFindingHistory


def record(session, finding_id, old_status, new_status, changed_by, notes=None) -> None:
    """Enregistre une transition — no-op si l'ancien et le nouveau statut sont identiques
    (même garde-fou que record_status_change). Pas de commit ici, le commit du site
    d'appel couvre le finding et cette ligne dans la même transaction."""
    if old_status == new_status:
        return
    session.add(AuditFindingHistory(
        finding_id=finding_id,
        old_status=old_status,
        new_status=new_status,
        changed_at=datetime.now(timezone.utc),
        changed_by=changed_by,
        notes=notes,
    ))
