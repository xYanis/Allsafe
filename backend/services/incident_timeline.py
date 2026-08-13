"""
services/incident_timeline.py
Journal auditable, append-only, des incidents (module Incidents).

Fichier à part (pas dans routers/incidents.py) pour être importable depuis
services/nis2_deadlines.py sans risque de cycle d'import — même raison que
services/vuln_history.py pour VulnerabilityStatusHistory. Fabrique commune avec
services/crisis_timeline.py (structure identique, sibling exact) dans
services/timeline.py — signature inchangée ici pour ne pas toucher les imports
existants.
"""

from models import IncidentTimelineEntry
from services.timeline import record_entry


def record(session, incident_id, event_type, author, old_value=None, new_value=None, notes=None, meta=None) -> None:
    record_entry(session, IncidentTimelineEntry, "incident_id", incident_id, event_type, author,
                 old_value=old_value, new_value=new_value, notes=notes, meta=meta)
