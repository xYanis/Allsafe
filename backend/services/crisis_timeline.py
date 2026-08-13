"""
services/crisis_timeline.py
Journal auditable, append-only, des crises (module Incidents > Gestion de crise).

Fichier à part (pas dans routers/crises.py) pour être importable depuis
services/crisis.py sans risque de cycle d'import — même raison que
services/incident_timeline.py pour IncidentTimelineEntry. Fabrique commune avec
services/incident_timeline.py (structure identique, sibling exact) dans
services/timeline.py — signature inchangée ici pour ne pas toucher les imports
existants.
"""

from models import CrisisTimelineEntry
from services.timeline import record_entry


def record(session, crisis_id, event_type, author, old_value=None, new_value=None, notes=None, meta=None) -> None:
    record_entry(session, CrisisTimelineEntry, "crisis_id", crisis_id, event_type, author,
                 old_value=old_value, new_value=new_value, notes=notes, meta=meta)
