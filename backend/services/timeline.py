"""
services/timeline.py
Fabrique générique partagée par crisis_timeline.py et incident_timeline.py —
CrisisTimelineEntry/IncidentTimelineEntry ont la même structure de journal auditable
append-only, seuls le modèle ORM et le nom de la colonne de rattachement changent.

Pas destiné à être importé ailleurs : chaque module garde sa propre fonction record()
avec sa propre signature explicite (incident_id / crisis_id), pour que les sites
d'appel existants (services/crisis.py, services/nis2_deadlines.py, routers/crises.py,
routers/incidents.py) n'aient rien à changer.
"""

from datetime import datetime, timezone


def record_entry(session, model, id_field: str, entity_id, event_type, author,
                  old_value=None, new_value=None, notes=None, meta=None) -> None:
    """Enregistre une entrée de timeline — pas de commit ici, le commit du site
    d'appel couvre l'entité et cette ligne dans la même transaction."""
    session.add(model(**{
        id_field: entity_id,
        "event_type": event_type,
        "occurred_at": datetime.now(timezone.utc),
        "author": author,
        "old_value": old_value,
        "new_value": new_value,
        "notes": notes,
        "meta": meta,
    }))
