"""
services/crisis.py
Gestion de crise (31/07/2026) — logique métier des mutations sur une Crisis déjà créée
(la création elle-même vit dans routers/crises.py, même convention que
routers/incidents.py::create_incident). Même style que services/nis2_deadlines.py :
fonctions synchrones opérant sur un objet ORM déjà chargé, qui lèvent ValueError sur
tout état invalide plutôt que de renvoyer silencieusement un état incohérent — traduit
en HTTP par le `_guard` de routers/crises.py.
"""

from datetime import datetime, timezone

from services.crisis_timeline import record as record_timeline


def stand_down_crisis(session, crisis, analyst: str, justification: str) -> None:
    """Désactive une crise — toujours un acte humain explicite avec justification
    obligatoire, jamais automatique (même esprit que requires_notification sur Incident)."""
    if crisis.status == "stood_down":
        raise ValueError("Crise déjà désactivée.")
    if not justification or not justification.strip():
        raise ValueError("Justification obligatoire pour désactiver une crise.")

    now = datetime.now(timezone.utc)
    crisis.status = "stood_down"
    crisis.stood_down_at = now
    crisis.stood_down_by = analyst
    crisis.stand_down_justification = justification.strip()

    record_timeline(session, crisis.id, "stood_down", analyst, notes=justification.strip())


def assign_role(session, crisis, role: str, analyst_name: str, by: str) -> None:
    """Assigne un analyste à un rôle de la cellule de crise (Décideur, Communication,
    Technique, Juridique...) — remplace l'assignation existante pour ce rôle plutôt que
    d'empiler des doublons."""
    if not role or not role.strip():
        raise ValueError("Rôle obligatoire.")
    if not analyst_name or not analyst_name.strip():
        raise ValueError("Analyste obligatoire pour assigner un rôle.")

    role = role.strip()
    roles = [r for r in (crisis.crisis_roles or []) if r.get("role") != role]
    roles.append({"role": role, "analyst_name": analyst_name.strip()})
    crisis.crisis_roles = roles

    record_timeline(session, crisis.id, "role_assigned", by, new_value=f"{role}={analyst_name.strip()}")


def remove_role(session, crisis, role: str, by: str) -> None:
    roles = list(crisis.crisis_roles or [])
    if not any(r.get("role") == role for r in roles):
        raise ValueError(f"Rôle inconnu dans cette crise : {role}")
    crisis.crisis_roles = [r for r in roles if r.get("role") != role]

    record_timeline(session, crisis.id, "role_removed", by, old_value=role)


def link_incident(session, crisis, incident, by: str) -> None:
    """Rattache un incident à la crise — refusé si l'incident est déjà rattaché à une
    autre crise active (pas de double-rattachement, cf. Incident.crisis_id)."""
    if crisis.status == "stood_down":
        raise ValueError("Impossible de rattacher un incident à une crise désactivée.")
    if incident.crisis_id is not None and str(incident.crisis_id) != str(crisis.id):
        raise ValueError("Cet incident est déjà rattaché à une autre crise — le détacher d'abord.")

    incident.crisis_id = crisis.id
    record_timeline(session, crisis.id, "incident_linked", by, new_value=str(incident.id), notes=incident.title)


def unlink_incident(session, crisis, incident, by: str) -> None:
    if incident.crisis_id is None or str(incident.crisis_id) != str(crisis.id):
        raise ValueError("Cet incident n'est pas rattaché à cette crise.")

    incident.crisis_id = None
    record_timeline(session, crisis.id, "incident_unlinked", by, old_value=str(incident.id), notes=incident.title)


def record_decision(session, crisis, author: str, content: str) -> None:
    if not content or not content.strip():
        raise ValueError("Contenu obligatoire pour enregistrer une décision.")
    record_timeline(session, crisis.id, "decision", author, notes=content.strip())


def record_communication(session, crisis, author: str, content: str, audience: str) -> None:
    """Trace une communication interne/externe — n'envoie jamais rien elle-même, même
    garde-fou que le reste du module Incidents (cf. docs/INCIDENTS.md § 2)."""
    if not content or not content.strip():
        raise ValueError("Contenu obligatoire pour enregistrer une communication.")
    if audience not in ("interne", "externe"):
        raise ValueError("Audience invalide — 'interne' ou 'externe' attendu.")
    record_timeline(session, crisis.id, "communication", author, notes=content.strip(), meta={"audience": audience})
