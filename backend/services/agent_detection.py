"""
services/agent_detection.py
Détection d'évènements sensibles côté poste (19/08/2026, cf. docs/AGENT_DETECTION.md) —
Niveau 2 hybride : diff d'état (socle, toujours disponible) + journal natif (enrichissement,
transmis déjà catégorisé/résumé par l'agent). Appelé depuis `POST /agents/checkin`
(routers/agents.py), jamais `services/asset_scanner.py::apply_scan_result` — shape différent
(cf. doc § À vérifier à l'implémentation), les détections sont écrites par une fonction dédiée.

Fichier à part (comme vuln_history.py/incident_timeline.py/audit_finding_history.py) — même
raison : journal append-only, pas de raison de le fusionner dans le router.
"""

import json
import uuid as _uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Agent, AgentSecurityEvent, AgentStateSnapshot

# Même plafond que CHECKIN_MAX_ITEMS (routers/agents.py) — reste local à ce module plutôt
# que réimporté, pour ne pas créer de dépendance circulaire vers le router.
MAX_NATIVE_EVENTS = 300
MAX_SNAPSHOT_ITEMS = 300   # par catégorie (local_users/admin_members/persistence)
MAX_AUDIT_COVERAGE_BYTES = 4096

# Catégories valides (cf. doc § Catégories détectées) — un évènement natif hors de cette
# liste est rejeté silencieusement (agent buggé/compromis), pas de 500 pour ça.
VALID_CATEGORIES = {
    "account_created", "privilege_escalation", "account_reactivated",
    "persistence", "suspicious_process", "audit_tampering", "buffer_overflow",
}


def _clip_audit_coverage(audit_coverage) -> dict:
    """cf. docs/AGENT_DETECTION.md § Transport — dict libre (pas de schéma Pydantic strict
    clé par clé), donc un agent compromis/buggé pourrait y glisser un objet démesuré au lieu
    du petit dict de booléens attendu. Rejeté entièrement (pas tronqué — une troncature
    partielle n'a pas de sens sur un dict de booléens) au-delà d'un plafond généreux."""
    if not isinstance(audit_coverage, dict):
        return {}
    try:
        if len(json.dumps(audit_coverage)) > MAX_AUDIT_COVERAGE_BYTES:
            return {}
    except (TypeError, ValueError):
        return {}
    return audit_coverage


def _clip_state_snapshot(state_snapshot) -> dict:
    """Plafonne chaque catégorie indépendamment avant diff/stockage (cf. docs/AGENT_DETECTION.md
    § Transport) — un état réel (comptes/admins/tâches planifiées) peut être gros, rien ne
    garantit que l'agent respecte lui-même une limite côté client."""
    if not isinstance(state_snapshot, dict):
        return {}
    clipped = {}
    for key in ("local_users", "admin_members", "persistence"):
        value = state_snapshot.get(key)
        if isinstance(value, list):
            clipped[key] = value[:MAX_SNAPSHOT_ITEMS]
    return clipped


def _entry_key(entry) -> str:
    """Identité stable d'une entrée de snapshot pour le diff — clé naturelle si l'entrée est
    un dict (sid_or_uid > name), sinon la valeur elle-même (admin_members peut être une simple
    liste de noms bruts plutôt que d'objets structurés)."""
    if isinstance(entry, dict):
        return str(entry.get("sid_or_uid") or entry.get("name") or entry)
    return str(entry)


def _index_by_key(entries) -> dict:
    if not isinstance(entries, list):
        return {}
    return {_entry_key(e): e for e in entries if e is not None}


def _new_event(
    *, agent: Agent, category: str, severity: str, detection_method: str, summary: str,
    detail=None, occurred_at=None, native_source=None, native_event_id=None,
) -> AgentSecurityEvent:
    return AgentSecurityEvent(
        id=_uuid.uuid4(), agent_id=agent.id, hostname=agent.hostname, os=agent.os,
        category=category, severity=severity, detection_method=detection_method,
        occurred_at=occurred_at or datetime.now(timezone.utc),
        native_source=native_source, native_event_id=native_event_id,
        summary=summary, detail=detail or {},
    )


def _diff_state(agent: Agent, previous: "AgentStateSnapshot | None", current: dict) -> list:
    """Génère les détections state_diff en comparant l'état précédent au nouveau.

    `previous is None` (aucun snapshot antérieur — premier check-in de cet agent après
    enrôlement) : pas de diff possible, aucun évènement généré, on se contente de stocker
    l'état initial. Même principe de no-backfill que le journal natif côté agent (cf. doc
    § Mécanique agent, piège #1), appliqué ici côté socle diff — sans ça, le tout premier
    état constaté (souvent des dizaines de comptes/tâches déjà en place) remonterait comme
    autant de "créations" le jour de l'enrôlement."""
    if previous is None:
        return []

    events = []

    old_users = _index_by_key(previous.local_users)
    new_users = _index_by_key(current.get("local_users"))
    for key, entry in new_users.items():
        if key not in old_users:
            name = entry.get("name", key) if isinstance(entry, dict) else key
            events.append(_new_event(
                agent=agent, category="account_created", severity="warning",
                detection_method="state_diff",
                summary=f"Compte local créé : {name}", detail={"entry": entry},
            ))
        else:
            old_entry = old_users[key]
            if isinstance(entry, dict) and isinstance(old_entry, dict):
                if old_entry.get("enabled") is False and entry.get("enabled") is True:
                    name = entry.get("name", key)
                    events.append(_new_event(
                        agent=agent, category="account_reactivated", severity="warning",
                        detection_method="state_diff",
                        summary=f"Compte local réactivé : {name}", detail={"entry": entry},
                    ))

    old_admins = _index_by_key(previous.admin_members)
    new_admins = _index_by_key(current.get("admin_members"))
    for key, entry in new_admins.items():
        if key not in old_admins:
            events.append(_new_event(
                agent=agent, category="privilege_escalation", severity="critical",
                detection_method="state_diff",
                summary=f"Ajout au groupe administrateurs : {key}", detail={"entry": entry},
            ))

    old_persist = _index_by_key(previous.persistence)
    new_persist = _index_by_key(current.get("persistence"))
    for key, entry in new_persist.items():
        if key not in old_persist:
            label = entry.get("name", key) if isinstance(entry, dict) else key
            events.append(_new_event(
                agent=agent, category="persistence", severity="warning",
                detection_method="state_diff",
                summary=f"Nouvelle persistance détectée : {label}", detail={"entry": entry},
            ))

    return events


def _native_events(agent: Agent, raw_events) -> list:
    """Traduit les évènements bruts envoyés par l'agent (déjà catégorisés/résumés côté
    client, cf. doc § Modèle de données) en `AgentSecurityEvent` — rejette silencieusement
    une entrée malformée plutôt que de faire échouer tout le check-in pour ça (même esprit
    que le reste du payload check-in, cf. `services/asset_scanner.py`)."""
    if not isinstance(raw_events, list):
        return []
    out = []
    for raw in raw_events[:MAX_NATIVE_EVENTS]:
        if not isinstance(raw, dict):
            continue
        category = raw.get("category")
        summary = raw.get("summary")
        if category not in VALID_CATEGORIES or not summary:
            continue
        occurred_at = None
        if raw.get("occurred_at") is not None:
            try:
                occurred_at = datetime.fromtimestamp(float(raw["occurred_at"]), tz=timezone.utc)
            except (TypeError, ValueError, OverflowError):
                occurred_at = None
        detail = raw.get("detail")
        out.append(_new_event(
            agent=agent, category=category, severity=raw.get("severity") or "info",
            detection_method="native_log", summary=str(summary)[:500],
            detail=detail if isinstance(detail, dict) else {},
            occurred_at=occurred_at,
            native_source=raw.get("native_source"),
            native_event_id=str(raw["native_event_id"]) if raw.get("native_event_id") is not None else None,
        ))
    return out


async def apply_security_events(agent: Agent, payload_dict: dict, session: AsyncSession) -> None:
    """Point d'entrée unique appelé depuis `POST /agents/checkin`. Met à jour
    `Agent.audit_coverage`, le snapshot d'état (`AgentStateSnapshot`) et écrit les détections
    (`AgentSecurityEvent`) — diff d'abord (avant d'écraser le snapshot précédent), journal
    natif ensuite, dédoublonné sur `(agent_id, native_event_id)`."""
    agent.audit_coverage = _clip_audit_coverage(payload_dict.get("audit_coverage"))

    state_snapshot = _clip_state_snapshot(payload_dict.get("state_snapshot"))
    previous = await session.get(AgentStateSnapshot, agent.id)

    events = _diff_state(agent, previous, state_snapshot) if state_snapshot else []

    if state_snapshot:
        now = datetime.now(timezone.utc)
        if previous is None:
            session.add(AgentStateSnapshot(
                agent_id=agent.id,
                local_users=state_snapshot.get("local_users"),
                admin_members=state_snapshot.get("admin_members"),
                persistence=state_snapshot.get("persistence"),
                captured_at=now,
            ))
        else:
            previous.local_users = state_snapshot.get("local_users")
            previous.admin_members = state_snapshot.get("admin_members")
            previous.persistence = state_snapshot.get("persistence")
            previous.captured_at = now

    native = _native_events(agent, payload_dict.get("security_events"))

    # Dédoublonnage (agent_id, native_event_id) — le check-in relit une fenêtre du journal OS
    # à chaque cycle, un même évènement peut donc être renvoyé plusieurs fois tant qu'il reste
    # dans cette fenêtre. Pré-vérification en une requête plutôt qu'un ON CONFLICT par ligne —
    # volumes MVP (quelques dizaines par cycle), suffisant.
    candidate_ids = [e.native_event_id for e in native if e.native_event_id is not None]
    existing_ids = set()
    if candidate_ids:
        existing_ids = set((await session.execute(
            select(AgentSecurityEvent.native_event_id).where(
                AgentSecurityEvent.agent_id == agent.id,
                AgentSecurityEvent.native_event_id.in_(candidate_ids),
            )
        )).scalars().all())

    for event in events:
        session.add(event)
    for event in native:
        if event.native_event_id is not None and event.native_event_id in existing_ids:
            continue
        session.add(event)
