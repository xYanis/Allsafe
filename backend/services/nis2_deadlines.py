"""
services/nis2_deadlines.py
Échéances légales de notification NIS 2 (Directive, Art. 23) pour le module Incidents :
alerte précoce sous 24h après prise de connaissance (`aware_at`), notification
d'incident sous 72h, rapport final sous 1 mois (mois calendaire — cf. `_add_one_month`,
pas une approximation à 30 jours fixes).

⚠️ Garde-fou absolu, dans le même esprit que la règle CRITICAL toujours manuel de
CyberVuln (CLAUDE.md) : AUCUNE fonction ici n'est jamais appelée automatiquement par le
reste du code (création d'incident, préremplissage depuis security_event/vulnerability/
watch_item, tâche planifiée). `requires_notification` et les 3 jalons `*_sent_at` sont
TOUJOURS posés par un acte humain explicite, via les endpoints dédiés de
routers/incidents.py, jamais comme conséquence automatique de la sévérité ou de la
catégorie. L'app ne contacte jamais l'ANSSI ou un tiers — elle trace seulement qui a
déclaré/qualifié/envoyé quoi et quand ; l'envoi réel reste entièrement hors de l'app.
"""

import calendar
from datetime import datetime, timedelta, timezone

from services.incident_timeline import record as record_timeline

MILESTONES = ("early_warning", "incident_notification", "final_report")

# Vocabulaire du module Incidents — listes fixes (V1, cf. plan), pas pilotées en base
# contrairement à WatchSource : taxonomie bornée et connue à l'avance, pas ouverte par
# nature comme des flux de veille ajoutables par l'utilisateur.
CATEGORIES = ["ransomware", "data_breach", "intrusion", "dos", "phishing", "malware", "misconfiguration", "other"]
SEVERITIES = ["critical", "major", "minor"]
STATUSES   = ["declared", "in_progress", "contained", "resolved", "closed"]


def _add_one_month(dt: datetime) -> datetime:
    """Mois calendaire exact (ex: 31 janvier -> 28/29 février), pas une approximation à
    30 jours fixes — même soin que `week_bounds()` dans weekly_report.py pour les
    semaines ISO à cheval sur une année."""
    year = dt.year + dt.month // 12
    month = dt.month % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def compute_deadlines(aware_at: datetime) -> dict:
    """Les 3 échéances légales à partir de la prise de connaissance. Pure — n'écrit
    rien, ne lit rien ; appelée uniquement au moment de la qualification explicite
    (cf. qualify_for_notification) ou d'un recalcul explicite (cf. change_aware_at)."""
    return {
        "early_warning_due_at": aware_at + timedelta(hours=24),
        "incident_notification_due_at": aware_at + timedelta(hours=72),
        "final_report_due_at": _add_one_month(aware_at),
    }


def qualify_for_notification(session, incident, analyst: str, justification: str) -> None:
    """Qualifie un incident comme "à notifier" NIS 2 — toujours un acte humain
    explicite avec justification obligatoire. Fige les 3 échéances calculées depuis
    `aware_at` tel qu'il est au moment de l'appel."""
    if incident.requires_notification:
        raise ValueError("Incident déjà qualifié à notifier — déqualifier avant de requalifier.")
    if not justification or not justification.strip():
        raise ValueError("Justification obligatoire pour qualifier un incident à notifier.")

    deadlines = compute_deadlines(incident.aware_at)
    now = datetime.now(timezone.utc)

    incident.requires_notification      = True
    incident.notification_qualified_by  = analyst
    incident.notification_qualified_at  = now
    incident.notification_justification = justification.strip()
    incident.early_warning_due_at          = deadlines["early_warning_due_at"]
    incident.incident_notification_due_at  = deadlines["incident_notification_due_at"]
    incident.final_report_due_at           = deadlines["final_report_due_at"]

    record_timeline(
        session, incident.id, "notification_qualified", analyst,
        new_value="requires_notification=true", notes=justification.strip(),
        meta={"deadlines": {k: v.isoformat() for k, v in deadlines.items()}},
    )


def unqualify_notification(session, incident, analyst: str, reason: str) -> None:
    """Retire la qualification "à notifier" — refusé si un seul des 3 jalons a déjà
    été marqué envoyé : un envoi réel ne s'efface jamais, même par erreur de
    qualification en amont (même esprit que les états terminaux de CyberVuln)."""
    if incident.early_warning_sent_at or incident.incident_notification_sent_at or incident.final_report_sent_at:
        raise ValueError("Un jalon de notification a déjà été envoyé — déqualification impossible.")
    if not incident.requires_notification:
        raise ValueError("Incident déjà non qualifié.")
    if not reason or not reason.strip():
        raise ValueError("Justification obligatoire pour déqualifier un incident.")

    incident.requires_notification      = False
    incident.notification_qualified_by  = None
    incident.notification_qualified_at  = None
    incident.notification_justification = None
    incident.early_warning_due_at          = None
    incident.incident_notification_due_at  = None
    incident.final_report_due_at           = None

    record_timeline(
        session, incident.id, "notification_unqualified", analyst,
        new_value="requires_notification=false", notes=reason.strip(),
    )


def change_aware_at(session, incident, new_aware_at: datetime, analyst: str, recompute: bool) -> None:
    """Modifie la date de prise de connaissance. Refusé si `aware_at_locked` (un jalon
    déjà envoyé rend la base légale figée). `recompute` doit être coché explicitement
    côté UI — jamais un recalcul implicite — et ne touche que les échéances dont le
    jalon correspondant n'a pas encore été envoyé."""
    if incident.aware_at_locked:
        raise ValueError("aware_at verrouillé (un jalon de notification a déjà été envoyé) — modification impossible.")

    old_value = incident.aware_at.isoformat() if incident.aware_at else None
    incident.aware_at = new_aware_at

    if recompute and incident.requires_notification:
        deadlines = compute_deadlines(new_aware_at)
        if not incident.early_warning_sent_at:
            incident.early_warning_due_at = deadlines["early_warning_due_at"]
        if not incident.incident_notification_sent_at:
            incident.incident_notification_due_at = deadlines["incident_notification_due_at"]
        if not incident.final_report_sent_at:
            incident.final_report_due_at = deadlines["final_report_due_at"]

    record_timeline(
        session, incident.id, "aware_at_changed", analyst,
        old_value=old_value, new_value=new_aware_at.isoformat(),
        meta={"recompute": recompute},
    )


def mark_milestone_sent(session, incident, milestone: str, sent_by: str, sent_at: datetime | None = None, note: str | None = None) -> None:
    """Marque un jalon (alerte précoce / notification / rapport final) comme
    effectivement envoyé (hors app — l'app ne fait que tracer le fait). Idempotent :
    refusé si déjà marqué, pas d'endpoint pour "annuler" un envoi réel. Verrouille
    `aware_at_locked` dès le premier jalon envoyé."""
    if milestone not in MILESTONES:
        raise ValueError(f"Jalon inconnu : {milestone}")
    if not incident.requires_notification:
        raise ValueError("Incident non qualifié à notifier — aucun jalon à marquer.")

    sent_field = f"{milestone}_sent_at"
    by_field   = f"{milestone}_sent_by"
    if getattr(incident, sent_field):
        raise ValueError(f"Jalon '{milestone}' déjà marqué envoyé.")

    when = sent_at or datetime.now(timezone.utc)
    setattr(incident, sent_field, when)
    setattr(incident, by_field, sent_by)
    incident.aware_at_locked = True

    record_timeline(
        session, incident.id, "milestone_sent", sent_by,
        new_value=milestone, notes=note,
        meta={"milestone": milestone, "sent_at": when.isoformat()},
    )
