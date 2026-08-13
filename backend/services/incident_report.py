"""
services/incident_report.py
Contenu du rapport **par incident** (pas hebdomadaire, contrairement aux 3 autres
rapports — cf. docstring de `IncidentAttachment`/`nis2_deadlines.py` : un incident est
rare, jamais plusieurs la même semaine, son suivi se fait à l'unité). Généré à la
demande, jamais figé/persisté : les champs qui le composent sont déjà écrits une seule
fois et jamais modifiés ensuite (jalons envoyés, justifications), pas besoin de geler
un instantané comme pour cve/veille/surveillance dont la donnée source bouge en continu.
"""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Incident, IncidentTimelineEntry, IncidentAttachment, Crisis, CrisisTimelineEntry

CATEGORY_LABELS = {
    "ransomware": "Ransomware", "data_breach": "Fuite de données", "intrusion": "Intrusion",
    "dos": "Déni de service", "phishing": "Hameçonnage", "malware": "Logiciel malveillant",
    "misconfiguration": "Erreur de configuration", "other": "Autre",
}
SEVERITY_LABELS = {"critical": "Critique", "major": "Majeur", "minor": "Mineur"}
STATUS_LABELS   = {"declared": "Déclaré", "in_progress": "En cours", "contained": "Contenu", "resolved": "Résolu", "closed": "Clôturé"}
MILESTONES = ("early_warning", "incident_notification", "final_report")
MILESTONE_LABELS = {
    "early_warning": "Alerte précoce (24h)",
    "incident_notification": "Notification (72h)",
    "final_report": "Rapport final (1 mois)",
}

# Textes des étapes du Plan d'action, par catégorie — dupliqués depuis frontend/src/constants/
# incidentPlaybooks.js::RESPONSE_STEPS (même principe que les *_LABELS ci-dessus : le backend n'a
# aucun moyen d'importer du JS). `completed_response_steps` ne stocke qu'un index (cf.
# routers/incidents.py::ResponseStepCompletion) — sans ce texte, le rapport ne pourrait afficher
# que des numéros d'étape, illisibles hors contexte de l'application. À maintenir en synchronisation
# manuelle avec le fichier frontend si l'un des deux est modifié (même ordre, même longueur).
RESPONSE_STEPS = {
    "ransomware": [
        "Isoler immédiatement les systèmes touchés (débrancher le réseau) — NE PAS les éteindre, ça préserve la mémoire pour l'analyse",
        "Alerter le RSSI / la direction",
        "Ne jamais payer la rançon",
        "Préserver les preuves (journaux, images disque) avant toute remédiation",
        "Activer la cellule de crise si plusieurs systèmes sont touchés",
        "Informer le personnel : consignes claires (ne pas rallumer/manipuler les postes)",
        "Identifier l'étendue réelle de la compromission",
        "Qualifier l'incident au regard de NIS 2 (section Notification NIS 2 ci-dessus)",
        "Envoyer l'alerte précoce sous 24h si qualifié",
        "Déposer plainte auprès de la police/gendarmerie",
        "Restaurer depuis des sauvegardes saines, après vérification qu'elles ne sont pas compromises",
        "Envoyer la notification sous 72h si qualifié",
        "Envoyer le rapport final sous 1 mois si qualifié",
    ],
    "data_breach": [
        "Alerter le DPO et la direction",
        "Évaluer précisément le périmètre (données et personnes concernées)",
        "Révoquer les accès/identifiants compromis",
        "Informer le personnel concerné des mesures à suivre",
        "Qualifier l'incident au regard de NIS 2 (section Notification NIS 2 ci-dessus)",
        "Envoyer l'alerte précoce sous 24h si qualifié",
        "Notifier la CNIL sous 72h si risque pour les droits des personnes",
        "Envoyer la notification NIS 2 sous 72h si qualifié",
        "Informer individuellement les personnes concernées si risque élevé",
        "Documenter nature, volumétrie, conséquences probables, mesures prises",
        "Envoyer le rapport final sous 1 mois si qualifié",
    ],
    "intrusion": [
        "Isoler les systèmes compromis",
        "Alerter le RSSI",
        "Analyser les journaux pour identifier le vecteur d'entrée",
        "Changer les identifiants compromis, en priorité les comptes à privilèges",
        "Rechercher une éventuelle persistance (comptes créés, tâches planifiées, implants)",
        "Informer les équipes techniques concernées",
        "Qualifier l'incident au regard de NIS 2 (section Notification NIS 2 ci-dessus)",
        "Envoyer l'alerte précoce sous 24h si qualifié",
        "Déposer plainte auprès de la police/gendarmerie",
        "Envoyer la notification sous 72h si qualifié",
        "Envoyer le rapport final sous 1 mois si qualifié",
    ],
    "dos": [
        "Alerter les équipes infrastructure/réseau",
        "Contacter l'hébergeur/FAI pour une mitigation (filtrage, scrubbing)",
        "Activer le plan de continuité si un service critique est impacté",
        "Informer le personnel/support client de la situation",
        "Documenter chronologie et volumétrie de l'attaque",
        "Qualifier l'incident au regard de NIS 2 (section Notification NIS 2 ci-dessus)",
        "Communiquer publiquement si un service public/critique est impacté",
        "Envoyer l'alerte précoce sous 24h si qualifié",
        "Envoyer la notification sous 72h si qualifié",
        "Envoyer le rapport final sous 1 mois si qualifié",
    ],
    "phishing": [
        "Bloquer le domaine/l'expéditeur frauduleux",
        "Alerter en urgence les utilisateurs internes",
        "Réinitialiser les identifiants des comptes ayant pu saisir leurs accès",
        "Si des comptes sont compromis, traiter aussi comme une intrusion",
        "Qualifier l'incident au regard de NIS 2 si des comptes sensibles sont compromis",
        "Envoyer l'alerte précoce sous 24h si qualifié",
        "Envoyer la notification sous 72h si qualifié",
        "Envoyer le rapport final sous 1 mois si qualifié",
    ],
    "malware": [
        "Isoler la machine infectée du réseau",
        "Alerter l'équipe sécurité",
        "Analyser l'échantillon avec l'EDR/antivirus",
        "Rechercher une propagation latérale",
        "Informer le personnel concerné",
        "Qualifier l'incident au regard de NIS 2 si la propagation est significative",
        "Envoyer l'alerte précoce sous 24h si qualifié",
        "Envoyer la notification sous 72h si qualifié",
        "Envoyer le rapport final sous 1 mois si qualifié",
    ],
    "misconfiguration": [
        "Corriger la configuration immédiatement",
        "Alerter l'équipe technique responsable",
        "Vérifier les journaux d'accès pendant toute la fenêtre d'exposition",
        "Si des données ont pu être consultées par un tiers : traiter aussi comme une fuite de données",
        "Qualifier l'incident au regard de NIS 2/notifier la CNIL selon les données exposées",
        "Envoyer l'alerte précoce sous 24h si qualifié",
        "Envoyer la notification sous 72h si qualifié",
        "Envoyer le rapport final sous 1 mois si qualifié",
    ],
    "other": [
        "Alerter le RSSI / la direction",
        "Documenter précisément les faits connus",
        "Mobiliser les équipes concernées",
        "Évaluer si la CNIL ou l'ANSSI/CERT-FR sont concernés selon la nature réelle de l'incident",
        "Envoyer l'alerte précoce sous 24h si qualifié",
        "Envoyer la notification sous 72h si qualifié",
        "Envoyer le rapport final sous 1 mois si qualifié",
    ],
}


def _fmt_json_dt(iso: str | None) -> str:
    """`completed_response_steps` est un JSON brut (pas des colonnes ORM) — `at` y est déjà
    une chaîne ISO, contrairement aux dates de l'incident lui-même (objets datetime)."""
    if not iso:
        return "—"
    try:
        return datetime.fromisoformat(iso).strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return iso


async def build_incident_report(session: AsyncSession, incident: Incident) -> str:
    """Markdown du rapport pour CET incident — généré à la volée, rien n'est écrit
    en base. Reprend, pour l'alerte précoce et la notification, le contenu réel
    consigné au moment du "Marquer envoyé" (pas juste un statut) ; le rapport final
    s'appuie sur les PDF joints plutôt que sur un texte."""
    entries = (await session.execute(
        select(IncidentTimelineEntry).where(IncidentTimelineEntry.incident_id == incident.id)
        .order_by(IncidentTimelineEntry.occurred_at.asc())
    )).scalars().all()

    milestone_entries = {
        e.meta.get("milestone"): e for e in entries
        if e.event_type == "milestone_sent" and e.meta and e.meta.get("milestone")
    }

    attachments = (await session.execute(
        select(IncidentAttachment).where(IncidentAttachment.incident_id == incident.id)
        .order_by(IncidentAttachment.uploaded_at.asc())
    )).scalars().all()

    # Escalade en crise (31/07/2026) — pas de rapport dédié à la Gestion de crise (cf. CLAUDE.md,
    # 3 des 4 rapports sont hebdomadaires figés, Incidents est le seul à la demande/par incident) :
    # si cet incident a été rattaché à une crise, son suivi (cellule, journal) n'apparaît nulle
    # part ailleurs qu'ici — sans cette section le rapport d'incident était silencieux dessus.
    crisis = await session.get(Crisis, incident.crisis_id) if incident.crisis_id else None
    crisis_entries: list[CrisisTimelineEntry] = []
    if crisis:
        crisis_entries = (await session.execute(
            select(CrisisTimelineEntry).where(CrisisTimelineEntry.crisis_id == crisis.id)
            .order_by(CrisisTimelineEntry.occurred_at.asc())
        )).scalars().all()

    return _render(incident, entries, milestone_entries, attachments, crisis, crisis_entries)


def _render(
    incident: Incident,
    entries: list[IncidentTimelineEntry],
    milestone_entries: dict[str, IncidentTimelineEntry],
    attachments: list[IncidentAttachment],
    crisis: Crisis | None = None,
    crisis_entries: list[CrisisTimelineEntry] | None = None,
) -> str:
    L: list[str] = []
    L.append(f"# Rapport d'incident — {incident.title}")
    L.append("")
    L.append(
        f"**{CATEGORY_LABELS.get(incident.category, incident.category)}** · "
        f"Sévérité **{SEVERITY_LABELS.get(incident.severity, incident.severity)}** · "
        f"Statut **{STATUS_LABELS.get(incident.status, incident.status)}**"
    )
    L.append("")
    L.append(f"Prise de connaissance : {incident.aware_at.strftime('%d/%m/%Y %H:%M') if incident.aware_at else '—'}")
    L.append(f"Déclaré par : {incident.reported_by or '—'}")
    L.append("")

    if incident.description:
        L.append("## Description")
        L.append(incident.description)
        L.append("")

    L.append("## Qualification NIS 2 (Art. 23)")
    if incident.requires_notification:
        L.append(f"**Qualifié à notifier**, par {incident.notification_qualified_by or '—'} "
                  f"le {incident.notification_qualified_at.strftime('%d/%m/%Y %H:%M') if incident.notification_qualified_at else '—'}.")
        if incident.notification_justification:
            L.append("")
            L.append(f"*{incident.notification_justification}*")
    else:
        L.append("Non qualifié — aucune échéance légale suivie pour cet incident.")
    L.append("")

    if incident.requires_notification:
        for m in ("early_warning", "incident_notification"):
            L.append(f"## {MILESTONE_LABELS[m]}")
            due = getattr(incident, f"{m}_due_at")
            sent = getattr(incident, f"{m}_sent_at")
            sent_by = getattr(incident, f"{m}_sent_by")
            if sent:
                L.append(f"**Envoyé** le {sent.strftime('%d/%m/%Y %H:%M')} par {sent_by or '—'}.")
                note = milestone_entries.get(m)
                if note and note.notes:
                    L.append("")
                    L.append(note.notes)
            else:
                L.append(f"En attente — échéance {due.strftime('%d/%m/%Y %H:%M') if due else '—'}.")
            L.append("")

        L.append(f"## {MILESTONE_LABELS['final_report']}")
        due = incident.final_report_due_at
        sent = incident.final_report_sent_at
        if sent:
            L.append(f"**Envoyé** le {sent.strftime('%d/%m/%Y %H:%M')} par {incident.final_report_sent_by or '—'}.")
        else:
            L.append(f"En attente — échéance {due.strftime('%d/%m/%Y %H:%M') if due else '—'}.")
        L.append("")
        if attachments:
            L.append("Pièce(s) jointe(s) :")
            for a in attachments:
                L.append(f"- [{a.filename}](/api/incidents/{incident.id}/attachments/{a.id}/download) ({a.size_bytes / 1024:.0f} Ko)")
        else:
            L.append("Aucune pièce jointe.")
        L.append("")

    steps = RESPONSE_STEPS.get(incident.category, RESPONSE_STEPS["other"])
    completed = incident.completed_response_steps or []
    L.append("## Plan d'action")
    L.append(f"{len(completed)}/{len(steps)} étape(s) réalisée(s).")
    L.append("")
    if completed:
        L.append("| # | Étape | Réalisé par | Date |")
        L.append("|---|---|---|---|")
        for c in sorted(completed, key=lambda c: c.get("index", 0)):
            idx = c.get("index", 0)
            text = steps[idx] if 0 <= idx < len(steps) else f"Étape #{idx + 1} (catégorie modifiée depuis)"
            L.append(f"| {idx + 1} | {text} | {c.get('by') or '—'} | {_fmt_json_dt(c.get('at'))} |")
        L.append("")

    if incident.affected_asset_ids:
        L.append("## Actifs concernés")
        L.append(f"{len(incident.affected_asset_ids)} actif(s) — cf. détail de l'incident dans l'application.")
        L.append("")

    if crisis:
        L.append("## Escalade en crise")
        status_label = "Active" if crisis.status == "active" else "Désactivée"
        L.append(f"Rattaché à la crise **{crisis.title}** — statut **{status_label}**.")
        L.append(f"Activée par {crisis.activated_by or '—'} le {crisis.activated_at.strftime('%d/%m/%Y %H:%M') if crisis.activated_at else '—'}.")
        if crisis.status == "stood_down":
            justification = f" — {crisis.stand_down_justification}" if crisis.stand_down_justification else ""
            L.append(f"Désactivée par {crisis.stood_down_by or '—'} le {crisis.stood_down_at.strftime('%d/%m/%Y %H:%M') if crisis.stood_down_at else '—'}{justification}.")
        L.append("")

        roles = crisis.crisis_roles or []
        if roles:
            L.append("Cellule de crise : " + ", ".join(f"{r.get('role')} — {r.get('analyst_name')}" for r in roles) + ".")
            L.append("")

        if crisis_entries:
            L.append("Journal de la crise :")
            L.append("")
            L.append("| Date | Évènement | Auteur | Détail |")
            L.append("|---|---|---|---|")
            for e in crisis_entries:
                detail = (e.notes or e.new_value or "")[:80].replace("|", "-").replace("\n", " ")
                L.append(f"| {e.occurred_at.strftime('%d/%m/%Y %H:%M')} | {e.event_type} | {e.author} | {detail} |")
            L.append("")

    L.append("## Chronologie complète")
    L.append("| Date | Évènement | Auteur | Détail |")
    L.append("|---|---|---|---|")
    for e in entries:
        detail = (e.notes or e.new_value or "")[:80].replace("|", "-").replace("\n", " ")
        L.append(f"| {e.occurred_at.strftime('%d/%m/%Y %H:%M')} | {e.event_type} | {e.author} | {detail} |")
    L.append("")

    return "\n".join(L)
