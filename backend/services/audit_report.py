"""
services/audit_report.py
Rapport d'un audit (module Audits) — markdown généré à la demande, jamais persisté, rendu
côté frontend par ReportMarkdown.jsx (impression PDF navigateur, pas de génération serveur —
même principe que services/incident_report.py). Calqué sur ce dernier.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Audit, AuditAsset, AuditAttachment, AuditFinding, Asset

TYPE_LABELS = {
    "architecture": "Architecture", "configuration": "Configuration", "code": "Code source",
    "pentest": "Test d'intrusion", "redteam": "Red Team",
}
METHODOLOGY_LABELS = {"boite_noire": "Boîte noire", "boite_grise": "Boîte grise", "boite_blanche": "Boîte blanche"}
STATUS_LABELS = {
    "cadrage": "Cadrage", "autorise": "Autorisé", "en_cours": "En cours",
    "termine": "Terminé", "archive": "Archivé",
}
FINDING_STATUS_LABELS = {
    "ouvert": "Ouvert", "remediation_planifiee": "Remédiation planifiée",
    "corrige": "Corrigé", "risque_accepte": "Risque accepté", "faux_positif": "Faux positif",
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _fmt(dt) -> str:
    return dt.strftime("%d/%m/%Y %H:%M") if dt else "—"


async def build_audit_report(session: AsyncSession, audit: Audit) -> str:
    findings = (await session.execute(
        select(AuditFinding).where(AuditFinding.audit_id == audit.id)
        .order_by(AuditFinding.discovered_at.asc())
    )).scalars().all()

    asset_ids = (await session.execute(
        select(AuditAsset.asset_id).where(AuditAsset.audit_id == audit.id)
    )).scalars().all()
    asset_names = []
    if asset_ids:
        rows = (await session.execute(select(Asset.name).where(Asset.id.in_(asset_ids)))).scalars().all()
        asset_names = list(rows)

    attachments = (await session.execute(
        select(AuditAttachment).where(AuditAttachment.audit_id == audit.id)
        .order_by(AuditAttachment.uploaded_at.asc())
    )).scalars().all()

    return _render(audit, findings, asset_names, attachments)


def _render(audit: Audit, findings: list[AuditFinding], asset_names: list[str], attachments: list[AuditAttachment]) -> str:
    L: list[str] = []
    L.append(f"# Rapport d'audit — {audit.title}")
    L.append("")
    L.append(
        f"**{TYPE_LABELS.get(audit.type, audit.type)}** · "
        f"Statut **{STATUS_LABELS.get(audit.status, audit.status)}**"
        + (f" · Méthodologie **{METHODOLOGY_LABELS.get(audit.methodology, audit.methodology)}**" if audit.methodology else "")
        + (f" · Référentiel **{audit.referential}**" if audit.referential else "")
    )
    L.append("")
    L.append(f"Conduit par : {audit.conducted_by or '—'}")
    L.append(f"Période : {_fmt(audit.started_at)} → {_fmt(audit.ended_at)}")
    L.append("")

    if asset_names:
        L.append("## Périmètre — actifs ciblés")
        L.append(", ".join(sorted(asset_names)) + ".")
        L.append("")

    L.append("## Cadrage et autorisation")
    if audit.scope:
        L.append("**Périmètre technique**")
        L.append("")
        L.append(audit.scope)
        L.append("")
    if audit.rules_of_engagement:
        L.append("**Règles d'engagement**")
        L.append("")
        L.append(audit.rules_of_engagement)
        L.append("")
    if audit.authorized_by:
        L.append(f"Autorisé par **{audit.authorized_by}** le {_fmt(audit.authorized_at)}.")
    else:
        L.append("Non autorisé — aucun finding ne peut être saisi tant que cette étape n'est pas franchie.")
    L.append("")

    mandate = [a for a in attachments if a.kind == "mandate"]
    if mandate:
        L.append("Mandat écrit joint :")
        for a in mandate:
            L.append(f"- [{a.filename}](/api/audits/{audit.id}/attachments/{a.id}/download) ({a.size_bytes / 1024:.0f} Ko)")
        L.append("")

    L.append("## Synthèse des findings")
    if not findings:
        L.append("Aucun finding saisi.")
        L.append("")
    else:
        by_sev = {s: [f for f in findings if f.severity == s] for s in SEVERITY_ORDER}
        counts = " · ".join(f"{s} : {len(by_sev[s])}" for s in SEVERITY_ORDER if by_sev[s])
        L.append(counts or f"{len(findings)} finding(s).")
        L.append("")
        L.append("| Sévérité | Titre | Statut | Retest |")
        L.append("|---|---|---|---|")
        ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 99, f.discovered_at or ""))
        for f in ordered:
            retest = f.retest_result or ("non retesté" if f.status in ("corrige", "risque_accepte") else "—")
            L.append(f"| {f.severity} | {f.title} | {FINDING_STATUS_LABELS.get(f.status, f.status)} | {retest} |")
        L.append("")

        L.append("## Détail des findings")
        for f in ordered:
            L.append(f"### {f.severity} — {f.title}")
            L.append(f"Statut : **{FINDING_STATUS_LABELS.get(f.status, f.status)}** · Découvert le {_fmt(f.discovered_at)}")
            if f.cwe_id or f.owasp_ref or f.cvss_score:
                meta = " · ".join(x for x in [f.cwe_id, f.owasp_ref, f"CVSS {f.cvss_score}" if f.cvss_score else None] if x)
                L.append(meta)
            if f.cve_id:
                L.append(f"CVE liée : {f.cve_id}")
            L.append("")
            if f.description:
                L.append(f.description)
                L.append("")
            if f.affected_component:
                L.append(f"**Composant affecté** : {f.affected_component}")
                L.append("")
            if f.impact:
                L.append("**Impact**")
                L.append(f.impact)
                L.append("")
            if f.proof_of_concept:
                L.append("**Preuve de concept**")
                L.append(f.proof_of_concept)
                L.append("")
            if f.recommendation:
                L.append("**Recommandation**")
                L.append(f.recommendation)
                L.append("")
            if f.retested_at:
                L.append(f"**Retest** : {f.retest_result or '—'}, le {_fmt(f.retested_at)} par {f.retested_by or '—'}.")
                L.append("")
            elif f.status in ("corrige", "risque_accepte"):
                L.append("⚠️ **Non retesté** — statut déclaré sans contre-vérification tracée.")
                L.append("")

    L.append("## Synthèse exécutive")
    L.append(audit.executive_summary or "Non rédigée.")
    L.append("")

    return "\n".join(L)
