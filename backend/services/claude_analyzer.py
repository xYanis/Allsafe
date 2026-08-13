"""
Analyseur de vulnérabilités — logique locale, aucun appel API externe.
Produit des analyses structurées à partir des données CVSS/EPSS/CPE.
"""

import logging
from services.remediation import build_recommendation

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — détection et enrichissement local
# ─────────────────────────────────────────────────────────────────────────────

def _detect_vuln_type_fr(description: str | None) -> str | None:
    """Détecte le type de vulnérabilité à partir de mots-clés anglais courants."""
    if not description:
        return None
    d = description.lower()
    types = []
    if any(k in d for k in ["remote code execution", "execute code", " rce "]):
        types.append("Exécution de code à distance (RCE)")
    if any(k in d for k in ["sql injection", "sqli"]):
        types.append("Injection SQL")
    if any(k in d for k in ["buffer overflow", "stack overflow", "heap overflow", "stack-based buffer"]):
        types.append("Dépassement de tampon (Buffer Overflow)")
    if any(k in d for k in ["denial of service", " dos ", "crash"]):
        types.append("Déni de service (DoS)")
    if any(k in d for k in ["privilege escalation", "elevat", "local privilege"]):
        types.append("Élévation de privilèges")
    if any(k in d for k in ["cross-site scripting", " xss "]):
        types.append("Injection XSS")
    if any(k in d for k in ["path traversal", "directory traversal"]):
        types.append("Traversée de répertoires")
    if any(k in d for k in ["authentication bypass", "bypass auth", "unauthenticated"]):
        types.append("Contournement d'authentification")
    if any(k in d for k in ["information disclosure", "memory disclosure", "memory leak", "sensitive information"]):
        types.append("Divulgation d'informations")
    if any(k in d for k in ["use-after-free", "use after free"]):
        types.append("Use-After-Free (CWE-416)")
    if any(k in d for k in ["command injection", "os command", "arbitrary command"]):
        types.append("Injection de commandes OS")
    if any(k in d for k in ["server-side request", "ssrf"]):
        types.append("SSRF")
    if any(k in d for k in ["integer overflow", "integer underflow", "wraparound"]):
        types.append("Dépassement d'entier (CWE-190)")
    if any(k in d for k in ["out-of-bounds", "out of bounds", "oob read", "oob write"]):
        types.append("Lecture/écriture hors limites")
    if any(k in d for k in ["xml external", " xxe "]):
        types.append("Injection XXE")
    if any(k in d for k in ["deserialization", "deserializ"]):
        types.append("Désérialisation non sécurisée")
    return " · ".join(types[:3]) if types else None


def _detect_cwe(description: str | None) -> str | None:
    if not description:
        return None
    d = description.lower()
    if any(k in d for k in ["integer overflow", "integer underflow", "wraparound"]):
        return "CWE-190 — Integer Overflow"
    if any(k in d for k in ["stack-based buffer", "heap overflow"]):
        return "CWE-121/122 — Stack/Heap Buffer Overflow"
    if any(k in d for k in ["buffer overflow"]):
        return "CWE-787 — Out-of-bounds Write"
    if any(k in d for k in ["use-after-free"]):
        return "CWE-416 — Use After Free"
    if "sql injection" in d:
        return "CWE-89 — SQL Injection"
    if any(k in d for k in ["cross-site scripting", " xss "]):
        return "CWE-79 — Cross-site Scripting"
    if any(k in d for k in ["path traversal", "directory traversal"]):
        return "CWE-22 — Path Traversal"
    if any(k in d for k in ["command injection", "os command"]):
        return "CWE-78 — OS Command Injection"
    if any(k in d for k in ["deserialization"]):
        return "CWE-502 — Deserialization of Untrusted Data"
    if any(k in d for k in ["authentication bypass", "bypass auth"]):
        return "CWE-287 — Improper Authentication"
    if any(k in d for k in ["information disclosure", "memory disclosure"]):
        return "CWE-200 — Exposure of Sensitive Information"
    if any(k in d for k in ["null pointer", "null dereference"]):
        return "CWE-476 — NULL Pointer Dereference"
    return None


def _parse_cvss_vector(vector: str | None) -> dict:
    """Extrait les composants clés d'un vecteur CVSS v3 pour l'affichage."""
    if not vector:
        return {}
    labels = {
        "AV": {"N": "Réseau", "A": "Adjacent", "L": "Local", "P": "Physique"},
        "AC": {"L": "Faible", "H": "Élevée"},
        "PR": {"N": "Aucun", "L": "Faible", "H": "Élevé"},
        "UI": {"N": "Non requis", "R": "Requis"},
        "S":  {"U": "Inchangé", "C": "Modifié"},
        "C":  {"N": "Aucun", "L": "Faible", "H": "Élevé"},
        "I":  {"N": "Aucun", "L": "Faible", "H": "Élevé"},
        "A":  {"N": "Aucun", "L": "Faible", "H": "Élevé"},
    }
    names = {
        "AV": "Vecteur d'attaque", "AC": "Complexité", "PR": "Privilèges requis",
        "UI": "Interaction utilisateur", "S": "Portée", "C": "Confidentialité",
        "I": "Intégrité", "A": "Disponibilité",
    }
    result = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        if key in labels and val in labels[key]:
            result[names.get(key, key)] = labels[key][val]
    return result


def _generate_contexte_technique(breakdown: dict, cvss: float, severity: str) -> dict:
    """Génère un contexte technique lisible en français depuis le vecteur CVSS."""
    av  = breakdown.get("Vecteur d'attaque", "")
    ac  = breakdown.get("Complexité", "")
    pr  = breakdown.get("Privilèges requis", "")
    ui  = breakdown.get("Interaction utilisateur", "")
    c   = breakdown.get("Confidentialité", "")
    i   = breakdown.get("Intégrité", "")
    a   = breakdown.get("Disponibilité", "")

    acces_map = {
        "Réseau":    "Exploitable à distance via le réseau (pas d'accès local requis)",
        "Adjacent":  "Exploitable depuis un réseau adjacent uniquement",
        "Local":     "Exploitation locale uniquement (accès physique ou session requise)",
        "Physique":  "Exploitation physique uniquement",
    }
    acces = acces_map.get(av, "Vecteur d'accès non précisé")

    conditions = []
    if pr == "Aucun":
        conditions.append("aucun compte ou privilège requis")
    elif pr == "Faible":
        conditions.append("compte bas-privilège suffisant")
    else:
        conditions.append("compte administrateur requis")
    if ui == "Non requis":
        conditions.append("aucune interaction utilisateur nécessaire")
    if ac == "Faible":
        conditions.append("reproductible sans conditions particulières")
    elif ac == "Élevée":
        conditions.append("conditions d'exploitation complexes")

    impacts = []
    if c == "Élevé": impacts.append("confidentialité totale compromise")
    elif c == "Faible": impacts.append("confidentialité partiellement compromise")
    if i == "Élevé": impacts.append("intégrité totale compromise")
    elif i == "Faible": impacts.append("intégrité partiellement compromise")
    if a == "Élevé": impacts.append("système potentiellement indisponible")
    elif a == "Faible": impacts.append("disponibilité partiellement dégradée")

    score_context = (
        "Score maximal — exploitabilité et impact critiques"   if cvss >= 9.5 else
        "Score critique élevé"                                 if cvss >= 9.0 else
        "Score élevé"                                          if cvss >= 7.0 else
        "Score modéré"                                         if cvss >= 4.0 else
        "Score faible"
    )

    return {
        "acces":         acces,
        "conditions":    " · ".join(conditions),
        "impact":        " · ".join(impacts) if impacts else "Impact limité",
        "score_context": score_context,
    }


def _extract_product_from_cpe(cpe_list: list | None) -> str | None:
    for cpe in (cpe_list or []):
        parts = cpe.split(":")
        if len(parts) >= 5 and parts[4] not in ("*", "-", ""):
            vendor  = parts[3].replace("_", " ").title()
            product = parts[4].replace("_", " ").title()
            return f"{vendor} — {product}"
    return None


def _build_links(cve_id: str, description: str | None, cpe_list: list | None) -> dict:
    d = (description or "").lower()
    is_microsoft = (
        "microsoft" in d or "windows" in d or
        any("microsoft" in (c or "").lower() for c in (cpe_list or []))
    )
    links = {"nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}
    if is_microsoft:
        links["msrc"] = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"
    return links


# ─────────────────────────────────────────────────────────────────────────────
# API publique
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_cve_for_asset(cve, asset, api_key=None) -> dict:
    """
    Analyse locale d'une CVE pour un actif donné.
    Basée sur CVSS, EPSS et criticité de l'actif — aucun appel externe.
    """
    cvss      = cve.cvss_score or 0.0
    epss      = cve.epss_score or 0.0
    severity  = cve.severity or "UNKNOWN"
    criticite = (asset.tags or {}).get("criticite", "moyenne")
    breakdown = _parse_cvss_vector(cve.cvss_vector)

    # Priorité de correction
    if cvss >= 9.0:
        priority, urgency = "immédiate", "Corriger dans les 24-48 heures."
    elif cvss >= 7.0:
        priority, urgency = "haute", "Corriger dans les 7 jours."
    elif cvss >= 4.0:
        priority, urgency = "normale", "Corriger dans le mois."
    else:
        priority, urgency = "faible", "Corriger à la prochaine fenêtre de maintenance."

    # Contexte EPSS
    if epss >= 0.5:
        epss_ctx = f"Exploitation active dans la nature (EPSS {epss:.1%}) — risque immédiat."
    elif epss >= 0.1:
        epss_ctx = f"Exploitation connue (EPSS {epss:.1%}) — surveiller activement."
    else:
        epss_ctx = f"Exploitation peu documentée (EPSS {epss:.1%})."

    crit_note = {
        "haute":   "Actif critique — appliquer ce correctif en priorité absolue.",
        "moyenne": "Actif de criticité standard.",
        "faible":  "Actif non critique — impact opérationnel limité.",
    }.get(criticite, "")

    summary = " ".join(filter(None, [
        f"Vulnérabilité {severity} (CVSS {cvss:.1f}).",
        epss_ctx,
        crit_note,
        urgency,
    ]))

    # Date de publication formatée
    published_fr = None
    if cve.published:
        try:
            published_fr = cve.published.strftime("%-d %B %Y").replace(
                "January","janvier").replace("February","février").replace(
                "March","mars").replace("April","avril").replace(
                "May","mai").replace("June","juin").replace(
                "July","juillet").replace("August","août").replace(
                "September","septembre").replace("October","octobre").replace(
                "November","novembre").replace("December","décembre")
        except Exception:
            published_fr = str(cve.published)[:10]

    return {
        "analysis": {
            "priority":                 priority,
            "urgency":                  urgency,
            "exploitation_probability": epss_ctx,
            "criticite_asset":          criticite,
            "summary":                  summary,
            "description_fr":           _detect_vuln_type_fr(cve.description),
            "cwe":                      _detect_cwe(cve.description),
            "affected_product":         _extract_product_from_cpe(cve.cpe),
            "published_fr":             published_fr,
            "cvss_score":               cvss,
            "contexte_technique":       _generate_contexte_technique(breakdown, cvss, severity),
            "links":                    _build_links(cve.cve_id, cve.description, cve.cpe),
            "cvss_breakdown":           breakdown,
            "recommendation":           build_recommendation(cve, asset),
            "source":                   "local",
        }
    }


def _md_escape_cell(value) -> str:
    """Échappe une valeur pour une cellule de tableau markdown (pas de | ni de saut de ligne)."""
    return str(value if value not in (None, "") else "—").replace("|", "\\|").replace("\n", " ").strip()


def _md_table(headers: list[str], rows: list[list]) -> list[str]:
    if not rows:
        return []
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(["---"] * len(headers)) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_md_escape_cell(c) for c in row) + " |")
    return lines


def _activity_table(title: str, icon: str, items: list[dict], total: int | None = None) -> list[str]:
    """Sous-section de "Ce qui a été fait" en tableau — une ligne par vuln, avec
    l'analyste et l'annotation quand ils existent (awaiting_fix/false_positive).
    Table plutôt que puces imbriquées : bien plus lisible dès qu'il y a plus de
    2-3 entrées, cf. retour utilisateur.

    `total` (03/08/2026) : le vrai compte, distinct de `len(items)` — `items`
    arrive déjà plafonné à `ACTIVITY_ROW_CAP` (routers/reports.py), le CSV
    export l'est désormais aussi (même incident OOM qui a motivé le plafond),
    donc l'en-tête et le "et N de plus" doivent s'appuyer sur `total`, pas sur
    la taille de la liste tronquée."""
    if not items:
        return []
    total = total if total is not None else len(items)
    lines = [f"### {icon} {total} {title}"]
    rows = [
        [
            item["cve_id"],
            item["severity"] or "?",
            item["asset_name"],
            item.get("validated_by"),
            (item["notes"][:100] + "…") if item.get("notes") and len(item["notes"]) > 100 else item.get("notes"),
        ]
        for item in items
    ]
    lines += _md_table(["CVE", "Sévérité", "Actif", "Validé par", "Annotation"], rows)
    if total > len(items):
        lines.append(f"*… et {total - len(items)} de plus (non listées, liste plafonnée — le total ci-dessus reste exact).*")
    return lines


async def generate_executive_summary(
    stats: dict,
    top_cves: list,
    critical_unresolved: int,
    high_unresolved: int,
    activity: dict | None = None,
    period_label: str | None = None,
    asset_label: str | None = None,
    awaiting_fix_notes: dict | None = None,
    api_key=None,
) -> str:
    """
    Résumé exécutif généré localement à partir des statistiques agrégées.
    Aucun appel externe, aucune donnée nominative envoyée où que ce soit — reste
    100% dans l'infra locale (contrairement à claude_analyzer dans son ensemble,
    ce résumé n'a jamais fait d'appel API, cf. CLAUDE.md).

    `activity`/`period_label` (optionnels) : quand fournis, ajoute une section
    "Ce qui a été fait" (vulns corrigées/en attente/faux positifs/détectées
    depuis `period_days`) — pensé pour un envoi hebdomadaire à l'équipe
    sécurité, plutôt qu'un simple instantané de l'état courant.

    `critical_unresolved`/`high_unresolved` : nombre de CVE encore réellement à
    traiter (ni `patched` ni `false_positive`), distinct de
    `stats["critical_cves"]`/`["high_cves"]` qui comptent le total historique
    matché au parc (patché ou non). Utilisés pour le niveau de risque et les
    recommandations — sans cette distinction, une CVE déjà corrigée sur tous
    les actifs pouvait quand même déclencher "N CVE critique(s) en attente"
    dans les recommandations et peser sur le niveau de risque global.

    `awaiting_fix_notes` (optionnel) : {CVE.id: annotation} pour les CVE du Top
    5 ayant au moins une vulnérabilité en statut `awaiting_fix` — affichée dans
    la colonne "Statut" pour montrer qu'une CVE encore "à traiter" est bel et
    bien suivie (correctif éditeur/distro pas encore sorti), pas ignorée.
    """
    total_assets  = stats.get("total_assets", 0)
    exposed       = stats.get("exposed_assets", 0)
    open_vulns    = stats.get("open_vulnerabilities", 0)
    patched_vulns = stats.get("patched_vulnerabilities", 0)
    critical_cves = stats.get("critical_cves", 0)
    high_cves     = stats.get("high_cves", 0)
    patch_rate    = stats.get("patch_rate_percent", 0)

    if critical_unresolved > 20 or patch_rate < 20:
        risk_global = "CRITIQUE"
    elif critical_unresolved > 5 or patch_rate < 50:
        risk_global = "ÉLEVÉ"
    elif patch_rate < 80:
        risk_global = "MODÉRÉ"
    else:
        risk_global = "FAIBLE"

    lines = ["# Résumé exécutif — Posture de sécurité", ""]
    subtitle_parts = [p for p in (asset_label, f"Période : {period_label}" if period_label else None) if p]
    if subtitle_parts:
        lines += [" · ".join(subtitle_parts), ""]
    lines += [f"**Niveau de risque global : {risk_global}**"]

    if activity is not None:
        # Chaque section vaut {"items": [...plafonné...], "total": N} depuis le
        # 03/08/2026 (cf. routers/reports.py::_activity_during_period) — `total`
        # est le vrai compte, `items` peut être tronqué sur une semaine avec un
        # volume massif (ex: run de matching, cf. incident OOM documenté).
        def _section(key):
            v = activity.get(key) or {}
            return (v.get("items", []), v.get("total", 0)) if isinstance(v, dict) else (v, len(v))

        patched_items, patched_total = _section("patched")
        awaiting_items, awaiting_total = _section("awaiting_fix")
        false_pos_items, false_pos_total = _section("false_positive")
        _, detected_total = _section("detected")

        total_activity = patched_total + awaiting_total + false_pos_total
        lines += ["", f"## Ce qui a été fait — {period_label}"]
        if total_activity == 0 and not detected_total:
            lines.append("Aucune activité de traitement sur la période.")
        else:
            for section in (
                _activity_table("vulnérabilité(s) corrigée(s)", "✅", patched_items, patched_total),
                _activity_table("vulnérabilité(s) mise(s) en attente d'un correctif éditeur/distro", "⏳", awaiting_items, awaiting_total),
                _activity_table("faux positif(s) écarté(s)", "🚫", false_pos_items, false_pos_total),
            ):
                if section:
                    lines += [""] + section
        if detected_total:
            lines += ["", f"🆕 **{detected_total}** nouvelle(s) vulnérabilité(s) détectée(s) sur le parc durant la période."]

    lines += [
        "",
        "## État actuel",
        f"- {exposed} actif(s) exposé(s) sur {total_assets} au total "
        f"({round(exposed / total_assets * 100) if total_assets else 0}%)",
        f"- {open_vulns} vulnérabilité(s) ouverte(s), {patched_vulns} corrigée(s)",
        f"- Taux de correction : {patch_rate}%",
        "",
        "## CVE critiques et hautes",
        f"- {critical_cves} CVE de sévérité CRITICAL au total sur le parc, "
        f"dont **{critical_unresolved}** encore à traiter",
        f"- {high_cves} CVE de sévérité HIGH au total sur le parc, "
        f"dont **{high_unresolved}** encore à traiter",
    ]

    if top_cves:
        lines += ["", "## Top CVE critiques à traiter en priorité"]
        awaiting_fix_notes = awaiting_fix_notes or {}
        rows = []
        for cve in top_cves[:5]:
            notes = awaiting_fix_notes.get(cve.id)
            if notes:
                statut = "⏳ " + notes
            else:
                statut = "—"
            rows.append([cve.cve_id, cve.cvss_score or "?", (cve.description or "")[:150] + "…", statut])
        lines += _md_table(["CVE", "CVSS", "Description", "Statut"], rows)
    elif critical_cves > 0:
        lines += ["", "## Top CVE critiques à traiter en priorité", "Aucune — toutes les CVE critiques détectées sur le parc sont déjà corrigées ou écartées."]

    lines += ["", "## Recommandations"]
    if patch_rate < 50:
        lines.append("- ⚠ Taux de correction insuffisant — prioriser les CVE CRITICAL et HIGH.")
    if critical_unresolved > 0:
        lines.append(f"- ⚠ {critical_unresolved} CVE critique(s) encore à traiter — planifier des fenêtres de patch urgentes.")
    if total_assets and exposed > total_assets * 0.5:
        lines.append("- ⚠ Plus de la moitié des actifs sont exposés — lancer un cycle de patch global.")
    if patch_rate >= 80:
        lines.append("- ✓ Bon taux de correction — maintenir la cadence de patch.")

    return "\n".join(lines)
