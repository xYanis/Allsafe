"""
Remediation service — recommandations et scripts de correctifs
Logique entièrement locale, aucun appel API externe.
⚠️ CyberVuln propose uniquement. L'analyste valide, teste et applique.
"""

import logging
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Asset, CVE, Vulnerability

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_windows(asset: Asset) -> bool:
    return "windows" in (asset.os or "").lower()


def _extract_product(cpe_list: list) -> str:
    """Extrait 'Vendor Product' depuis la liste de CPE de la CVE."""
    for cpe in cpe_list or []:
        parts = cpe.split(":")
        # cpe:2.3:<type>:<vendor>:<product>:...
        if len(parts) >= 5 and parts[4] not in ("*", "-", ""):
            vendor  = parts[3].replace("_", " ").title()
            product = parts[4].replace("_", " ").title()
            return f"{vendor} {product}"
    return "le composant concerné"


def _effort(cvss: float | None) -> str:
    if cvss is None:
        return "Variable"
    if cvss >= 9.0:
        return "Urgent — 1-2h max"
    if cvss >= 7.0:
        return "30-60 min"
    return "15-30 min"


# ─────────────────────────────────────────────────────────────────────────────
# Niveau 1 — Recommandation textuelle
# ─────────────────────────────────────────────────────────────────────────────

def build_recommendation(cve: CVE, asset: Asset) -> dict:
    product  = _extract_product(cve.cpe or [])
    is_win   = _is_windows(asset)
    refs     = [r for r in (cve.references or []) if isinstance(r, str)][:3]

    if is_win:
        steps = [
            "Identifier le numéro de KB associé à cette CVE sur catalog.update.microsoft.com",
            f"Ouvrir Windows Update et rechercher les mises à jour pour {product}",
            "Appliquer le correctif de sécurité correspondant",
            "Vérifier l'installation dans Paramètres → Windows Update → Historique",
            "Redémarrer le serveur si requis, hors heure de production",
        ]
        kb_pkg   = f"Voir catalog.update.microsoft.com — rechercher {cve.cve_id}"
        verify   = f"Get-HotFix | Where-Object {{$_.Description -eq 'Security Update'}} | Sort-Object InstalledOn -Desc | Select-Object -First 5"
        reboot   = True
    else:
        pkg_name = (cve.cpe or [""])[0].split(":")[4].replace("_", "-") if cve.cpe else product.lower()
        steps = [
            "sudo apt-get update  # ou : sudo yum check-update",
            f"sudo apt-get upgrade {pkg_name}  # ou : sudo yum update {pkg_name}",
            f"Vérifier la version installée : dpkg -l {pkg_name} | grep {pkg_name}",
            "Redémarrer le service concerné si nécessaire",
            "Confirmer la version corrigée dans les notes de version du paquet",
        ]
        kb_pkg   = pkg_name
        verify   = f"dpkg -l | grep {pkg_name}  # ou : rpm -qa | grep {pkg_name}"
        reboot   = False

    result = {
        "steps":            steps,
        "kb_or_package":    kb_pkg,
        "verification_cmd": verify,
        "reboot_required":  reboot,
        "estimated_effort": _effort(cve.cvss_score),
        "source":           "local",
    }
    if refs:
        result["references"] = refs
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Niveau 2 — Script correctif
# ─────────────────────────────────────────────────────────────────────────────

def _build_powershell_script(cve: CVE) -> str:
    cve_id = cve.cve_id
    return f"""# AVERTISSEMENT : Tester en recette avant production
# CVE : {cve_id}  |  CVSS : {cve.cvss_score}  |  Sévérité : {cve.severity}
# Rechercher le numéro de KB sur : https://catalog.update.microsoft.com

$CveId = "{cve_id}"

# ── Vérification pré-patch ──────────────────────────────────────────────────
Write-Host "Vérification des mises à jour installées récentes..." -ForegroundColor Cyan
$installed = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20
$installed | Format-Table HotFixID, Description, InstalledOn -AutoSize

# ── Application du correctif ────────────────────────────────────────────────
Write-Host "Lancement de Windows Update..." -ForegroundColor Cyan
try {{
    Install-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
    $status = "PATCHED"
}} catch {{
    # Si le module PSWindowsUpdate n'est pas installé :
    # Install-Module PSWindowsUpdate -Force
    Write-Warning "Module PSWindowsUpdate requis. Commande manuelle : Install-Module PSWindowsUpdate -Force"
    $status = "FAILED"
}}

# ── Vérification post-patch ─────────────────────────────────────────────────
Write-Host "État final : $status" -ForegroundColor $(if ($status -eq "PATCHED") {{"Green"}} else {{"Red"}})
Write-Host $status
"""


def _build_bash_script(cve: CVE, asset: Asset) -> str:
    cve_id   = cve.cve_id
    cpe_list = cve.cpe or []
    pkg_name = cpe_list[0].split(":")[4].replace("_", "-") if cpe_list else "PAQUET_A_REMPLACER"

    return f"""#!/bin/bash
# AVERTISSEMENT : Tester en recette avant production
# CVE : {cve_id}  |  CVSS : {cve.cvss_score}  |  Sévérité : {cve.severity}

PKG="{pkg_name}"  # Adapter si nécessaire

# ── Détection du gestionnaire de paquets ────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PM="apt-get"
elif command -v yum &>/dev/null; then
    PM="yum"
elif command -v dnf &>/dev/null; then
    PM="dnf"
else
    echo "FAILED - Gestionnaire de paquets non reconnu"
    exit 1
fi

# ── Vérification pré-patch ──────────────────────────────────────────────────
echo "=== Version actuelle de $PKG ==="
if [ "$PM" = "apt-get" ]; then
    dpkg -l | grep "$PKG" | head -5
else
    rpm -qa | grep "$PKG" | head -5
fi

# ── Mise à jour ─────────────────────────────────────────────────────────────
echo "=== Mise à jour via $PM ==="
if sudo $PM update -y && sudo $PM upgrade "$PKG" -y; then
    PATCH_STATUS="PATCHED"
else
    PATCH_STATUS="FAILED"
fi

# ── Vérification post-patch ─────────────────────────────────────────────────
echo "=== Version après mise à jour ==="
if [ "$PM" = "apt-get" ]; then
    dpkg -l | grep "$PKG" | head -5
else
    rpm -qa | grep "$PKG" | head -5
fi

echo "$PATCH_STATUS"
"""


# ─────────────────────────────────────────────────────────────────────────────
# API publique
# ─────────────────────────────────────────────────────────────────────────────

async def get_recommendation(vuln_id: UUID, db: AsyncSession) -> dict:
    vuln, cve, asset = await _load_vuln_context(vuln_id, db)
    recommendation = build_recommendation(cve, asset)

    existing = dict(vuln.ai_analysis or {})
    existing["recommendation"] = recommendation
    vuln.ai_analysis = existing
    await db.commit()

    return {"vuln_id": str(vuln_id), "recommendation": recommendation}


async def get_script(vuln_id: UUID, db: AsyncSession) -> dict:
    vuln, cve, asset = await _load_vuln_context(vuln_id, db)
    is_win = _is_windows(asset)

    script_type = "powershell" if is_win else "bash"
    script = _build_powershell_script(cve) if is_win else _build_bash_script(cve, asset)

    existing = dict(vuln.ai_analysis or {})
    existing["script"] = {"type": script_type, "content": script}
    vuln.ai_analysis = existing
    await db.commit()

    return {
        "vuln_id":     str(vuln_id),
        "script_type": script_type,
        "script":      script,
        "warning":     "Tester en recette avant toute application en production.",
    }


async def _load_vuln_context(
    vuln_id: UUID, db: AsyncSession
) -> tuple[Vulnerability, CVE, Asset]:
    row = (await db.execute(
        select(Vulnerability, CVE, Asset)
        .join(CVE, Vulnerability.cve_id == CVE.id)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .where(Vulnerability.id == vuln_id)
    )).one_or_none()

    if row is None:
        raise HTTPException(404, f"Vulnérabilité {vuln_id} introuvable")

    return row
