"""
services/cvss_bte.py
CVSS-BTE (Base + Temporal + Environnemental) — score CVSS v3.1 réel, par (CVE, actif) et non
par CVE seule (contrairement à `CVE.cvss_score`, générique/identique pour tout le monde) :
coexiste avec `risk_score` (formule maison cvss×epss×criticité, cf. services/scoring.py) sans
le remplacer, cf. docs/MATCHING.md § CVSS-BTE.

Calcul via la librairie `cvss` (Red Hat Product Security, LGPLv3+) — évite de réimplémenter à
la main l'arrondi CVSS v3.1 (`round_up`, source connue de bugs subtils en cas d'erreur
d'arrondi flottant).

Périmètre volontairement limité à Temporal (E/RL/RC) + Environmental Requirements (CR/IR/AR) —
pas de Modified Base Metrics (MAV/MAC/...), non dérivables automatiquement de ce qu'Allsafe
connaît déjà sur un actif.

Dérivation automatique des six métriques :
- E  (Exploit Code Maturity) : `kev` (CISA, exploitation active confirmée) → H, le niveau le
  plus fort de l'échelle ; sinon `msf_module` (module Metasploit intégré) → F — la définition
  CVSS de "Functional exploit code available" correspond directement à un module intégré à un
  framework majeur, indépendamment de son `rank` de fiabilité qui mesure autre chose ; sinon X
  (Not Defined, neutre).
- RL (Remediation Level) : statut `awaiting_fix`/`awaiting_fix_partial` (aucun correctif publié
  par la distribution, cf. CLAUDE.md §1) → U (Unavailable) ; sinon X (pas de signal fiable pour
  distinguer un correctif officiel du reste).
- RC (Report Confidence) : toujours C (Confirmed) — CVE publiées par NVD, source confirmée.
  Même multiplicateur que X (1.0), gardé explicite pour la traçabilité du vecteur stocké.
- CR/IR/AR (Confidentiality/Integrity/Availability Requirements) : dérivés de
  `asset.tags["criticite"]`, déjà utilisé par `risk_score` (docs/MATCHING.md § Criticité
  métier) — une seule dimension métier existante réutilisée sur les trois axes plutôt que
  d'inventer trois réglages séparés.
"""

import logging

from cvss import CVSS3
from cvss.exceptions import CVSS3Error

logger = logging.getLogger(__name__)

_CRITICITE_TO_REQUIREMENT = {"haute": "H", "moyenne": "M", "faible": "L"}
_AWAITING_FIX_STATUSES = ("awaiting_fix", "awaiting_fix_partial")


def compute_cvss_bte(
    cvss_vector: str | None,
    kev: bool,
    msf_module: bool,
    vuln_status: str,
    criticite: str = "moyenne",
) -> tuple[float | None, str | None]:
    """
    Retourne (score_environnemental, vecteur_TE) ou (None, None) si le calcul est impossible
    (pas de vecteur de base connu, ou vecteur autre que CVSS v3.0/3.1 — ex. fallback CVSS v2,
    cf. nvd_fetcher.py::_parse_cve_item — la lib `cvss` ne couvre alors pas ce cas ici).
    """
    if not cvss_vector or not cvss_vector.startswith("CVSS:3."):
        return None, None

    exploit_maturity = "H" if kev else ("F" if msf_module else "X")
    remediation_level = "U" if vuln_status in _AWAITING_FIX_STATUSES else "X"
    requirement = _CRITICITE_TO_REQUIREMENT.get(criticite, "X")

    te_vector = f"E:{exploit_maturity}/RL:{remediation_level}/RC:C/CR:{requirement}/IR:{requirement}/AR:{requirement}"
    extended_vector = f"{cvss_vector}/{te_vector}"

    try:
        result = CVSS3(extended_vector)
    except CVSS3Error:
        logger.warning("Vecteur CVSS3 invalide pour le calcul CVSS-BTE : %r", cvss_vector)
        return None, None

    # `environmental_score` est un decimal.Decimal (arrondi CVSS via ROUND_CEILING) — converti
    # explicitement en float pour matcher la colonne `Vulnerability.cvss_bte` (Float) : asyncpg
    # n'encode pas un Decimal tel quel sur une colonne float8.
    return float(result.environmental_score), te_vector
