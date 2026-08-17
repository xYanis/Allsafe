"""
tests/test_cvss_bte.py
Score CVSS-BTE (services/cvss_bte.py) — fonction pure, aucune I/O (la lib `cvss` fait le calcul
en mémoire). Couvre la dérivation des 6 métriques (E/RL/RC/CR/IR/AR) et les cas de repli.

CVE-2021-44228 (Log4Shell) sert de vecteur de base connu pour les cas nominaux — score de base
10.0, pratique pour distinguer un score coupé par le plafond CVSS d'un vrai bug de calcul.
"""

from services.cvss_bte import compute_cvss_bte

LOG4SHELL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


class TestComputeCvssBte:
    def test_no_vector_returns_none(self):
        assert compute_cvss_bte(None, kev=False, msf_module=False, vuln_status="open") == (None, None)

    def test_empty_vector_returns_none(self):
        assert compute_cvss_bte("", kev=False, msf_module=False, vuln_status="open") == (None, None)

    def test_cvss_v2_vector_returns_none(self):
        # Pas de "CVSS:3." en préfixe — fallback CVSS v2 (cf. nvd_fetcher.py), hors périmètre
        # de la lib `cvss.CVSS3`.
        v2 = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
        assert compute_cvss_bte(v2, kev=False, msf_module=False, vuln_status="open") == (None, None)

    def test_malformed_v3_vector_returns_none(self):
        score, vector = compute_cvss_bte("CVSS:3.1/GARBAGE", kev=False, msf_module=False, vuln_status="open")
        assert score is None
        assert vector is None

    def test_kev_gives_exploit_maturity_high(self):
        score, vector = compute_cvss_bte(LOG4SHELL_VECTOR, kev=True, msf_module=False, vuln_status="open")
        assert "E:H" in vector
        assert isinstance(score, float)

    def test_msf_module_without_kev_gives_exploit_maturity_functional(self):
        score, vector = compute_cvss_bte(LOG4SHELL_VECTOR, kev=False, msf_module=True, vuln_status="open")
        assert "E:F" in vector

    def test_kev_takes_priority_over_msf_module(self):
        # Les deux signaux sont vrais en même temps — KEV (H) l'emporte sur Metasploit (F),
        # jamais l'inverse ni une moyenne.
        _, vector = compute_cvss_bte(LOG4SHELL_VECTOR, kev=True, msf_module=True, vuln_status="open")
        assert "E:H" in vector

    def test_no_kev_no_msf_gives_exploit_maturity_not_defined(self):
        _, vector = compute_cvss_bte(LOG4SHELL_VECTOR, kev=False, msf_module=False, vuln_status="open")
        assert "E:X" in vector

    def test_awaiting_fix_gives_remediation_level_unavailable(self):
        _, vector = compute_cvss_bte(LOG4SHELL_VECTOR, kev=False, msf_module=False, vuln_status="awaiting_fix")
        assert "RL:U" in vector

    def test_awaiting_fix_partial_also_gives_remediation_level_unavailable(self):
        _, vector = compute_cvss_bte(LOG4SHELL_VECTOR, kev=False, msf_module=False, vuln_status="awaiting_fix_partial")
        assert "RL:U" in vector

    def test_open_status_gives_remediation_level_not_defined(self):
        _, vector = compute_cvss_bte(LOG4SHELL_VECTOR, kev=False, msf_module=False, vuln_status="open")
        assert "RL:X" in vector

    def test_report_confidence_always_confirmed(self):
        _, vector = compute_cvss_bte(LOG4SHELL_VECTOR, kev=False, msf_module=False, vuln_status="open")
        assert "RC:C" in vector

    def test_criticite_haute_maps_to_requirement_high(self):
        _, vector = compute_cvss_bte(LOG4SHELL_VECTOR, kev=False, msf_module=False, vuln_status="open", criticite="haute")
        assert "CR:H/IR:H/AR:H" in vector

    def test_criticite_moyenne_maps_to_requirement_medium(self):
        _, vector = compute_cvss_bte(LOG4SHELL_VECTOR, kev=False, msf_module=False, vuln_status="open", criticite="moyenne")
        assert "CR:M/IR:M/AR:M" in vector

    def test_criticite_faible_maps_to_requirement_low(self):
        _, vector = compute_cvss_bte(LOG4SHELL_VECTOR, kev=False, msf_module=False, vuln_status="open", criticite="faible")
        assert "CR:L/IR:L/AR:L" in vector

    def test_unknown_criticite_maps_to_requirement_not_defined(self):
        _, vector = compute_cvss_bte(LOG4SHELL_VECTOR, kev=False, msf_module=False, vuln_status="open", criticite="inconnue")
        assert "CR:X/IR:X/AR:X" in vector

    def test_score_is_plain_float_not_decimal(self):
        # Regression réelle rencontrée en conditions réelles (17/08/2026, cf. STATUS.md) :
        # environmental_score de la lib `cvss` est un decimal.Decimal, asyncpg ne l'encode
        # pas tel quel sur une colonne Float — doit être explicitement converti.
        score, _ = compute_cvss_bte(LOG4SHELL_VECTOR, kev=True, msf_module=False, vuln_status="open", criticite="haute")
        assert type(score) is float

    def test_score_capped_at_ten(self):
        score, _ = compute_cvss_bte(LOG4SHELL_VECTOR, kev=True, msf_module=True, vuln_status="awaiting_fix", criticite="haute")
        assert score <= 10.0
