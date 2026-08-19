"""
tests/test_patch_checker_guardrails.py
Garde-fous de bascule automatique (services/patch_checker.py) — la partie la
plus sensible du projet : un bug ici a déjà écrasé des décisions humaines en
conditions réelles (cf. STATUS.md, incidents du 21/07 et du 27/07/2026).

Tests unitaires purs : `vuln`/`cve` sont de simples instances de modèle en
mémoire (jamais persistées), `session` est un mock — aucune base de données
requise, aucun risque pour les données réelles.
"""

from unittest.mock import MagicMock

import pytest

from models import Vulnerability, CVE, Asset
from services.patch_checker import (
    apply_patch_result, _check_debian_tracker, _check_windows_app_patch, _format_version_range,
)


def _vuln(status="open", validated_by=None, notes=None):
    return Vulnerability(status=status, validated_by=validated_by, notes=notes)


def _cve(severity="HIGH"):
    return CVE(severity=severity)


def _cve_with_range(product, severity="CRITICAL", **constraint):
    criteria = f"cpe:2.3:a:{product}:{product}:*:*:*:*:*:*:*:*"
    return CVE(
        severity=severity,
        cpe=[criteria],
        raw_data={"cve": {"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": criteria, **constraint}
        ]}]}]}},
    )


def _windows_asset(packages):
    return Asset(name="deployapp", os="Windows Server", installed_packages=packages)


class TestSeverityGuard:
    """CRITICAL = signalement seul, jamais de bascule automatique — règle absolue (CLAUDE.md)."""

    @pytest.mark.parametrize("check_result", [
        {"patch_detected": True},
        {"not_applicable": True},
        {"no_fix_available": True},
        {"partial_fix": True},
    ])
    def test_critical_never_auto_transitions(self, check_result):
        vuln = _vuln(status="open")
        cve = _cve(severity="CRITICAL")
        changed = apply_patch_result(vuln, cve, check_result, MagicMock())
        assert changed is False
        assert vuln.status == "open"

    @pytest.mark.parametrize("severity", ["HIGH", "MEDIUM", "LOW"])
    def test_non_critical_patch_detected_auto_patches(self, severity):
        vuln = _vuln(status="open")
        cve = _cve(severity=severity)
        changed = apply_patch_result(vuln, cve, {"patch_detected": True}, MagicMock())
        assert changed is True
        assert vuln.status == "patched"
        assert vuln.validated_by == "Auto (patch check)"


class TestTerminalStateGuard:
    """États terminaux : jamais modifiés automatiquement, quelle que soit l'origine de la décision."""

    @pytest.mark.parametrize("status", ["patched", "false_positive", "accepted_risk"])
    @pytest.mark.parametrize("check_result", [
        {"patch_detected": True},
        {"not_applicable": True},
        {"no_fix_available": True},
        {"partial_fix": True},
    ])
    def test_terminal_status_never_overwritten(self, status, check_result):
        vuln = _vuln(status=status, validated_by="Yanis Hortholary", notes="décision humaine")
        cve = _cve(severity="HIGH")
        changed = apply_patch_result(vuln, cve, check_result, MagicMock())
        assert changed is False
        assert vuln.status == status
        assert vuln.validated_by == "Yanis Hortholary"
        assert vuln.notes == "décision humaine"


class TestHumanQualifiedNonTerminalGuard:
    """Décision humaine sur awaiting_fix : seule la détection d'un correctif peut la faire évoluer."""

    def test_human_awaiting_fix_blocks_requalification(self):
        vuln = _vuln(status="awaiting_fix", validated_by="Yanis Hortholary", notes="annotation")
        cve = _cve(severity="HIGH")
        changed = apply_patch_result(vuln, cve, {"not_applicable": True}, MagicMock())
        assert changed is False
        assert vuln.status == "awaiting_fix"
        assert vuln.notes == "annotation"

    def test_human_awaiting_fix_still_progresses_to_patched(self):
        vuln = _vuln(status="awaiting_fix", validated_by="Yanis Hortholary", notes="annotation")
        cve = _cve(severity="HIGH")
        changed = apply_patch_result(vuln, cve, {"patch_detected": True}, MagicMock())
        assert changed is True
        assert vuln.status == "patched"

    def test_auto_qualified_awaiting_fix_keeps_reevaluating(self):
        # validated_by="Auto (patch check)" : pas une décision humaine, le
        # garde-fou ne s'applique pas, le cycle peut continuer à réévaluer.
        vuln = _vuln(status="awaiting_fix", validated_by="Auto (patch check)")
        cve = _cve(severity="HIGH")
        changed = apply_patch_result(vuln, cve, {"not_applicable": True}, MagicMock())
        assert changed is True
        assert vuln.status == "false_positive"


class TestAgentReportedLabel:
    """agent_reported=True (18/08/2026, cf. audit/AUDIT_SECURITE.md #34) — la bascule auto
    reste identique à un actif service_account (décision explicite), seule la piste d'audit
    change (validated_by), pour que NIS 2 reste honnête sur la provenance de la donnée."""

    def test_agent_reported_uses_distinct_label(self):
        vuln = _vuln(status="open")
        cve = _cve(severity="HIGH")
        changed = apply_patch_result(vuln, cve, {"patch_detected": True}, MagicMock(), agent_reported=True)
        assert changed is True
        assert vuln.validated_by == "Auto (patch check, agent-reported)"

    def test_non_agent_keeps_original_label(self):
        vuln = _vuln(status="open")
        cve = _cve(severity="HIGH")
        changed = apply_patch_result(vuln, cve, {"patch_detected": True}, MagicMock(), agent_reported=False)
        assert changed is True
        assert vuln.validated_by == "Auto (patch check)"

    def test_agent_reported_label_still_counts_as_non_human_for_reevaluation(self):
        # Une vuln déjà auto-qualifiée via le libellé agent doit continuer à se
        # réévaluer au cycle suivant, exactement comme le libellé historique
        # (cf. test_auto_qualified_awaiting_fix_keeps_reevaluating ci-dessus).
        vuln = _vuln(status="awaiting_fix", validated_by="Auto (patch check, agent-reported)")
        cve = _cve(severity="HIGH")
        changed = apply_patch_result(vuln, cve, {"not_applicable": True}, MagicMock(), agent_reported=True)
        assert changed is True
        assert vuln.status == "false_positive"


class TestPartialFixStatus:
    """`awaiting_fix_partial` (27/07/2026) — cas mixte, même règle de sévérité que les trois autres."""

    def test_non_critical_partial_fix_auto_transitions(self):
        vuln = _vuln(status="open")
        cve = _cve(severity="HIGH")
        changed = apply_patch_result(vuln, cve, {
            "partial_fix": True,
            "partial_fix_reason": "raison technique",
        }, MagicMock())
        assert changed is True
        assert vuln.status == "awaiting_fix_partial"
        assert vuln.notes == "raison technique"
        assert vuln.validated_by == "Auto (patch check)"
        assert vuln.awaiting_fix_at is not None


class TestDebianTrackerPartialFixDetection:
    """Détection pure (`_check_debian_tracker`) du cas mixte — aucune I/O, snapshot en dur."""

    def test_absent_plus_no_fix_is_partial(self):
        snapshot = {"by_source": {"perl": [("perl", "5.36.0-7")]}}
        fixes = [
            {"package": "libhttp-tiny-perl", "status": "open", "fixed_version": None},
            {"package": "perl", "status": "open", "fixed_version": None},
        ]
        result = _check_debian_tracker(snapshot, None, "bookworm", fixes)
        assert result["partial_fix"] is True
        assert result["no_fix_available"] is False
        assert result.get("not_applicable") is not True

    def test_all_absent_is_not_applicable_not_partial(self):
        snapshot = {"by_source": {}}
        fixes = [
            {"package": "libhttp-tiny-perl", "status": "open", "fixed_version": None},
        ]
        result = _check_debian_tracker(snapshot, None, "bookworm", fixes)
        assert result["not_applicable"] is True
        assert result.get("partial_fix") is not True

    def test_all_no_fix_is_no_fix_available_not_partial(self):
        snapshot = {"by_source": {
            "expat": [("libexpat1", "2.5.0-1")],
            "firefox-esr": [("firefox-esr", "115.0-1")],
        }}
        fixes = [
            {"package": "expat", "status": "open", "fixed_version": None},
            {"package": "firefox-esr", "status": "open", "fixed_version": None},
        ]
        result = _check_debian_tracker(snapshot, None, "bookworm", fixes)
        assert result["no_fix_available"] is True
        assert result.get("partial_fix") is not True

    def test_real_open_vuln_with_fix_available_is_not_partial(self):
        # Un paquet réellement vulnérable avec correctif disponible mais non
        # appliqué ne doit jamais être classé "partiel" — reste une vraie vuln
        # ouverte (cf. invariant dédié, STATUS.md).
        snapshot = {"by_source": {
            "openssl": [("openssl", "1.0-1")],
        }}
        fixes = [
            {"package": "libhttp-tiny-perl", "status": "open", "fixed_version": None},
            {"package": "openssl", "status": "resolved", "fixed_version": "2.0-1"},
        ]
        result = _check_debian_tracker(snapshot, None, "bookworm", fixes)
        assert result.get("partial_fix") is not True


class TestWindowsAppVersionCheck:
    """`_check_windows_app_patch` (03/08/2026) — comparaison de version pour les applications
    Windows tierces matchées via WindowsAppMapping (PuTTY, Wireshark...), sur le même principe
    que `_check_debian_tracker`/plages NVD côté Linux. Jusqu'ici absente : `check_patch_windows`
    ne savait vérifier que l'OS (KB/build), jamais une application tierce — incident réel qui a
    motivé cette fonction : CVE-2016-2563/DEPLOYAPP, PuTTY 0.81.0.0 installé (corrigé depuis
    0.67), jamais détecté faute de comparaison de version côté Windows."""

    def test_no_windows_mappings_returns_none(self):
        cve = _cve_with_range("putty", versionEndIncluding="0.66")
        asset = _windows_asset([{"name": "PuTTY release 0.81 (64-bit)", "version": "0.81.0.0"}])
        assert _check_windows_app_patch(asset, cve, []) is None

    def test_no_matching_installed_app_returns_none(self):
        cve = _cve_with_range("putty", versionEndIncluding="0.66")
        asset = _windows_asset([{"name": "Wireshark 4.6.6 x64", "version": "4.6.6"}])
        assert _check_windows_app_patch(asset, cve, [("putty", "putty")]) is None

    def test_missing_version_field_is_ignored(self):
        cve = _cve_with_range("putty", versionEndIncluding="0.66")
        asset = _windows_asset([{"name": "PuTTY release 0.81 (64-bit)"}])  # pas de champ version
        assert _check_windows_app_patch(asset, cve, [("putty", "putty")]) is None

    def test_installed_version_above_range_is_patched(self):
        cve = _cve_with_range("putty", versionEndIncluding="0.66")
        asset = _windows_asset([{"name": "PuTTY release 0.81 (64-bit)", "version": "0.81.0.0"}])
        result = _check_windows_app_patch(asset, cve, [("putty", "putty")])
        assert result["patch_detected"] is True
        assert result["method"] == "windows-app-version"

    def test_installed_version_within_range_is_vulnerable(self):
        cve = _cve_with_range("putty", versionEndIncluding="0.66")
        asset = _windows_asset([{"name": "PuTTY release 0.60 (64-bit)", "version": "0.60.0.0"}])
        result = _check_windows_app_patch(asset, cve, [("putty", "putty")])
        assert result["patch_detected"] is False

    def test_no_exploitable_constraint_is_indeterminate(self):
        cve = CVE(severity="HIGH", cpe=["cpe:2.3:a:putty:putty:*:*:*:*:*:*:*:*"], raw_data={})
        asset = _windows_asset([{"name": "PuTTY release 0.81 (64-bit)", "version": "0.81.0.0"}])
        result = _check_windows_app_patch(asset, cve, [("putty", "putty")])
        assert result["patch_detected"] is None

    def test_real_case_deployapp_putty_cve_2016_2563(self):
        cve = _cve_with_range("putty", versionEndIncluding="0.66")
        asset = _windows_asset([{"name": "PuTTY release 0.81 (64-bit)", "version": "0.81.0.0"}])
        result = _check_windows_app_patch(asset, cve, [("putty", "putty")])
        assert result["patch_detected"] is True

    def test_severity_guard_still_applies_via_apply_patch_result(self):
        # La détection de version ne court-circuite jamais la règle de sévérité :
        # CRITICAL reste signalement seul, même avec un verdict ferme "patché".
        cve = _cve_with_range("putty", severity="CRITICAL", versionEndIncluding="0.66")
        asset = _windows_asset([{"name": "PuTTY release 0.81 (64-bit)", "version": "0.81.0.0"}])
        check_result = _check_windows_app_patch(asset, cve, [("putty", "putty")])
        vuln = _vuln(status="open")
        changed = apply_patch_result(vuln, cve, check_result, MagicMock())
        assert changed is False


class TestVersionRangeFormatting:
    """`_format_version_range` + précision du texte/du bloc structuré (03/08/2026, demande
    explicite : le patch check doit dire explicitement contre quelle plage NVD la version
    installée a été comparée, pas seulement rendre un verdict brut)."""

    def test_end_including_only(self):
        assert _format_version_range([{"versionEndIncluding": "0.66"}]) == "≤ 0.66"

    def test_end_excluding_only(self):
        assert _format_version_range([{"versionEndExcluding": "0.67"}]) == "< 0.67"

    def test_start_and_end(self):
        assert _format_version_range([
            {"versionStartIncluding": "1.2", "versionEndExcluding": "1.5"}
        ]) == "≥ 1.2 et < 1.5"

    def test_exact_version(self):
        assert _format_version_range([{"exact_version": "0.66"}]) == "= 0.66"

    def test_no_constraints_returns_placeholder(self):
        assert _format_version_range([]) == "plage non exploitable"

    def test_app_version_check_block_and_details_mention_the_range(self):
        cve = _cve_with_range("putty", versionEndIncluding="0.66")
        asset = _windows_asset([{"name": "PuTTY release 0.81 (64-bit)", "version": "0.81.0.0"}])
        result = _check_windows_app_patch(asset, cve, [("putty", "putty")])

        assert result["app_version_check"] == [{
            "name": "PuTTY release 0.81 (64-bit)", "version": "0.81.0.0",
            "product": "putty", "verdict": True, "range": "≤ 0.66",
        }]
        assert "0.81.0.0" in result["details"]
        assert "≤ 0.66" in result["details"]

    def test_vulnerable_details_also_mention_the_range(self):
        cve = _cve_with_range("putty", versionEndIncluding="0.66")
        asset = _windows_asset([{"name": "PuTTY release 0.60 (64-bit)", "version": "0.60.0.0"}])
        result = _check_windows_app_patch(asset, cve, [("putty", "putty")])
        assert "0.60.0.0" in result["details"]
        assert "≤ 0.66" in result["details"]
