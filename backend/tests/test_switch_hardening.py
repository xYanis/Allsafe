"""
tests/test_switch_hardening.py
Durcissement switches Cisco (services/switch_hardening.py) : construction des checks à partir
de sorties `show running-config` (fonctions pures), et le point le plus fragile constaté en
conditions réelles — la fusion dans Asset.network_compliance ne doit JAMAIS écraser les checks
posés par un autre producteur (services/network_protocol_check.py, cf. docstring du module).

Tests unitaires purs, sans base de données ni serveur HTTP (mêmes conventions que
test_incidents_guardrails.py) : `session` mocké quand nécessaire, modèles en mémoire.
"""

from unittest.mock import AsyncMock, MagicMock

from models import Asset
from services.network_cli import InteractiveShellError
from services.switch_hardening import (
    CMD_AAA, CMD_BANNER, CMD_LINES, CMD_NTP, CMD_PWENC, CMD_SNMP, CMD_SYSLOG,
    _build_checks, _check_telnet_and_timeout, _presence_check, _snmp_check,
    check_switch, run_switch_hardening_checks,
)

ERROR_OUTPUT = "% Invalid input detected at '^' marker."


class TestTelnetAndTimeout:
    def test_no_transport_input_directive_defaults_to_telnet_allowed(self):
        output = "line vty 0 4\n exec-timeout 10 0\n login local\n"
        telnet, timeout = _check_telnet_and_timeout(output)
        assert telnet["status"] == "warn"
        assert timeout["status"] == "ok"

    def test_ssh_only_is_ok(self):
        output = "line vty 0 4\n transport input ssh\n exec-timeout 10 0\n"
        telnet, _ = _check_telnet_and_timeout(output)
        assert telnet["status"] == "ok"

    def test_telnet_explicitly_allowed_is_warn(self):
        output = "line vty 0 4\n transport input telnet ssh\n"
        telnet, _ = _check_telnet_and_timeout(output)
        assert telnet["status"] == "warn"

    def test_exec_timeout_zero_zero_is_warn(self):
        output = "line vty 0 4\n transport input ssh\n exec-timeout 0 0\n"
        _, timeout = _check_telnet_and_timeout(output)
        assert timeout["status"] == "warn"

    def test_no_vty_line_is_unknown(self):
        output = "line con 0\n exec-timeout 10 0\n"
        telnet, timeout = _check_telnet_and_timeout(output)
        assert telnet["status"] == "unknown"
        assert timeout["status"] == "unknown"

    def test_error_output_is_unknown(self):
        telnet, timeout = _check_telnet_and_timeout(ERROR_OUTPUT)
        assert telnet["status"] == "unknown"
        assert timeout["status"] == "unknown"


class TestSnmpCheck:
    def test_default_community_is_warn(self):
        assert _snmp_check("snmp-server community public RO\n")["status"] == "warn"

    def test_custom_community_is_ok(self):
        assert _snmp_check("snmp-server community S3cr3t RO 99\n")["status"] == "ok"

    def test_no_snmp_lines_is_ok(self):
        assert _snmp_check("")["status"] == "ok"

    def test_error_output_is_unknown(self):
        assert _snmp_check(ERROR_OUTPUT)["status"] == "unknown"


class TestPresenceCheck:
    def test_present_is_ok(self):
        result = _presence_check("password_encryption", "service password-encryption\n", "ok", "warn")
        assert result["status"] == "ok"

    def test_absent_is_warn(self):
        result = _presence_check("password_encryption", "", "ok", "warn")
        assert result["status"] == "warn"

    def test_error_output_is_unknown(self):
        result = _presence_check("password_encryption", ERROR_OUTPUT, "ok", "warn")
        assert result["status"] == "unknown"


class TestBuildChecks:
    def test_produces_eight_checks_all_ok_from_clean_config(self):
        output = {
            CMD_LINES: "line vty 0 4\n transport input ssh\n exec-timeout 10 0\n",
            CMD_SNMP: "snmp-server community S3cr3t RO 99\n",
            CMD_PWENC: "service password-encryption\n",
            CMD_AAA: "aaa new-model\n",
            CMD_BANNER: "banner motd ^C Warning ^C\n",
            CMD_SYSLOG: "logging host 10.0.0.5\n",
            CMD_NTP: "ntp server 10.0.0.1\n",
        }
        checks = _build_checks(output)
        assert len(checks) == 8
        assert all(c["status"] == "ok" for c in checks)
        assert {c["id"] for c in checks} == {
            "telnet_disabled", "console_vty_timeout", "snmp_default_community",
            "password_encryption", "aaa_authentication", "banner_motd",
            "syslog_configured", "ntp_configured",
        }

    def test_missing_directives_produce_warnings(self):
        # Sortie vide partout : aucune des 7 lectures n'a rien trouvé.
        output = {cmd: "" for cmd in (CMD_LINES, CMD_SNMP, CMD_PWENC, CMD_AAA, CMD_BANNER, CMD_SYSLOG, CMD_NTP)}
        checks = _build_checks(output)
        statuses = {c["id"]: c["status"] for c in checks}
        # telnet_disabled/console_vty_timeout : "unknown" (aucune ligne VTY trouvée), pas "warn"
        # — on ne peut pas conclure sur une config qu'on n'a pas pu lire.
        assert statuses["telnet_disabled"] == "unknown"
        assert statuses["console_vty_timeout"] == "unknown"
        assert statuses["snmp_default_community"] == "ok"  # pas de communauté par défaut = ok
        assert statuses["password_encryption"] == "warn"
        assert statuses["aaa_authentication"] == "warn"
        assert statuses["banner_motd"] == "warn"
        assert statuses["syslog_configured"] == "warn"
        assert statuses["ntp_configured"] == "warn"


class TestCheckSwitchConnectivity:
    async def test_no_ip_returns_all_unknown(self):
        asset = Asset(id="a1", name="switch1", asset_type="network", ip_address=None)
        result = await check_switch(asset)
        assert len(result["checks"]) == 8
        assert all(c["status"] == "unknown" for c in result["checks"])

    async def test_connection_failure_returns_all_unknown(self, monkeypatch):
        asset = Asset(id="a1", name="switch1", asset_type="network", ip_address="10.0.0.1",
                       scan_username="admin", scan_password_encrypted=None)

        async def fake_run_commands(*args, **kwargs):
            raise InteractiveShellError("boom")

        monkeypatch.setattr("services.switch_hardening.run_commands", fake_run_commands)
        result = await check_switch(asset)
        assert all(c["status"] == "unknown" for c in result["checks"])
        assert "boom" in result["checks"][0]["detail"]


class TestMergeNotOverwrite:
    """Le bug qu'on cherche justement à empêcher : un même switch peut être suivi à la fois par
    PRTG/Meraki (network_protocol_check.py, qui ÉCRASE network_compliance en entier) et par ce
    module — la fusion par id doit préserver les checks déjà posés par l'autre producteur."""

    async def test_existing_network_protocols_check_survives(self, monkeypatch):
        asset = Asset(
            id="a1", name="switch1", asset_type="network", status="active",
            ip_address="10.0.0.1", scan_username="admin",
            network_compliance={
                "checks": [{"id": "network_protocols", "label": "Protocoles d'admin non chiffrés",
                            "status": "ok", "detail": "Ni Telnet ni HTTP détectés"}],
                "checked_at": "2026-08-01T00:00:00+00:00",
            },
        )

        result = MagicMock()
        result.scalars.return_value.all.return_value = [asset]
        session = MagicMock()
        session.execute = AsyncMock(return_value=result)
        session.commit = AsyncMock()
        session.rollback = AsyncMock()

        async def fake_check_switch(a):
            return {"checks": [{"id": "telnet_disabled", "label": "x", "status": "warn", "detail": "d"}],
                    "checked_at": "2026-08-13T00:00:00+00:00"}

        monkeypatch.setattr("services.switch_hardening.check_switch", fake_check_switch)

        stats = await run_switch_hardening_checks(db=session)

        ids = {c["id"] for c in asset.network_compliance["checks"]}
        assert "network_protocols" in ids  # préservé, pas écrasé
        assert "telnet_disabled" in ids     # nouveau check ajouté
        assert stats["warnings"] == 1
        session.commit.assert_called_once()

    async def test_asset_last_scan_updated(self, monkeypatch):
        """Contrairement à network_protocol_check.py (jamais credentialed), une vraie session SSH
        authentifiée met à jour last_scan — vérifié explicitement car c'est une divergence
        volontaire documentée."""
        asset = Asset(id="a1", name="switch1", asset_type="network", status="active",
                       ip_address="10.0.0.1", scan_username="admin", last_scan=None)

        result = MagicMock()
        result.scalars.return_value.all.return_value = [asset]
        session = MagicMock()
        session.execute = AsyncMock(return_value=result)
        session.commit = AsyncMock()

        async def fake_check_switch(a):
            return {"checks": [], "checked_at": "2026-08-13T00:00:00+00:00"}

        monkeypatch.setattr("services.switch_hardening.check_switch", fake_check_switch)

        await run_switch_hardening_checks(db=session)

        assert asset.last_scan is not None
