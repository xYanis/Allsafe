"""
tests/test_vsphere_matcher.py
Intégration vSphere/ESXi (services/vsphere_matcher.py) : normalisation/matching par hostname,
construction de l'Asset pour un hôte non reconnu (collection_method="vsphere_api",
hostname=None), et le point le plus fragile — le CPE posé après sync doit bien déclencher le
matching CVE (run_cpe_matching_for_asset_task), seul mécanisme qui rattache un hôte ESXi au
reste du pipeline (aucun scan SSH/WinRM classique ne passe par ce chemin, cf. docstring du
module et le garde-fou de routers/assets.py::scan_asset_endpoint).

Tests unitaires purs, sans base de données ni serveur HTTP (mêmes conventions que
test_incidents_guardrails.py) : `session` mocké, modèles en mémoire.
"""

from unittest.mock import AsyncMock, MagicMock

from models import Asset
from services.vsphere_matcher import (
    _asset_from_vsphere_host, _hardware_patch, _normalize_hostname,
    match_hosts_to_assets, sync_esxi_hosts,
)

SAMPLE_HOST = {
    "name": "ESX3.aer.loc", "version": "6.0.0", "build": "3825889",
    "vendor": "IBM", "model": "IBM System x3550 M4", "uuid": "abc-123",
    "cpu_model": "Intel Xeon E5-2670", "cpu_cores": 16, "ram_gb": 192.0,
    "management_ip": "192.168.104.6", "connection_state": "connected",
    "vms": [{"name": "WDS2012", "power_state": "poweredOn"}],
    "hardening": {
        "lockdown_mode": "lockdownDisabled",
        "ssh_running": False,
        "ntp_servers": ["tintamarre.aer.loc"],
        # "" (chaîne vide) = option lue avec succès mais aucun hôte configuré (-> "warn").
        # None représenterait plutôt un échec de lecture (-> "unknown", cf.
        # services/vsphere_hardening.py) — distinction volontaire, pas testée ici.
        "syslog_host": "",
        "account_lock_failures": 10,
    },
}


class TestNormalizeHostname:
    def test_strips_domain_and_lowercases(self):
        assert _normalize_hostname("ESX3.aer.loc") == "esx3"

    def test_none_returns_none(self):
        assert _normalize_hostname(None) is None

    def test_empty_string_returns_none(self):
        assert _normalize_hostname("") is None


class TestHardwarePatch:
    def test_includes_esxi_specific_fields(self):
        patch = _hardware_patch(SAMPLE_HOST)
        assert patch["esxi_build"] == "3825889"
        assert patch["esxi_vms"] == SAMPLE_HOST["vms"]
        assert patch["vendor"] == "IBM"


class TestAssetFromVsphereHost:
    def test_hostname_left_none(self):
        # Colonne UNIQUE, host["name"] côté vCenter n'est pas garanti être un FQDN résolvable
        # — même raisonnement que meraki_matcher.py/prtg_matcher.py.
        asset = _asset_from_vsphere_host(SAMPLE_HOST)
        assert asset.hostname is None
        assert asset.name == "ESX3.aer.loc"

    def test_collection_method_and_source(self):
        asset = _asset_from_vsphere_host(SAMPLE_HOST)
        assert asset.collection_method == "vsphere_api"
        assert asset.source == "vsphere"
        assert asset.asset_type == "server"  # pas de nouvelle valeur, décision volontaire

    def test_os_fields(self):
        asset = _asset_from_vsphere_host(SAMPLE_HOST)
        assert asset.os == "VMware ESXi"
        assert asset.os_version == "6.0.0"


class TestMatchHostsToAssets:
    async def test_matches_by_hostname(self):
        existing = Asset(id="a1", name="other-name", hostname="esx3.aer.loc", status="active")
        session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = [existing]
        session.execute = AsyncMock(return_value=result)

        matched, unmatched = await match_hosts_to_assets([SAMPLE_HOST], session)

        assert matched["ESX3.aer.loc"] is existing
        assert unmatched == []

    async def test_matches_by_name_when_hostname_absent(self):
        existing = Asset(id="a1", name="ESX3.aer.loc", hostname=None, status="active")
        session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = [existing]
        session.execute = AsyncMock(return_value=result)

        matched, unmatched = await match_hosts_to_assets([SAMPLE_HOST], session)

        assert matched["ESX3.aer.loc"] is existing

    async def test_unmatched_when_no_asset(self):
        session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = []
        session.execute = AsyncMock(return_value=result)

        matched, unmatched = await match_hosts_to_assets([SAMPLE_HOST], session)

        assert matched == {}
        assert len(unmatched) == 1

    async def test_host_without_name_skipped(self):
        session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = []
        session.execute = AsyncMock(return_value=result)

        matched, unmatched = await match_hosts_to_assets([{**SAMPLE_HOST, "name": None}], session)

        assert matched == {}
        assert unmatched == []


class TestSyncEsxiHosts:
    async def test_not_configured_returns_error_dict(self, monkeypatch):
        monkeypatch.setattr("services.vsphere_matcher.vsphere_client.is_configured", lambda: False)
        result = await sync_esxi_hosts()
        assert result == {"error": "vsphere_not_configured"}

    async def test_matched_asset_gets_cpe_and_triggers_matching(self, monkeypatch):
        existing = Asset(id="a1", name="ESX3.aer.loc", hostname=None, status="active", asset_type="server")

        monkeypatch.setattr("services.vsphere_matcher.vsphere_client.is_configured", lambda: True)
        monkeypatch.setattr("services.vsphere_matcher.vsphere_client.get_hosts", lambda: [SAMPLE_HOST])

        result = MagicMock()
        result.scalars.return_value.all.return_value = [existing]
        session = MagicMock()
        session.execute = AsyncMock(return_value=result)
        session.commit = AsyncMock()
        session.get = AsyncMock(return_value=None)
        session.add = MagicMock()

        apply_async_mock = MagicMock()
        monkeypatch.setattr(
            "services.vsphere_matcher.run_cpe_matching_for_asset_task.apply_async", apply_async_mock,
        )

        stats = await sync_esxi_hosts(db=session)

        assert stats["matched_assets"] == 1
        # Aucun scan SSH/WinRM ne passe par un hôte ESXi (bloqué par scan_asset_endpoint) — c'est
        # cette sync qui doit poser le CPE directement, sinon l'hôte ne recevrait jamais aucune
        # CVE.
        assert existing.cpe_list == ["cpe:2.3:o:vmware:esxi:6.0.0:*:*:*:*:*:*:*"]
        apply_async_mock.assert_called_once_with(args=["a1"], queue="default")

    async def test_hardening_checks_written_to_last_scan_result(self, monkeypatch):
        existing = Asset(id="a1", name="ESX3.aer.loc", hostname=None, status="active", asset_type="server")

        monkeypatch.setattr("services.vsphere_matcher.vsphere_client.is_configured", lambda: True)
        monkeypatch.setattr("services.vsphere_matcher.vsphere_client.get_hosts", lambda: [SAMPLE_HOST])

        result = MagicMock()
        result.scalars.return_value.all.return_value = [existing]
        session = MagicMock()
        session.execute = AsyncMock(return_value=result)
        session.commit = AsyncMock()
        session.get = AsyncMock(return_value=None)
        session.add = MagicMock()
        monkeypatch.setattr("services.vsphere_matcher.run_cpe_matching_for_asset_task.apply_async", MagicMock())

        await sync_esxi_hosts(db=session)

        # asset_type="server" -> Durcissement.jsx::checksFor() lit last_scan_result.compliance,
        # pas network_compliance (réservé aux actifs asset_type="network").
        checks = existing.last_scan_result["compliance"]["checks"]
        assert len(checks) == 5
        statuses = {c["id"]: c["status"] for c in checks}
        assert statuses["lockdown_mode"] == "warn"  # lockdownDisabled dans SAMPLE_HOST
        assert statuses["ssh_service"] == "ok"       # ssh_running=False
        assert statuses["ntp_configured"] == "ok"
        assert statuses["syslog_configured"] == "warn"  # syslog_host=None
        assert statuses["account_lockout"] == "ok"

    async def test_unmatched_host_not_created_by_default(self, monkeypatch):
        monkeypatch.setattr("services.vsphere_matcher.vsphere_client.is_configured", lambda: True)
        monkeypatch.setattr("services.vsphere_matcher.vsphere_client.get_hosts", lambda: [SAMPLE_HOST])

        result = MagicMock()
        result.scalars.return_value.all.return_value = []
        session = MagicMock()
        session.execute = AsyncMock(return_value=result)
        session.commit = AsyncMock()
        # SyncState déjà existant : db.add() ne doit alors être appelé pour AUCUNE raison dans
        # cette branche (ni Asset — import_new_assets=False par défaut —, ni SyncState).
        session.get = AsyncMock(return_value=MagicMock())
        session.add = MagicMock()

        stats = await sync_esxi_hosts(db=session)  # import_new_assets=False (défaut)

        assert stats["assets_created"] == 0
        assert len(stats["unmatched_hosts"]) == 1
        session.add.assert_not_called()
