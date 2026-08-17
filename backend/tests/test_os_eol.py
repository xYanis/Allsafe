"""
tests/test_os_eol.py
Détection d'OS en fin de support (services/os_eol.py) — fonction pure, aucune I/O.

Le piège réel déjà rencontré en conditions réelles (cf. STATUS.md 17/08/2026) est couvert
explicitement : `Asset.os` générique côté Windows ("Windows Server", sans l'année), seul
`Asset.os_version` porte l'année — un matcher qui chercherait l'année dans `os` ne trouverait
jamais rien sur le vrai parc.
"""

from services import os_eol


class TestCheckOsEol:
    def test_windows_server_2012_expired(self):
        # Support étendu terminé le 2023-10-10 — toujours dépassé au moment d'écrire ce test.
        result = os_eol.check_os_eol("Windows Server", "2012")
        assert result is not None
        assert result["status"] == "warn"
        assert result["id"] == "os_eol"
        assert "2023-10-10" in result["detail"]

    def test_windows_server_2012_r2_same_expiry_as_plain_2012(self):
        # os_version ne distingue pas 2012 de 2012 R2 (l'année seule) — les deux doivent
        # matcher la même entrée avec la même date, pas une régression silencieuse.
        plain = os_eol.check_os_eol("Windows Server", "2012")
        r2 = os_eol.check_os_eol("Windows Server 2012 R2 Standard", "2012")
        assert plain["detail"] == r2["detail"]

    def test_windows_server_2022_still_supported(self):
        result = os_eol.check_os_eol("Windows Server", "2022")
        assert result["status"] == "ok"

    def test_windows_10_vs_windows_server_not_confused(self):
        # "windows" est un sous-mot de "windows server" — le garde `"server" not in o`
        # doit empêcher un Windows Server d'être classé "Windows 10" par erreur.
        server = os_eol.check_os_eol("Windows Server", "10")
        client = os_eol.check_os_eol("Windows 10 Pro", "10")
        assert server is None  # "10" n'est l'année d'aucune édition Windows Server connue
        assert client is not None
        assert "Windows 10" in client["detail"]

    def test_ubuntu_lts_version_prefix_match(self):
        # os_version peut porter un patch complet ("18.04.6 LTS") — startswith, pas égalité stricte.
        result = os_eol.check_os_eol("Ubuntu", "18.04.6 LTS")
        assert result["status"] == "warn"

    def test_ubuntu_24_04_still_supported(self):
        result = os_eol.check_os_eol("Ubuntu", "24.04")
        assert result["status"] == "ok"

    def test_debian_12_still_supported(self):
        result = os_eol.check_os_eol("Debian GNU/Linux 12 (bookworm)", "12")
        assert result["status"] == "ok"

    def test_centos_rhel_7_expired(self):
        result = os_eol.check_os_eol("CentOS Linux", "7")
        assert result["status"] == "warn"

    def test_case_insensitive(self):
        # check_os_eol() met `os` en minuscules avant de matcher (mêmes chaînes que la
        # colonne DB, casse non garantie).
        result = os_eol.check_os_eol("WINDOWS SERVER", "2019")
        assert result is not None
        assert result["status"] == "ok"

    def test_unknown_os_returns_none(self):
        # Ni "warn" ni "ok" hasardeux sur un OS absent de la table — None, explicitement.
        assert os_eol.check_os_eol("FreeBSD", "13") is None

    def test_empty_os_returns_none(self):
        assert os_eol.check_os_eol("", "12") is None
        assert os_eol.check_os_eol(None, None) is None

    def test_matching_os_wrong_version_returns_none(self):
        # "Ubuntu" seul matche la famille, mais aucune entrée ne couvre "16.04" —
        # ne doit pas retomber sur une autre version LTS par erreur.
        assert os_eol.check_os_eol("Ubuntu", "16.04") is None
