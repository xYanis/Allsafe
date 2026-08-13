"""
services/vsphere_client.py
Client de lecture seule pour l'API vSphere (pyVmomi), via vCenter Server (13/08/2026,
intégration ESXi — CVE hyperviseur à fort impact, cf. campagnes ransomware ESXiArgs 2023 sur
ESXi non patchés). Un seul point de connexion vCenter qui agrège tous les vim.HostSystem
qu'il gère (topologie confirmée avec l'utilisateur : ESXi géré par vCenter, pas d'hôtes
standalone dans ce parc) — même esprit que MERAKI_ORGANIZATION_ID absent = "toutes les
organisations visibles par la clé" (cf. services/meraki_client.py).

pyVmomi est synchrone (pas d'API asyncio, même contrainte que pywinrm dans
asset_scanner.py::_scan_windows) — get_hosts() doit toujours être appelé via
asyncio.get_event_loop().run_in_executor(None, ...) depuis le matcher, jamais directement
dans une coroutine.

Lecture seule stricte (cf. CLAUDE.md § Règles absolues, non-intervention) : aucun appel de
ce module n'écrit ni n'agit sur vCenter/ESXi, uniquement des lectures de propriétés déjà
exposées par l'API. L'inventaire VM par hôte reste informatif (Asset.hardware côté matcher) —
aucune VM n'est créée comme Asset dans cette passe, aucun rapprochement hostname VM↔Asset.
Durcissement esxcli explicitement hors scope (seule la sync inventaire + CPE est couverte ici).
"""

import logging
import re
import ssl
from typing import Optional

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

from config import settings

logger = logging.getLogger(__name__)

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class VsphereConfigError(RuntimeError):
    """Levée si VCENTER_URL / VCENTER_USER / VCENTER_PASSWORD ne sont pas configurés."""


def is_configured() -> bool:
    return bool(settings.VCENTER_URL and settings.VCENTER_USER and settings.VCENTER_PASSWORD)


def _ssl_context() -> Optional[ssl.SSLContext]:
    if settings.VCENTER_VERIFY_TLS:
        return None
    logger.warning(
        "VCENTER_VERIFY_TLS=false — vérification du certificat TLS désactivée pour %s "
        "(certificat auto-signé, cf. config.py)", settings.VCENTER_URL,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Politique de sécurité OpenSSL par défaut (SECLEVEL=2 dans cette image) trop stricte
    # pour le TLS embarqué de nombreux ESXi/vCenter, même récents — constaté en conditions
    # réelles (13/08/2026) : SSLEOFError systématique en handshake contre un ESXi malgré une
    # connexion TCP qui passe, alors que le même handshake réussit hors conteneur (OpenSSL
    # identique, seule la politique de ciphers diffère). SECLEVEL=1 uniquement dans cette
    # branche déjà "vérification désactivée" — jamais sur une connexion où le certificat est
    # vérifié, pour ne pas affaiblir la sécurité TLS d'un déploiement qui n'en a pas besoin.
    ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    return ctx


def _management_ip(host) -> Optional[str]:
    """Best-effort : contrairement à ce qu'on pourrait attendre, `summary.managementServerIp`
    est l'IP du vCenter qui gère l'hôte, pas celle de l'hôte lui-même (piège classique de
    l'API vSphere) — cherche la vnic taguée "management" dans virtualNicManagerInfo, repli
    sur host.name si celui-ci ressemble déjà à une IP. N'importe quelle erreur ici (host
    inaccessible, propriété absente sur cette version d'ESXi...) retombe sur None plutôt que
    de faire échouer la collecte de l'hôte entier."""
    try:
        net_config = host.config.virtualNicManagerInfo.netConfig
        for cfg in net_config:
            if cfg.nicType != "management" or not cfg.candidateVnic:
                continue
            selected = set(cfg.selectedVnic or [])
            for vnic in cfg.candidateVnic:
                if vnic.key in selected:
                    return vnic.spec.ip.ipAddress
    except Exception:
        pass
    name = host.name or ""
    return name if _IPV4_RE.match(name) else None


def _vm_dict(vm_obj) -> Optional[dict]:
    try:
        summary = vm_obj.summary
        config = summary.config
        runtime = summary.runtime
        return {
            "name": config.name if config else None,
            "power_state": runtime.powerState if runtime else None,
            "guest_os": config.guestFullName if config else None,
            "cpu": config.numCpu if config else None,
            "memory_mb": config.memorySizeMB if config else None,
        }
    except Exception:
        # Une VM inaccessible (permissions, migration en cours...) ne doit jamais faire
        # échouer la collecte de l'hôte qui l'héberge — juste absente de la liste.
        return None


def _advanced_option(host, name: str):
    """Lit une option avancée ESXi (Syslog.global.logHost, Security.AccountLockFailures...) via
    l'API vSphere elle-même — jamais de SSH sur l'hôte. None si absente/inaccessible plutôt
    qu'une exception qui remonte (droits insuffisants du compte de service, propriété absente
    sur cette version d'ESXi)."""
    try:
        opt = host.configManager.advancedOption.QueryOptions(name)
        return opt[0].value if opt else None
    except Exception:
        return None


def _hardening_facts(host) -> dict:
    """Faits bruts de durcissement (13/08/2026, cf. services/vsphere_hardening.py pour la
    construction des checks à partir de ces faits) — lus uniquement via l'API vSphere, jamais
    de SSH sur l'hôte ESXi lui-même (contrairement aux switches, où SSH était la seule voie
    disponible, cf. services/switch_hardening.py). Chaque fait retombe sur None
    indépendamment des autres en cas d'erreur (droits insuffisants, propriété absente sur
    cette version d'ESXi) — jamais toute la collecte de l'hôte qui échoue pour un seul fait
    manquant."""
    facts = {}

    try:
        facts["lockdown_mode"] = host.config.lockdownMode
    except Exception:
        facts["lockdown_mode"] = None

    try:
        services = host.config.service.service or []
        ssh = next((s for s in services if s.key == "TSM-SSH"), None)
        facts["ssh_running"] = ssh.running if ssh is not None else None
    except Exception:
        facts["ssh_running"] = None

    try:
        facts["ntp_servers"] = list(host.config.dateTimeInfo.ntpConfig.server or [])
    except Exception:
        facts["ntp_servers"] = None

    facts["syslog_host"] = _advanced_option(host, "Syslog.global.logHost")
    facts["account_lock_failures"] = _advanced_option(host, "Security.AccountLockFailures")

    return facts


def _host_dict(host) -> Optional[dict]:
    """Extrait les champs exploités côté matching/CPE/hardware/durcissement
    (services/vsphere_matcher.py). Retourne None si l'hôte est inaccessible plutôt que de
    faire échouer toute la sync."""
    try:
        summary = host.summary
        hw = summary.hardware
        product = summary.config.product if summary.config else None
        vms = [v for v in (_vm_dict(vm_obj) for vm_obj in (host.vm or [])) if v is not None]

        return {
            "name": (summary.config.name if summary.config else None) or host.name,
            "version": product.version if product else None,
            "build": product.build if product else None,
            "vendor": hw.vendor if hw else None,
            "model": hw.model if hw else None,
            "uuid": hw.uuid if hw else None,
            "cpu_model": hw.cpuModel if hw else None,
            "cpu_cores": hw.numCpuCores if hw else None,
            "ram_gb": round(hw.memorySize / (1024 ** 3), 1) if hw and hw.memorySize else None,
            "management_ip": _management_ip(host),
            "connection_state": summary.runtime.connectionState if summary.runtime else None,
            "vms": vms,
            "hardening": _hardening_facts(host),
        }
    except Exception:
        logger.warning("vSphere : hôte %r ignoré (propriétés inaccessibles)", getattr(host, "name", "?"))
        return None


def get_hosts() -> list[dict]:
    """Synchrone (pyVmomi) — à appeler via run_in_executor depuis le matcher. Une seule
    connexion vCenter, énumère tous les vim.HostSystem visibles par le compte de service."""
    if not is_configured():
        raise VsphereConfigError("VCENTER_URL / VCENTER_USER / VCENTER_PASSWORD non configurés dans .env")

    si = SmartConnect(
        host=settings.VCENTER_URL,
        user=settings.VCENTER_USER,
        pwd=settings.VCENTER_PASSWORD,
        sslContext=_ssl_context(),
    )
    try:
        content = si.RetrieveContent()
        container = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)
        try:
            return [h for h in (_host_dict(host) for host in container.view) if h is not None]
        finally:
            container.Destroy()
    finally:
        Disconnect(si)
