"""
asset_importer.py
Cartographie automatique des 80 VM on-premise.

Stratégie :
  - Windows (≈60 VM) : import depuis Active Directory via LDAP
  - Linux  (≈20 VM)  : collecte SSH directe sur chaque machine

Les deux sources sont consolidées dans la table `assets` avec
déduplication sur le hostname. Aucune donnée ne sort du réseau interne.

Dépendances :
    pip install ldap3 asyncssh
"""

import asyncio
import asyncssh
import logging
import re
from datetime import datetime, timezone
from typing import Optional

import ldap3
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import Asset
from database import get_session
from config import settings

logger = logging.getLogger(__name__)


# ─── Constantes CPE ───────────────────────────────────────────────────────────
# Mapping OS → CPE de base pour le matching CVE
# La version exacte est ajoutée dynamiquement après collecte

CPE_MAP_WINDOWS = {
    "2022": "cpe:2.3:o:microsoft:windows_server_2022",
    "2019": "cpe:2.3:o:microsoft:windows_server_2019",
    "2016": "cpe:2.3:o:microsoft:windows_server_2016",
    "2012": "cpe:2.3:o:microsoft:windows_server_2012",
    "2008": "cpe:2.3:o:microsoft:windows_server_2008",
}

CPE_MAP_LINUX = {
    "ubuntu": "cpe:2.3:o:canonical:ubuntu_linux",
    "debian": "cpe:2.3:o:debian:debian_linux",
    "centos": "cpe:2.3:o:centos:centos",
    "rhel":   "cpe:2.3:o:redhat:enterprise_linux",
    "rocky":  "cpe:2.3:o:rocky-linux:rocky_linux",
    "alma":   "cpe:2.3:o:almalinux:almalinux",
}

# ESXi (13/08/2026, intégration vSphere) : même forme que CPE_MAP_LINUX (version = composant
# séparé, pas de scan SSH/WinRM de l'hôte lui-même — c'est services/vsphere_matcher.py qui
# appelle _build_cpe("esxi", version) directement après la sync vCenter).
CPE_MAP_ESXI = {
    "esxi": "cpe:2.3:o:vmware:esxi",
}


def _build_cpe(os_name: str, os_version: str) -> Optional[str]:
    """
    Construit un CPE 2.3 à partir du nom et de la version OS.

    Format CPE 2.3 : cpe:2.3:part:vendor:product:version:update:edition:
    language:sw_edition:target_sw:target_hw:other — 11 composants après
    "cpe:2.3". `base` (ex: "cpe:2.3:o:microsoft:windows_server_2019") fournit
    déjà part/vendor/product (3 composants) ; il n'en reste donc que 8 à
    ajouter (version + 7 wildcards), pas 9. Bug corrigé (session 20/07/2026,
    incident CVE-2022-30190) : un `:*` de trop produisait un CPE à 12
    composants, rejeté par NVD (404) dès qu'on l'interrogeait directement —
    ce même CPE malformé restait « invisible » pour toute requête NVD
    ciblée par CPE, bien que le matching interne (comparaison composant par
    composant, tronquée à `min(len(asset_parts), len(cve_parts))`) tolère ce
    décalage sans erreur.
    """
    os_lower = os_name.lower()
    version = os_version.strip()

    # CPE_MAP_WINDOWS a déjà la version dans le produit ("windows_server_2019"),
    # contrairement à CPE_MAP_LINUX ("debian_linux" générique + version réelle
    # à part) — le composant "version" doit donc être "-" (convention NVD pour
    # ce cas, cf. son propre catalogue), pas répéter l'année une 2e fois. Bug
    # corrigé (session 20/07/2026, incident CVE-2022-30190) : avec la version
    # répétée, le matching interne (tolérant aux wildcards de part et d'autre)
    # fonctionnait quand même, mais toute requête NVD directe par CPE (backfill,
    # vérification manuelle) ne trouvait presque rien — NVD restreint la
    # recherche à ce composant précis plutôt que de le traiter comme un
    # wildcard universel.
    for key, base in CPE_MAP_WINDOWS.items():
        if key in os_lower or key in version:
            return f"{base}:-:*:*:*:*:*:*:*"

    for key, base in CPE_MAP_LINUX.items():
        if key in os_lower:
            return f"{base}:{version}:*:*:*:*:*:*:*"

    for key, base in CPE_MAP_ESXI.items():
        if key in os_lower:
            return f"{base}:{version}:*:*:*:*:*:*:*"

    return None


# ─── Import Active Directory ───────────────────────────────────────────────────

class ADImporter:
    """
    Importe les VM Windows depuis Active Directory via LDAP.

    Paramètres dans .env :
        AD_SERVER   = ldap://dc01.domaine.local
        AD_USER     = CN=svc-cybervuln,OU=ServiceAccounts,DC=domaine,DC=local
        AD_PASSWORD = ****
        AD_BASE_DN  = DC=domaine,DC=local
        AD_OU       = OU=Servers,DC=domaine,DC=local  (optionnel, filtre sur une OU)
    """

    ATTRIBUTES = [
        "cn",                       # Nom machine
        "dNSHostName",              # FQDN
        "operatingSystem",          # "Windows Server 2019 Standard"
        "operatingSystemVersion",   # "10.0 (17763)"
        "description",
        "lastLogonTimestamp",
        "whenCreated",
        "distinguishedName",
    ]

    def __init__(self):
        self.server = ldap3.Server(
            settings.AD_SERVER,
            get_info=ldap3.ALL,
            # AUDIT_SECURITE.md #3 : ni use_ssl ni start_tls() → le mot de
            # passe du compte de service AD (bind SIMPLE) transitait en clair
            # à chaque import. AD_USE_TLS=False (défaut) → StartTLS sur le
            # ldap:// existant (389, sans changer l'URL/le port) ; True →
            # TLS implicite (ldaps://, 636) si le DC l'expose. Toujours
            # chiffré, seul le mécanisme change.
            use_ssl=settings.AD_USE_TLS,
            connect_timeout=10,
        )

    def _connect(self) -> ldap3.Connection:
        conn = ldap3.Connection(
            self.server,
            user=settings.AD_USER,
            password=settings.AD_PASSWORD,
            authentication=ldap3.SIMPLE,
            auto_bind=False,
        )
        conn.open()
        if not settings.AD_USE_TLS:
            conn.start_tls()
        conn.bind()
        if not conn.bound:
            raise ldap3.core.exceptions.LDAPBindError(f"Échec du bind LDAP : {conn.result}")
        return conn

    def _parse_os(self, os_string: str) -> tuple[str, str]:
        """
        Extrait OS et version depuis la chaîne AD.
        "Windows Server 2019 Standard" → ("Windows Server", "2019")
        """
        os_string = os_string or ""
        version_match = re.search(r"(20\d{2}|2008|2012|2016|2019|2022)", os_string)
        version = version_match.group(1) if version_match else "unknown"

        if "windows" in os_string.lower():
            return "Windows Server", version
        return os_string, version

    def _parse_lastlogon(self, value) -> Optional[datetime]:
        """Convertit le timestamp Windows (100ns depuis 1601) en datetime."""
        if not value:
            return None
        try:
            ts = int(str(value))
            if ts == 0:
                return None
            # Décalage entre epoch Windows (1601) et Unix (1970)
            unix_ts = (ts / 10_000_000) - 11644473600
            return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
        except Exception:
            return None

    def fetch(self) -> list[dict]:
        """
        Récupère tous les objets Computer de l'AD.
        Filtre sur l'OU serveurs si AD_OU est défini.
        """
        search_base = getattr(settings, "AD_OU", None) or settings.AD_BASE_DN
        search_filter = "(&(objectClass=computer)(operatingSystem=Windows Server*))"

        try:
            conn = self._connect()
            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=self.ATTRIBUTES,
            )
        except ldap3.core.exceptions.LDAPException as e:
            logger.error(f"Erreur connexion AD: {e}")
            return []

        assets = []
        for entry in conn.entries:
            try:
                name = str(entry.cn)
                hostname = str(entry.dNSHostName) if entry.dNSHostName else name
                os_raw = str(entry.operatingSystem) if entry.operatingSystem else ""
                os_name, os_version = self._parse_os(os_raw)
                last_logon = self._parse_lastlogon(
                    entry.lastLogonTimestamp.value if entry.lastLogonTimestamp else None
                )

                cpe = _build_cpe(os_name, os_version)

                assets.append({
                    "name": name,
                    "hostname": hostname.lower(),
                    "os": os_name,
                    "os_version": os_version,
                    "asset_type": "server",
                    "source": "active_directory",
                    "last_scan": last_logon or datetime.now(timezone.utc),
                    "status": "active",
                    "cpe_list": [cpe] if cpe else [],
                    "tags": {"env": "on-premise", "source": "ad"},
                })
            except Exception as e:
                logger.warning(f"Erreur parsing entrée AD {entry.cn}: {e}")

        logger.info(f"AD : {len(assets)} VM Windows importées")
        conn.unbind()
        return assets


# ─── Import Linux via SSH ──────────────────────────────────────────────────────

class SSHImporter:
    """
    Collecte les informations système sur les VM Linux via SSH.

    Paramètres dans .env :
        SSH_USER        = svc-cybervuln
        SSH_KEY_PATH    = /app/keys/id_ed25519   (clé privée sans passphrase)
        LINUX_HOSTS     = 10.0.1.50,10.0.1.51,... (IPs ou hostnames séparés par virgule)

    Recommandation sécurité :
        - Créer un compte dédié à droits limités (pas root, pas sudo)
        - Autoriser uniquement les commandes nécessaires via sudoers si besoin
        - La clé SSH ne doit pas avoir de passphrase pour l'automatisation
    """

    # Commandes exécutées sur chaque VM Linux (lecture seule, pas de sudo)
    COMMANDS = {
        "hostname":    "hostname -f",
        "os_name":     "cat /etc/os-release | grep '^NAME=' | cut -d= -f2 | tr -d '\"'",
        "os_version":  "cat /etc/os-release | grep '^VERSION_ID=' | cut -d= -f2 | tr -d '\"'",
        "os_pretty":   "cat /etc/os-release | grep '^PRETTY_NAME=' | cut -d= -f2 | tr -d '\"'",
        "kernel":      "uname -r",
        "arch":        "uname -m",
        "packages":    "dpkg -l 2>/dev/null | awk 'NR>5 {print $2\",\"$3}' || rpm -qa --queryformat '%{NAME},%{VERSION}\\n' 2>/dev/null",
    }

    def __init__(self):
        self.user = settings.SSH_USER
        self.key_path = settings.SSH_KEY_PATH
        self.hosts = [
            h.strip()
            for h in (getattr(settings, "LINUX_HOSTS", "") or "").split(",")
            if h.strip()
        ]

    async def _collect_host(self, host: str) -> Optional[dict]:
        """Collecte les infos d'un host Linux via SSH."""
        try:
            async with asyncssh.connect(
                host,
                username=self.user,
                client_keys=[self.key_path],
                known_hosts=None,       # À durcir en prod : pointer vers known_hosts
                connect_timeout=15,
            ) as conn:
                results = {}
                for key, cmd in self.COMMANDS.items():
                    result = await conn.run(cmd, check=False)
                    results[key] = result.stdout.strip() if result.returncode == 0 else ""

                os_name = results["os_name"] or "Linux"
                os_version = results["os_version"] or "unknown"
                hostname = results["hostname"] or host
                cpe = _build_cpe(os_name, os_version)

                # Parse packages (limité aux 200 premiers pour ne pas surcharger la BDD)
                packages = []
                for line in results["packages"].splitlines()[:200]:
                    parts = line.split(",", 1)
                    if len(parts) == 2:
                        packages.append({"name": parts[0], "version": parts[1]})

                return {
                    "name": hostname.split(".")[0],
                    "hostname": hostname.lower(),
                    "ip_address": host,
                    "os": os_name,
                    "os_version": os_version,
                    "asset_type": "server",
                    "source": "ssh",
                    "last_scan": datetime.now(timezone.utc),
                    "status": "active",
                    "cpe_list": [cpe] if cpe else [],
                    "tags": {
                        "env": "on-premise",
                        "source": "ssh",
                        "kernel": results["kernel"],
                        "arch": results["arch"],
                    },
                    "packages": packages,
                }

        except asyncssh.DisconnectError as e:
            logger.warning(f"SSH {host} déconnecté: {e}")
        except asyncssh.PermissionDenied:
            logger.error(f"SSH {host} : accès refusé (vérifier clé/utilisateur)")
        except asyncssh.ConnectionLost:
            logger.warning(f"SSH {host} : connexion perdue")
        except Exception as e:
            logger.error(f"SSH {host} erreur inattendue: {e}")
        return None

    async def fetch(self, max_concurrent: int = 10) -> list[dict]:
        """
        Collecte en parallèle (max 10 connexions simultanées).
        """
        if not self.hosts:
            logger.warning("Aucun host Linux configuré dans LINUX_HOSTS")
            return []

        semaphore = asyncio.Semaphore(max_concurrent)

        async def _bounded(host):
            async with semaphore:
                return await self._collect_host(host)

        results = await asyncio.gather(*[_bounded(h) for h in self.hosts])
        assets = [r for r in results if r is not None]
        logger.info(f"SSH : {len(assets)}/{len(self.hosts)} VM Linux collectées")
        return assets


# ─── Consolidation en base ────────────────────────────────────────────────────

async def upsert_asset(session: AsyncSession, data: dict) -> tuple[Asset, bool]:
    """
    Insère ou met à jour un actif.
    Déduplication sur le hostname (insensible à la casse).
    """
    hostname = (data.get("hostname") or "").lower()
    result = await session.execute(
        select(Asset).where(Asset.hostname == hostname)
    )
    existing = result.scalar_one_or_none()

    if existing:
        for field, value in data.items():
            if field not in ("source", "packages"):
                setattr(existing, field, value)
        existing.last_scan = datetime.now(timezone.utc)
        return existing, False
    else:
        asset = Asset(**{k: v for k, v in data.items() if k != "packages"})
        session.add(asset)
        return asset, True


# ─── Point d'entrée ───────────────────────────────────────────────────────────

async def run_asset_import() -> dict:
    """
    Import complet : AD (Windows) + SSH (Linux).
    Appelé manuellement ou via tâche Celery quotidienne.
    """
    stats = {
        "windows_found": 0,
        "linux_found": 0,
        "created": 0,
        "updated": 0,
        "errors": 0,
    }

    # 1. Collecte AD (synchrone)
    ad_assets = []
    try:
        ad = ADImporter()
        ad_assets = ad.fetch()
        stats["windows_found"] = len(ad_assets)
    except Exception as e:
        logger.error(f"Import AD échoué: {e}")
        stats["errors"] += 1

    # 2. Collecte SSH (asynchrone)
    ssh_assets = []
    try:
        ssh = SSHImporter()
        ssh_assets = await ssh.fetch()
        stats["linux_found"] = len(ssh_assets)
    except Exception as e:
        logger.error(f"Import SSH échoué: {e}")
        stats["errors"] += 1

    # 3. Upsert en base
    all_assets = ad_assets + ssh_assets
    async for session in get_session():
        try:
            for asset_data in all_assets:
                try:
                    _, created = await upsert_asset(session, asset_data)
                    if created:
                        stats["created"] += 1
                    else:
                        stats["updated"] += 1
                except Exception as e:
                    logger.error(f"Erreur upsert {asset_data.get('hostname')}: {e}")
                    stats["errors"] += 1

            await session.commit()
        except Exception as e:
            await session.rollback()
            raise

    total = stats["created"] + stats["updated"]
    logger.info(
        f"Import actifs terminé : {total} VM traitées "
        f"({stats['created']} nouvelles, {stats['updated']} mises à jour)"
    )
    return stats
