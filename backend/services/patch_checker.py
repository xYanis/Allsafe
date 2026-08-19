"""
patch_checker.py
Vérifie (lecture seule) si un correctif est détecté sur un actif.

Workflow :
  1. CyberVuln détecte si le patch semble appliqué → signale à l'analyste
  2. L'analyste valide et marque manuellement la vuln comme `patched`
  CyberVuln ne modifie JAMAIS le statut d'une vulnérabilité automatiquement.

Windows : WinRM read-only → Get-HotFix (KB) + Get-Package
Linux   : SSH read-only  → dpkg/rpm version check
"""

import re
import json
import logging
import asyncio
import functools
import asyncssh
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import winrm
from sqlalchemy import select, or_, update, func

from config import settings
from models import Asset, CVE, Vulnerability, SyncState, PatchCheckAssetCompletion
from services.ssh_trust import connect_trusted
from services.vuln_history import record_status_change
from database import SessionLocal
from services.crypto import decrypt_password
from services.debian_tracker import (
    debian_release_for_asset,
    get_debian_fix_info,
    is_cve_tracked,
    deb_version_compare,
)
from services.kb_build import resolve_fixed_build
from services.cpe_matcher import (
    cpe_is_platform_component, still_matches, _load_windows_mappings,
    _windows_app_candidates, _cve_products,
)

# Au-delà de ce délai, une vuln déjà contrôlée est recontrôlée automatiquement —
# sans ça, un patch appliqué après le premier check (ex: mise à jour Linux) ne
# serait jamais revu par le cycle automatique/"Patch check global".
RECHECK_INTERVAL = timedelta(hours=24)

# En-deçà de ce délai, le bouton "Patch check" unitaire (routers/patch_check.py)
# renvoie le résultat déjà en base au lieu de rejouer un vrai contrôle WinRM/SSH
# — évite de resolliciter l'actif pour un double-clic ou une modale rouverte
# juste après, mais aussi (07/08/2026, retour utilisateur réel) pour l'usage le
# plus courant du bouton : contrôler plusieurs vulns du même actif à la suite,
# puis revenir sur l'une d'elles déjà faite. 30s étaient trop court pour ce
# second cas (le temps de checker 2-3 autres vulns dépasse déjà la fenêtre) —
# 30s restent adaptés à l'anti-double-clic seul, pas à une session de contrôle
# de plusieurs vulns. L'analyste peut toujours forcer un contrôle réel malgré
# tout (paramètre `force`, bouton "🔄 Relancer un scan" côté UI quand le
# résultat est en cache).
MIN_RECHECK_GAP = timedelta(minutes=5)

# Le cycle automatique (run_startup_patch_checks, jamais le bouton "Patch check"
# unitaire d'une ligne précise) ne vérifie que les CVE publiées il y a moins de
# ce délai (07/08/2026, demande explicite : "l'analyse en cours" doit rester en
# corrélation avec le dashboard, lui-même borné à 2 ans — cf. GET /vulnerabilities
# ?max_age_years côté Dashboard.jsx, même valeur que CANDIDATE_MAX_AGE_YEARS dans
# routers/vulnerabilities.py). Toutes les invocations réelles de
# run_full_patch_check_cycle partent du dashboard (bouton, démarrage, cycle
# périodique Celery, déclenchement post-scan) — aucune ne justifie aujourd'hui de
# lever cette borne, contrairement au bouton "CVE anciennes" de la page
# Vulnérabilités qui reste, lui, indépendant de ce cycle.
PATCH_CHECK_MAX_AGE_YEARS = 2

# En-deçà de cet âge, une CVE absente du Debian Security Tracker n'est pas
# considérée comme "sans objet" : le tracker peut simplement ne pas l'avoir
# encore indexée. Au-delà, une absence complète signifie qu'aucun paquet Debian
# n'est concerné (cf. check_patch_linux, voie 1).
TRACKER_LAG_DAYS = timedelta(days=30)

# CVE Windows corrigées par **configuration** et non par KB — Microsoft publie
# pour elles une mitigation optionnelle à activer, jamais installée par une mise
# à jour. Elles n'ont donc aucun KB associé, et tous les signaux basés sur les KB
# ou le build restent muets (cas repéré session 21/07/2026 : CVE-2013-3900,
# "Why is Microsoft republishing a CVE from 2013?").
#
# Table plutôt que cas codé en dur : ajouter une CVE de ce type ne demande qu'une
# entrée. `value` attendue pour considérer la mitigation active ; les deux vues
# du registre (natif + WOW6432Node) doivent l'avoir, Microsoft l'exigeant pour
# couvrir les binaires 32 et 64 bits.
REGISTRY_MITIGATIONS: dict[str, dict] = {
    "CVE-2013-3900": {
        "keys": [
            r"HKLM:\Software\Microsoft\Cryptography\Wintrust\Config",
            r"HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config",
        ],
        "name": "EnableCertPaddingCheck",
        "expected": "1",
        "label": "Vérification du remplissage de certificat WinVerifyTrust",
        "remediation": (
            "Créer la valeur REG_SZ `EnableCertPaddingCheck = \"1\"` dans les deux clés "
            "(native et Wow6432Node) — mitigation optionnelle, non installée par les mises à jour."
        ),
    },
}

logger = logging.getLogger(__name__)

# État du check automatique de démarrage, pour affichage live sur le dashboard
# (process FastAPI unique — pas besoin de Redis pour un simple indicateur d'avancement).
_current_check: Optional[dict] = None
_last_completed: Optional[dict] = None
# Horodatage de début du cycle en cours — côté serveur plutôt que dans le
# navigateur (Dashboard.jsx) : un simple rechargement de page ne doit pas faire
# perdre le point de départ utilisé pour estimer un temps restant.
_cycle_started_at: Optional[datetime] = None
# Avancement par actif du cycle en cours (ordre de traitement), pour afficher au
# dashboard quels actifs sont déjà traités / en cours / pas encore atteints —
# pas juste le dernier actif en cours (`_current_check`) comme avant.
_asset_progress: list = []


def get_current_check() -> Optional[dict]:
    return _current_check


def get_last_completed() -> Optional[dict]:
    return _last_completed


def get_cycle_started_at() -> Optional[str]:
    return _cycle_started_at.isoformat() if _cycle_started_at else None


def get_asset_progress() -> list:
    return _asset_progress


# Clé sync_state dédiée au cycle complet (pas un check unitaire) — persisté en base
# contrairement au reste de l'état ci-dessus (mémoire, perdu à chaque redémarrage) :
# c'est justement ce qui permet de détecter un cycle coupé en plein milieu par un
# redémarrage du process (--reload en dev, OOM, déploiement...), cf.
# main.py::_check_interrupted_patch_cycle. "running" posé ici, "completed" au retour
# normal de run_full_patch_check_cycle ; "interrupted" n'est jamais écrit depuis cette
# fonction — seul le prochain démarrage peut constater qu'un "running" n'a jamais été
# refermé.
PATCH_CYCLE_STATE_KEY = "patch_check_cycle"


async def _set_cycle_state(status: str) -> None:
    session = SessionLocal()
    try:
        state = await session.get(SyncState, PATCH_CYCLE_STATE_KEY)
        if not state:
            state = SyncState(key=PATCH_CYCLE_STATE_KEY)
            session.add(state)
        state.status = status
        state.last_synced_at = datetime.now(timezone.utc)
        await session.commit()
    finally:
        await session.close()


async def get_last_cycle_state(session) -> dict:
    """Statut du dernier cycle connu (lecture, réutilise la session de l'appelant —
    contrairement à _set_cycle_state qui en ouvre une dédiée pour rester appelable
    depuis main.py avant que get_session() ne soit disponible). Cf. GET /patch-check/status."""
    state = await session.get(SyncState, PATCH_CYCLE_STATE_KEY)
    if not state:
        return {"status": None, "at": None}
    return {
        "status": state.status,
        "at": state.last_synced_at.isoformat() if state.last_synced_at else None,
    }

# Regex pour extraire les numéros KB depuis les URLs de références NVD
_KB_RE = re.compile(r"KB(\d{6,8})", re.IGNORECASE)

MSRC_API = "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct"


# ─── Extraction KB depuis les références CVE ─────────────────────────────────

def extract_kb_numbers(cve: CVE) -> list[str]:
    """
    Extrait les numéros KB Microsoft depuis les références NVD de la CVE.
    ex: https://support.microsoft.com/...KB5040434 → ["5040434"]
    """
    refs = cve.references or []
    kbs = set()
    for url in refs:
        for match in _KB_RE.finditer(url):
            kbs.add(match.group(1))
    return sorted(kbs)


async def fetch_msrc_kb_products(cve_id: str) -> tuple[dict[str, list[str]], Optional[datetime]]:
    """
    Interroge l'API publique MSRC et retourne, pour chaque KB associé à la CVE,
    la liste des produits/OS qu'il cible (ex: "5094123" → ["Windows Server 2019", ...]),
    ainsi que la date de sortie la plus ancienne parmi ces KB (`releaseDate` MSRC —
    la date de sortie réelle du correctif, plus précise que `cve.published` pour le
    signal 3/repli par date de `check_patch_windows`, session 20/07/2026 : les deux
    dates sont généralement proches pour du Patch Tuesday coordonné mais pas
    toujours identiques).
    Le mapping produits est utilisé à titre informatif uniquement — ne conditionne
    jamais patch_detected.
    """
    kb_products: dict[str, set[str]] = {}
    release_dates: list[datetime] = []
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                MSRC_API,
                params={"$filter": f"cveNumber eq '{cve_id}'"},
            )
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("value", []):
                # Vérifie que c'est bien notre CVE (filtre défensif)
                if item.get("cveNumber", "").upper() != cve_id.upper():
                    continue
                product = str(item.get("product", "") or "")
                release_date_str = item.get("releaseDate")
                if release_date_str:
                    try:
                        release_dates.append(datetime.fromisoformat(release_date_str.replace("Z", "+00:00")))
                    except ValueError:
                        pass
                for article in item.get("kbArticles", []):
                    name = str(article.get("articleName", "") or "")
                    url  = str(article.get("articleUrl", "") or "")
                    found = {m.group(1) for m in _KB_RE.finditer(name + " " + url)}
                    if re.match(r"^\d{6,8}$", name):
                        found.add(name)
                    for kb in found:
                        kb_products.setdefault(kb, set()).add(product)
    except Exception as e:
        logger.warning(f"MSRC API inaccessible pour {cve_id} : {e}")
    earliest_release = min(release_dates) if release_dates else None
    return {kb: sorted(products) for kb, products in kb_products.items()}, earliest_release


def _kb_matches_asset_os(products: list[str], asset: Asset) -> Optional[bool]:
    """
    Indication informative : le produit MSRC du KB semble-t-il correspondre à
    l'OS déclaré de l'actif ? Ne conditionne jamais patch_detected — juste un
    repère pour l'analyste (les KB incompatibles ne peuvent de toute façon pas
    s'installer sur la mauvaise version d'OS).
    Retourne None si l'information est indisponible (pas de donnée MSRC).
    """
    if not products:
        return None
    os_tokens = [t.lower() for t in (asset.os or "").split() if t]
    version = (asset.os_version or "").lower()
    for product in products:
        p = product.lower()
        if version and version not in p:
            continue
        if os_tokens and not all(tok in p for tok in os_tokens):
            continue
        return True
    return False


# ─── Vérification Windows via WinRM ──────────────────────────────────────────

def _asset_os_product(asset: Asset) -> Optional[str]:
    """Nom de produit CPE (ex: "windows_server_2019") depuis `asset.cpe_list` —
    nécessaire pour croiser le build Windows installé aux plages de versions
    NVD (`_extract_version_constraints(..., part="o")`)."""
    for cpe in asset.cpe_list or []:
        parts = cpe.split(":")
        if len(parts) >= 5 and parts[2] == "o":
            return parts[4]
    return None


def _order_kbs_by_os(kb_numbers: list[str], kb_products: Optional[dict], asset: Asset) -> list[str]:
    """
    Trie les KB d'une CVE pour placer en tête ceux que MSRC déclare comme
    ciblant l'OS de l'actif. Sert uniquement à limiter les requêtes réseau de
    `services/kb_build.py` (le bon KB est trouvé au 1er essai plutôt qu'après
    en avoir interrogé une dizaine d'autres) — jamais à décider d'un verdict,
    la branche de build restant revérifiée en aval.
    """
    kb_products = kb_products or {}

    def rank(kb: str) -> int:
        m = _kb_matches_asset_os(kb_products.get(str(kb).replace("KB", ""), []), asset)
        return 0 if m is True else (1 if m is None else 2)

    return sorted(kb_numbers, key=rank)


def _winrm_session(host: str) -> winrm.Session:
    """Crée une session WinRM en lecture seule vers un hôte Windows."""
    user = settings.WINRM_USER or settings.AD_USER
    password = settings.WINRM_PASSWORD or settings.AD_PASSWORD

    # Extrait DOMAINE\user depuis un DN complet si nécessaire
    # CN=cybervuln,OU=...,DC=AER,DC=LOC → AER\cybervuln
    if user and "CN=" in user:
        cn_match = re.search(r"CN=([^,]+)", user, re.IGNORECASE)
        dc_match = re.findall(r"DC=([^,]+)", user, re.IGNORECASE)
        if cn_match and dc_match:
            user = f"{dc_match[0].upper()}\\{cn_match.group(1)}"

    return winrm.Session(
        f"http://{host}:{settings.WINRM_PORT}/wsman",
        auth=(user, password),
        transport=settings.WINRM_TRANSPORT,
        read_timeout_sec=30,
        operation_timeout_sec=25,
    )


def _fetch_windows_patch_snapshot(asset: Asset) -> dict:
    """
    Un seul appel WinRM par actif — relève l'ensemble des KB installés connus
    (sources 1-3, dont le scan complet du journal Windows Update, l'opération
    la plus coûteuse), le build/révision OS et la date de mise à jour la plus
    récente. Ce relevé est identique quelle que soit la CVE : l'appelant
    (`check_patch`/cycle de patch check) le calcule une seule fois par actif et
    le réutilise pour toutes les CVE de cet actif dans le même cycle plutôt que
    de le rejouer à chaque CVE (incident lenteur, session 21/07/2026 — ~4600
    CVE sur un seul actif Windows non encore vérifiées, faute de temps, car
    chaque CVE rouvrait une session WinRM et rescannait tout le journal System
    pour un résultat strictement identique d'une CVE à l'autre du même cycle).

    Retourne {"error": ...} si injoignable/mal configuré — laisse l'appelant
    décider comment refléter l'échec sur chaque CVE concernée par cet actif.
    """
    host = asset.ip_address or asset.hostname
    if not host:
        return {"error": "Adresse IP / hostname manquant"}

    if not (settings.WINRM_USER or settings.AD_USER):
        return {"error": "WINRM_USER non configuré"}

    try:
        session = _winrm_session(host)

        # PowerShell read-only — trois sources KB, plus le build/révision OS :
        # 1. Journal événements WindowsUpdateClient (Event 19 = CU installed) — natif, sans module
        # 2. WMI Win32_QuickFixEngineering (hotfixes classiques)
        # 3. Get-WUHistory (PSWindowsUpdate AllUsers scope si installé)
        # 4. HKLM CurrentVersion (CurrentBuildNumber + UBR) — même registre que asset_scanner.py,
        #    aucun droit WMI/DCOM requis (le compte de service n'en a pas).
        ps_script = r"""
$found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# Source 1 : System log — les events WU (ID 19 = installé) y sont accessibles
# sans permissions spéciales (Event Log Readers suffit). Fournit aussi la date
# de la mise à jour la plus récente (signal 3, repli par date) — testé en
# conditions réelles (session 20/07/2026) : Get-HotFix ET Get-WmiObject
# Win32_QuickFixEngineering renvoient tous deux "Accès refusé" sur le compte
# de service utilisé ici (droits WMI/DCOM insuffisants, comme déjà documenté
# pour asset_scanner.py) — Get-WinEvent reste la seule source fiable, KB et
# date comprises, d'où son rôle central plutôt qu'un simple 1er essai.
$lastUpdateDate = $null
try {
    $events = Get-WinEvent -LogName "System" -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -eq "Microsoft-Windows-WindowsUpdateClient" -and $_.Id -eq 19 }
    foreach ($e in $events) {
        [regex]::Matches($e.Message, 'KB\d+') | ForEach-Object { [void]$found.Add($_.Value) }
    }
    $dates = $events | ForEach-Object { $_.TimeCreated }
    if ($dates) { $lastUpdateDate = ($dates | Sort-Object -Descending | Select-Object -First 1).ToString("yyyy-MM-dd") }
} catch { }

# Source 2 : WMI Win32_QuickFixEngineering (hotfixes classiques) — best-effort,
# peut échouer selon les droits WMI/DCOM du compte de service (cf. ci-dessus) ;
# la détection KB ne dépend donc jamais uniquement de cette source.
try {
    Get-WmiObject -Class Win32_QuickFixEngineering -ErrorAction SilentlyContinue |
        ForEach-Object { [void]$found.Add($_.HotFixID) }
} catch { }

# Source 3 : Get-WUHistory (PSWindowsUpdate AllUsers scope requis)
if (Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue) {
    try {
        Import-Module PSWindowsUpdate -ErrorAction Stop
        Get-WUHistory -ErrorAction SilentlyContinue | ForEach-Object {
            [regex]::Matches($_.Title, 'KB\d+') | ForEach-Object { [void]$found.Add($_.Value) }
        }
    } catch { }
}

# Source 4 : build/révision OS — insensible à la supersession par CU
$osInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
$buildString = if ($osInfo.CurrentBuildNumber) { "10.0.$($osInfo.CurrentBuildNumber).$($osInfo.UBR)" } else { $null }

# Source 5 : mitigations par clé de registre (CVE sans KB, cf. REGISTRY_MITIGATIONS).
# Relevé ici pour rester sur une seule session WinRM par actif.
$mitig = @{}
$mitig["EnableCertPaddingCheck"] = @(
  "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config",
  "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
) | ForEach-Object {
  $v = (Get-ItemProperty -Path $_ -Name EnableCertPaddingCheck -ErrorAction SilentlyContinue).EnableCertPaddingCheck
  if ($null -eq $v) { "" } else { "$v" }
}

[PSCustomObject]@{ Kbs = @($found); Build = $buildString; LastUpdate = $lastUpdateDate; Mitigations = $mitig } | ConvertTo-Json -Compress -Depth 3
"""
        result = session.run_ps(ps_script)

        if result.status_code != 0:
            err = result.std_err.decode("utf-8", errors="replace").strip()
            return {"error": f"WinRM erreur : {err}"}

        output = result.std_out.decode("utf-8", errors="replace").strip()
        if not output:
            return {"error": "Aucune donnée retournée"}

        data = json.loads(output)
        kbs = data.get("Kbs") or []
        # json peut retourner une chaîne si un seul KB, ou une liste
        if isinstance(kbs, str):
            kbs = [kbs]

        return {
            "kbs": set(kbs),
            "build": data.get("Build"),
            "last_update": data.get("LastUpdate"),
            "mitigations": data.get("Mitigations") or {},
            # Commande + retour brut (07/08/2026, demande explicite bouton "Détail"
            # de la modale) — un seul appel WinRM par actif, donc identique pour
            # toutes les CVE de ce cycle ; propagé par check_patch() vers le résultat
            # final (cf. sa fin de fonction), jamais reconstruit ici pour chaque CVE.
            "_raw": [{"command": ps_script.strip(), "output": output}],
        }

    except Exception as e:
        logger.error(f"WinRM {host} erreur (relevé patch) : {e}")
        return {"error": str(e)}


def check_patch_windows(
    asset: Asset,
    cve: CVE,
    kb_numbers: list[str],
    kb_products: Optional[dict[str, list[str]]] = None,
    msrc_release_date: Optional[datetime] = None,
    snapshot: Optional[dict] = None,
    msft_build: Optional[dict] = None,
) -> dict:
    """
    Vérifie si le correctif d'une CVE est présent sur un actif Windows, à
    partir d'un relevé WinRM (read-only) de l'actif. Quatre signaux combinés,
    par ordre de priorité décroissante :

    1. **KB** — cherche les numéros KB associés (journal Windows Update / WMI
       Win32_QuickFixEngineering / historique PSWindowsUpdate). Limite connue
       (incident CVE-2022-30190, session 20/07/2026) : Windows Server
       fonctionne en mises à jour **cumulatives** — un KB ancien absorbé par
       une CU plus récente n'apparaît plus jamais dans aucune de ces sources,
       même sur un système entièrement à jour. Faux négatif systématique pour
       toute CVE dont le correctif date de plusieurs mois/années.
    2. **Build/révision OS via NVD** — compare le build Windows installé
       (`CurrentBuildNumber.UBR`, lu par registre, insensible à la
       supersession par CU) aux plages de versions vulnérables fournies par
       NVD pour ce produit CPE (`versionEndExcluding` etc., type "o" — cf.
       `_extract_version_constraints`/`_version_patched`, déjà utilisées côté
       paquets applicatifs Linux, étendues ici au type OS). Plus fiable que
       le KB quand la donnée existe ; sert de repli sinon.
    2bis. **Build/révision OS via l'article KB Microsoft** (`msft_build`,
       session 21/07/2026, résolu en amont par `services/kb_build.py`) — même
       raisonnement que le signal 2, mais le seuil corrigé vient du titre de
       l'article support.microsoft.com au lieu de NVD. Comble le trou du signal
       2 sur les CVE anciennes (2019-2021), pour lesquelles NVD n'encode aucune
       plage de version exploitable (vérifié : ni NVD ni les deux API MSRC ne
       fournissent de build pour ces millésimes). **Même niveau de certitude
       que le signal 2** — comparaison de version objective, donc alimente
       `patch_detected` et l'auto-bascule (non-CRITICAL), contrairement au
       signal 3 ci-dessous.
    3. **Repli par date** — purement indicatif, n'alimente jamais le verdict.

    `snapshot` : relevé déjà effectué par `_fetch_windows_patch_snapshot`, mis
    en cache par l'appelant pour tout un cycle (un seul appel WinRM par actif,
    réutilisé pour toutes ses CVE). Si absent, un relevé est fait à la volée
    pour ce seul appel (cas du bouton "Patch check" unitaire côté UI).

    Retourne un rapport — ne modifie rien sur l'actif ni en base.
    """
    host = asset.ip_address or asset.hostname
    if not host:
        return {"patch_detected": None, "error": "Adresse IP / hostname manquant"}

    if not (settings.WINRM_USER or settings.AD_USER):
        return {"patch_detected": None, "error": "WINRM_USER non configuré"}

    # Mitigation par clé de registre (CVE sans KB, cf. REGISTRY_MITIGATIONS) —
    # évaluée en premier : c'est le seul signal exploitable pour ces CVE, et il
    # est ferme (la valeur est là ou elle n'y est pas).
    mitig = REGISTRY_MITIGATIONS.get(cve.cve_id)
    if mitig and snapshot is not None and not snapshot.get("error"):
        valeurs = (snapshot.get("mitigations") or {}).get(mitig["name"])
        if isinstance(valeurs, str):
            valeurs = [valeurs]
        if valeurs:
            active = all(str(v) == mitig["expected"] for v in valeurs)
            return {
                "patch_detected": active,
                "mitigation": {
                    "name": mitig["name"],
                    "label": mitig["label"],
                    "active": active,
                    "values": list(valeurs),
                    "remediation": None if active else mitig["remediation"],
                },
                "kb_checked": [],
                "details": (
                    f"{'✅' if active else '❌'} {mitig['label']} — clé `{mitig['name']}` "
                    f"{'activée sur les deux vues du registre' if active else 'absente ou incomplète'}."
                    + ("" if active else f"\n➡ {mitig['remediation']}")
                ),
                "note": "Cette CVE n'est corrigée par aucun KB : Microsoft publie une mitigation "
                        "optionnelle à activer dans le registre. Vérification en lecture seule.",
            }

    os_product = _asset_os_product(asset)
    build_constraints = _extract_version_constraints(cve, os_product, part="o") if os_product else []

    if not kb_numbers and not build_constraints:
        return {
            "patch_detected": None,
            "kb_checked": [],
            "details": "Aucun KB trouvé dans NVD ni via l'API MSRC, et aucune plage de version "
                       "OS exploitable pour cette CVE. Vérification manuelle requise.",
        }

    if snapshot is None:
        snapshot = _fetch_windows_patch_snapshot(asset)

    if snapshot.get("error"):
        return {"patch_detected": None, "error": snapshot["error"]}

    found = snapshot.get("kbs") or set()
    installed_build = snapshot.get("build")
    last_update_str = snapshot.get("last_update")

    kb_data = [{"KB": f"KB{kb}", "Installed": f"KB{kb}" in found} for kb in kb_numbers]
    installed = [e for e in kb_data if e["Installed"]]
    missing   = [e for e in kb_data if not e["Installed"]]

    # Signal build/révision — prioritaire quand exploitable (cf. docstring),
    # insensible à la supersession par mise à jour cumulative contrairement au KB.
    build_verdict = _version_patched(installed_build, build_constraints) if installed_build else None

    # Signal 2bis — seuil de build issu de l'article KB Microsoft, résolu en
    # amont (cf. `check_patch`/`services/kb_build.py`). Même certitude que le
    # signal 2 : uniquement une comparaison de version, sur un KB dont on a
    # vérifié qu'il cible bien la branche d'OS de l'actif. Placé APRÈS le
    # signal 2 pour ne rien changer aux verdicts déjà rendus par NVD — il ne
    # sert que là où NVD ne dit rien (le cas des CVE anciennes).
    msft_build_verdict = msft_build.get("patched") if msft_build else None

    if build_verdict is not None:
        patch_detected = build_verdict
    elif msft_build_verdict is not None:
        patch_detected = msft_build_verdict
    else:
        # Repli KB — un seul KB suffit : chaque KB de la liste cible une version Windows différente
        patch_detected = len(installed) > 0 if kb_numbers else None

    # Signal 3 — repli par date, uniquement informatif (ne pilote jamais
    # patch_detected/l'auto-bascule) : compare la date de publication NVD de
    # la CVE à la date de la mise à jour la plus récente installée. Utile
    # pour les CVE anciennes (2019-2021) sans plage de version NVD/MSRC
    # exploitable (incident CVE-2020-1467 et consorts, session 20/07/2026) —
    # les CU étant strictement cumulatives dans le temps, une mise à jour
    # installée après la publication de la CVE inclut forcément son
    # correctif. Approximation (la date de publication n'est pas toujours
    # exactement la date de sortie du correctif) — présentée comme telle,
    # jamais comme une preuve au même titre que le signal build/révision.
    # Date de référence pour le repli : la sortie réelle du correctif côté MSRC
    # (releaseDate) si disponible, plus précise que cve.published (peut différer
    # de quelques jours du Patch Tuesday réel) — sinon repli sur cve.published.
    reference_date = msrc_release_date or cve.published
    date_heuristic = None
    if build_verdict is None and msft_build_verdict is None and last_update_str and reference_date:
        try:
            last_update_dt = datetime.strptime(last_update_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            reference_date = reference_date if reference_date.tzinfo else reference_date.replace(tzinfo=timezone.utc)
            date_heuristic = last_update_dt > reference_date
        except ValueError:
            pass

    details_parts = []
    if installed_build:
        if build_verdict is True:
            details_parts.append(f"✅ Build installé {installed_build} ≥ seuil corrigé NVD (CU ultérieure incluant le correctif)")
        elif build_verdict is False:
            details_parts.append(f"❌ Build installé {installed_build} toujours dans la plage vulnérable NVD")
        elif msft_build_verdict is None:
            details_parts.append(f"ℹ️ Build installé {installed_build} (pas de plage de version NVD exploitable pour cet OS — repli sur le check KB)")
    if msft_build_verdict is not None:
        icon = "✅" if msft_build_verdict else "❌"
        rel = "≥" if msft_build_verdict else "<"
        details_parts.append(
            f"{icon} Build installé {msft_build['installed_build']} {rel} {msft_build['fixed_build']}, "
            f"build corrigé publié par Microsoft pour {msft_build['kb']} — "
            f"{'correctif inclus' if msft_build_verdict else 'correctif absent'} "
            f"(mises à jour cumulatives)."
        )
    for e in installed:
        details_parts.append(f"✅ {e['KB']} installé")
    for e in missing:
        details_parts.append(f"❌ {e['KB']} non trouvé")
    if date_heuristic is not None:
        verb = "postérieure" if date_heuristic else "antérieure ou égale"
        date_label = "sortie du correctif MSRC" if msrc_release_date else "publication de la CVE"
        details_parts.append(
            f"📅 Indicatif seulement : dernière mise à jour installée le {last_update_str}, "
            f"{verb} à la {date_label} ({reference_date.date()}) — "
            f"{'probablement corrigée' if date_heuristic else 'pas de garantie'}, "
            f"à valider par l'analyste."
        )

    # Info uniquement — indique si le KB installé correspond bien à l'OS déclaré
    # de l'actif. Ne change jamais patch_detected (les autres KB de la liste ciblent
    # d'autres versions Windows et ne pourraient de toute façon pas s'y installer).
    kb_products = kb_products or {}
    kb_os_hint = [
        {
            "kb": f"KB{e['KB'].replace('KB', '')}",
            "products": kb_products.get(e["KB"].replace("KB", ""), []),
            "matches_asset_os": _kb_matches_asset_os(
                kb_products.get(e["KB"].replace("KB", ""), []), asset
            ),
        }
        for e in installed
    ]

    return {
        "patch_detected": patch_detected,
        "build_installed": installed_build,
        "build_verdict": build_verdict,
        "msft_build": msft_build,          # {kb, fixed_build, installed_build, patched} ou None
        "last_update_installed": last_update_str,
        "date_heuristic": date_heuristic,
        "date_heuristic_reference": reference_date.date().isoformat() if date_heuristic is not None else None,
        "date_heuristic_source": ("msrc_release" if msrc_release_date else "cve_published") if date_heuristic is not None else None,
        "kb_checked": [f"KB{kb}" for kb in kb_numbers],
        "kb_installed": [f"KB{e['KB'].replace('KB','')}" for e in installed],
        "kb_missing":   [f"KB{e['KB'].replace('KB','')}" for e in missing],
        "kb_os_hint": kb_os_hint,
        "details": "\n".join(details_parts),
        "note": "Résultat indicatif — l'analyste doit valider avant de marquer la vuln comme corrigée.",
    }


# ─── Comparaison de version (best-effort, mêmes limites que kb_os_hint côté Windows) ──

_VERSION_NUM_RE = re.compile(r"\d+")


def _version_key(v: str) -> tuple[int, ...]:
    """
    Clé de comparaison numérique. Ignore l'epoch dpkg (`2:2.4.52-1ubuntu4.7` →
    partie après `:`) et les suffixes non numériques (~beta, +deb12u2...) : seuls
    les groupes de chiffres comptent, dans l'ordre. Best-effort — suffisant pour
    comparer une version de paquet à la version corrigée indiquée par NVD, mais ne
    détecte pas un correctif backporté par la distro sans bump de version amont
    (limite connue des trackers CPE, cf. docs/SECURITY.md).
    """
    if ":" in v:
        v = v.split(":", 1)[1]
    nums = tuple(int(n) for n in _VERSION_NUM_RE.findall(v))
    return nums or (0,)


def _compare_versions(a: str, b: str) -> int:
    ka, kb = _version_key(a), _version_key(b)
    length = max(len(ka), len(kb))
    ka = ka + (0,) * (length - len(ka))
    kb = kb + (0,) * (length - len(kb))
    return (ka > kb) - (ka < kb)


def _extract_version_constraints(cve: CVE, product: str, part: str = "a") -> list[dict]:
    """
    Extrait, depuis les données NVD brutes (cve.raw_data), les plages de versions
    vulnérables pour le produit donné (ex: "openssl") : versionStart/EndIncluding/
    Excluding, ou version exacte si NVD n'a pas fourni de plage. Liste vide si
    aucune information exploitable pour ce produit.

    `part` : "a" (application, comportement historique — `product` normalisé
    tirets comme les paquets Linux, ex: "libssl" reste "libssl") ou "o" (OS,
    ajouté session 20/07/2026 — incident CVE-2022-30190/Windows Server 2019,
    cf. `_installed_windows_build`). Pour "o", `product` doit être le nom de
    produit CPE exact (ex: "windows_server_2019", underscore conservé — pas de
    normalisation tiret, contrairement aux paquets applicatifs).
    """
    constraints = []
    raw = cve.raw_data or {}
    nvd_cve = raw.get("cve", raw)
    for config in nvd_cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = (match.get("criteria") or "").split(":")
                if len(parts) < 5 or parts[2] != part:
                    continue
                cpe_product = parts[4].replace("_", "-").lower() if part == "a" else parts[4].lower()
                if cpe_product != product.lower():
                    continue
                constraint = {
                    k: match.get(k)
                    for k in (
                        "versionStartIncluding", "versionStartExcluding",
                        "versionEndIncluding", "versionEndExcluding",
                    )
                    if match.get(k)
                }
                if not constraint and parts[5] not in ("*", "-", ""):
                    constraint["exact_version"] = parts[5]
                if constraint:
                    constraints.append(constraint)
    return constraints


def _version_patched(installed: str, constraints: list[dict]) -> Optional[bool]:
    """
    True si `installed` est hors de toutes les plages vulnérables NVD (patché),
    False si elle tombe dans au moins une plage (toujours vulnérable), None si
    aucune contrainte exploitable (indéterminé — comparaison manuelle requise).
    """
    if not constraints:
        return None
    for c in constraints:
        if "exact_version" in c:
            if _compare_versions(installed, c["exact_version"]) == 0:
                return False
            continue
        in_range = True
        if c.get("versionStartIncluding") and _compare_versions(installed, c["versionStartIncluding"]) < 0:
            in_range = False
        if c.get("versionStartExcluding") and _compare_versions(installed, c["versionStartExcluding"]) <= 0:
            in_range = False
        if c.get("versionEndIncluding") and _compare_versions(installed, c["versionEndIncluding"]) > 0:
            in_range = False
        if c.get("versionEndExcluding") and _compare_versions(installed, c["versionEndExcluding"]) >= 0:
            in_range = False
        if in_range:
            return False
    return True


def _format_version_range(constraints: list[dict]) -> str:
    """
    Rend une liste de contraintes NVD lisible pour l'analyste (ex: '≤ 0.66',
    'de 1.2 à 1.5 (exclu)') — sans ça, le patch check dit seulement "patché"/
    "vulnérable" sans jamais préciser contre quelle plage la version installée
    a été comparée (demande explicite utilisateur, 03/08/2026 : CVE-2016-2563).
    """
    parts = []
    for c in constraints:
        if "exact_version" in c:
            parts.append(f"= {c['exact_version']}")
            continue
        start = end = None
        if c.get("versionStartIncluding"):
            start = f"≥ {c['versionStartIncluding']}"
        elif c.get("versionStartExcluding"):
            start = f"> {c['versionStartExcluding']}"
        if c.get("versionEndIncluding"):
            end = f"≤ {c['versionEndIncluding']}"
        elif c.get("versionEndExcluding"):
            end = f"< {c['versionEndExcluding']}"
        bound = " et ".join(p for p in (start, end) if p)
        if bound:
            parts.append(bound)
    return " ou ".join(parts) or "plage non exploitable"


def _check_windows_app_patch(asset: Asset, cve: CVE, windows_mappings: list[tuple[str, str]]) -> Optional[dict]:
    """
    Vérifie la version installée d'une application Windows tierce (PuTTY, Wireshark...)
    matchée via `WindowsAppMapping`, contre les plages de versions vulnérables NVD —
    même mécanique que `check_patch_linux` "Voie 2" (`_extract_version_constraints`/
    `_version_patched`, déjà en place pour les paquets Debian), jusqu'ici jamais
    branchée côté Windows.

    `check_patch_windows` ne sait vérifier que l'OS lui-même (KB/build) : une CVE dont
    le seul CPE pertinent est applicatif ("a:putty:putty") n'y trouve ni KB (aucun
    numéro KB pour un logiciel tiers) ni plage de version OS exploitable, et retombe
    systématiquement sur "vérification manuelle requise" — même quand la version
    installée (déjà relevée en base, `installed_packages[].version`, ex: PuTTY
    "0.81.0.0") suffirait à trancher (incident réel CVE-2016-2563/DEPLOYAPP,
    03/08/2026 : correctif présent depuis longtemps, jamais détecté automatiquement).

    Renvoie `None` si cette CVE ne cible aucune application Windows installée
    correspondue (repli sur `check_patch_windows`, chemin OS/KB inchangé) — jamais
    `None` par erreur d'I/O puisque tout est déjà en base (aucune connexion WinRM ici).
    """
    if not windows_mappings:
        return None
    cve_products = _cve_products(cve)
    if not cve_products:
        return None

    matches = []
    for pkg in (asset.installed_packages or []):
        if not isinstance(pkg, dict):
            continue
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version:
            continue
        for product in _windows_app_candidates(name, windows_mappings) & cve_products:
            constraints = _extract_version_constraints(cve, product, part="a")
            matches.append({
                "name": name, "version": version, "product": product,
                "verdict": _version_patched(version, constraints),
                "range": _format_version_range(constraints) if constraints else None,
            })

    if not matches:
        return None

    if any(m["verdict"] is False for m in matches):
        patch_detected = False
    elif any(m["verdict"] is None for m in matches):
        patch_detected = None
    else:
        patch_detected = True

    lines = []
    for m in matches:
        icon = "✅" if m["verdict"] is True else "❌" if m["verdict"] is False else "➖"
        if m["verdict"] is True:
            comparaison = f"version installée {m['version']}, hors de la plage vulnérable ({m['range']})"
        elif m["verdict"] is False:
            comparaison = f"version installée {m['version']}, dans la plage vulnérable ({m['range']})"
        else:
            comparaison = f"version installée {m['version']}, aucune plage de version exploitable dans NVD pour ce produit"
        lines.append(f"{icon} {m['name']} — {comparaison} (produit CPE `{m['product']}`)")

    return {
        "patch_detected": patch_detected,
        "method": "windows-app-version",
        "packages_checked": [m["product"] for m in matches],
        "app_version_check": [
            {"name": m["name"], "version": m["version"], "product": m["product"],
             "verdict": m["verdict"], "range": m["range"]}
            for m in matches
        ],
        "details": "\n".join(lines) + (
            "" if patch_detected is not None else
            "\nComparaison manuelle requise."
        ),
        "note": "Version installée comparée aux plages de versions vulnérables NVD pour cette "
                "application (cf. Administration > Correspondances Windows) — pas un contrôle "
                "en direct (WinRM), la version vient du dernier scan d'inventaire.",
    }


def _cap_lines(text: str, max_lines: int = 500) -> str:
    """Tronque une sortie de commande à `max_lines` (07/08/2026, bouton "Détail"
    de la modale patch check) — un `dpkg-query` sur un actif à plusieurs
    milliers de paquets ne doit pas gonfler indéfiniment la réponse HTTP."""
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return "\n".join(lines[:max_lines]) + f"\n… ({len(lines) - max_lines} lignes supplémentaires tronquées)"


# ─── Vérification Debian via Security Tracker ─────────────────────────────────

async def _fetch_linux_package_snapshot(asset: Asset) -> dict:
    """
    Une seule connexion SSH par actif — relève tous les paquets dpkg (+ rpm en
    repli) installés, avec mapping vers leur paquet source pour dpkg, et le
    noyau en cours d'exécution. Réutilisé par l'appelant pour toutes les CVE de
    cet actif dans le même cycle plutôt que rouvert à chaque CVE (même
    principe que `_fetch_windows_patch_snapshot` côté Windows, session
    21/07/2026 — sur un actif à plusieurs centaines de vulns, ça évite autant
    de connexions/authentifications SSH redondantes pour un relevé strictement
    identique d'une CVE à l'autre).

    Retourne {"error": ...} si injoignable/mal configuré.
    """
    host = asset.ip_address or asset.hostname
    if not host:
        return {"error": "Adresse IP / hostname manquant"}

    # Priorité aux identifiants stockés sur l'actif (phase de test), sinon la clé
    # SSH partagée du parc — même ordre que services/asset_scanner.py.
    ssh_user = asset.scan_username or settings.SSH_USER
    ssh_password = decrypt_password(asset.scan_password_encrypted) if asset.scan_password_encrypted else None

    if not ssh_user:
        return {"error": "Aucun identifiant SSH (ni sur l'actif, ni SSH_USER configuré)"}

    connect_kwargs = dict(username=ssh_user, connect_timeout=15)
    if ssh_password:
        connect_kwargs["password"] = ssh_password
    else:
        connect_kwargs["client_keys"] = [settings.SSH_KEY_PATH] if settings.SSH_KEY_PATH else None

    try:
        async with await connect_trusted(host, **connect_kwargs) as conn:
            by_source: dict[str, list[tuple[str, str]]] = {}
            flat: dict[str, str] = {}

            r = await conn.run(
                "dpkg-query -W -f='${Package}\\t${Version}\\t${source:Package}\\n' 2>/dev/null",
                check=False,
            )
            for line in r.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) == 3 and parts[1]:
                    pkg, ver, src = parts[0], parts[1], (parts[2] or parts[0])
                    flat[pkg] = ver
                    by_source.setdefault(src, []).append((pkg, ver))
                    # Les noyaux Secure Boot (et autres binaires signés) viennent
                    # d'un paquet source wrapper "X-signed[-arch]" (ex:
                    # linux-image-6.1.0-49-amd64 ← source linux-signed-amd64),
                    # alors que le tracker référence la source de base ("linux").
                    # Sans cette normalisation, le noyau installé est invisible
                    # et une machine NON patchée serait déclarée "non affectée".
                    signed = re.match(r"^(.+?)-signed(?:-[a-z0-9]+)?$", src)
                    if signed:
                        by_source.setdefault(signed.group(1), []).append((pkg, ver))

            # Repli rpm (distros non-dpkg) — même connexion, une commande de plus
            r_rpm = await conn.run(
                "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null",
                check=False,
            )
            for line in r_rpm.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) == 2 and parts[0] not in flat:
                    flat[parts[0]] = parts[1]

            uname = (await conn.run("uname -r", check=False)).stdout.strip()

        return {
            "by_source": by_source, "flat": flat, "uname": uname,
            # Commandes + retour brut (07/08/2026, bouton "Détail" de la modale) —
            # cf. commentaire équivalent sur _fetch_windows_patch_snapshot.
            # `_cap_lines` : un dpkg-query sur un actif à plusieurs milliers de
            # paquets ne doit pas gonfler indéfiniment la réponse HTTP.
            "_raw": [
                {"command": "dpkg-query -W -f='${Package}\\t${Version}\\t${source:Package}\\n' 2>/dev/null", "output": _cap_lines(r.stdout)},
                {"command": "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null", "output": _cap_lines(r_rpm.stdout)},
                {"command": "uname -r", "output": uname},
            ],
        }

    except Exception as e:
        logger.error(f"SSH {host} erreur (relevé paquets) : {e}")
        return {"error": str(e)}


def _check_debian_tracker(snapshot: dict, cve: CVE, release: str, fixes: list[dict]) -> dict:
    """
    Compare les versions dpkg installées (relevé déjà effectué, cf.
    `_fetch_linux_package_snapshot`) aux versions corrigées du Debian Security
    Tracker. `fixes` = entrées {package, status, fixed_version} du tracker
    pour cette CVE/release (une par paquet source affecté).
    """
    by_source: dict[str, list[tuple[str, str]]] = snapshot.get("by_source") or {}
    uname = snapshot.get("uname")

    results = []
    reboot_note = None
    for fix in fixes:
        src = fix["package"]
        status = fix.get("status")
        fixed_version = fix.get("fixed_version")
        installed = by_source.get(src, [])

        if not installed:
            results.append({
                "package": src, "patched": True, "not_installed": True,
                "detail": f"aucun paquet issu de la source '{src}' installé",
            })
            continue

        if status != "resolved" or not fixed_version:
            results.append({
                "package": src, "patched": False, "no_fix": True,
                "detail": f"aucun correctif publié par Debian pour {release} "
                          f"(statut tracker : {status or 'inconnu'})",
            })
            continue

        if fixed_version == "0":
            # Convention tracker : "0" = cette release n'a jamais été affectée
            results.append({
                "package": src, "patched": True,
                "detail": f"{release} non affectée selon le tracker Debian",
            })
            continue

        version_key = functools.cmp_to_key(deb_version_compare)
        newest_pkg, newest_ver = max(installed, key=lambda pv: version_key(pv[1]))
        patched = deb_version_compare(newest_ver, fixed_version) >= 0
        results.append({
            "package": src, "patched": patched,
            "detail": f"{newest_pkg} {newest_ver} installé — "
                      f"corrigé à partir de {fixed_version} ({release})",
        })

        # Cas noyau : le paquet corrigé peut être installé sans que le
        # noyau en cours d'exécution soit le bon (redémarrage en attente)
        if src == "linux" and patched and uname:
            running = dict(by_source.get(src, [])).get(f"linux-image-{uname}")
            if running and deb_version_compare(running, fixed_version) < 0:
                reboot_note = (
                    f"⚠ noyau corrigé installé, mais le noyau en cours d'exécution "
                    f"({uname}, version {running}) est antérieur au correctif — "
                    f"redémarrage requis pour être réellement protégé"
                )

    # Aucun paquet source de la CVE présent sur l'actif → CVE sans objet ici.
    # Même raisonnement que la voie 2 : ce n'est pas "corrigé", c'est "ne
    # s'applique pas" — destiné au faux positif après validation d'un analyste.
    # Le comportement historique (bascule en `patched`) a produit 206 lignes
    # avant ce changement ; elles ne sont pas rétro-corrigées automatiquement,
    # `patched` étant un état terminal (cf. STATUS.md 21/07/2026).
    if results and all(r.get("not_installed") for r in results):
        return {
            "patch_detected": None,
            "not_applicable": True,
            "not_applicable_reason": (
                f"Aucun paquet issu des sources visées par cette CVE n'est installé "
                f"({', '.join(sorted(r['package'] for r in results)[:5])})."
            ),
            "method": "debian-security-tracker",
            "release": release,
            "details": "\n".join(f"➖ {r['package']} : {r['detail']}" for r in results),
            "note": "CVE sans objet sur cet actif — aucun paquet concerné installé. "
                    "À qualifier en faux positif par un analyste, pas en 'corrigé'.",
        }

    patch_detected = (
        False if any(r["patched"] is False for r in results)
        else True if results else None
    )

    details = "\n".join(
        f"{'✅' if r['patched'] else '❌'} {r['package']} : {r['detail']}" for r in results
    )
    if reboot_note:
        details += f"\n{reboot_note}"

    # Aucun correctif publié par Debian pour aucun des paquets concernés : il n'y
    # a rien à appliquer sur le serveur, la mise à jour n'existe pas encore. Ce
    # n'est ni "corrigé" ni "à traiter" — c'est "en attente de correctif", statut
    # déjà prévu et réévalué automatiquement à chaque cycle (bascule en `patched`
    # dès publication, sans action manuelle).
    aucun_correctif = bool(results) and all(r.get("no_fix") for r in results)

    # Cas mixte : certains paquets visés ne sont pas installés (hors sujet) et au
    # moins un paquet réellement installé n'a aucun correctif Debian — ni "sans
    # objet" (un paquet concerné est bien là) ni "aucun correctif" au sens strict
    # (ce champ exige que TOUS les paquets soient sans correctif). Jusqu'ici ce
    # cas ne matchait aucune branche d'`apply_patch_result` et restait ouvert
    # sans signal exploitable (3 CVE sur gitlab.aer.loc qualifiées manuellement
    # le 21/07, cf. STATUS.md). Exclut les paquets réellement vulnérables avec
    # correctif disponible mais non appliqué (`patched is False` sans `no_fix`) —
    # ce cas reste une vraie vuln ouverte, pas une attente de correctif amont.
    no_fix_entries = [r for r in results if r.get("no_fix")]
    not_installed_entries = [r for r in results if r.get("not_installed")]
    other_entries = [r for r in results if not r.get("no_fix") and not r.get("not_installed")]
    partial_fix = (
        bool(no_fix_entries) and bool(not_installed_entries)
        and all(r["patched"] for r in other_entries)
    )
    partial_fix_reason = None
    if partial_fix:
        absents = sorted(r["package"] for r in not_installed_entries)
        presents = sorted(r["package"] for r in no_fix_entries)
        absents_verbe = "ne sont pas installés" if len(absents) > 1 else "n'est pas installé"
        presents_verbe = "le sont bien" if len(presents) > 1 else "l'est bien"
        partial_fix_reason = (
            f"Cette CVE vise plusieurs paquets : {', '.join(absents)} {absents_verbe} "
            f"sur cet actif, mais {', '.join(presents)} {presents_verbe} et aucun correctif "
            f"Debian n'est encore publié pour {release}."
        )

    return {
        "patch_detected": patch_detected,
        "no_fix_available": aucun_correctif,
        "no_fix_reason": (
            f"Debian n'a publié aucun correctif pour {release} "
            f"({', '.join(sorted(r['package'] for r in results)[:5])}) — statut tracker « open »."
        ) if aucun_correctif else None,
        "partial_fix": partial_fix,
        "partial_fix_reason": partial_fix_reason,
        "method": "debian-security-tracker",
        "release": release,
        "details": details,
        "note": "Comparaison contre les versions corrigées Debian (Security Tracker) — "
                "fiable y compris pour les correctifs backportés et le noyau.",
    }


# ─── Vérification Linux via SSH ───────────────────────────────────────────────

async def check_patch_linux(asset: Asset, cve: CVE, snapshot: Optional[dict] = None) -> dict:
    """
    Vérifie si les paquets affectés sont à jour, à partir d'un relevé SSH
    (read-only) de l'actif.

    Deux voies, par ordre de priorité :
    1. Debian Security Tracker (actifs Debian) — compare la version dpkg installée
       à la version *Debian* corrigée publiée par le tracker. Fiable y compris pour
       les backports et le noyau, là où NVD ne voit que les versions amont.
    2. Plages de versions NVD (autres distros, ou CVE inconnue du tracker) —
       best-effort, ne voit pas les backports.

    `snapshot` : relevé déjà effectué par `_fetch_linux_package_snapshot`, mis
    en cache par l'appelant pour tout un cycle (une seule connexion SSH par
    actif, réutilisée pour toutes ses CVE). Si absent, un relevé est fait à la
    volée pour ce seul appel (cas du bouton "Patch check" unitaire côté UI).

    Même règle d'auto-bascule que Windows (cf. apply_patch_result) — ne modifie
    rien sur le serveur ni en base ici.
    """
    host = asset.ip_address or asset.hostname
    if not host:
        return {"patch_detected": None, "error": "Adresse IP / hostname manquant"}

    if snapshot is None:
        snapshot = await _fetch_linux_package_snapshot(asset)

    if snapshot.get("error"):
        return {"patch_detected": None, "error": snapshot["error"]}

    # Voie 1 : Debian Security Tracker
    release = debian_release_for_asset(asset)
    if release:
        fixes = await get_debian_fix_info(cve.cve_id, release)
        if fixes:
            return _check_debian_tracker(snapshot, cve, release, fixes)

        # CVE totalement absente du tracker → ne concerne aucun paquet Debian.
        # Le tracker référence toute CVE touchant un paquet Debian, y compris
        # celles marquées "non affecté" — l'absence complète est donc un signal
        # de non-applicabilité, pas un trou de données (session 21/07/2026).
        #
        # Deux garde-fous, sans lesquels ce signal produirait des faux négatifs :
        #  - `is_cve_tracked` renvoie None si le tracker est injoignable : on ne
        #    conclut rien dans ce cas.
        #  - Les CVE publiées depuis moins de TRACKER_LAG_DAYS sont exclues : le
        #    tracker peut légitimement ne pas encore les avoir indexées, et les
        #    déclarer "sans objet" masquerait une vulnérabilité réelle et récente.
        published = cve.published
        if published and published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        assez_ancienne = published is not None and (
            datetime.now(timezone.utc) - published > TRACKER_LAG_DAYS
        )
        if assez_ancienne and await is_cve_tracked(cve.cve_id) is False:
            return {
                "patch_detected": None,
                "not_applicable": True,
                "not_applicable_reason": (
                    f"CVE absente du Debian Security Tracker : elle ne concerne aucun paquet "
                    f"Debian, donc pas cet actif ({release})."
                ),
                "method": "debian-security-tracker",
                "release": release,
                "details": f"➖ CVE inconnue du Debian Security Tracker — aucun paquet Debian concerné ({release}).",
                "note": "CVE sans objet sur cet actif — le tracker Debian, qui référence toute CVE "
                        "touchant un paquet Debian (y compris 'non affecté'), ne la connaît pas.",
            }

    # Voie 2 : plages NVD (fallback)
    cve_cpes = cve.cpe or []
    package_names = _extract_packages_from_cpe(cve_cpes)

    if not package_names:
        return {
            "patch_detected": None,
            "details": "Impossible de déduire les paquets affectés depuis les CPE de cette CVE.",
        }

    flat: dict[str, str] = snapshot.get("flat") or {}

    # Un relevé vide signifie une collecte ratée (dpkg/rpm muets), pas une machine
    # sans aucun paquet — ne surtout pas en conclure "non affecté" pour tout.
    if not flat:
        return {
            "patch_detected": None,
            "packages_checked": package_names,
            "details": "Relevé des paquets vide — impossible de conclure (collecte dpkg/rpm sans résultat).",
        }

    # Aucun des paquets visés par la CVE n'est installé → la CVE **ne s'applique
    # pas** à cet actif. Signalé comme tel (`not_applicable`) et **jamais** comme
    # "corrigé" : rien n'a été corrigé, le produit n'a simplement jamais été là.
    # La distinction compte pour l'audit (NIS 2) — un rapport annonçant "corrigé"
    # pour un logiciel absent est trompeur. C'est donc au faux positif que ces
    # lignes sont destinées, après validation manuelle de l'analyste
    # (cf. /api/vulnerabilities/false-positive-candidates).
    absents = [pkg for pkg in package_names if not flat.get(pkg)]
    if len(absents) == len(package_names):
        return {
            "patch_detected": None,
            "not_applicable": True,
            "not_applicable_reason": (
                f"Aucun des paquets visés par cette CVE n'est installé sur l'actif "
                f"({', '.join(sorted(package_names)[:5])}"
                f"{'…' if len(package_names) > 5 else ''})."
            ),
            "packages_checked": package_names,
            "packages_found": [],
            "details": "\n".join(f"➖ {pkg} : non installé" for pkg in sorted(package_names)),
            "note": "CVE sans objet sur cet actif — le produit concerné n'y est pas installé. "
                    "À qualifier en faux positif par un analyste, pas en 'corrigé'.",
        }

    results = []
    for pkg in package_names:
        installed_version = flat.get(pkg)
        constraints = _extract_version_constraints(cve, pkg)
        # Paquet absent alors que d'autres sont présents : neutre pour le verdict
        # (`None`), il ne peut ni prouver ni infirmer la correction.
        patched = _version_patched(installed_version, constraints) if installed_version else None
        results.append({
            "package": pkg,
            "installed": f"{pkg} {installed_version}" if installed_version else None,
            "installed_version": installed_version,
            "patched": patched,
            "detail": None if installed_version else "non installé",
        })

    determinate = [r["patched"] for r in results if r["patched"] is not None]
    if not determinate:
        patch_detected = None
    elif all(determinate):
        patch_detected = True
    else:
        patch_detected = False

    def _icon(r):
        if r["patched"] is True:
            return "✅"
        if r["patched"] is False:
            return "❌"
        return "❓"

    return {
        "patch_detected": patch_detected,
        "packages_checked": package_names,
        "packages_found": [r["package"] for r in results if r["installed"]],
        "details": "\n".join(
            f"{_icon(r)} {r['package']} : {r['detail'] or r['installed'] or 'non trouvé'}"
            + (
                ""
                if r["patched"] is not None or not r["installed"]
                else " (aucune plage de version exploitable dans NVD — comparaison manuelle requise)"
            )
            for r in results
        ),
        "note": "Comparaison de version best-effort contre les plages NVD — ne détecte pas un correctif "
                "backporté par la distro sans changement du numéro de version amont (ex: Debian/Ubuntu "
                "security updates). En cas de doute, comparer manuellement.",
    }


def _extract_packages_from_cpe(cpe_list: list[str]) -> list[str]:
    """
    Extrait des noms de paquets applicatifs ("a:") depuis les CPE d'une CVE.

    Si la CVE porte aussi un CPE noyau générique (cpe:2.3:o:linux:linux_kernel),
    les entrées "a:" sont ignorées : ce sont typiquement des produits commerciaux
    tiers qui embarquent leur propre noyau (ex: CVE-2026-31431 "crypto:
    algif_aead" — listée par NVD contre Arista CloudVision, SUSE Manager, RedHat
    OpenShift, VMware VeloCloud...) sans le moindre rapport avec les paquets
    dpkg/rpm réellement installés sur l'actif. Un vendor-allowlist basé sur l'OS
    de l'actif casserait au passage le cas normal (CVE d'un paquet upstream réel
    comme openssl/curl/apache, dont le vendor CPE n'est jamais celui de la
    distro) — la présence du CPE noyau est un signal plus fiable qu'un vendor.
    Il n'existe de toute façon aucun paquet "noyau Linux" générique vérifiable
    via dpkg/rpm : une vraie vérification demanderait de comparer `uname -r`,
    non implémenté ici.
    """
    if any(cpe.startswith("cpe:2.3:o:linux:linux_kernel:") for cpe in cpe_list):
        return []

    packages = []
    for cpe in cpe_list:
        # Composant d'une plateforme applicative (plugin Jenkins, module
        # Kubernetes…) : pas un paquet dpkg/rpm, cf. services/cpe_matcher.py
        if cpe_is_platform_component(cpe):
            continue
        parts = cpe.split(":")
        # cpe:2.3:a:vendor:product:version → product
        if len(parts) >= 5 and parts[2] == "a":
            pkg = parts[4].replace("_", "-")
            if pkg and pkg != "*":
                packages.append(pkg)
    return list(set(packages))


# ─── Point d'entrée unifié ────────────────────────────────────────────────────

async def check_patch(
    asset: Asset,
    cve: CVE,
    *,
    windows_snapshot: Optional[dict] = None,
    linux_snapshot: Optional[dict] = None,
    msrc_cache: Optional[dict] = None,
    windows_mappings: Optional[list] = None,
) -> dict:
    """
    Dispatche la vérification selon l'OS de l'actif.
    Retourne toujours un dict avec au minimum :
      - patch_detected : True / False / None (indéterminé)
      - details        : explication lisible pour l'analyste

    `windows_snapshot`/`linux_snapshot` : relevé WinRM/SSH déjà effectué pour
    cet actif (cf. `_fetch_windows_patch_snapshot`/`_fetch_linux_package_snapshot`),
    à passer par l'appelant quand plusieurs CVE du même actif sont vérifiées
    dans le même cycle — sinon un relevé est fait à la volée pour ce seul appel.
    `msrc_cache` : dict partagé par l'appelant pour tout un cycle, évite de
    réinterroger l'API MSRC pour une même CVE déjà vue sur un actif.
    `windows_mappings` : à charger une fois par cycle via `_load_windows_mappings(db)`
    et transmis ici (cf. `run_startup_patch_checks`) — sans lui, `still_matches`
    ci-dessous ignore les applications Windows correspondant via `WindowsAppMapping`.

    **Validité du rattachement, vérifiée en premier** (22/07/2026) : avant même
    de chercher un KB ou un paquet, on vérifie que ce rattachement actif × CVE
    serait encore créé par les règles de matching *actuelles* (`still_matches`,
    même fonction que `GET /false-positive-candidates`). Sans ce contrôle, un
    rattachement déjà identifié comme artefact (ex: CPE dégénéré `-:-:-`,
    cf. docs/MATCHING.md) tombait dans les branches Windows/Linux normales, qui
    ne trouvent logiquement ni KB ni paquet pertinent et répondent un générique
    "Vérification manuelle requise" — sans jamais dire que le rattachement
    lui-même est en cause. Constaté en réel sur CVE-2017-13091/DEPLOYAPP : le
    bouton "Patch check" ne donnait aucune indication sur la raison pour
    laquelle cette ligne figurait parmi les faux positifs suggérés, alors que
    cette raison est calculée depuis longtemps ailleurs dans le code.
    Résultat : `not_applicable`, consommé par `apply_patch_result` exactement
    comme "produit absent" — même règle de sévérité (CRITICAL signalé
    seulement, HIGH/MEDIUM/LOW basculé automatiquement en `false_positive`).
    """
    if not still_matches(asset, cve, windows_mappings):
        return {
            "patch_detected": None,
            "not_applicable": True,
            "not_applicable_reason": (
                "Le rattachement de cette CVE à cet actif ne serait plus créé par les règles "
                "de matching actuelles (CPE NVD n'identifiant aucun produit) — probablement "
                "un artefact d'une ancienne règle de matching depuis corrigée."
            ),
            "details": (
                "⚠️ Rattachement invalide selon les règles de matching actuelles : le CPE de "
                "cette CVE n'identifie ni vendeur ni produit, ou aucun paquet/mot-clé ne "
                "correspond à cet actif. Cette CVE ne semble pas réellement concerner la "
                "machine — voir la justification ci-dessus."
            ),
            "kb_checked": [],
            "cve_id": cve.cve_id,
            "asset": asset.name,
            "os": asset.os,
        }

    os_lower = (asset.os or "").lower()

    if "windows" in os_lower:
        # 0. Application tierce (PuTTY, Wireshark...) matchée via WindowsAppMapping —
        #    vérifiée par version installée plutôt que KB/build (cf. docstring
        #    _check_windows_app_patch). None si cette CVE ne cible aucune application
        #    Windows installée correspondue : repli sur le chemin OS/KB ci-dessous,
        #    inchangé.
        app_result = _check_windows_app_patch(asset, cve, windows_mappings or [])
        if app_result is not None:
            app_result["cve_id"] = cve.cve_id
            app_result["asset"] = asset.name
            app_result["os"] = asset.os
            return app_result

        # 1. Cherche KB dans les références NVD
        kb_numbers = extract_kb_numbers(cve)
        # 2. Toujours interroger MSRC : sert de fallback si NVD est vide, fournit le
        #    mapping KB → produit/OS (info seule, cf. kb_os_hint), et la date de
        #    sortie réelle du correctif (plus précise que cve.published pour le
        #    signal 3/repli par date, cf. check_patch_windows). Mis en cache par
        #    CVE (indépendant de l'actif) quand l'appelant fournit msrc_cache.
        if msrc_cache is not None and cve.cve_id in msrc_cache:
            kb_products, msrc_release_date = msrc_cache[cve.cve_id]
        else:
            kb_products, msrc_release_date = await fetch_msrc_kb_products(cve.cve_id)
            if msrc_cache is not None:
                msrc_cache[cve.cve_id] = (kb_products, msrc_release_date)
        if not kb_numbers:
            logger.info(f"Aucun KB dans NVD pour {cve.cve_id} → utilisation MSRC API")
            kb_numbers = sorted(kb_products.keys())

        loop = asyncio.get_event_loop()

        # 3. Relevé WinRM read-only (synchrone dans pywinrm → thread). Récupéré
        #    ici plutôt que dans check_patch_windows : le build installé est
        #    nécessaire dès maintenant pour résoudre le seuil corrigé (étape 4),
        #    qui doit se faire en contexte async (accès base + HTTP).
        if windows_snapshot is None:
            windows_snapshot = await loop.run_in_executor(
                None, _fetch_windows_patch_snapshot, asset
            )

        # 4. Seuil de build corrigé publié par Microsoft (signal 2bis) — comble
        #    l'absence de plage de version NVD sur les CVE anciennes. Seulement
        #    si NVD ne tranche pas déjà : évite un appel réseau (et du
        #    rate-limit) là où le verdict est déjà acquis.
        msft_build = None
        installed_build = (windows_snapshot or {}).get("build")
        if installed_build and not windows_snapshot.get("error"):
            os_product = _asset_os_product(asset)
            nvd_constraints = (
                _extract_version_constraints(cve, os_product, part="o") if os_product else []
            )
            if _version_patched(installed_build, nvd_constraints) is None:
                # Ordonne les KB pour tester d'abord ceux que MSRC associe à l'OS
                # de l'actif : une CVE Windows liste un KB par version d'OS (jusqu'à
                # 14), et chaque KB non résolu coûte une requête réseau throttlée.
                # Pure optimisation — `resolve_fixed_build` revérifie de toute façon
                # la branche de build, donc l'ordre ne peut pas fausser le verdict.
                ordered_kbs = _order_kbs_by_os(kb_numbers, kb_products, asset)
                try:
                    msft_build = await resolve_fixed_build(ordered_kbs, installed_build)
                except Exception as e:
                    logger.warning(f"{cve.cve_id} : résolution build KB impossible ({type(e).__name__})")

        result = await loop.run_in_executor(
            None, check_patch_windows, asset, cve, kb_numbers, kb_products,
            msrc_release_date, windows_snapshot, msft_build,
        )
    else:
        # Relevé ici (pas seulement dans check_patch_linux) pour que le snapshot,
        # avec son `_raw` (commande + retour brut), reste accessible dans CETTE
        # portée pour le merge ci-dessous — une réaffectation de `snapshot` à
        # l'intérieur de check_patch_linux ne serait pas visible ici sinon.
        if linux_snapshot is None:
            linux_snapshot = await _fetch_linux_package_snapshot(asset)
        result = await check_patch_linux(asset, cve, linux_snapshot)

    result["cve_id"] = cve.cve_id
    result["asset"] = asset.name
    result["os"] = asset.os
    # Commande(s) + retour brut de ce contrôle (07/08/2026, bouton "Détail" de la
    # modale, cf. _fetch_windows_patch_snapshot/_fetch_linux_package_snapshot) —
    # jamais persisté tel quel en base (cf. apply_patch_result qui le filtre
    # avant d'écrire `vuln.patch_check_result`, pour ne pas dupliquer un relevé
    # identique sur chaque vulnérabilité de l'actif).
    raw = (windows_snapshot or linux_snapshot or {}).get("_raw")
    if raw:
        result["debug_commands"] = raw
    return result


# ─── Application du résultat à la vulnérabilité ───────────────────────────────

# Étiquettes de bascule automatique (18/08/2026, cf. audit/AUDIT_SECURITE.md #34) — deux
# variantes plutôt qu'une seule : `installed_packages` d'un actif `collection_method="agent"`
# vient d'un check-in poussé par le binaire posé sur le poste, sans relecture indépendante
# côté serveur (contrairement à un actif SSH/WinRM, où le backend lit lui-même la machine).
# La bascule auto reste identique dans les deux cas (décision explicite : garder la même
# logique agent/compte de service) — seule la piste d'audit change, pour que NIS 2 reste
# honnête sur le niveau de confiance réel de la donnée qui a déclenché la décision.
AUTO_VALIDATED_BY = "Auto (patch check)"
AUTO_VALIDATED_BY_AGENT = "Auto (patch check, agent-reported)"
AUTO_VALIDATED_BY_LABELS = {AUTO_VALIDATED_BY, AUTO_VALIDATED_BY_AGENT}


def apply_patch_result(vuln: Vulnerability, cve: CVE, check_result: dict, session, agent_reported: bool = False) -> bool:
    """
    Enregistre le résultat du check sur la vuln, et applique la bascule
    automatique quand elle est permise.

    **Règle CLAUDE.md, valable pour les deux issues ci-dessous** : les CVE
    CRITICAL exigent toujours une validation manuelle — jamais de bascule
    automatique, quel que soit le signal. Pour HIGH/MEDIUM/LOW, la bascule est
    automatique et l'analyste peut réouvrir à tout moment.

    Deux issues distinctes, à ne pas confondre :

    - **`patched`** — un correctif a été *détecté* sur la machine
      (`patch_detected: true`).
    - **`false_positive`** — la CVE ne s'applique pas : aucun des paquets visés
      n'est installé (`not_applicable: true`, cf. `check_patch_linux`). Rien n'a
      été corrigé, le produit n'a jamais été là — d'où un statut différent, la
      distinction comptant pour l'audit NIS 2. La raison est recopiée dans
      `notes` pour que la piste d'audit soit exploitable sans rouvrir le rapport
      technique.

    Retourne True si la vuln a été basculée automatiquement (dans l'un ou
    l'autre statut).
    """
    vuln.last_patch_check = datetime.now(timezone.utc)
    # `debug_commands` (07/08/2026, bouton "Détail" de la modale patch check)
    # jamais persisté : identique pour toutes les vulns d'un même actif dans un
    # même cycle (un seul relevé WinRM/SSH réutilisé), le dupliquer sur chaque
    # ligne gonflerait `vulnerabilities` sans raison — reste dans `check_result`
    # (objet en mémoire de l'appelant, renvoyé tel quel dans la réponse HTTP),
    # juste absent de ce qui est écrit en base.
    vuln.patch_check_result = {k: v for k, v in check_result.items() if k != "debug_commands"}

    # ── Garde-fou : ne JAMAIS écraser une décision humaine ────────────────────
    # Le cycle autonome ne traite que open/in_progress/awaiting_fix, mais le
    # bouton "Patch check" unitaire peut être cliqué sur n'importe quelle ligne,
    # y compris déjà qualifiée. Sans ce garde-fou, un contrôle manuel sur une
    # vuln qualifiée "faux positif" par un analyste la rebasculait
    # automatiquement (statut ET annotation remplacés), détruisant la décision
    # et sa piste d'audit — constaté en conditions réelles le 21/07/2026.
    #
    # 1. États terminaux : jamais touchés, quelle que soit l'origine de la décision.
    if vuln.status in ("false_positive", "patched", "accepted_risk"):
        return False

    # 2. Décision humaine sur un état non terminal (typiquement `awaiting_fix`
    #    annoté par un analyste) : une **seule** évolution reste permise, la
    #    détection d'un correctif. C'est précisément la raison d'être du statut
    #    "en attente" — il doit se résoudre seul dès que le correctif sort, sans
    #    action manuelle (comportement documenté de longue date).
    #    Toute autre requalification automatique (faux positif, remise en
    #    attente) écraserait un jugement humain et reste donc bloquée.
    qualifiee_par_humain = bool(vuln.validated_by) and vuln.validated_by not in AUTO_VALIDATED_BY_LABELS
    if qualifiee_par_humain and check_result.get("patch_detected") is not True:
        return False

    if cve.severity == "CRITICAL":
        # Signalement seul : l'analyste tranche (règle non négociable).
        return False

    auto_label = AUTO_VALIDATED_BY_AGENT if agent_reported else AUTO_VALIDATED_BY

    if check_result.get("patch_detected") is True:
        record_status_change(session, vuln.id, vuln.status, "patched", validated_by=auto_label)
        vuln.status = "patched"
        vuln.patched_at = datetime.now(timezone.utc)
        vuln.awaiting_fix_at = None
        vuln.false_positive_at = None
        vuln.validated_by = auto_label
        return True

    if check_result.get("no_fix_available") is True:
        # Aucun correctif éditeur/distro disponible : rien à appliquer. Statut
        # `awaiting_fix`, **volontairement conservé dans le cycle de recheck**
        # (contrairement à `false_positive`) — la vuln bascule seule en `patched`
        # dès que le correctif sort, sans action manuelle.
        notes = check_result.get("no_fix_reason") or "Aucun correctif publié par la distribution pour cette CVE."
        record_status_change(session, vuln.id, vuln.status, "awaiting_fix", validated_by=auto_label, notes=notes)
        vuln.status = "awaiting_fix"
        vuln.awaiting_fix_at = datetime.now(timezone.utc)
        vuln.patched_at = None
        vuln.false_positive_at = None
        vuln.validated_by = auto_label
        vuln.notes = notes
        return True

    if check_result.get("partial_fix") is True:
        # Cas mixte (27/07/2026) : un des paquets visés par la CVE n'est pas
        # installé (hors sujet) mais un autre l'est bien et Debian n'a publié
        # aucun correctif — même logique que `awaiting_fix` (rien à appliquer,
        # réévalué à chaque cycle, bascule seule en `patched` dès publication),
        # avec un statut dédié pour ne pas laisser croire que *tous* les
        # paquets visés sont concernés. Cf. CLAUDE.md.
        notes = check_result.get("partial_fix_reason") or "Correctif partiellement en attente : un paquet visé par cette CVE est absent, l'autre n'a pas encore de correctif Debian."
        record_status_change(session, vuln.id, vuln.status, "awaiting_fix_partial", validated_by=auto_label, notes=notes)
        vuln.status = "awaiting_fix_partial"
        vuln.awaiting_fix_at = datetime.now(timezone.utc)
        vuln.patched_at = None
        vuln.false_positive_at = None
        vuln.validated_by = auto_label
        vuln.notes = notes
        return True

    if check_result.get("not_applicable") is True:
        notes = check_result.get("not_applicable_reason") or "Aucun des paquets visés par cette CVE n'est installé sur l'actif."
        record_status_change(session, vuln.id, vuln.status, "false_positive", validated_by=auto_label, notes=notes)
        vuln.status = "false_positive"
        vuln.false_positive_at = datetime.now(timezone.utc)
        vuln.patched_at = None
        vuln.awaiting_fix_at = None
        vuln.validated_by = auto_label
        vuln.notes = notes
        return True

    return False


async def record_asset_completion(session, asset: Asset, checked_count: int, auto_bascule_count: int) -> None:
    """
    Journalise la fin de la passe de contrôle patch d'UN actif (11/08/2026,
    demande explicite — cf. `models.py::PatchCheckAssetCompletion`). Appelée une
    fois par actif, à la fin de sa boucle CVE dans `run_startup_patch_checks` —
    jamais si `checked_count` est nul (un actif de `asset_ids` a par construction
    au moins une vuln à vérifier, cf. la requête qui construit cette liste).
    """
    session.add(PatchCheckAssetCompletion(
        asset_id=asset.id,
        asset_name=asset.name,
        hostname=asset.hostname,
        checked_count=checked_count,
        auto_bascule_count=auto_bascule_count,
        completed_at=datetime.now(timezone.utc),
    ))


# ─── Rattrapage des résultats déjà collectés ──────────────────────────────────

# Taille de page pour les requêtes par lot (backfill_auto_patch,
# run_startup_patch_checks) — évite de matérialiser tout le stock de
# vulnérabilités en mémoire d'un coup. Incident (28/07/2026) : `.scalars().all()`
# sans pagination sur ~265 000 vulnérabilités ouvertes (premier cycle après
# l'élargissement de l'import AD à tout le parc, jusque-là testé sur 2 actifs
# seulement) a saturé la limite mémoire du conteneur (6 Go) et bloqué le
# backend — combiné à `poolclass=NullPool` (une connexion Postgres neuve par
# requête, cf. database.py), le commit au fil de l'eau à ce volume a aussi
# fait s'accumuler les timeouts de connexion. Fonctionnait jusqu'ici parce que
# jamais testé au-delà de quelques milliers de lignes (cf. l'incident ~4600 CVE
# du 21/07 déjà documenté plus bas, qui portait sur la lenteur, pas la mémoire).
BATCH_SIZE = 2000


async def backfill_auto_patch(asset_ids: Optional[list] = None) -> dict:
    """
    Réapplique la règle de bascule automatique (apply_patch_result) aux vulns déjà
    contrôlées dont le résultat n'a jamais été reconcilié — typiquement des checks
    effectués avant l'introduction de cette règle. N'effectue AUCUN nouveau contrôle
    SSH/WinRM : réutilise le patch_check_result déjà stocké en base (lecture seule,
    aucune sollicitation des serveurs). Tout le parc par défaut ; restreint à
    `asset_ids` si fourni (cf. run_full_patch_check_cycle).

    Paginé par keyset (Vulnerability.id > dernier vu, cf. BATCH_SIZE) plutôt
    qu'un .all() global — le curseur avance à chaque ligne lue, qu'elle soit
    réconciliée ou non (skip via `continue`), donc pas de risque de reboucler
    indéfiniment sur les lignes ignorées.
    """
    stats = {"reconciled": 0}
    session = SessionLocal()
    try:
        last_id = None
        while True:
            filters = [
                # awaiting_fix inclus : une vuln annotée "pas de correctif dispo"
                # doit être revérifiée comme les autres pour basculer en patched
                # dès que le correctif sort, sans action manuelle.
                Vulnerability.status.in_(["open", "in_progress", "awaiting_fix", "awaiting_fix_partial"]),
                Vulnerability.last_patch_check.isnot(None),
            ]
            if asset_ids:
                filters.append(Vulnerability.asset_id.in_(asset_ids))
            if last_id is not None:
                filters.append(Vulnerability.id > last_id)

            result = await session.execute(
                select(Vulnerability).where(*filters).order_by(Vulnerability.id).limit(BATCH_SIZE)
            )
            batch = result.scalars().all()
            if not batch:
                break
            last_id = batch[-1].id

            for vuln in batch:
                check_result = vuln.patch_check_result or {}
                if (check_result.get("patch_detected") is not True
                        and check_result.get("not_applicable") is not True
                        and check_result.get("no_fix_available") is not True):
                    continue
                cve = await session.get(CVE, vuln.cve_id)
                if not cve:
                    continue
                asset = await session.get(Asset, vuln.asset_id)
                agent_reported = bool(asset) and asset.collection_method == "agent"
                if apply_patch_result(vuln, cve, check_result, session, agent_reported=agent_reported):
                    stats["reconciled"] += 1

            await session.commit()
    except Exception:
        await session.rollback()
        logger.exception("Erreur rattrapage patch check")
        raise
    finally:
        await session.close()

    if stats["reconciled"]:
        logger.info(f"Rattrapage patch check : {stats['reconciled']} vuln(s) basculée(s) en patched")
    return stats


async def reset_patch_check_timestamps(asset_ids: Optional[list] = None) -> int:
    """
    Rend les vulnérabilités ouvertes à nouveau éligibles au cycle de patch
    check, en effaçant leur horodatage `last_patch_check`. Tout le parc par
    défaut ; restreint à `asset_ids` si fourni (cf. run_full_patch_check_cycle)
    — une réévaluation forcée scopée à un actif ne doit pas remettre à zéro le
    reste du parc, sans quoi le prochain cycle global re-contrôlerait des
    milliers de vulns sans rapport avec la demande.

    Utilité : le cycle ignore ce qui a été contrôlé il y a moins de
    RECHECK_INTERVAL (24h). Quand un **signal de détection est amélioré**
    (ex: ajout du signal 2bis build Microsoft, session 21/07/2026), tout le
    stock déjà contrôlé porte un résultat périmé calculé par l'ancienne
    logique, et resterait figé jusqu'à 24h — voire indéfiniment sur un parc
    contrôlé en continu.

    Volontairement non destructif : n'efface que l'horodatage, jamais
    `patch_check_result` (le dernier rapport reste consultable tant qu'il n'est
    pas remplacé) ni le statut/validateur d'une vuln. Ne touche pas non plus
    aux `patched`/`false_positive` : une décision d'analyste ne se réévalue pas
    toute seule.

    Retourne le nombre de lignes rendues éligibles.
    """
    session = SessionLocal()
    try:
        filters = [
            Vulnerability.status.in_(["open", "in_progress", "awaiting_fix", "awaiting_fix_partial"]),
            Vulnerability.last_patch_check.isnot(None),
        ]
        if asset_ids:
            filters.append(Vulnerability.asset_id.in_(asset_ids))

        result = await session.execute(
            update(Vulnerability).where(*filters).values(last_patch_check=None)
        )
        await session.commit()
        count = result.rowcount or 0
        logger.info(f"Réévaluation forcée : {count} vulnérabilité(s) rendues éligibles au patch check")
        return count
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def count_pending_patch_checks(asset_ids: Optional[list] = None) -> int:
    """Nombre de vulnérabilités que run_startup_patch_checks contrôlerait avec ce
    périmètre — mêmes filtres exacts que cette fonction (statut ouvert, jamais
    vérifié ou vérifié il y a plus de RECHECK_INTERVAL, CVE pas trop ancienne).
    Calculé de façon synchrone avant de lancer le cycle en tâche de fond
    (cf. routers/patch_check.py::trigger_patch_check_run) pour donner un retour
    immédiat et fiable au clic ("rien à vérifier" vs "N à vérifier") — GET /status
    ne convient pas ici, son compteur `pending` n'est pas scopé à `asset_ids`
    (cf. sa docstring)."""
    session = SessionLocal()
    try:
        recheck_cutoff = datetime.now(timezone.utc) - RECHECK_INTERVAL
        age_cutoff = datetime.now(timezone.utc) - timedelta(days=365 * PATCH_CHECK_MAX_AGE_YEARS)
        filters = [
            Vulnerability.status.in_(["open", "in_progress", "awaiting_fix", "awaiting_fix_partial"]),
            or_(
                Vulnerability.last_patch_check.is_(None),
                Vulnerability.last_patch_check < recheck_cutoff,
            ),
            CVE.published >= age_cutoff,
        ]
        if asset_ids:
            filters.append(Vulnerability.asset_id.in_(asset_ids))
        return (await session.execute(
            select(func.count(func.distinct(Vulnerability.id)))
            .select_from(Vulnerability)
            .join(CVE, Vulnerability.cve_id == CVE.id)
            .where(*filters)
        )).scalar_one()
    finally:
        await session.close()


# ─── Vérification automatique au démarrage ────────────────────────────────────

async def run_startup_patch_checks(asset_ids: Optional[list] = None) -> dict:
    """
    Vérifie (lecture seule) les vulnérabilités ouvertes jamais contrôlées, ou dont
    le dernier contrôle date de plus de RECHECK_INTERVAL — sans ce second critère,
    une vuln resterait bloquée sur un résultat périmé (ex: `patch_detected: None`
    avant qu'un correctif Linux ne soit appliqué) et ne serait plus jamais
    revérifiée automatiquement, y compris par "Patch check global".

    CRITICAL : signalement seul, validation manuelle obligatoire.
    HIGH/MEDIUM/LOW : bascule automatique en `patched` si patch_detected=true
    (cf. apply_patch_result).

    `asset_ids` : restreint le cycle à ces actifs — validation ciblée avant de
    relâcher le cycle complet sur tout le parc (cf. incident mémoire du
    28/07/2026 ; devenu sélectionnable depuis le bouton "Patch check global"
    du Dashboard le 04/08/2026 quand le filtre d'actifs est actif), sans
    impact sur l'appel normal (défaut None = tout le parc).

    CVE publiées il y a plus de PATCH_CHECK_MAX_AGE_YEARS exclues (07/08/2026,
    inconditionnel — pas seulement quand `asset_ids` est absent) : "l'analyse en
    cours" du dashboard doit rester en corrélation avec les listes affichées,
    elles-mêmes bornées à 2 ans par défaut (cf. Dashboard.jsx). N'affecte pas
    `backfill_auto_patch` (pure reconciliation depuis un résultat déjà en base,
    aucun nouveau contrôle SSH/WinRM — pas de charge à réduire là).
    """
    stats = {"checked": 0, "patch_detected": 0, "errors": 0}

    session = SessionLocal()
    try:
        recheck_cutoff = datetime.now(timezone.utc) - RECHECK_INTERVAL
        age_cutoff = datetime.now(timezone.utc) - timedelta(days=365 * PATCH_CHECK_MAX_AGE_YEARS)
        base_filters = [
            # awaiting_fix inclus : une vuln annotée "pas de correctif dispo"
            # doit être revérifiée comme les autres pour basculer en patched
            # dès que le correctif sort, sans action manuelle.
            Vulnerability.status.in_(["open", "in_progress", "awaiting_fix", "awaiting_fix_partial"]),
            or_(
                Vulnerability.last_patch_check.is_(None),
                Vulnerability.last_patch_check < recheck_cutoff,
            ),
            # Cf. PATCH_CHECK_MAX_AGE_YEARS — nécessite le join CVE ci-dessous sur
            # les deux requêtes qui utilisent base_filters.
            CVE.published >= age_cutoff,
        ]
        if asset_ids:
            base_filters.append(Vulnerability.asset_id.in_(asset_ids))

        # Liste des actifs concernés d'abord (petite, une ligne par actif) plutôt
        # que de matérialiser tout le stock de vulnérabilités en mémoire — cf.
        # BATCH_SIZE. Chaque actif est ensuite traité avec sa propre requête
        # bornée, jamais plus de quelques milliers de lignes en mémoire à la fois.
        asset_ids = (await session.execute(
            select(Vulnerability.asset_id)
            .join(CVE, Vulnerability.cve_id == CVE.id)
            .where(*base_filters).distinct()
        )).scalars().all()

        if not asset_ids:
            logger.info("Patch check démarrage : rien à vérifier (tout a déjà été contrôlé récemment)")
            return stats

        logger.info(f"Patch check démarrage : {len(asset_ids)} actif(s) avec au moins une vulnérabilité à (re)vérifier")

        global _current_check, _last_completed, _cycle_started_at, _asset_progress
        _cycle_started_at = datetime.now(timezone.utc)
        # Total par actif en une seule requête groupée plutôt qu'une par actif
        # (asset_ids reste petit — "configurés" uniquement, cf. get_configured_asset_ids —
        # mais autant éviter le pattern N+1 par principe).
        asset_totals = dict((await session.execute(
            select(Vulnerability.asset_id, func.count())
            .join(CVE, Vulnerability.cve_id == CVE.id)
            .where(*base_filters).group_by(Vulnerability.asset_id)
        )).all())
        # Noms/hostnames de TOUS les actifs du cycle dès le départ (pas seulement
        # celui en cours) — sans ça, un actif encore en file affichait son UUID
        # brut côté dashboard jusqu'à ce que le cycle séquentiel l'atteigne enfin
        # (constaté en direct, cf. STATUS.md).
        asset_names = {
            row.id: (row.name, row.hostname)
            for row in (await session.execute(
                select(Asset.id, Asset.name, Asset.hostname).where(Asset.id.in_(asset_ids))
            )).all()
        }
        _asset_progress = [
            {
                "asset_id": str(aid),
                "asset_name": asset_names.get(aid, (None, None))[0],
                "hostname": asset_names.get(aid, (None, None))[1],
                "checked": 0,
                "total": asset_totals.get(aid, 0),
            }
            for aid in asset_ids
        ]
        msrc_cache: dict = {}
        windows_mappings = await _load_windows_mappings(session)

        # Séquentiel (actif par actif, CVE par CVE) : évite de partager une
        # AsyncSession entre coroutines concurrentes (non thread/task-safe) et
        # reste prudent vis-à-vis des 80 serveurs on-premise.
        for asset_id in asset_ids:
            asset = await session.get(Asset, asset_id)
            if not asset:
                continue

            asset_progress_entry = next((e for e in _asset_progress if e["asset_id"] == str(asset_id)), None)
            if asset_progress_entry:
                asset_progress_entry["asset_name"] = asset.name
                asset_progress_entry["hostname"] = asset.hostname

            os_lower = (asset.os or "").lower()
            windows_snapshot = linux_snapshot = None
            if "windows" in os_lower:
                windows_snapshot = await asyncio.get_event_loop().run_in_executor(
                    None, _fetch_windows_patch_snapshot, asset
                )
            else:
                linux_snapshot = await _fetch_linux_package_snapshot(asset)

            # Le relevé WinRM/SSH (KB installés, build, paquets…) ci-dessus est
            # strictement identique d'une CVE à l'autre pour un même actif dans ce
            # cycle — il n'est donc récupéré qu'une fois par actif plutôt que
            # rejoué à chaque CVE (incident lenteur, session 21/07/2026 : ~4600 CVE
            # jamais vérifiées sur un seul actif Windows faute de temps, chaque CVE
            # rouvrant sa propre session WinRM et rescannant tout le journal
            # System). La réponse MSRC par CVE est mise en cache pour tout le
            # cycle, quel que soit l'actif — utile dès qu'une même CVE touche
            # plusieurs serveurs.
            #
            # Les vulns de CET actif sont chargées par lot (BATCH_SIZE) plutôt que
            # d'un bloc : un actif du parc réel peut en porter plusieurs milliers
            # (cf. incident mémoire du 28/07 sur ~265 000 vulns tous actifs
            # confondus, chargées en une seule fois avant ce correctif).
            # Compteurs propres à CET actif — remis à zéro à chaque tour de la boucle
            # `for asset_id`, alimentent `record_asset_completion` une fois la passe finie.
            asset_checked_count = 0
            asset_auto_bascule_count = 0
            last_id = None
            while True:
                batch_filters = list(base_filters) + [Vulnerability.asset_id == asset_id]
                if last_id is not None:
                    batch_filters.append(Vulnerability.id > last_id)
                batch = (await session.execute(
                    select(Vulnerability)
                    .join(CVE, Vulnerability.cve_id == CVE.id)
                    .where(*batch_filters).order_by(Vulnerability.id).limit(BATCH_SIZE)
                )).scalars().all()
                if not batch:
                    break
                last_id = batch[-1].id

                for vuln in batch:
                    cve = await session.get(CVE, vuln.cve_id)
                    if not cve:
                        continue

                    _current_check = {
                        "vuln_id": str(vuln.id),
                        "asset_name": asset.name,
                        "hostname": asset.hostname,
                        "os": asset.os,
                        "cve_id": cve.cve_id,
                        "severity": cve.severity,
                    }

                    try:
                        check_result = await check_patch(
                            asset, cve,
                            windows_snapshot=windows_snapshot,
                            linux_snapshot=linux_snapshot,
                            msrc_cache=msrc_cache,
                            windows_mappings=windows_mappings,
                        )
                    except Exception as e:
                        logger.error(f"Erreur patch check démarrage {cve.cve_id}/{asset.name}: {e}")
                        check_result = {"patch_detected": None, "error": str(e)}

                    auto_patched = apply_patch_result(vuln, cve, check_result, session, agent_reported=asset.collection_method == "agent")
                    stats["checked"] += 1
                    asset_checked_count += 1
                    if asset_progress_entry:
                        asset_progress_entry["checked"] += 1
                    if check_result.get("patch_detected") is True:
                        stats["patch_detected"] += 1
                    if auto_patched:
                        stats["auto_patched"] = stats.get("auto_patched", 0) + 1
                        asset_auto_bascule_count += 1
                    if check_result.get("error"):
                        stats["errors"] += 1

                    _last_completed = {
                        **_current_check,
                        "patch_detected": check_result.get("patch_detected"),
                        "auto_patched": auto_patched,
                        # Distingue les deux issues d'une bascule auto : `patched`
                        # (correctif détecté) ou `false_positive` (produit absent) —
                        # le frontend doit déplacer la ligne dans le bon statut.
                        "not_applicable": check_result.get("not_applicable") is True,
                        # Horodatage pour dédupliquer côté frontend : si la même vuln est
                        # vérifiée deux fois (ex: réouverte puis re-checkée), le vuln_id seul
                        # ne suffit pas à distinguer les deux complétions.
                        "checked_at": datetime.now(timezone.utc).isoformat(),
                    }
                    # Pas de remise à None ici : chaque vérification individuelle est
                    # souvent trop rapide (snapshot déjà en cache, pas d'aller-retour
                    # réseau) pour qu'un polling concurrent (GET /patch-check/status,
                    # toutes les 3s côté dashboard) tombe jamais dans la fenêtre non-null
                    # — en pratique `current` restait vu comme `null` en continu malgré
                    # un cycle actif (constaté en direct, 29/07/2026). `_current_check`
                    # reste donc affiché jusqu'à être écrasé par le prochain élément
                    # (ligne plus haut) ; il n'est remis à None que dans le `finally`,
                    # une fois le cycle entièrement terminé.

                    # Commit au fil de l'eau pour ne rien perdre si le process est interrompu
                    await session.commit()

            # Passe finie pour CET actif (pas encore tout le cycle, cf. la boucle englobante) —
            # journalisée même si aucune bascule n'a eu lieu, pour que "l'actif a été revérifié,
            # rien à signaler" reste distinguable de "jamais revérifié depuis la dernière fois".
            if asset_checked_count > 0:
                await record_asset_completion(session, asset, asset_checked_count, asset_auto_bascule_count)
                await session.commit()

    except Exception:
        await session.rollback()
        logger.exception("Erreur patch check démarrage")
        raise
    finally:
        # Pas de remise à None/[] ici (11/08/2026, bug réel corrigé — cf. STATUS.md) :
        # cette fonction est rejouée à chaque passe d'un cycle avec relance enchaînée
        # (cf. run_full_patch_check_cycle § Auto-relance, son unique appelant). Remettre
        # `_current_check`/`_cycle_started_at`/`_asset_progress` à vide ici les effaçait
        # entre CHAQUE passe, pas seulement à la toute fin du cycle complet — une fenêtre
        # où un poll GET /api/patch-check/status voyait `running: true` (au niveau
        # `_cycle_running`) mais `assets: []`/`started_at: None`, un flicker incohérent
        # côté dashboard. La remise à zéro se fait désormais une seule fois, dans le
        # `finally` de run_full_patch_check_cycle — après la toute dernière passe.
        await session.close()

    logger.info(f"Patch check démarrage terminé : {stats}")
    return stats


# ─── Cycle complet réutilisable (démarrage + déclenchement manuel) ────────────

_cycle_running = False


def is_patch_check_cycle_running() -> bool:
    return _cycle_running


# Cf. run_full_patch_check_cycle § Auto-relance. Mémorise la demande la plus
# permissive reçue pendant un cycle déjà en cours (dict {"asset_ids", "refresh_configured"}
# ou None) — PAS un simple booléen (bug réel corrigé, 11/08/2026, cf. STATUS.md) : un
# booléen ne porte aucune information sur CE QUI a été redemandé, la relance rejouait
# toujours le périmètre du tout premier appelant (celui qui a démarré le cycle), jamais
# celui de l'appelant qui a effectivement demandé la relance. Scénario réel possible :
# un scan déclenche un cycle scopé à un seul actif (routers/assets.py) pile au moment où
# le cycle périodique Celery (tasks/scheduled_tasks.py, refresh_configured=True, tout le
# parc) tombe dans la même fenêtre — la relance ne rejouait que l'actif unique, le
# balayage complet attendu par le déclenchement Celery était silencieusement absorbé,
# `_set_cycle_state("completed")` écrit quand même à la fin (le dashboard affichait un
# cycle "terminé avec succès" sans avoir couvert le périmètre réellement demandé).
_rerun_requested: Optional[dict] = None


async def run_full_patch_check_cycle(asset_ids: Optional[list] = None, refresh_configured: bool = False) -> dict:
    """
    Exécute exactement le même cycle qu'au démarrage de l'application :
    rattrapage des résultats déjà collectés, puis contrôle des vulns jamais
    vérifiées. Réutilisable depuis un bouton manuel du dashboard.

    `asset_ids` : restreint le cycle (rattrapage compris) à ces actifs plutôt
    qu'à tout le parc — reflète le filtre d'actifs actif sur le Dashboard au
    moment du clic sur "Patch check global" (cf. routers/patch_check.py). Une
    sélection explicite comme celle-ci n'est jamais élargie automatiquement,
    quoi qu'il arrive pendant le cycle.

    `refresh_configured` (07/08/2026, demande explicite) : au lieu d'un
    `asset_ids` figé, recalcule le périmètre "actifs configurés" (cf.
    `services/stats.py::get_configured_asset_ids`) à **chaque passage** de la
    boucle ci-dessous — utilisé par les déclenchements automatiques
    (`main.py::_startup_patch_check`, cycle périodique Celery, et désormais
    juste après un scan réussi qui vient de configurer un actif, cf.
    `routers/assets.py`). Sans ça, un actif tout juste configuré pendant qu'un
    cycle tourne déjà n'était couvert qu'au **prochain déclenchement manuel ou
    planifié** (jusqu'à 6h plus tard) — le cycle se terminait et restait
    inactif entre-temps, constaté en conditions réelles (ARMADASENONCHES
    configuré en cours de cycle, resté hors périmètre jusqu'à relance
    manuelle, 07/08/2026).

    **Auto-relance** : si `run_full_patch_check_cycle` est appelée pendant
    qu'un cycle tourne déjà, la demande n'est pas perdue (`already_running`
    ignoré comme avant) — `_rerun_requested` la mémorise, et une passe
    supplémentaire s'enchaîne dès la fin de la passe en cours, tant qu'une
    nouvelle demande est arrivée entre-temps. Combiné à `refresh_configured`,
    ça couvre le vrai scénario voulu : scanner un nouvel actif pendant qu'un
    cycle tourne le fait automatiquement rejoindre la passe suivante, sans
    action manuelle ni cycle qui "tourne mais ne fait plus rien" une fois son
    périmètre initial épuisé. Le périmètre effectivement rejoué à la passe
    suivante est désormais celui de la demande de relance (fusionné si
    plusieurs sont arrivées pendant la passe en cours — `refresh_configured`
    l'emporte dès qu'une seule des demandes en attente le veut, sinon les
    `asset_ids` explicites sont réunis), jamais figé sur le tout premier appel.
    """
    global _cycle_running, _rerun_requested
    if _cycle_running:
        if _rerun_requested is None:
            _rerun_requested = {"asset_ids": asset_ids, "refresh_configured": refresh_configured}
        elif refresh_configured:
            _rerun_requested["refresh_configured"] = True
        elif not _rerun_requested["refresh_configured"]:
            existing = set(_rerun_requested["asset_ids"] or [])
            _rerun_requested["asset_ids"] = list(existing | set(asset_ids or []))
        return {"status": "already_running", "rerun_queued": True}

    _cycle_running = True
    await _set_cycle_state("running")
    try:
        backfill_stats = check_stats = {}
        passes = 0
        while True:
            passes += 1
            scope = asset_ids
            if refresh_configured:
                from services.stats import get_configured_asset_ids
                session = SessionLocal()
                try:
                    scope = await get_configured_asset_ids(session)
                finally:
                    await session.close()
                if not scope:
                    logger.info("Patch check : aucun actif configuré, cycle non lancé")
                    break

            backfill_stats = await backfill_auto_patch(asset_ids=scope)
            check_stats = await run_startup_patch_checks(asset_ids=scope)

            if not _rerun_requested:
                break
            # Rejoue le périmètre de la demande de relance (pas celui du tout premier
            # appel, cf. docstring § Auto-relance) — `asset_ids`/`refresh_configured`
            # locaux réassignés pour que le prochain tour de `while True` les reprenne.
            pending, _rerun_requested = _rerun_requested, None
            asset_ids = pending["asset_ids"]
            refresh_configured = pending["refresh_configured"]
            logger.info(
                "Patch check : relance enchaînée (passe %d) — nouvelle demande reçue pendant le cycle "
                "(refresh_configured=%s, %d actif(s) explicite(s))",
                passes + 1, refresh_configured, len(asset_ids or []),
            )

        await _set_cycle_state("completed")
        return {"status": "done", "passes": passes, "backfill": backfill_stats, "check": check_stats}
    except Exception:
        # Distinct de l'interruption par redémarrage (cf. main.py::
        # _check_interrupted_patch_cycle, qui ne constate que "running" jamais
        # refermé) : ici le process est resté vivant, l'exception est connue
        # tout de suite — pas besoin d'attendre un prochain démarrage pour la
        # signaler côté dashboard (GET /patch-check/status::last_cycle_status).
        await _set_cycle_state("failed")
        raise
    finally:
        _cycle_running = False
        # Remise à zéro déplacée depuis le `finally` de run_startup_patch_checks
        # (11/08/2026, cf. son commentaire) : une seule fois ici, à la toute fin du
        # cycle complet (dernière passe incluse), jamais entre deux passes enchaînées.
        global _current_check, _cycle_started_at, _asset_progress
        _current_check = None
        _cycle_started_at = None
        _asset_progress = []
