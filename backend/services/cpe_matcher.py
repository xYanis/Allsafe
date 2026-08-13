"""
CPE Matcher — croiser asset.cpe_list avec cve.cpe
Matching par préfixe (jamais de regex, gestion wildcards *)
Déclenché après sync NVD, import actifs, ou manuellement via POST /api/sync/match
"""

import re
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, and_
from sqlalchemy.orm import load_only
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from database import SessionLocal
from models import Asset, CVE, Vulnerability, SyncState, WindowsAppMapping
from services.scoring import calculate_risk_score

logger = logging.getLogger(__name__)

# Cf. commentaire sur son usage dans run_cpe_matching ci-dessous — même principe
# que CANDIDATE_YIELD_EVERY (routers/vulnerabilities.py), coût par itération plus
# faible ici (un seul test CPE/mots-clés) donc intervalle plus large.
MATCHING_YIELD_EVERY = 200


def _keywords_from_asset(asset) -> list[str]:
    """
    Dérive des mots-clés de recherche depuis le CPE et l'OS de l'actif.
    Utilisé pour matcher les CVEs qui n'ont pas de CPE renseigné dans NVD.
    Ex: windows_server_2019 + "2019" → ["windows server 2019", "windows server"]

    Le nom d'OS seul ("debian", "windows"...) n'est jamais ajouté comme mot-clé :
    trop générique, il matche des phrases qui ne parlent pas du produit lui-même
    (ex: CVE-2026-11852/11853 "Debusine... a Debian-based distribution" — outil
    sans rapport avec le paquet Debian). Seule la combinaison avec la version
    (assez spécifique) ou un couple vendor+produit dérivé du CPE est gardé.
    """
    keywords = set()

    os_name = (asset.os or "").lower().strip()
    os_ver  = (asset.os_version or "").lower().strip()
    if os_name and os_ver:
        keywords.add(f"{os_name} {os_ver}")

    # Depuis les CPE de l'actif
    for cpe in (asset.cpe_list or []):
        parts = cpe.split(":")
        if len(parts) >= 5:
            product = parts[4].replace("_", " ").lower()
            vendor  = parts[3].replace("_", " ").lower()
            if product not in ("*", "-", ""):
                keywords.add(product)
                keywords.add(f"{vendor} {product}")
                # Ajouter aussi la famille sans version (ex: "windows server")
                base = " ".join(w for w in product.split() if not w.isdigit())
                if base and base != product:
                    keywords.add(base)

    # Filtrer les keywords trop courts ou trop génériques
    return [k for k in keywords if len(k) >= 5 and k not in ("windows", "linux", "server")]


def _keyword_matches(description: str | None, keywords: list[str]) -> bool:
    """
    Retourne True si la description mentionne un keyword — en mot entier (\\b),
    pas en sous-chaîne — dans les 150 premiers caractères, là où NVD décrit
    toujours le produit affecté. Le mot entier évite les faux positifs où le
    mot-clé apparaît accolé à un autre mot sans rapport.
    """
    if not description or not keywords:
        return False
    d = description[:150].lower()
    return any(re.search(rf"\b{re.escape(k)}\b", d) for k in keywords)


# Index du composant "version" dans un CPE 2.3 URI splitté sur ":"
# (cpe : 2.3 : part : vendor : product : version : update : ...)
#   0     1     2       3        4         5
_CPE_VERSION_INDEX = 5


def _version_component_equal(a: str, b: str) -> bool:
    """
    Compare deux segments de version CPE en tolérant le padding zéro implicite
    ("12" == "12.0") plutôt qu'une égalité de chaîne stricte — sans quoi un actif
    "Debian 12" ne matcherait jamais un CVE listé contre "Debian 12.0" (format
    NVD), alors que c'est la même version.
    """
    if a == b:
        return True
    na = tuple(int(n) for n in re.findall(r"\d+", a))
    nb = tuple(int(n) for n in re.findall(r"\d+", b))
    if not na or not nb:
        return False
    length = max(len(na), len(nb))
    na += (0,) * (length - len(na))
    nb += (0,) * (length - len(nb))
    return na == nb


def _cpe_matches(asset_cpe: str, cve_cpe_list: list[str]) -> bool:
    """
    Retourne True si asset_cpe matche au moins un CPE de la CVE — comparaison
    composant par composant (part/vendor/product/version/...), pas en préfixe de
    la chaîne CPE entière. L'ancienne comparaison par préfixe de chaîne globale
    traitait par erreur "...debian_linux:12" comme préfixe de
    "...debian_linux:12.0" uniquement parce que "12.0" commence littéralement par
    les caractères "12" — un actif "Debian 1" aurait matché tout aussi bien
    "Debian 12", "Debian 120", etc. Un composant "*"/"-"/absent (CPE tronqué)
    matche n'importe quoi ; le composant version tolère le padding zéro implicite.

    **Exception : les CPE sans vendeur NI produit sont ignorés** (session
    21/07/2026). NVD publie pour certaines CVE un CPE dégénéré du type
    `cpe:2.3:o:-:-:-:*:*:*:*:*:*:*` (ex: CVE-2017-13091 à 13095, la faille du
    standard IEEE P1735 sur le chiffrement d'IP de circuits électroniques). En
    sémantique CPE, `-` signifie "non applicable / non renseigné", pas "tous" —
    mais la règle joker ci-dessus le traitait comme un caractère générique, si
    bien que ce CPE matchait **tous les actifs du parc**, quel que soit leur OS.
    Un CPE dépourvu à la fois de vendeur et de produit ne porte aucune
    information d'identification : il ne peut légitimement désigner aucun actif,
    donc l'ignorer ne fait perdre aucun vrai positif (vérifié sur le parc :
    14 vulns concernées, toutes issues de CVE n'ayant *que* ce type de CPE —
    aucun cas mixte où un vrai CPE cohabiterait avec un dégénéré).
    """
    def _is_degenerate(parts: list[str]) -> bool:
        """CPE sans vendeur ni produit exploitable — n'identifie rien."""
        if len(parts) < 5:
            return True
        return parts[3] in ("-", "*", "") and parts[4] in ("-", "*", "")

    asset_parts = asset_cpe.split(":")
    if _is_degenerate(asset_parts):
        return False
    for cve_cpe in cve_cpe_list:
        cve_parts = cve_cpe.split(":")
        if _is_degenerate(cve_parts):
            continue
        length = min(len(asset_parts), len(cve_parts))
        if length < 5:
            continue

        matched = True
        for i in range(2, length):
            a, b = asset_parts[i], cve_parts[i]
            if a in ("*", "-", "") or b in ("*", "-", ""):
                continue
            if i == _CPE_VERSION_INDEX:
                if not _version_component_equal(a, b):
                    matched = False
                    break
            elif a != b:
                matched = False
                break

        if matched:
            return True
    return False


# ─── CPE : environnement d'exécution (`target_sw`) ────────────────────────────

# `target_sw` (composant 10 d'un CPE 2.3) désigne l'environnement logiciel dans
# lequel le produit s'exécute. Quand il nomme une **plateforme applicative**, le
# produit est un module/plugin de cette plateforme, pas un paquet système :
# `cpe:2.3:a:jenkins:git:*:*:*:*:*:jenkins:*:*` est le plugin Git *de Jenkins*,
# pas le binaire `git` de la distribution (faux positif réel : 3 CVE Jenkins
# rattachées au paquet `git` de gitlab.aer.loc, session 21/07/2026).
#
# Quand `target_sw` nomme un **OS**, en revanche, le produit est bien un logiciel
# installable sur la machine (ex: openssl target_sw=linux) — d'où cette liste,
# qui neutralise la règle dans ce cas plutôt que de rejeter aveuglément tout CPE
# ayant un `target_sw`.
_TARGET_SW_OS = {
    "linux", "linux_kernel", "windows", "unix", "macos", "mac_os", "mac_os_x",
    "android", "ios", "ipados", "freebsd", "openbsd", "netbsd", "solaris",
    "debian", "ubuntu", "redhat", "fedora", "suse", "centos", "*", "-", "",
}


def cpe_target_sw(cpe: str) -> str:
    """`target_sw` d'un CPE 2.3, ou "" si absent/tronqué."""
    parts = cpe.split(":")
    return parts[10].lower() if len(parts) > 10 else ""


def cpe_is_platform_component(cpe: str) -> bool:
    """
    Ce CPE désigne-t-il un composant d'une plateforme applicative (plugin,
    module) plutôt qu'un logiciel installable sur l'OS ?
    """
    return cpe_target_sw(cpe) not in _TARGET_SW_OS


# ─── Matching par paquets installés ────────────────────────────────────────────
# asset.cpe_list ne contient que l'OS (cf. _build_cpe) — une CVE qui ne porte
# qu'un CPE applicatif ("a:libssh2:libssh2") sans CPE OS associé ne matchait
# donc jamais aucun actif, même si le paquet vulnérable est réellement installé
# (cf. CVE-2026-55200, libssh2-1 installé sur "hortholary", jamais détectée
# avant ce fix). Comparé ici à asset.installed_packages (collecté par le scan
# read-only, cf. asset_scanner.py) plutôt qu'à asset.cpe_list.

def _package_candidates(pkg_name: str) -> set[str]:
    """
    Dérive les noms de produit CPE plausibles depuis un nom de paquet Debian/RPM
    installé. Best-effort et volontairement conservateur — les noms de paquets
    distro divergent souvent du nom de produit amont d'une façon impossible à
    deviner sans table de correspondance (ex: libssl3 → openssl) : on préfère
    rater ces cas plutôt qu'ajouter du bruit (cf. principe "pas de CVE sans
    rapport" en tête de ce document).
      libssh2-1        → {libssh2-1, libssh2}
      libcurl4         → {libcurl4, libcurl, curl}
      python3-flask    → {python3-flask, flask}
      openssl          → {openssl}
    """
    name = (pkg_name or "").strip().lower()
    if not name:
        return set()
    # Suffixe multi-arch Debian (libssh2-1:amd64, libc6:i386...)
    name = name.split(":")[0]
    candidates = {name}

    # Suffixe de version/soname Debian (libfoo2, libfoo-1, libfoo1.1...)
    stripped = re.sub(r"[-.]?\d+(\.\d+)*$", "", name)
    if stripped and stripped != name:
        candidates.add(stripped)

    # Préfixe "lib" (après le strip ci-dessus : libcurl4 → libcurl → curl)
    for c in list(candidates):
        if c.startswith("lib") and len(c) > 3:
            candidates.add(c[3:])

    # Bindings Python (python3-flask, python3.11-flask → flask)
    m = re.match(r"^python3(?:\.\d+)?-(.+)$", name)
    if m:
        candidates.add(m.group(1))

    return {c for c in candidates if len(c) >= 3}


def _windows_app_candidates(display_name: str, windows_mappings: list[tuple[str, str]]) -> set[str]:
    """
    Équivalent de `_package_candidates` pour Windows : un nom d'application Windows
    (texte libre de registre, ex: "PuTTY release 0.81 (64-bit)") ne suit aucune
    convention exploitable par regex — contrairement aux paquets Debian/RPM. Résolu
    via `WindowsAppMapping` (réglable en base, cf. models.py), jamais par heuristique
    devinée. `pattern` est cherché comme sous-chaîne, insensible à la casse : survit
    aux changements de version/architecture dans le nom affiché.
    """
    name = (display_name or "").strip().lower()
    if not name:
        return set()
    return {product for pattern, product in windows_mappings if pattern in name}


async def _load_windows_mappings(db: AsyncSession) -> list[tuple[str, str]]:
    """Charge `WindowsAppMapping` une seule fois par cycle de matching (mêmes raisons
    de performance que `_cve_product_index` : évite une requête par actif/par ligne)."""
    rows = (await db.execute(select(WindowsAppMapping))).scalars().all()
    return [(m.pattern, m.cpe_product) for m in rows]


def _installed_package_products(asset, windows_mappings: list[tuple[str, str]] | None = None) -> set[str]:
    """
    Union des candidats produit dérivés de tous les paquets/applications installés de
    l'actif. Windows (texte libre, résolu via `windows_mappings` seulement — les
    conventions Debian/RPM de `_package_candidates` n'ont aucun sens sur ces noms) vs.
    Linux (conventions de nommage, `_package_candidates`), distingués par `asset.os`.
    """
    products = set()
    is_windows = "windows" in (asset.os or "").lower()
    for pkg in (asset.installed_packages or []):
        pkg_name = pkg.get("name") if isinstance(pkg, dict) else None
        if not pkg_name:
            continue
        if is_windows:
            if windows_mappings:
                products |= _windows_app_candidates(pkg_name, windows_mappings)
        else:
            products |= _package_candidates(pkg_name)
    return products


def _cve_products(cve: CVE) -> set[str]:
    """
    Noms de produit des CPE applicatifs ("a:") d'une CVE, en excluant les
    composants de plateforme (`target_sw` applicatif — cf. `cpe_is_platform_component`) :
    un plugin Jenkins n'est pas un paquet installable sur la machine.
    """
    products = set()
    for cpe in (cve.cpe or []):
        if cpe_is_platform_component(cpe):
            continue
        parts = cpe.split(":")
        if len(parts) >= 5 and parts[2] == "a":
            p = parts[4].replace("_", "-").lower()
            if p not in ("*", "-", ""):
                products.add(p)
    return products


def _cve_product_index(cves: list[CVE]) -> dict[str, list[CVE]]:
    """
    Index produit → CVE, construit une fois par cycle de matching pour comparer
    efficacement des centaines de paquets installés par actif sans boucle
    imbriquée paquets × CVE.
    """
    index: dict[str, list[CVE]] = {}
    for cve in cves:
        for product in _cve_products(cve):
            index.setdefault(product, []).append(cve)
    return index


def _package_matched_cve_ids(product_index: dict[str, list[CVE]], asset_products: set[str]) -> set:
    ids = set()
    for product in asset_products:
        for cve in product_index.get(product, []):
            ids.add(cve.id)
    return ids


_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


async def get_installed_package_vulnerabilities(asset: Asset, db: AsyncSession) -> dict[str, dict]:
    """
    Pour chaque paquet installé (module Inventaire/Actifs, `asset.installed_packages`),
    les CVE **déjà matchées** à cet actif et encore non résolues (session 27/07/2026 —
    "est-ce que ces applications sont à jour ?"). Ne relance PAS un matching contre
    tout le référentiel CVE (coûteux, cf. `run_cpe_matching_for_asset` déporté sur
    Celery) : croise seulement les vulnérabilités déjà en base pour cet actif avec
    les noms de paquets, borné et rapide.

    `patched`/`false_positive` exclus (résolus) ; `accepted_risk` inclus (toujours
    vulnérable, risque juste assumé plutôt que corrigé).

    Windows : la dérivation des candidats produit passe par `WindowsAppMapping`
    (réglable en base), pas par `_package_candidates` (conventions Debian/RPM, sans
    rapport avec le texte libre des noms d'applications Windows) — cf.
    `_installed_package_products`.
    """
    cves = (
        await db.execute(
            select(CVE)
            .join(Vulnerability, Vulnerability.cve_id == CVE.id)
            .where(Vulnerability.asset_id == asset.id)
            .where(Vulnerability.status.in_(["open", "in_progress", "awaiting_fix", "accepted_risk"]))
        )
    ).scalars().all()
    product_index = _cve_product_index(cves)
    is_windows = "windows" in (asset.os or "").lower()
    windows_mappings = await _load_windows_mappings(db) if is_windows else []

    result: dict[str, dict] = {}
    for pkg in (asset.installed_packages or []):
        name = pkg.get("name") if isinstance(pkg, dict) else None
        if not name:
            continue
        candidates = _windows_app_candidates(name, windows_mappings) if is_windows else _package_candidates(name)
        matched: dict = {}
        for candidate in candidates:
            for cve in product_index.get(candidate, []):
                matched[cve.id] = cve
        if matched:
            worst = max((c.severity for c in matched.values()), key=lambda s: _SEVERITY_ORDER.get(s, 0))
            result[name] = {
                "count": len(matched),
                "severity": worst,
                "cve_ids": sorted(c.cve_id for c in matched.values()),
            }
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Insertion protégée contre les courses entre passes de matching concurrentes
# ─────────────────────────────────────────────────────────────────────────────

async def _insert_vulnerability_if_new(
    db: AsyncSession, asset_id: UUID, cve_id: UUID, risk_score: float, component_type: str,
) -> bool:
    """Insère la Vulnerability (asset_id, cve_id) si elle n'existe pas déjà, retourne
    False sinon. Utilisée par les 3 variantes de matching ci-dessous (global/par
    actif/par CVE), qui peuvent tourner en même temps (démarrage backend + scan
    d'actif en cours, ou clic manuel pendant un cycle automatique) — sans garde,
    deux passes constatant chacune "pas encore là" insèrent chacune leur ligne
    (incident réel, 11/08/2026 : 6 doublons trouvés en base, cf. STATUS.md).

    Le check préalable évite l'aller-retour DB dans le cas courant (déjà là) ;
    la SAVEPOINT (`begin_nested`) ne couvre que la fenêtre de course entre ce
    check et l'insert, protégée en dernier ressort par la contrainte unique
    `uq_vulnerabilities_asset_cve` (cf. schema_patches.sql) — sans elle,
    l'IntegrityError attrapée ici ne se déclencherait jamais."""
    exists = (await db.execute(
        select(Vulnerability.id).where(
            and_(Vulnerability.asset_id == asset_id, Vulnerability.cve_id == cve_id)
        )
    )).scalar_one_or_none()
    if exists is not None:
        return False

    try:
        async with db.begin_nested():
            db.add(Vulnerability(
                asset_id=asset_id,
                cve_id=cve_id,
                status="open",
                risk_score=risk_score,
                detected_at=datetime.now(timezone.utc),
                component_type=component_type,
            ))
            await db.flush()
    except IntegrityError:
        return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Matching global (tous actifs × toutes CVE)
# ─────────────────────────────────────────────────────────────────────────────

async def run_cpe_matching(db: AsyncSession | None = None) -> dict:
    """
    Matching CPE complet : tous les actifs actifs contre toutes les CVE.
    Crée les Vulnerability manquantes, ignore les doublons.
    Peut être appelé sans session (crée la sienne).
    """
    own_session = db is None
    if own_session:
        db = SessionLocal()

    matched = created = skipped = 0
    # Détail par actif (demande explicite, 11/08/2026) : le bouton "Matching CVE"
    # du Dashboard confirme désormais combien de CVE ont été rajoutées et sur quel
    # actif — un compteur global ne suffisait pas. Clé = asset.id, valeur = compteur
    # de Vulnerability créées pour cet actif (les actifs sans nouvelle CVE n'y
    # apparaissent pas, cf. construction de `created_by_asset` en sortie).
    created_by_asset: dict = {}

    try:
        assets = (
            await db.execute(select(Asset).where(Asset.status == "active"))
        ).scalars().all()

        # `load_only(..., raiseload=True)` (08/08/2026, même correctif que les
        # endpoints "candidats" de routers/vulnerabilities.py le 28/07/2026) :
        # `select(CVE)` chargeait `raw_data`, le JSON NVD brut (377 Mo en base,
        # jusqu'à 268 Ko/CVE) pour ~187 000 lignes à chaque clic sur "Matching
        # CVE", alors qu'aucune colonne hors de celles listées ici n'est lue par
        # cette fonction. `raiseload=True` fait qu'une colonne oubliée lève une
        # exception explicite plutôt que de dégénérer en requête N+1 silencieuse.
        cves = (await db.execute(
            select(CVE).options(load_only(
                CVE.id, CVE.cpe, CVE.description, CVE.cvss_score, CVE.epss_score,
                raiseload=True,
            ))
        )).scalars().all()
        product_index = _cve_product_index(cves)
        windows_mappings = await _load_windows_mappings(db)

        logger.info("CPE matching démarré : %d actifs × %d CVE", len(assets), len(cves))

        # `MATCHING_YIELD_EVERY` : jusqu'à 72 actifs × 187 000 CVE ≈ 13,4 millions
        # d'itérations Python pur (regex CPE/mots-clés), sans le moindre point de
        # cession avant ce correctif — l'event loop asyncio, mono-thread, restait
        # gelé pour toute autre requête (même symptôme déjà rencontré et corrigé
        # sur les endpoints "candidats", cf. STATUS.md § Lenteurs généralisées).
        # Compteur global (pas remis à zéro par actif) pour céder la main à
        # intervalle régulier sur l'ensemble du calcul, pas seulement en tout début
        # de boucle externe.
        i = 0
        for asset in assets:
            asset_cpe_list: list = asset.cpe_list or []
            asset_products = _installed_package_products(asset, windows_mappings)
            if not asset_cpe_list and not asset_products:
                continue
            criticite = (asset.tags or {}).get("criticite", "moyenne")
            keywords   = _keywords_from_asset(asset)
            package_matched_ids = _package_matched_cve_ids(product_index, asset_products)

            for cve in cves:
                i += 1
                if i % MATCHING_YIELD_EVERY == 0:
                    await asyncio.sleep(0)

                cve_cpe_list: list = cve.cpe or []

                if cve_cpe_list:
                    # Matching CPE exact (composant par composant) ou paquet installé.
                    # `component_type` (07/08/2026) : priorité "application" quand un
                    # paquet installé matche — plus actionnable pour l'analyste qu'un
                    # simple CPE OS, cf. models.py::Vulnerability.
                    cpe_hit = any(_cpe_matches(ac, cve_cpe_list) for ac in asset_cpe_list)
                    pkg_hit = cve.id in package_matched_ids
                    if not (cpe_hit or pkg_hit):
                        continue
                    component_type = "application" if pkg_hit else "system"
                else:
                    # Fallback : matching par mots-clés OS dans la description
                    if not _keyword_matches(cve.description, keywords):
                        continue
                    component_type = "system"

                matched += 1

                created_now = await _insert_vulnerability_if_new(
                    db, asset.id, cve.id,
                    calculate_risk_score(cve.cvss_score, cve.epss_score, criticite),
                    component_type,
                )
                if not created_now:
                    skipped += 1
                    continue
                created += 1
                created_by_asset[asset.id] = created_by_asset.get(asset.id, 0) + 1

        now = datetime.now(timezone.utc)
        state = await db.get(SyncState, "cpe_match")
        if state is None:
            state = SyncState(key="cpe_match")
            db.add(state)
        state.last_synced_at = now

        await db.commit()
        logger.info("CPE matching terminé : %d créées, %d doublons ignorés", created, skipped)

    except Exception:
        await db.rollback()
        raise
    finally:
        if own_session:
            await db.close()

    asset_by_id = {a.id: a for a in assets}
    created_by_asset_list = sorted(
        (
            {
                "asset_id": str(asset_id),
                "name": asset_by_id[asset_id].name,
                "hostname": asset_by_id[asset_id].hostname,
                "count": count,
            }
            for asset_id, count in created_by_asset.items()
        ),
        key=lambda a: a["count"],
        reverse=True,
    )

    return {
        "matched": matched,
        "created": created,
        "skipped": skipped,
        "synced_at": now.isoformat(),
        "created_by_asset": created_by_asset_list,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Matching ciblé — appelé après import d'un actif
# ─────────────────────────────────────────────────────────────────────────────

async def run_cpe_matching_for_asset(asset_id: UUID, db: AsyncSession) -> dict:
    """Matching CPE pour un seul actif (après import ou mise à jour de ses CPE)."""
    asset = (
        await db.execute(select(Asset).where(Asset.id == asset_id))
    ).scalar_one_or_none()

    if asset is None:
        return {"error": "asset_not_found", "matched": 0, "created": 0, "skipped": 0}

    windows_mappings = await _load_windows_mappings(db)
    asset_cpe_list: list = asset.cpe_list or []
    asset_products = _installed_package_products(asset, windows_mappings)
    if not asset_cpe_list and not asset_products:
        return {"matched": 0, "created": 0, "skipped": 0}

    criticite = (asset.tags or {}).get("criticite", "moyenne")
    keywords  = _keywords_from_asset(asset)
    # Même correctif que run_cpe_matching ci-dessus (raw_data inutile ici aussi) —
    # cette fonction tourne côté Celery worker après chaque scan d'actif, pas dans
    # le process backend, donc pas de risque de geler l'API web, mais le coût
    # mémoire/réseau du blob de 377 Mo reste payé à chaque scan sans raison.
    cves = (await db.execute(
        select(CVE).options(load_only(
            CVE.id, CVE.cpe, CVE.description, CVE.cvss_score, CVE.epss_score,
            raiseload=True,
        ))
    )).scalars().all()
    product_index = _cve_product_index(cves)
    package_matched_ids = _package_matched_cve_ids(product_index, asset_products)

    matched = created = skipped = 0

    for cve in cves:
        cve_cpe_list: list = cve.cpe or []

        if cve_cpe_list:
            cpe_hit = any(_cpe_matches(ac, cve_cpe_list) for ac in asset_cpe_list)
            pkg_hit = cve.id in package_matched_ids
            if not (cpe_hit or pkg_hit):
                continue
            component_type = "application" if pkg_hit else "system"
        else:
            if not _keyword_matches(cve.description, keywords):
                continue
            component_type = "system"

        matched += 1

        created_now = await _insert_vulnerability_if_new(
            db, asset.id, cve.id,
            calculate_risk_score(cve.cvss_score, cve.epss_score, criticite),
            component_type,
        )
        if not created_now:
            skipped += 1
            continue
        created += 1

    await db.commit()
    return {"matched": matched, "created": created, "skipped": skipped}


# ─────────────────────────────────────────────────────────────────────────────
# Matching ciblé — appelé après ingestion d'une nouvelle CVE
# ─────────────────────────────────────────────────────────────────────────────

async def run_cpe_matching_for_cve(cve_id: UUID, db: AsyncSession) -> dict:
    """Matching CPE pour une seule CVE (après une nouvelle sync NVD)."""
    cve = (
        await db.execute(select(CVE).where(CVE.id == cve_id))
    ).scalar_one_or_none()

    if cve is None:
        return {"error": "cve_not_found", "matched": 0, "created": 0, "skipped": 0}

    cve_cpe_list: list = cve.cpe or []
    if not cve_cpe_list:
        return {"matched": 0, "created": 0, "skipped": 0}

    cve_products = _cve_products(cve)

    assets = (
        await db.execute(select(Asset).where(Asset.status == "active"))
    ).scalars().all()
    windows_mappings = await _load_windows_mappings(db) if cve_products else []

    matched = created = skipped = 0

    for asset in assets:
        asset_cpe_list: list = asset.cpe_list or []
        asset_products = _installed_package_products(asset, windows_mappings) if cve_products else set()
        if not asset_cpe_list and not asset_products:
            continue
        cpe_hit = any(_cpe_matches(ac, cve_cpe_list) for ac in asset_cpe_list)
        pkg_hit = bool(asset_products & cve_products)
        if not (cpe_hit or pkg_hit):
            continue
        component_type = "application" if pkg_hit else "system"

        matched += 1
        criticite = (asset.tags or {}).get("criticite", "moyenne")

        created_now = await _insert_vulnerability_if_new(
            db, asset.id, cve.id,
            calculate_risk_score(cve.cvss_score, cve.epss_score, criticite),
            component_type,
        )
        if not created_now:
            skipped += 1
            continue
        created += 1

    await db.commit()
    return {"matched": matched, "created": created, "skipped": skipped}


# ─────────────────────────────────────────────────────────────────────────────
# Revérification d'un rattachement existant
# ─────────────────────────────────────────────────────────────────────────────

def still_matches(asset: Asset, cve: CVE, windows_mappings: list[tuple[str, str]] | None = None) -> bool:
    """
    Ce rattachement actif × CVE serait-il encore créé par les règles de matching
    **actuelles** ?

    `run_cpe_matching` ne fait que créer, jamais supprimer : quand une règle est
    corrigée (ex: CPE dégénéré `-:-:-` ignoré depuis le 21/07/2026, cf. § Bugs de
    matching corrigés dans docs/MATCHING.md), les rattachements erronés déjà en
    base subsistent. Cette fonction les identifie pour les proposer à l'analyste
    en faux positif — elle ne modifie **rien** elle-même : la qualification reste
    un geste humain, avec annotation et nom d'analyste
    (cf. /api/vulnerabilities/false-positive-candidates).

    Volontairement construite sur les mêmes primitives que le matching lui-même,
    pour qu'une future correction de règle bénéficie automatiquement à cette
    revérification sans code en double.

    Pour vérifier **beaucoup** de CVE contre le même actif (cas des endpoints
    "candidats", cf. routers/vulnerabilities.py), passer par
    `asset_match_context()` + `still_matches_ctx()` : cette signature-ci
    recalcule les données dérivées de l'actif à chaque appel.

    `windows_mappings` (optionnel) : à charger une fois par l'appelant via
    `_load_windows_mappings(db)` s'il a une session sous la main (cf.
    `bulk_false_positive` dans routers/vulnerabilities.py) — sans ça, un actif Windows
    n'obtient aucun candidat produit issu de ses applications installées, comme avant
    l'introduction de `WindowsAppMapping`.
    """
    return still_matches_ctx(asset_match_context(asset, windows_mappings), cve)


def asset_match_context(asset: Asset, windows_mappings: list[tuple[str, str]] | None = None) -> dict:
    """
    Pré-calcule tout ce que `still_matches` dérive de l'**actif seul** (paquets
    installés → candidats produit, mots-clés). Ces deux calculs ne dépendent
    jamais de la CVE, mais étaient refaits à chaque appel — soit, sur les
    endpoints "candidats", une fois par **ligne** au lieu d'une fois par actif :
    ~86 000 recalculs pour 72 actifs, dont `gitlab.aer.loc` et ses 300 paquets
    passés à `_package_candidates` (regex par paquet) à chaque ligne. C'était le
    poste de coût dominant des lenteurs constatées le 28/07/2026 — le backend
    saturait un cœur pendant que PostgreSQL restait à 3% de CPU.

    À construire une fois par actif, puis à réutiliser via `still_matches_ctx`.
    `windows_mappings` : à charger une fois pour tout le lot via
    `_load_windows_mappings(db)`, pas par actif (même échelle que `product_index`).

    `key` identifie le **profil de matching** de l'actif, pas l'actif lui-même :
    deux serveurs distincts avec le même CPE d'OS et aucun paquet relevé donnent
    le même verdict pour toute CVE. Le parc réel est très homogène de ce point de
    vue (72 actifs pour une poignée de profils : Windows Server 2019/2022, Debian
    12), ce qui permet à l'appelant de mémoïser le résultat par (profil, CVE) —
    cf. `routers/vulnerabilities.py`.
    """
    cpe_list = asset.cpe_list or []
    package_products = _installed_package_products(asset, windows_mappings)
    keywords = _keywords_from_asset(asset)
    return {
        "cpe_list": cpe_list,
        "package_products": package_products,
        "keywords": keywords,
        "key": (tuple(sorted(cpe_list)), frozenset(package_products), frozenset(keywords)),
    }


def still_matches_ctx(ctx: dict, cve: CVE) -> bool:
    """`still_matches` avec les données de l'actif déjà calculées (cf.
    `asset_match_context`). Logique strictement identique."""
    return match_component_type_ctx(ctx, cve) is not None


def match_component_type_ctx(ctx: dict, cve: CVE) -> Optional[str]:
    """"system" (composant OS) / "application" (paquet installé) / None (aucun
    rattachement) — même verdict que `still_matches_ctx`, mais renvoie l'origine
    du match plutôt qu'un booléen (07/08/2026, cf. models.py::Vulnerability §
    component_type). Priorité "application" quand un paquet installé matche en
    plus du CPE OS : plus actionnable pour l'analyste. Utilisé par
    `backfill_component_types` pour classer rétroactivement les rattachements
    déjà en base — jamais par le matching bulk lui-même (`run_cpe_matching` et
    consorts), qui a sa propre boucle optimisée par catalogue et calcule
    `component_type` en ligne pour ne pas reconstruire `ctx` par CVE."""
    cve_cpe_list: list = cve.cpe or []
    if cve_cpe_list:
        if _cve_products(cve) & ctx["package_products"]:
            return "application"
        if any(_cpe_matches(ac, cve_cpe_list) for ac in ctx["cpe_list"]):
            return "system"
        return None
    return "system" if _keyword_matches(cve.description, ctx["keywords"]) else None


async def backfill_component_types(db: Optional[AsyncSession] = None) -> dict:
    """Classe rétroactivement `component_type` des `Vulnerability` créées avant
    son introduction (07/08/2026) — `run_cpe_matching` ne modifie jamais un
    rattachement déjà en base (`exists is not None: skipped`), seul ce backfill
    comble le passé. Contexte calculé une fois par actif (`asset_match_context`),
    pas par ligne — même optimisation que `still_matches_ctx`, indispensable vu
    le volume (~86k vulnérabilités, cf. STATUS.md 28/07/2026).

    Laisse `component_type` à `None` (pas d'écriture) pour : les rattachements
    dont la règle de matching a changé depuis (candidats faux positifs, cf.
    `still_matches`) et ceux d'origine WithSecure (`services/withsecure_matcher.py`,
    jamais classés — pas de signal fiable côté API pour distinguer OS/application
    dans les correctifs "Software Updater" remontés, cf. STATUS.md 07/08/2026)."""
    own_session = db is None
    if own_session:
        db = SessionLocal()

    updated = skipped_no_match = 0
    try:
        windows_mappings = await _load_windows_mappings(db)
        vulns = (await db.execute(
            select(Vulnerability).where(Vulnerability.component_type.is_(None))
        )).scalars().all()
        total = len(vulns)

        assets_by_id = {a.id: a for a in (await db.execute(select(Asset))).scalars().all()}
        cves_by_id = {c.id: c for c in (await db.execute(select(CVE))).scalars().all()}
        ctx_by_asset_id: dict = {}

        for vuln in vulns:
            asset = assets_by_id.get(vuln.asset_id)
            cve = cves_by_id.get(vuln.cve_id)
            if asset is None or cve is None:
                continue
            ctx = ctx_by_asset_id.get(asset.id)
            if ctx is None:
                ctx = asset_match_context(asset, windows_mappings)
                ctx_by_asset_id[asset.id] = ctx
            component_type = match_component_type_ctx(ctx, cve)
            if component_type is None:
                skipped_no_match += 1
                continue
            vuln.component_type = component_type
            updated += 1

        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        if own_session:
            await db.close()

    return {"total": total, "updated": updated, "skipped_no_match": skipped_no_match}
