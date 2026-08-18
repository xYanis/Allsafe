"""
models/__init__.py + models complets
CVE, Asset, Vulnerability, Feed
"""

# models/cve.py
from sqlalchemy import Column, String, Float, DateTime, Text, JSON, Boolean, Integer, Date
from sqlalchemy.dialects.postgresql import UUID
import uuid
from database import Base


class CVE(Base):
    __tablename__ = "cves"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id      = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text)
    published   = Column(DateTime(timezone=True))
    modified    = Column(DateTime(timezone=True))
    cvss_score  = Column(Float)
    cvss_vector = Column(String)
    epss_score  = Column(Float)
    severity    = Column(String, index=True)   # CRITICAL / HIGH / MEDIUM / LOW
    references  = Column(JSON, default=list)
    cpe         = Column(JSON, default=list)
    source      = Column(String, default="nvd")
    raw_data    = Column(JSON)
    # KEV (17/08/2026) — CISA Known Exploited Vulnerabilities, cf. services/kev_fetcher.py.
    kev             = Column(Boolean, nullable=False, default=False)
    kev_date_added  = Column(Date)
    kev_ransomware  = Column(Boolean, nullable=False, default=False)
    # Maturité d'exploit (17/08/2026) — présence dans Metasploit, cf.
    # services/exploit_maturity_fetcher.py. msf_best_rank : échelle native du framework
    # (0=manual, 600=excellent), pas une échelle réinventée.
    msf_module       = Column(Boolean, nullable=False, default=False)
    msf_best_rank    = Column(Integer)
    msf_module_count = Column(Integer, nullable=False, default=0)


# models/asset.py
from sqlalchemy import Column, String, DateTime, JSON, Boolean, func as _asset_func
from sqlalchemy.dialects.postgresql import UUID, INET
import uuid
from database import Base


class Asset(Base):
    __tablename__ = "assets"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name        = Column(String, nullable=False)
    hostname    = Column(String, unique=True, index=True)
    ip_address  = Column(String)
    os          = Column(String)
    os_version  = Column(String)
    asset_type  = Column(String, default="server")  # server / workstation / network
    tags        = Column(JSON, default=dict)
    cpe_list    = Column(JSON, default=list)
    installed_packages = Column(JSON, default=list)  # [{name, version}] — dernier scan, lecture seule
    last_scan_result   = Column(JSON)  # Rapport de fiabilité du dernier scan (déclaré vs détecté)
    # scan_reachable/scan_error (04/08/2026) : copie légère de last_scan_result.reachable/.error,
    # colonnes dédiées plutôt que de reparser le JSON — ConnectivityDot.jsx (ex-ConnectivityDot,
    # pastille "actif bien relié à CBR" sur Actifs/Vulnérabilités/Dashboard) a besoin de ce
    # signal sur des endpoints qui chargent l'Asset avec un load_only(raiseload=True) restreint
    # pour des raisons de perf (cf. routers/vulnerabilities.py::_CANDIDATE_LOAD_OPTIONS,
    # incident documenté sur last_scan_result/installed_packages) — impossible d'y ajouter le
    # blob complet sans réintroduire ce même incident.
    scan_reachable     = Column(Boolean)
    scan_error         = Column(Text)
    hardware    = Column(JSON)  # {cpu, cores, ram_gb, disks: [{name, total_gb, free_gb}]} — module Inventaire
    source      = Column(String)                     # active_directory / ssh / csv / manual / meraki / prtg / agent
    # Comment cet actif est ACTIVEMENT scanné, distinct de `source` ci-dessus qui documente
    # comment il a été DÉCOUVERT/importé (12/08/2026, module Agents — cf. docs sur l'agent
    # poste Windows/Linux). "service_account" = pull centralisé existant (SSH/WinRM, ce
    # champ ne change rien à `asset_scanner.py`) ; "agent" = push par un agent Rust enrôlé
    # (cf. models.Agent) — un actif AD-importé peut très bien basculer sur "agent" plus tard
    # sans que `source` ne change rétroactivement.
    collection_method = Column(String, default="service_account")
    last_scan   = Column(DateTime(timezone=True))
    status      = Column(String, default="active")
    # Identifiants SSH par machine — phase de test uniquement (à terme : clé SSH par machine,
    # cf. STATUS.md). Mot de passe chiffré (Fernet, cf. services/crypto.py), jamais renvoyé par
    # l'API (write-only). Utilisés en priorité sur la clé SSH partagée du parc si renseignés.
    scan_username           = Column(String)
    scan_password_encrypted = Column(String)
    # {"checks": [...], "checked_at": iso} — protocoles d'admin non chiffrés détectés
    # par connexion TCP passive (07/08/2026, asset_type="network" uniquement : switches/
    # pare-feux PRTG/Meraki, sur lesquels CBR n'a aucun accès identifiant contrairement
    # aux serveurs SSH/WinRM). Même forme que le "compliance" des serveurs
    # (services/asset_scanner.py::_check), mais colonne dédiée plutôt que dans
    # `last_scan_result` — ces actifs ne passent jamais par un scan SSH/WinRM, il n'y a
    # pas de "dernier scan" au même sens. Cf. services/network_protocol_check.py.
    network_compliance = Column(JSON)
    # Site web (17/08/2026, asset_type="website") — même principe que network_compliance
    # juste au-dessus : ces actifs n'ont ni OS ni scan SSH/WinRM, checks 100% passifs
    # (en-têtes HTTP, protocole TLS). `url` est la seule donnée nécessaire pour ce type
    # d'actif. Cf. services/web_hardening.py.
    url             = Column(String)
    web_compliance  = Column(JSON)
    # Badge "Nouveau" sur Actifs (13/08/2026) — server_default plutôt qu'un défaut Python
    # (uuid.uuid4() ci-dessus est un défaut Python volontairement, mais une date de création
    # doit rester exacte même pour une ligne insérée hors SQLAlchemy). Les actifs déjà en base
    # au moment de l'ajout de cette colonne sont rétrodatés (schema_patches.sql), pour ne pas
    # tous apparaître "nouveaux" le jour de la migration.
    created_at  = Column(DateTime(timezone=True), server_default=_asset_func.now())


# models/vulnerability.py
from sqlalchemy import Column, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
import uuid
from database import Base


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id     = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False, index=True)
    cve_id       = Column(UUID(as_uuid=True), ForeignKey("cves.id"), nullable=False, index=True)
    status       = Column(String, default="open")     # open / in_progress / patched / accepted_risk / awaiting_fix / false_positive
    risk_score   = Column(Float)
    # CVSS-BTE (17/08/2026) — score CVSS v3.1 Temporal+Environmental réel, par (CVE, actif),
    # coexiste avec risk_score (formule maison) sans le remplacer, cf. services/cvss_bte.py.
    cvss_bte        = Column(Float)
    cvss_bte_vector = Column(String)   # ex. "E:H/RL:X/RC:C/CR:H/IR:H/AR:H" — traçabilité
    detected_at  = Column(DateTime(timezone=True))
    patched_at   = Column(DateTime(timezone=True))
    awaiting_fix_at = Column(DateTime(timezone=True))  # date de passage en "awaiting_fix"
    false_positive_at = Column(DateTime(timezone=True))  # date de passage en "false_positive"
    accepted_risk_until = Column(DateTime(timezone=True))  # date de revue obligatoire (accepted_risk) — jamais auto-appliquée, cf. schema_patches.sql
    validated_by = Column(String)                     # Analyste ayant validé la correction
    notes        = Column(Text)                        # Aussi utilisé comme annotation/justification pour "awaiting_fix"/"false_positive"
    ai_analysis  = Column(JSON)                       # Résultat analyse Claude (anonymisé)
    last_patch_check   = Column(DateTime(timezone=True))  # NULL = jamais vérifié
    patch_check_result = Column(JSON)                     # Dernier rapport patch_checker (signalement, pas une vérité)
    # "system" (composant OS) / "application" (paquet/logiciel installé) / NULL
    # (indéterminé — origine WithSecure, création manuelle, ou rattachement dont
    # la règle de matching a changé depuis, cf. services/cpe_matcher.py::backfill_component_types)
    # (07/08/2026). Posé à la création par cpe_matcher.py, jamais recalculé
    # automatiquement ensuite — sert à distinguer mise à jour système vs
    # applicative sur la page Actifs (cf. routers/assets.py).
    component_type    = Column(String)


class VulnerabilityStatusHistory(Base):
    """Historique des transitions de statut (27/07/2026) — jamais écrasé, jamais
    supprimé. Prospectif : ne couvre que les transitions à partir de sa mise en
    service, cf. schema_patches.sql. Alimenté par services/vuln_history.py,
    appelé à chaque site qui modifie Vulnerability.status (manuel et auto)."""
    __tablename__ = "vulnerability_status_history"

    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    old_status       = Column(String)   # NULL possible (jamais utilisé aujourd'hui : record_status_change no-op si absent)
    new_status       = Column(String, nullable=False)
    # Posé explicitement par record_status_change() à l'insertion (comme
    # patched_at/awaiting_fix_at ailleurs dans ce fichier) — pas de défaut ORM,
    # pour ne pas dépendre d'un DEFAULT SQL différent selon que la table a été
    # créée par schema_patches.sql ou par create_all sur une base neuve.
    changed_at       = Column(DateTime(timezone=True), nullable=False)
    validated_by     = Column(String)   # Analyste, ou "Auto (patch check)"
    notes            = Column(Text)


from sqlalchemy import Column, String, DateTime, Integer
from sqlalchemy.dialects.postgresql import UUID
import uuid


class PatchCheckAssetCompletion(Base):
    """Journal append-only — un actif a fini sa passe de contrôle patch (11/08/2026,
    demande explicite : la notification toast "actif terminé" côté Dashboard.jsx
    disparaissait sans laisser de trace après 6s, contrairement aux bascules de CVE
    (dérivées de `Vulnerability.patched_at`/`false_positive_at`, donc déjà consultables
    après coup via `auto-bascule-summary`) — rien n'existait côté serveur pour rejouer
    "cet actif a fini" une fois le toast disparu. Alimenté par
    services/patch_checker.py::record_asset_completion, appelé une fois par actif à la
    fin de sa boucle CVE dans run_startup_patch_checks (pas à chaque vuln individuelle).

    `asset_name`/`hostname` dupliqués en texte (pas seulement `asset_id`) : l'actif peut
    être supprimé entre-temps (DeleteAssetModal), l'historique doit rester lisible sans
    jointure obligatoire — même raisonnement que `_current_check`/`_last_completed`
    (mémoire, patch_checker.py) qui portent déjà ces champs en clair."""
    __tablename__ = "patch_check_asset_completions"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id            = Column(UUID(as_uuid=True), index=True)   # pas de FK — snapshot, survit à la suppression de l'actif
    asset_name          = Column(String, nullable=False)
    hostname            = Column(String)
    checked_count       = Column(Integer, nullable=False)          # vulns vérifiées pendant cette passe
    auto_bascule_count  = Column(Integer, nullable=False, default=0)  # dont bascules automatiques (patched/false_positive)
    completed_at        = Column(DateTime(timezone=True), nullable=False)


class AssetDeletionLog(Base):
    """Journal append-only — un actif a été supprimé (18/08/2026, demande explicite :
    étoffer le bandeau "depuis votre dernière visite" du Dashboard, qui ne pouvait
    montrer que des CVE/ajouts d'actifs, jamais des suppressions — la ligne disparaît
    de `assets` sans laisser de trace, contrairement à un ajout (`Asset.created_at`,
    toujours consultable après coup). Alimenté par routers/assets.py::delete_asset,
    juste avant la suppression réelle.

    `asset_name`/`hostname` en texte, pas de FK vers `assets` (l'actif n'existe plus par
    définition) — même raisonnement que `PatchCheckAssetCompletion` juste au-dessus."""
    __tablename__ = "asset_deletion_logs"

    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_name   = Column(String, nullable=False)
    hostname     = Column(String)
    asset_type   = Column(String)
    deleted_at   = Column(DateTime(timezone=True), nullable=False)


# models/feed.py
from sqlalchemy import Column, String, DateTime, Boolean, Integer
from sqlalchemy.dialects.postgresql import UUID
import uuid
from database import Base


class Feed(Base):
    __tablename__ = "feeds"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name            = Column(String, nullable=False)
    url             = Column(String, unique=True, nullable=False)
    feed_type       = Column(String)                 # rss / atom / nvd_api
    active          = Column(Boolean, default=True)
    last_fetch      = Column(DateTime(timezone=True))
    fetch_interval  = Column(Integer, default=60)    # minutes


class ConnectionLog(Base):
    __tablename__ = "connection_logs"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip          = Column(String)
    user_agent  = Column(String)
    accessed_at = Column(DateTime(timezone=True))


# models/watch_item.py
from sqlalchemy import Column, String, DateTime, Text, JSON as _JSON, Boolean as _Boolean
from sqlalchemy import Integer, ForeignKey, Index as _Index, func as _func, text as _text
from sqlalchemy.dialects.postgresql import UUID as _UUID
import uuid as _uuid
from database import Base as _Base


class WatchItem(_Base):
    __tablename__ = "watch_items"

    id            = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    source        = Column(String, nullable=False, index=True)   # cert-fr-avis, anssi, sekoia…
    source_label  = Column(String)                               # "CERT-FR Avis"
    title         = Column(String, nullable=False)
    url           = Column(String, unique=True)                  # clé de déduplication
    summary       = Column(Text)
    published_at  = Column(DateTime(timezone=True))              # date de publication source
    received_at   = Column(DateTime(timezone=True), index=True)  # date d'import CyberVuln
    severity      = Column(String, default="informational", index=True)  # critical/important/informational
    status        = Column(String, default="new", index=True)    # new/in_review/treated/not_applicable
    reviewed_by   = Column(String)                               # analyste ayant traité l'item
    reviewed_at   = Column(DateTime(timezone=True))              # date de traitement
    decision      = Column(Text)                                 # action décidée (texte libre)
    linked_cve_id = Column(String)                               # CVE-ID lié manuellement (ex: CVE-2025-1234)
    cve_ids_found = Column(_JSON, default=list)                  # CVE-IDs détectés automatiquement dans le contenu
    themes        = Column(_JSON, default=list)                  # thèmes auto-catégorisés : Cyber, Admin, Réseau, Hardware, Software, Données, Réglementation, Ransomware, APT, Vulnérabilité, IA
    country       = Column(String, index=True)                   # pays concerné par la fuite, ISO 3166-1 alpha-2 (FR, US…) — depuis l'API pour ransomware.live, défaut FR pour les trackers dédiés français
    # Actifs du parc concernés par cet élément de veille, désignés à la main par
    # l'analyste au moment du traitement (22/07/2026). Liste d'UUID en JSON et
    # non une table de liaison : même approche que `themes`/`cve_ids_found`, et
    # le volume reste faible (quelques actifs par item, sur des items qu'on
    # traite un par un). Les noms ne sont **pas** stockés ici — ils sont résolus
    # à la lecture depuis `assets`, pour qu'un actif renommé le soit partout.
    # Un id d'actif supprimé entre-temps est simplement ignoré à la lecture.
    asset_ids     = Column(_JSON, default=list)


class WatchSource(_Base):
    """Flux RSS/Atom ajoutés dynamiquement par l'utilisateur — depuis Fuite de
    données (category="leak") ou Veille technologique (category="general") —
    en plus des sources codées en dur dans watch_fetcher.py. `slug` sert de
    clé technique = WatchItem.source pour les items collectés. `category`
    détermine uniquement le routage d'affichage (une source "leak" est
    incluse par défaut dans Fuite de données et exclue de Veille
    technologique via GET /watch/leak-sources ; une source "general" apparaît
    normalement dans Veille technologique et jamais dans Fuite de données) —
    la collecte elle-même (run_watch_sync) ne fait aucune distinction."""
    __tablename__ = "watch_sources"

    id         = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    name       = Column(String, nullable=False)                  # libellé affiché ("Mon flux perso")
    slug       = Column(String, unique=True, nullable=False, index=True)  # dérivé du nom, unique
    url        = Column(String, nullable=False)                  # URL du flux RSS/Atom
    feed_type  = Column(String, default="rss")                   # rss | atom
    category   = Column(String, default="general")                # general | leak
    country    = Column(String)                                  # pays par défaut assigné aux items (optionnel, ISO alpha-2)
    enabled    = Column(_Boolean, default=True)
    created_at = Column(DateTime(timezone=True))


class SyncState(_Base):
    """Horodatage de la dernière exécution d'une tâche de synchronisation
    récurrente — une ligne par clé de tâche (`key`, ex: "watch", "cpe_match"),
    mise à jour aussi bien par le déclenchement manuel (bouton dans l'UI) que
    par le cycle automatique (Celery beat ou démarrage de l'app, selon la
    tâche). Nécessaire pour afficher la date de dernière synchronisation dès
    le chargement de page, sans dépendre d'un clic manuel dans la session en
    cours. Une seule table générique plutôt qu'une par tâche — cf. principe
    "penser scalable" (CLAUDE.md) : la 2e tâche à en avoir besoin (matching
    CPE, après la veille) est le signal qu'il ne faut pas dupliquer le modèle
    une 3e fois."""
    __tablename__ = "sync_state"

    key            = Column(String, primary_key=True)  # "watch", "cpe_match"...
    last_synced_at = Column(DateTime(timezone=True))
    # Optionnel, seul "patch_check_cycle" l'utilise pour l'instant (10/08/2026) :
    # distingue un cycle qui vient de finir proprement ("completed") de celui
    # qu'un redémarrage du process a coupé en plein milieu ("interrupted",
    # détecté au démarrage suivant — cf. main.py::_check_interrupted_patch_cycle)
    # de celui en cours ("running"). Colonne générique plutôt qu'un champ dédié
    # à patch_check_cycle, même raisonnement que le reste de cette table.
    status         = Column(String, nullable=True)


class KbBuild(_Base):
    """Numéro de build OS produit par un KB Microsoft — récupéré depuis le titre
    de l'article support.microsoft.com (ex: "March 12, 2019—KB4489899 (OS Build
    17763.379)"), seule source publique exploitable trouvée : ni NVD ni les deux
    API MSRC (sug v2 `affectedBinaries`, CVRF v3 `AffectedFiles`) ne fournissent
    de build pour les CVE anciennes — vérifié en session (21/07/2026).

    Sert à trancher avec certitude les CVE Windows sans plage de version NVD
    exploitable : les CU Windows étant strictement cumulatives, un build installé
    supérieur au build du correctif contient forcément ce correctif (même
    raisonnement que le signal build NVD, cf. docs/MATCHING.md).

    Mis en cache définitivement : le couple KB→build est immuable une fois
    publié, et support.microsoft.com rate-limite agressivement (constaté en
    conditions réelles) — une CVE peut porter 14 KB, un actif des milliers de
    CVE. `builds` est une liste car un même KB couvre parfois plusieurs branches
    (ex: "OS Builds 19042.1237, 19043.1237, and 19044.1237").
    `found=False` mémorise un échec définitif (article sans build dans le titre)
    pour ne pas retenter indéfiniment."""
    __tablename__ = "kb_builds"

    kb         = Column(String, primary_key=True)      # "4489899" (sans préfixe KB)
    builds     = Column(_JSON, default=list)           # ["17763.379"]
    title      = Column(String)                        # titre brut, traçabilité analyste
    found      = Column(_Boolean, default=True)
    fetched_at = Column(DateTime(timezone=True))


class WatchedIdentity(_Base):
    """Identité de l'entreprise à surveiller dans les fuites de données —
    module Surveillance Identités (CyberVeille). `kind` = `name` (ex: "AER"),
    `domain` (ex: "aer.fr"), `ip`/`ip_range`, ou `email` (28/07/2026, ex:
    "contact@aer.fr" — cf. services/leak_lookup.py § XposedOrNot).
    Aucune collecte propre pour name/domain : le module croise ces valeurs
    avec les items de fuite déjà agrégés par run_watch_sync (sources leak :
    ransomware.live, ZATAZ, DataBreaches.net, HIBP…). ip/ip_range et email
    sont vérifiés en direct contre des sources tierces gratuites
    (services/ip_watch.py, services/leak_lookup.py) — 100% gratuit dans tous
    les cas, mais pas "aucune source externe" au sens strict pour ces
    trois-là. Liste pilotée en base et éditable dans l'interface (principe
    "penser scalable", CLAUDE.md), pas de valeur codée en dur.

    Limite assumée : on ne voit que ce qui est publiquement rapporté par ces
    sources — une fuite d'identifiants jamais relayée reste invisible sans
    source payante (HIBP Domain Search notamment)."""
    __tablename__ = "watched_identities"

    id         = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    value      = Column(String, nullable=False)   # "AER" | "aer.fr" | "contact@aer.fr"
    kind       = Column(String, nullable=False)   # name | domain | ip | ip_range | email
    enabled    = Column(_Boolean, default=True)
    created_at = Column(DateTime(timezone=True))


class WatchProfileItem(_Base):
    """Profil de veille — ce que le parc utilise réellement (OS, logiciels), pour
    mettre en avant les éléments de veille qui le concernent.

    **Ne filtre jamais la collecte ni le registre** : le registre NIS 2 doit
    rester complet, un auditeur doit pouvoir constater qu'on a bien tout reçu.
    Le profil ne sert qu'à *marquer* et à *trier* — décision explicite de
    l'utilisateur (22/07/2026), face à l'alternative « ne plus afficher/collecter
    ce qui ne correspond pas », écartée car un mot-clé mal réglé ferait
    silencieusement disparaître un élément sans laisser de trace.

    Une ligne par terme surveillé, sur le modèle de `WatchedIdentity` : liste
    pilotée en base et éditable dans l'interface, jamais codée en dur (principe
    "penser scalable", CLAUDE.md).

    `origin` trace d'où vient le terme — `inventory` (proposé depuis les actifs
    et l'inventaire, puis coché par l'analyste) ou `manual` (saisi à la main,
    ex. un équipement réseau qui n'apparaît dans aucun scan). Sert à repérer ce
    qui a été ajouté hors inventaire, pas à traiter les deux différemment.
    """
    __tablename__ = "watch_profile"

    id         = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    kind       = Column(String, nullable=False, index=True)   # os | software
    value      = Column(String, nullable=False)               # "Debian", "openssl"…
    origin     = Column(String, default="manual")             # inventory | manual
    enabled    = Column(_Boolean, default=True)
    created_at = Column(DateTime(timezone=True))

    __table_args__ = (
        _Index("uq_watch_profile_kind_value", "kind", "value", unique=True),
    )


class Report(_Base):
    """Rapport hebdomadaire **figé**, identifié par sa semaine ISO ("S30/2026").

    Figé, et pas recalculé à l'ouverture : un rapport doit dire ce qui était
    vrai *cette semaine-là*. Le parc bouge en permanence (syncs NVD, cycle de
    patch check, qualifications de l'analyste) — un rapport recalculé afficherait
    les chiffres d'aujourd'hui sous une étiquette S30, ce qui est exactement ce
    qu'un audit NIS 2 ne doit pas pouvoir se permettre. D'où `summary`
    (markdown déjà rendu), `stats` et `activity` stockés tels quels : tout ce
    qu'il faut pour réafficher et exporter le rapport sans jamais réinterroger
    l'état courant.

    `kind` distingue les trois rapports du module (`cve`, `veille`,
    `surveillance`) dans **une seule** table plutôt qu'une par rapport — même
    raisonnement que SyncState (cf. principe "penser scalable", CLAUDE.md) : la
    mécanique hebdo (semaine ISO, archives, export) est identique pour les trois,
    seul le contenu diffère. Ajouter un 4e rapport = une valeur de `kind`, pas
    une table ni un écran de plus.

    Semaine ISO et non calendaire : `iso_year` peut différer de l'année de
    `period_start` fin décembre (le 2029-12-31 appartient à la semaine 1 de
    2030) — d'où le stockage explicite du couple année/semaine ISO plutôt qu'un
    calcul depuis la date.
    """
    __tablename__ = "reports"

    id           = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    kind         = Column(String, nullable=False, index=True)   # cve | veille | surveillance
    label        = Column(String, nullable=False)               # "S30/2026"
    iso_year     = Column(Integer, nullable=False)
    iso_week     = Column(Integer, nullable=False)
    period_start = Column(DateTime(timezone=True))              # lundi 00:00 (UTC)
    period_end   = Column(DateTime(timezone=True))              # lundi suivant 00:00 (exclu)
    generated_at = Column(DateTime(timezone=True))
    generated_by = Column(String)                               # "Auto (hebdomadaire)" | analyste
    summary      = Column(Text)                                 # markdown figé
    stats        = Column(_JSON, default=dict)                  # KPI figés
    activity     = Column(_JSON, default=dict)                  # corrigées/en attente/faux positifs/détectées

    # Portée du rapport : NULL = tout le parc, sinon un actif précis. Un rapport
    # par actif est généré chaque semaine en plus du rapport global — seul moyen
    # d'avoir un rapport par actif *fidèle* : régénéré après coup, il ne verrait
    # que ce qui est encore vrai aujourd'hui (rouvrir une vuln efface sa date de
    # clôture, elle disparaît alors du rapport de la semaine où elle a été
    # clôturée). `asset_label` fige le nom affiché même si l'actif est renommé
    # ou supprimé ensuite.
    asset_id     = Column(_UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True)
    asset_label  = Column(String)

    __table_args__ = (
        # Un seul rapport par type, semaine et portée — la régénération écrase la
        # ligne existante au lieu d'empiler des doublons (cf. force=true).
        # `coalesce` et non un UNIQUE simple : en SQL, deux NULL sont considérés
        # distincts, donc une contrainte portant sur `asset_id` NULL n'empêcherait
        # pas d'empiler plusieurs rapports globaux pour la même semaine.
        _Index(
            "uq_report_kind_week_asset",
            "kind", "iso_year", "iso_week",
            _func.coalesce(asset_id, _text("'00000000-0000-0000-0000-000000000000'::uuid")),
            unique=True,
        ),
    )


from sqlalchemy import Column, String, DateTime, Text, Boolean, BigInteger, func as _sfunc
from sqlalchemy.dialects.postgresql import INET as _INET, JSONB as _JSONB


class SecurityEvent(Base):
    """Journal des événements de déception (honeypots DB). Table réelle — PAS un
    leurre. Alimentée AU MOMENT DE LA REQUÊTE par les fonctions SECURITY DEFINER
    de backend/db/deception_setup.sql (lecture/écriture des vues leurres, rôles
    leurres). Lue par routers/security.py. La création de la table et de tous les
    objets leurres se fait via ce script SQL (hors ORM) : create_all ne crée que
    cette table-ci si absente, jamais les vues/fonctions/rôles."""
    __tablename__ = "security_events"

    id           = Column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at  = Column(DateTime(timezone=True), server_default=_sfunc.now())
    source       = Column(String, nullable=False)   # honey_read | honey_write | decoy_role
    object_name  = Column(String)
    operation    = Column(String)
    db_user      = Column(String, nullable=False)
    client_addr  = Column(_INET)
    detail       = Column(_JSONB)
    acknowledged = Column(Boolean, nullable=False, default=False)
    ack_by       = Column(String)
    ack_at       = Column(DateTime(timezone=True))


# models/incident.py
class Incident(Base):
    """Registre d'incidents de sécurité, avec suivi des délais légaux de notification
    NIS 2 (Directive, Art. 23) : alerte précoce sous 24h après prise de connaissance
    (`aware_at`), notification d'incident sous 72h, rapport final sous 1 mois — pour les
    seuls incidents qu'un analyste qualifie explicitement `requires_notification` (jamais
    automatique, cf. services/nis2_deadlines.py). L'app ne notifie jamais elle-même une
    autorité externe (ANSSI) : elle trace uniquement qui a déclaré/qualifié/envoyé quoi
    et quand — même esprit que la règle CRITICAL toujours manuel de CyberVuln."""
    __tablename__ = "incidents"

    id          = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    title       = Column(String, nullable=False)
    description = Column(Text)                    # markdown, rendu via MarkdownNote.jsx
    category    = Column(String, nullable=False)   # ransomware|data_breach|intrusion|dos|phishing|malware|misconfiguration|other
    severity    = Column(String, nullable=False)   # critical|major|minor (échelle propre, pas CVSS)
    status      = Column(String, nullable=False, default="declared")  # declared|in_progress|contained|resolved|closed

    detected_at = Column(DateTime(timezone=True))   # constat technique — peut précéder aware_at
    aware_at    = Column(DateTime(timezone=True), nullable=False)  # point de départ légal Art. 23
    # Verrouillé dès qu'un jalon de notification est marqué envoyé — plus aucune
    # modification de aware_at possible ensuite (cf. change_aware_at, nis2_deadlines.py).
    aware_at_locked = Column(Boolean, nullable=False, default=False)

    reported_by = Column(String, nullable=False)    # analyste déclarant (ANALYSTS, ValidateDropdown.jsx)
    created_at  = Column(DateTime(timezone=True), server_default=_sfunc.now())
    updated_at  = Column(DateTime(timezone=True))

    # Qualification NIS 2 — jamais automatique, toujours un acte humain explicite
    # (cf. nis2_deadlines.qualify_for_notification). Justification obligatoire.
    requires_notification      = Column(Boolean, nullable=False, default=False)
    notification_qualified_by  = Column(String)
    notification_qualified_at  = Column(DateTime(timezone=True))
    notification_justification = Column(Text)

    # Échéances figées au moment de la qualification (mois calendaire pour le rapport
    # final, cf. nis2_deadlines.py). Un jalon déjà envoyé (`*_sent_at` renseigné) garde sa
    # date pour toujours — aucun recalcul ne peut l'écraser (cf. change_aware_at).
    early_warning_due_at          = Column(DateTime(timezone=True))
    early_warning_sent_at         = Column(DateTime(timezone=True))
    early_warning_sent_by         = Column(String)
    incident_notification_due_at  = Column(DateTime(timezone=True))
    incident_notification_sent_at = Column(DateTime(timezone=True))
    incident_notification_sent_by = Column(String)
    final_report_due_at           = Column(DateTime(timezone=True))
    final_report_sent_at          = Column(DateTime(timezone=True))
    final_report_sent_by          = Column(String)

    # Liens optionnels vers l'origine du signal — SET NULL et non CASCADE : l'incident
    # (et son audit trail) doit survivre à la suppression de sa source.
    security_event_id = Column(BigInteger, ForeignKey("security_events.id", ondelete="SET NULL"), nullable=True)
    vulnerability_id   = Column(_UUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True)
    watch_item_id      = Column(_UUID(as_uuid=True), ForeignKey("watch_items.id", ondelete="SET NULL"), nullable=True)
    # Finding d'audit à l'origine de la déclaration (03/08/2026, module Audits) — même
    # SET NULL que les 3 FK ci-dessus : l'incident survit à la suppression du finding source.
    audit_finding_id   = Column(_UUID(as_uuid=True), ForeignKey("audit_findings.id", ondelete="SET NULL"), nullable=True)

    # Crise regroupant éventuellement cet incident avec d'autres (31/07/2026, cf. Crisis
    # ci-dessous) — SET NULL et non CASCADE : supprimer la crise ne doit pas supprimer les
    # incidents qu'elle regroupait, même logique que les 3 FK optionnelles ci-dessus.
    crisis_id = Column(_UUID(as_uuid=True), ForeignKey("crises.id", ondelete="SET NULL"), nullable=True)

    # Actifs concernés — même pattern que WatchItem.asset_ids : liste d'UUID en JSON,
    # pas de table de liaison (volume faible), résolue à la lecture depuis `assets`.
    affected_asset_ids = Column(_JSON, default=list)

    # Indices (dans RESPONSE_STEPS[category], frontend/src/constants/incidentPlaybooks.js) des
    # étapes de la checklist "Plan d'action" cochées par l'analyste — simple aide-mémoire, PAS
    # une pièce d'audit (la traçabilité réelle des envois reste la qualification NIS 2 + la
    # chronologie). Persisté pour ne pas perdre la progression entre deux ouvertures de
    # l'incident. Remplace l'ancienne checklist "bonnes pratiques" séparée
    # (`completed_playbook_steps`, retirée le 29/07/2026 : contenu fusionné ici pour éliminer
    # la redondance entre les deux listes, cf. schema_patches.sql).
    completed_response_steps = Column(_JSON, default=list)


class IncidentTimelineEntry(Base):
    """Journal auditable, append-only, de tout ce qui arrive à un incident : création,
    changement de statut, note libre, qualification/déqualification NIS 2, jalon de
    notification envoyé, modification de aware_at. Générique — contrairement à
    VulnerabilityStatusHistory qui ne suit que les transitions de statut — car un audit
    NIS 2 veut la chronologie complète des décisions, pas seulement les statuts."""
    __tablename__ = "incident_timeline_entries"

    id          = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    incident_id = Column(_UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type  = Column(String, nullable=False)  # created|status_change|note|notification_qualified|
                                                    # notification_unqualified|milestone_sent|aware_at_changed
    occurred_at = Column(DateTime(timezone=True), nullable=False, server_default=_sfunc.now())
    author      = Column(String, nullable=False)   # toujours un analyste (ANALYSTS) — jamais "Auto"
    old_value   = Column(String)
    new_value   = Column(String)
    notes       = Column(Text)                     # markdown, justification libre
    meta        = Column(_JSONB)                    # ex: {"milestone": "early_warning", "due_at": "..."}


class IncidentAttachment(Base):
    """Pièce jointe (PDF) du rapport final d'un incident — 5 Mo max, cf.
    services/incident_attachments.py pour la validation (taille + signature %PDF-).
    Fichier écrit sur disque (volume Docker `incident_attachments`, jamais sous le nom
    fourni par le client — toujours renommé en {uuid4()}.pdf, cf. path traversal),
    métadonnées seules en base."""
    __tablename__ = "incident_attachments"

    id              = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    incident_id     = Column(_UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    milestone       = Column(String, nullable=False, default="final_report")
    filename        = Column(String, nullable=False)   # nom d'origine, pour l'affichage/téléchargement
    stored_filename = Column(String, nullable=False)    # {uuid4()}.pdf sur disque
    size_bytes      = Column(Integer, nullable=False)
    uploaded_by     = Column(String, nullable=False)
    uploaded_at     = Column(DateTime(timezone=True), server_default=_sfunc.now())


class Crisis(Base):
    """Gestion de crise (31/07/2026) — escalade au-delà d'un incident seul : une crise peut
    regrouper plusieurs incidents concurrents (ex: un ransomware qui déclenche aussi une fuite
    de données, cf. `Incident.crisis_id`). Comble le vide identifié par
    ROADMAP_RNCP42335.md (Bloc 1.5 « Gestion de crise cyber ») : IncidentRoadmap.jsx hébergeait
    déjà un plan d'action par catégorie, mais aucune structure d'escalade/cellule de crise.
    Activation et désactivation toujours un acte humain explicite, jamais automatique — même
    esprit que `requires_notification` sur Incident."""
    __tablename__ = "crises"

    id             = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    title          = Column(String, nullable=False)
    description    = Column(Text)                       # markdown, rendu via MarkdownNote.jsx
    status         = Column(String, nullable=False, default="active")  # active | stood_down

    activated_at   = Column(DateTime(timezone=True), nullable=False, server_default=_sfunc.now())
    activated_by   = Column(String, nullable=False)

    stood_down_at  = Column(DateTime(timezone=True))
    stood_down_by  = Column(String)
    stand_down_justification = Column(Text)

    # Cellule de crise — même pattern que Incident.affected_asset_ids : liste JSON, pas de
    # table de liaison séparée (volume faible, pas de CRUD indépendant des rôles nécessaire).
    # [{"role": "Décideur", "analyst_name": "..."}]
    crisis_roles   = Column(_JSON, default=list)

    # Plan d'action de la crise (31/07/2026) — indices cochés dans CRISIS_STEPS
    # (frontend/src/constants/crisisPlaybook.js), même forme {index, by, at} et même garde-fou
    # qu'Incident.completed_response_steps : simple aide-mémoire, pas une pièce d'audit.
    completed_crisis_steps = Column(_JSON, default=list)

    created_at     = Column(DateTime(timezone=True), server_default=_sfunc.now())


class CrisisTimelineEntry(Base):
    """Journal auditable, append-only, d'une crise — sibling exact d'IncidentTimelineEntry
    (même structure, même raison d'être : reconstituer qui a décidé/communiqué quoi et quand)."""
    __tablename__ = "crisis_timeline_entries"

    id          = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    crisis_id   = Column(_UUID(as_uuid=True), ForeignKey("crises.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type  = Column(String, nullable=False)  # activated|stood_down|role_assigned|role_removed|
                                                    # incident_linked|incident_unlinked|decision|communication
    occurred_at = Column(DateTime(timezone=True), nullable=False, server_default=_sfunc.now())
    author      = Column(String, nullable=False)   # toujours un analyste — jamais "Auto"
    old_value   = Column(String)
    new_value   = Column(String)
    notes       = Column(Text)                     # markdown, contenu de la décision/communication
    meta        = Column(_JSONB)                    # ex: {"audience": "interne"|"externe"}


class CrisisContact(Base):
    """Intervenant personnalisé à prévenir en cas de crise (31/07/2026) — Direction, PR, assureur
    dédié, avocat spécialisé... — en complément des rôles-type codés en dur côté frontend
    (`NATIVE_CRISIS_CONTACTS`, frontend/src/constants/crisisPlaybook.js). Distinct
    d'`IncidentNotificationContact` : celui-ci vise les autorités réglementaires (ANSSI/CNIL,
    filtrées par catégorie d'incident), la crise vise la mobilisation interne — pas de notion de
    catégorie ici (`Crisis` n'en a pas), d'où l'absence du champ `categories`."""
    __tablename__ = "crisis_contacts"

    id          = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    name        = Column(String, nullable=False)
    role        = Column(String)
    email       = Column(String)
    phone       = Column(String)
    website_url = Column(String)
    notes       = Column(Text)
    created_at  = Column(DateTime(timezone=True), server_default=_sfunc.now())


class IncidentNotificationContact(Base):
    """Contact personnalisé ajouté par l'utilisateur (assureur cyber, avocat, cellule de
    communication...) pour la roadmap d'un incident, en complément des organismes officiels
    codés en dur côté frontend (frontend/src/constants/incidentPlaybooks.js — ANSSI/CERT-FR,
    CNIL, police/gendarmerie, cybermalveillance.gouv.fr). Même principe que WatchSource pour
    la veille : natif en code, personnalisé en base."""
    __tablename__ = "incident_notification_contacts"

    id          = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    name        = Column(String, nullable=False)
    role        = Column(String)                # à quel moment / pourquoi le contacter
    email       = Column(String)
    phone       = Column(String)
    website_url = Column(String)
    categories  = Column(_JSON, default=list)    # [] = toutes catégories
    notes       = Column(Text)
    created_at  = Column(DateTime(timezone=True), server_default=_sfunc.now())


class Analyst(Base):
    """Registre des analystes (29/07/2026) — remplace la liste `ANALYSTS` codée en dur
    (frontend/src/components/ValidateDropdown.jsx) utilisée partout comme menu déroulant
    d'attribution (validé par, déclaré par, jalon envoyé par...). Ne porte aucune
    authentification : ni mot de passe, ni session serveur, ni restriction d'accès à
    l'API — une vraie authentification est prévue séparément (cf. STATUS.md)."""
    __tablename__ = "analysts"

    id          = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    name        = Column(String, nullable=False, unique=True)
    created_at  = Column(DateTime(timezone=True), server_default=_sfunc.now())


class Service(Base):
    """Service/département (31/07/2026) — regroupe les postes du registre `OrganizationRole`
    (RH, DSI, Juridique, Direction... liste ouverte, ajoutable sans code). Porte un code couleur
    (`color`, hex) pour distinguer visuellement les services dans la grille de cartes
    d'Administration > Rôles. `icon` (31/07/2026) : clé d'une palette fixe côté frontend
    (`components/ServiceIcon.jsx::SERVICE_ICON_KEYS`), pas un champ libre — nullable pour les
    services créés avant l'ajout du champ, le frontend replie alors sur une icône par défaut."""
    __tablename__ = "services"

    id          = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    name        = Column(String, nullable=False, unique=True)
    color       = Column(String, nullable=False)  # hex, ex: "#58a6ff"
    icon        = Column(String, nullable=True)  # clé SERVICE_ICON_KEYS, ex: "users"
    created_at  = Column(DateTime(timezone=True), server_default=_sfunc.now())


class OrganizationRole(Base):
    """Registre « Rôles » — organigramme simple (31/07/2026) : quel poste (RSSI, DPO, Direction
    générale...) est tenu par quelle personne, avec son email. Distinct du registre `Analyst`
    ci-dessus (noms utilisés dans les dropdowns d'attribution `validated_by`...) : ici on répond à
    « à qui se référer selon le poste », utilisé par la Gestion de crise (`CrisisRoadmap.jsx`) et
    les Incidents (`IncidentRoadmap.jsx`) pour savoir qui contacter en interne. `position` en texte
    libre (pas une liste fermée) — une organisation peut avoir des postes non prévus d'avance.
    `service_id` (optionnel) rattache le poste à un `Service` — `SET NULL` et non `CASCADE` :
    supprimer un service ne doit pas supprimer les postes qui y étaient rattachés.
    `reports_to_id` (31/07/2026, optionnel) : auto-référence vers un autre `OrganizationRole`,
    alimente le mini organigramme par service (Administration > Services). `SET NULL` comme
    `service_id` — supprimer un manager ne doit pas supprimer ses subordonnés, juste les détacher.
    Cycles empêchés côté API (routers/organization_roles.py), jamais au niveau DB."""
    __tablename__ = "organization_roles"

    id             = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    position       = Column(String, nullable=False)
    name           = Column(String, nullable=False)
    email          = Column(String)
    reports_to_id  = Column(_UUID(as_uuid=True), ForeignKey("organization_roles.id", ondelete="SET NULL"), nullable=True)
    service_id  = Column(_UUID(as_uuid=True), ForeignKey("services.id", ondelete="SET NULL"), nullable=True)
    created_at  = Column(DateTime(timezone=True), server_default=_sfunc.now())


class WindowsAppMapping(Base):
    """Correspondance nom d'application Windows -> produit CPE (31/07/2026). Les noms de
    paquets Linux se dérivent par convention (`services/cpe_matcher.py::_package_candidates`),
    mais un nom d'application Windows est du texte libre de registre ("PuTTY release 0.81
    (64-bit)", "F-Secure Policy Manager 15.30 build 96312...") sans convention exploitable —
    d'où cette table réglable en base plutôt qu'un heuristique deviné ("premier mot" aurait
    donné "microsoft" pour "Microsoft Edge"). `pattern` est une sous-chaîne (insensible à la
    casse) recherchée dans le nom affiché, pas une égalité stricte : survit aux changements de
    version/architecture dans le nom sans qu'il faille rajouter une ligne à chaque mise à jour
    du logiciel. Alimentée au fil des applications réellement rencontrées sur le parc, jamais
    pré-remplie par supposition. `cpe_vendor` est informatif seulement — le matching
    (`_cve_products`) n'indexe que par produit, jamais par couple vendeur+produit."""
    __tablename__ = "windows_app_mappings"

    id          = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    pattern     = Column(String, nullable=False, unique=True)
    cpe_product = Column(String, nullable=False)
    cpe_vendor  = Column(String)
    created_at  = Column(DateTime(timezone=True), server_default=_sfunc.now())


class User(Base):
    """Compte de connexion réel (30/07/2026) — authentification email/mot de passe, RBAC
    binaire (`role` : admin | analyst). Distinct du registre `Analyst` ci-dessus (noms
    utilisés dans les menus déroulants d'attribution `validated_by`) : pas de fusion pour
    cette phase, cf. STATUS.md. Un compte créé s'auto-intègre au registre `Analyst` (même
    nom) pour éviter la double saisie — cf. routers/users.py::_ensure_analyst.

    `allowed_pages` (31/07/2026) : restriction de modules/pages pour un compte `analyst`
    (`role == "admin"` voit toujours tout, ce champ n'est alors jamais consulté). `NULL` =
    accès total (comportement par défaut à la création) ; une liste = uniquement les pages
    listées (clés de `services/access_control.py::PAGE_KEYS`). Appliqué à la fois côté
    frontend (nav/routes) et côté API (`auth_deps.py::require_page`, posé par module sur les
    routers dans main.py) — un simple masquage visuel sans contrôle serveur n'aurait aucune
    valeur de sécurité (c'est exactement pour ça que l'ancien sélecteur "Je suis…" avait été
    retiré le 30/07/2026, cf. CLAUDE.md)."""
    __tablename__ = "users"

    id                   = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    email                = Column(String, nullable=False, unique=True)
    full_name            = Column(String, nullable=False)
    password_hash        = Column(String, nullable=False)
    role                 = Column(String, nullable=False, default="analyst")  # admin | analyst
    is_active            = Column(_Boolean, nullable=False, default=True)
    must_change_password = Column(_Boolean, nullable=False, default=False)
    allowed_pages        = Column(JSON, nullable=True)  # None = accès total ; sinon liste de clés PAGE_KEYS
    created_at           = Column(DateTime(timezone=True), server_default=_sfunc.now())
    updated_at           = Column(DateTime(timezone=True), server_default=_sfunc.now())


class UserSession(Base):
    """Session serveur (30/07/2026, table `sessions`) — le cookie ne porte qu'un token
    aléatoire opaque ; seul son hash SHA-256 est stocké ici (`session_token_hash`), jamais
    le token en clair. Nom de classe `UserSession` (pas `Session`) pour éviter toute
    collision avec `sqlalchemy.ext.asyncio.AsyncSession` importé ailleurs dans le code."""
    __tablename__ = "sessions"

    id                 = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    user_id            = Column(_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_token_hash = Column(String, nullable=False, unique=True)
    ip_address         = Column(String)
    user_agent         = Column(Text)
    expires_at         = Column(DateTime(timezone=True), nullable=False)
    created_at         = Column(DateTime(timezone=True), server_default=_sfunc.now())


class AuthAuditLog(Base):
    """Journal d'audit des connexions (30/07/2026) — traçabilité + base du verrou
    anti-bruteforce (comptage par email/IP, cf. services/auth.py::count_recent_failures).
    Loggue TOUTES les tentatives, y compris email inexistant, sinon le comptage par email
    n'a aucun sens (permettrait l'énumération de comptes)."""
    __tablename__ = "auth_audit_logs"

    id            = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    event_type    = Column(String, nullable=False)  # LOGIN_SUCCESS | LOGIN_FAILED | LOGOUT | ROLE_CHANGE
    user_id       = Column(_UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    email_attempt = Column(String)
    ip_address    = Column(String)
    user_agent    = Column(Text)
    details       = Column(_JSONB)
    created_at    = Column(DateTime(timezone=True), server_default=_sfunc.now())


class DocumentType(Base):
    """Type de document de gouvernance (31/07/2026) — module Documentation, conformité NIS 2.
    Liste ouverte, ajoutable sans code (même principe que Service/OrganizationRole) : PSSI,
    Charte Administrateur, Charte Utilisateur, Organigramme... en seed initial, l'utilisateur
    peut en ajouter d'autres. Spécifique au module Documentation — pas géré dans Administration
    contrairement à Service/OrganizationRole, qui sont consommés par plusieurs modules."""
    __tablename__ = "document_types"

    id          = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    name        = Column(String, nullable=False, unique=True)
    created_at  = Column(DateTime(timezone=True), server_default=_sfunc.now())


class Document(Base):
    """Document de gouvernance uploadé (31/07/2026) — fichier sur disque (volume Docker
    `documents`, monté uniquement dans `backend`), toujours renommé en `{uuid4()}{ext}` avant
    écriture (`filename` du client conservé en métadonnée d'affichage seulement, jamais comme
    chemin réel — path traversal, même principe qu'IncidentAttachment). Validation dans
    `services/document_storage.py` (taille, extension, signature — PDF/Word/Excel).

    Pas de table de versions séparée : chaque upload crée une nouvelle ligne du même
    `document_type_id`, rien n'est supprimé automatiquement — la liste triée par `uploaded_at`
    décroissant EST l'historique, la plus récente est la version courante.

    `document_type_id` sans `ondelete` (défaut Postgres NO ACTION) : supprimer un type encore
    utilisé par des documents est bloqué au niveau DB, intercepté proprement en 409 côté API
    (routers/documents.py) plutôt que de laisser remonter une erreur SQL brute."""
    __tablename__ = "documents"

    id               = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    document_type_id = Column(_UUID(as_uuid=True), ForeignKey("document_types.id"), nullable=False, index=True)
    filename         = Column(String, nullable=False)
    stored_filename  = Column(String, nullable=False)
    size_bytes       = Column(Integer, nullable=False)
    uploaded_by      = Column(String, nullable=False)
    notes            = Column(Text)
    uploaded_at      = Column(DateTime(timezone=True), server_default=_sfunc.now())


class NoteTheme(Base):
    """Thème de notes (12/08/2026, module Documentation > Notes) — remplace le glossaire plat
    initial (terme/définition/maîtrisé) suite à docs/Notes.md : l'outil devient une prise de
    notes structurée (Thème > Sujet > Markdown), pas un simple dico. Registre ouvert, seedé
    avec 4 thèmes par défaut (Cybersécurité/Réseau/Système/IA, cf. schema_patches.sql) mais
    ajoutable sans code, même principe que DocumentType/Service. `icon` est un simple emoji
    (cohérent avec le reste de l'app, cf. CLAUDE.md § Style — pas la palette de clés fixes
    d'icônes SVG utilisée par ServiceIcon.jsx, overkill ici pour un registre personnel)."""
    __tablename__ = "note_themes"

    id          = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    name        = Column(String, nullable=False, unique=True)
    icon        = Column(String, nullable=False, default='📁')
    color       = Column(String, nullable=False, default='#8b949e')
    created_at  = Column(DateTime(timezone=True), server_default=_sfunc.now())


class NoteSubject(Base):
    """Sujet (fiche de cours) au sein d'un thème — contenu en Markdown, rendu via
    MarkdownNote.jsx (marked + DOMPurify, déjà utilisé pour les annotations d'analyste) côté
    frontend. `theme_id` CASCADE : supprimer un thème supprime ses sujets, assumé (pas de
    sujets orphelins à gérer séparément)."""
    __tablename__ = "note_subjects"

    id                = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    theme_id          = Column(_UUID(as_uuid=True), ForeignKey("note_themes.id", ondelete="CASCADE"), nullable=False, index=True)
    title             = Column(String, nullable=False)
    content_markdown  = Column(Text, nullable=False, default='')
    created_at        = Column(DateTime(timezone=True), server_default=_sfunc.now())
    updated_at        = Column(DateTime(timezone=True), server_default=_sfunc.now())


class NoteImage(Base):
    """Image insérée dans un sujet (glisser-déposer/upload, cf. services/note_images.py) —
    fichier sur disque (volume Docker `note_images`), même principe que Document/
    IncidentAttachment (nom renommé en `{uuid4()}{ext}`, jamais le nom client comme chemin
    réel). `subject_id` nullable : une image peut être déposée avant la première sauvegarde
    du sujet (le textarea insère déjà `![...](url)` à l'upload, le sujet n'existe pas encore
    forcément en base à cet instant) — reliée après coup si besoin, sinon reste orpheline
    sans conséquence (pas de nettoyage automatique pour l'instant, cf. STATUS.md)."""
    __tablename__ = "note_images"

    id               = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    subject_id       = Column(_UUID(as_uuid=True), ForeignKey("note_subjects.id", ondelete="CASCADE"), nullable=True)
    filename         = Column(String, nullable=False)
    stored_filename  = Column(String, nullable=False)
    size_bytes       = Column(Integer, nullable=False)
    uploaded_at      = Column(DateTime(timezone=True), server_default=_sfunc.now())


class Audit(Base):
    """Module Audits (03/08/2026, cf. docs/AUDITS.md) — hub de suivi des audits techniques
    (architecture/configuration/code/pentest/redteam), un seul modèle pour les 5 types
    (`type`). CBR héberge et trace l'audit, ne l'exécute jamais (même principe de
    non-intervention que pour les serveurs, CLAUDE.md §1) : aucun scan, aucun outil offensif,
    seuls les résultats rédigés à la main entrent.

    Garde-fou central : `scope`/`rules_of_engagement`/`authorized_by`/`authorized_at` sont
    posés ensemble par `POST /audits/{id}/authorize` (routers/audits.py) et deviennent
    immuables ensuite — appliqué côté API, pas en contrainte DB, même logique que
    `aware_at_locked` sur Incident. Aucun finding ne peut être saisi tant que `status`
    vaut `cadrage` (cf. AuditFinding)."""
    __tablename__ = "audits"

    id                  = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    title               = Column(String, nullable=False)
    type                = Column(String, nullable=False)   # architecture|configuration|code|pentest|redteam
    methodology         = Column(String)                    # boite_noire|boite_grise|boite_blanche
    referential         = Column(String)                     # libre : OWASP ASVS, CIS, PTES, ANSSI...
    status              = Column(String, nullable=False, default="cadrage")  # cadrage|autorise|en_cours|termine|archive

    scope               = Column(Text)
    rules_of_engagement = Column(Text)
    authorized_by       = Column(String)   # immuable une fois posé
    authorized_at       = Column(DateTime(timezone=True))   # immuable une fois posé

    conducted_by        = Column(String)   # registre Analyst existant
    started_at          = Column(DateTime(timezone=True))
    ended_at            = Column(DateTime(timezone=True))
    executive_summary   = Column(Text)     # markdown, rédigé en fin d'audit

    created_at          = Column(DateTime(timezone=True), server_default=_sfunc.now())


class AuditAsset(Base):
    """Liaison audit ↔ actif déjà connu de CBR (les 72 machines importées d'AD/SSH) — vraie
    table de liaison, pas un JSON comme Incident.affected_asset_ids : un audit cible un
    périmètre technique précis, une vraie clé composite permet un JOIN/index propre."""
    __tablename__ = "audit_assets"

    audit_id = Column(_UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), primary_key=True)
    asset_id = Column(_UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True)


class AuditFinding(Base):
    """Finding d'audit — ne peut être créé que sur un audit `autorise`/`en_cours`/`termine`/
    `archive` (jamais `cadrage`, garde-fou vérifié dans routers/audits.py). Le retest
    (`retested_at`/`retest_result`/`retested_by`) est ce qui distingue un processus d'audit
    mature d'une simple liste de problèmes — cf. docs/AUDITS.md §5."""
    __tablename__ = "audit_findings"

    id                 = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    audit_id           = Column(_UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    title              = Column(String, nullable=False)
    description        = Column(Text)
    severity           = Column(String, nullable=False)   # CRITICAL|HIGH|MEDIUM|LOW|INFO (SeverityBadge.jsx)
    cvss_vector        = Column(String)
    cvss_score         = Column(Float)
    cwe_id             = Column(String)     # ex: CWE-89
    owasp_ref          = Column(String)     # ex: A03:2021
    affected_asset_id  = Column(_UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    affected_component = Column(String)     # URL, endpoint, fichier:ligne (audit de code)
    cve_id             = Column(String, ForeignKey("cves.cve_id"), nullable=True)   # si le finding retombe sur une CVE connue
    proof_of_concept   = Column(Text)
    impact             = Column(Text)
    recommendation     = Column(Text)
    status             = Column(String, nullable=False, default="ouvert")  # ouvert|remediation_planifiee|corrige|risque_accepte|faux_positif
    mitre_techniques   = Column(_JSONB, default=list)   # ["T1078", "T1021.001"] — surtout redteam

    discovered_at      = Column(DateTime(timezone=True), server_default=_sfunc.now())
    retested_at        = Column(DateTime(timezone=True))
    retest_result      = Column(String)   # corrige|partiellement_corrige|non_corrige
    retested_by        = Column(String)

    created_at         = Column(DateTime(timezone=True), server_default=_sfunc.now())


class AuditFindingHistory(Base):
    """Transitions de statut d'un finding, append-only — même pattern que
    services/vuln_history.py::record_status_change (pas incident_timeline.py, qui est un
    journal d'événements libres : décision de ne pas fusionner les trois formes de journal
    du projet, leurs formes diffèrent trop, cf. docs/AUDITS.md §4)."""
    __tablename__ = "audit_finding_history"

    id          = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    finding_id  = Column(_UUID(as_uuid=True), ForeignKey("audit_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    old_status  = Column(String)
    new_status  = Column(String, nullable=False)
    changed_at  = Column(DateTime(timezone=True), nullable=False, server_default=_sfunc.now())
    changed_by  = Column(String, nullable=False)
    notes       = Column(Text)


class AuditAttachment(Base):
    """Pièce jointe (PDF/PNG/JPEG, cf. services/audit_attachments.py) — soit le mandat écrit
    d'un audit (`audit_id` posé, `finding_id` NULL), soit une capture d'écran de preuve d'un
    finding (`finding_id` posé, `audit_id` NULL) : une seule table, exactement un des deux FK
    posé selon l'endpoint d'upload utilisé (mêmes schéma/validation dans les deux cas). Fichier
    toujours renommé `{uuid4()}{ext}` sur disque (volume `audit_attachments`), jamais sous le
    nom fourni par le client (path traversal, même principe qu'IncidentAttachment)."""
    __tablename__ = "audit_attachments"

    id              = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    audit_id        = Column(_UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), nullable=True, index=True)
    finding_id      = Column(_UUID(as_uuid=True), ForeignKey("audit_findings.id", ondelete="CASCADE"), nullable=True, index=True)
    kind            = Column(String, nullable=False, default="mandate")   # mandate|evidence
    filename        = Column(String, nullable=False)
    stored_filename = Column(String, nullable=False)
    size_bytes      = Column(Integer, nullable=False)
    uploaded_by     = Column(String, nullable=False)
    uploaded_at     = Column(DateTime(timezone=True), server_default=_sfunc.now())


class NetworkStatus(Base):
    """État réseau d'un actif remonté par une sonde externe (04/08/2026) — Meraki en
    premier (`services/meraki_client.py`), PRTG ensuite le même jour
    (`services/prtg_client.py` + `prtg_matcher.py`) : `source` distingue les deux, jamais
    nommée en dur dans le code métier au-delà de ces deux modules. Comble le vide identifié
    lors de la discussion PRTG du 31/07/2026 — rapprochement par hostname aux `Asset`
    existants ; les deux sondes peuvent créer un `Asset` sur demande explicite
    (`import_new_assets`, jamais par défaut), pour les devices sans correspondance —
    PRTG exclut en plus structurellement ses propres objets internes (sonde, serveur
    central, cf. prtg_matcher.py::_is_prtg_internal) ; badge affiché à la fois sur
    Actifs et sur Inventaire.

    `metrics` en JSON plutôt que des colonnes figées : l'intention de « scaler » vers
    d'autres métriques (bande passante, CPU...) plus tard, déjà annoncée par l'utilisateur,
    ne doit pas exiger une migration à chaque nouvelle métrique. `status`/`last_reported_at`
    restent des colonnes dédiées (pas dans `metrics`) car lus à chaque affichage de badge —
    éviter de parser le JSON juste pour savoir si un actif est en ligne.

    Une ligne par (actif, source) — mise à jour en place à chaque cycle de synchronisation,
    pas un historique (cf. `Asset.last_scan`/`last_scan_result`, même esprit d'instantané)."""
    __tablename__ = "network_status"

    id               = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    asset_id         = Column(_UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    source           = Column(String, nullable=False, default="meraki")   # extensible à d'autres sondes plus tard
    status           = Column(String)          # online | offline | alerting | dormant (vocabulaire Meraki)
    last_reported_at = Column(DateTime(timezone=True))
    metrics          = Column(_JSON, default=dict)
    updated_at       = Column(DateTime(timezone=True), server_default=_sfunc.now(), onupdate=_sfunc.now())

    __table_args__ = (
        _Index("uq_network_status_asset_source", "asset_id", "source", unique=True),
    )


class Agent(Base):
    """Agent posé sur un poste Windows/Linux (12/08/2026, module Sécurité > Agents) — identité
    d'appareil non-humaine, distincte des comptes `User` (RBAC admin/analyst). Complète le scan
    centralisé SSH/WinRM existant (`services/asset_scanner.py`) pour les postes qu'il atteint
    mal (éteints, hors réseau, VPN) — jamais un remplacement des 80 VM serveurs.

    `credential_hash` : SHA-256 du secret généré à l'enrôlement (cf. routers/agents.py),
    jamais le secret en clair côté DB — même idiome que `UserSession.session_token_hash`
    (services/auth.py), pas le Fernet réversible de services/crypto.py : le backend n'a
    jamais besoin de rejouer ce secret ailleurs.

    Révocation par flag (`status`/`revoked_at`), pas de suppression de ligne — un agent est
    une identité d'appareil digne d'un audit trail, plus proche de `User.is_active` que de
    `delete_session` (session humaine éphémère, celle-là supprimée pour de bon)."""
    __tablename__ = "agents"

    id              = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    asset_id        = Column(_UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    hostname        = Column(String, nullable=False)   # auto-déclaré par l'agent à l'enrôlement
    os              = Column(String, nullable=False)   # "windows" | "linux"
    credential_hash = Column(String, nullable=False, unique=True)
    status          = Column(String, nullable=False, default="enrolled")   # enrolled | revoked
    enrolled_at     = Column(DateTime(timezone=True), server_default=_sfunc.now())
    last_seen_at    = Column(DateTime(timezone=True))
    agent_version   = Column(String)   # version du binaire allsafe-agent, déclarée à chaque check-in
    # Scan à la demande (13/08/2026) : posé par un admin (POST /agents/{id}/request-scan),
    # jamais lu que par l'agent lui-même (GET /agents/pending, sondage court côté client) —
    # le serveur n'initie jamais le contact (CLAUDE.md §1). Effacé par le check-in qu'il déclenche.
    pending_scan_requested_at = Column(DateTime(timezone=True))
    # Rapport de coupure (13/08/2026) : dernière coupure réseau connue, déclarée par l'agent
    # à son prochain check-in réussi (services/daemon.rs::DaemonState) — jamais effacé
    # silencieusement, reste visible jusqu'à ce qu'un nouveau rapport le remplace.
    last_gap_started_at      = Column(DateTime(timezone=True))
    last_gap_failed_attempts = Column(Integer)
    revoked_at      = Column(DateTime(timezone=True))
    revoked_by      = Column(String)
    # Enrôlement à l'échelle (13/08/2026) — quel jeton a créé cet agent, dérivable en sens
    # inverse (`Agent.enrollment_token_id == token.id`) pour lister tous les postes enrôlés
    # via un même jeton réutilisable. Remplace l'ancien `AgentEnrollmentToken.used_by_agent_id`
    # scalaire, qui ne pouvait référencer qu'un seul agent — inadapté à un jeton multi-usages.
    enrollment_token_id = Column(_UUID(as_uuid=True), ForeignKey("agent_enrollment_tokens.id", ondelete="SET NULL"), nullable=True)


class AgentEnrollmentToken(Base):
    """Jeton d'enrôlement (12/08/2026, généralisé à l'échelle le 13/08/2026) — généré par un
    admin (Sécurité > Agents), collé dans l'agent à l'installation, échangé contre une
    identité `Agent` propre à chaque poste. Même principe TOFU que `services/ssh_trust.py` :
    jamais de ré-apprentissage silencieux, un ré-enrôlement (ou un poste supplémentaire au-
    delà de `max_uses`) nécessite un nouveau jeton généré explicitement par un admin.

    `max_uses`/`use_count` (13/08/2026) remplacent l'ancien `used_at`/`used_by_agent_id`
    scalaires (usage strictement unique) — `max_uses=1` (défaut) reproduit exactement
    l'ancien comportement, `max_uses>1` permet un déploiement de parc avec un seul jeton
    partagé (ex. embarqué dans un script de démarrage GPO/une image de poste). Révocable à
    tout moment quel que soit `use_count` — stoppe les enrôlements futurs, n'affecte jamais
    les postes déjà enrôlés via ce jeton (cf. `Agent.enrollment_token_id`).

    `asset_id` optionnel : lié à un actif déjà existant (bascule sa méthode de collecte vers
    "agent") — n'a de sens que pour `max_uses=1` (un jeton multi-usages ne peut pas se lier à
    un actif précis, chaque enrôlement crée le sien, comme le jeton "libre" à usage unique)."""
    __tablename__ = "agent_enrollment_tokens"

    id                = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    token_hash        = Column(String, nullable=False, unique=True)
    asset_id          = Column(_UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True)
    label             = Column(String)              # note libre admin, ex. "Poste RH-042"
    created_by        = Column(String, nullable=False)
    created_at        = Column(DateTime(timezone=True), server_default=_sfunc.now())
    expires_at        = Column(DateTime(timezone=True), nullable=False)
    max_uses          = Column(Integer, nullable=False, default=1)
    use_count         = Column(Integer, nullable=False, default=0)


class ScanPolicy(Base):
    """Politique de scan planifié par criticité (17/08/2026) — 4 lignes fixes, une par valeur
    de `asset.tags.criticite` (critique/haute/moyenne/faible), chacune éditable indépendamment
    depuis Paramètres > Intégrations. Pilote `services/scan_policy.py::run_scan_for_criticite`
    (scan SSH/WinRM + durcissement web des actifs de ce groupe), déclenché par le poller horaire
    `tasks.scheduled_tasks.check_scan_policies`. Pas de colonne d'état d'exécution ici : le
    dernier run est tracé dans `SyncState` (clé `scan_policy_<criticite>`), même mécanisme que
    les autres intégrations (kev/exploit_maturity/meraki/prtg...) plutôt qu'un 2e mécanisme de
    suivi dédié."""
    __tablename__ = "scan_policies"

    id         = Column(_UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    criticite  = Column(String, nullable=False, unique=True)
    enabled    = Column(Boolean, nullable=False, default=True)
    frequency  = Column(String, nullable=False)   # 'daily' | 'weekly'
    hour       = Column(Integer, nullable=False, default=0)   # 0-23, heure locale Europe/Paris
    # 0=lundi..6=dimanche (date.weekday()), utilisé seulement si frequency == 'weekly'
    weekday    = Column(Integer, nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=_sfunc.now(), onupdate=_sfunc.now())
