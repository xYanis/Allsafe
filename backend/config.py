"""
config.py
Chargement et validation des variables d'environnement.
"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Base de données
    DB_USER: str = "cybervuln"
    DB_PASSWORD: str = "changeme"
    DB_NAME: str = "cybervuln"
    DB_HOST: str = "db"

    # Plafond de requêtes HTTP autorisées à détenir une session DB simultanément
    # (10/08/2026, cf. audit/AUDIT_SECURITE.md — le fuzzing schemathesis a fait geler le
    # backend entier >2min lors d'une rafale de requêtes concurrentes). Sémaphore
    # côté `database.py::get_session`, pas un pool SQLAlchemy classique : NullPool
    # reste nécessaire pour Celery (cf. commentaire sur `engine` dans database.py) —
    # un sémaphore ne retient ni ne réutilise aucune connexion entre deux requêtes,
    # il limite juste combien peuvent en détenir une EN MÊME TEMPS, donc compatible.
    # 5 = décision explicite de l'utilisateur (10/08/2026), relevé à 15 le 14/08/2026 :
    # confirmé trop restreint en usage réel — Dashboard.jsx génère à lui seul 8 requêtes
    # simultanées toutes les 30s (+ 1/3s de suivi patch-check), de quoi saturer le sémaphore
    # dès qu'un 2e onglet/utilisateur était actif en même temps (cf. STATUS.md 14/08/2026).
    DB_MAX_CONCURRENT_SESSIONS: int = 15

    # Rôle applicatif à privilèges réduits (least privilege) : DML seulement,
    # non-superuser, aucun DDL — l'app tourne avec lui, pas avec le superuser
    # `cybervuln` (réservé à l'admin/migrations/déception). Si non renseigné,
    # repli sur DB_USER/DB_PASSWORD (rétrocompatible). Créé par
    # backend/db/app_role.sql. ⚠️ create_all ne peut plus créer de table neuve
    # sous ce rôle : toute nouvelle table de modèle doit être créée par l'owner
    # (cybervuln) d'abord — cf. docs/ARCHITECTURE.md § Rôle applicatif.
    APP_DB_USER: Optional[str] = None
    APP_DB_PASSWORD: Optional[str] = None

    @property
    def DATABASE_URL(self) -> str:
        user = self.APP_DB_USER or self.DB_USER
        password = self.APP_DB_PASSWORD or self.DB_PASSWORD
        return f"postgresql://{user}:{password}@{self.DB_HOST}/{self.DB_NAME}"

    # Redis
    REDIS_URL: str = "redis://redis:6379"

    # Claude API (non utilisé — analyses effectuées localement)
    ANTHROPIC_API_KEY: Optional[str] = None

    # NVD
    NVD_API_KEY: Optional[str] = None

    # GitHub (recherche de code, Surveillance Identités — services/leak_lookup.py).
    # Token personnel gratuit, sans scope requis (l'API de recherche de code exige une
    # authentification même pour du contenu public, contrairement aux autres endpoints
    # GitHub). Vérification silencieusement désactivée si absent — pas une erreur.
    GITHUB_TOKEN: Optional[str] = None

    # Active Directory
    AD_SERVER: Optional[str] = None
    AD_USER: Optional[str] = None
    AD_PASSWORD: Optional[str] = None
    AD_BASE_DN: Optional[str] = None
    AD_OU: Optional[str] = None
    # Défaut False (StartTLS sur ldap:// existant, sans toucher port/URL) plutôt que
    # True (ldaps:// implicite, 636) — safe par défaut : on ne sait pas si le DC a
    # LDAPS activé, alors que StartTLS sur 389 est quasi universel sur AD. Passer à
    # True + AD_SERVER=ldaps://...:636 si le DC le permet (cf. audit/AUDIT_SECURITE.md #3).
    AD_USE_TLS: bool = False

    # SSH Linux
    SSH_USER: Optional[str] = None
    SSH_KEY_PATH: Optional[str] = None
    LINUX_HOSTS: Optional[str] = None
    SSH_KNOWN_HOSTS: Optional[str] = None  # défaut résolu à /app/ssh-state/known_hosts (TOFU, cf. ssh_trust.py)

    # WinRM (vérification patches Windows — lecture seule)
    WINRM_USER: Optional[str] = None      # DOMAINE\utilisateur (ex: AER\cybervuln)
    WINRM_PASSWORD: Optional[str] = None  # Si vide, utilise AD_PASSWORD
    WINRM_PORT: int = 5985                # 5985 HTTP, 5986 HTTPS
    WINRM_TRANSPORT: str = "ntlm"         # ntlm / kerberos / credssp

    # WithSecure Elements API (lecture seule — client "Read-only" côté Security
    # Center). Complète l'EDR/EPP déjà déployé sur le parc : events/incidents +
    # correctifs manquants avec CVE/CVSS (cf. services/withsecure_client.py).
    # Le module Vulnerability Management (ex-Radar) n'est PAS souscrit — seule
    # l'API Elements standard est accessible.
    WITHSECURE_API_CLIENT_ID: Optional[str] = None
    WITHSECURE_API_CLIENT_SECRET: Optional[str] = None

    # Cisco Meraki Dashboard API (lecture seule — clé API, jamais de write côté Meraki
    # depuis CBR). Supervision réseau en ligne/hors ligne (cf. services/meraki_client.py) —
    # comble le vide identifié lors de la discussion PRTG du 31/07/2026, jamais codée.
    # MERAKI_ORGANIZATION_ID optionnel : si absent, la première organisation visible par
    # la clé est utilisée (cf. get_organizations()) — à renseigner explicitement si la
    # clé a accès à plusieurs organisations.
    MERAKI_API_KEY: Optional[str] = None
    MERAKI_ORGANIZATION_ID: Optional[str] = None

    # PRTG Network Monitor — API cœur (pas Multiboard, qui sert à agréger des widgets
    # visuels entre instances, pas à interroger le statut d'un device par hostname).
    # Lecture seule — auth par apitoken (query param `apitoken`, supporté nativement
    # par l'API PRTG en alternative à username/passhash). Même rôle que Meraki
    # (cf. services/prtg_client.py) : source supplémentaire de la table network_status.
    PRTG_URL: Optional[str] = None
    PRTG_API_TOKEN: Optional[str] = None
    # true (défaut) = vérification TLS standard. À passer à false si le serveur PRTG
    # présente un certificat signé par une CA interne (AD CS...) non présente dans le
    # magasin de confiance du conteneur — cas constaté en conditions réelles (04/08/2026,
    # CA `AER-ALADDIN-CA`). Explicite plutôt que désactivé en dur : ne pas affaiblir la
    # vérification pour un déploiement futur dont le certificat serait public.
    PRTG_VERIFY_TLS: bool = True

    # GLPI — CMDB patrimoine (lecture seule, API REST). Contrairement à Meraki/PRTG,
    # n'alimente jamais NetworkStatus ni ne crée d'actif : enrichit uniquement les actifs
    # déjà connus (modèle, n° de série, n° d'inventaire, fabricant, localisation) — décision
    # explicite de l'utilisateur (11/08/2026, cf. services/glpi_matcher.py). Auth en deux
    # jetons (App-Token du client API + User-Token du compte de service dédié en lecture
    # seule) → Session-Token via initSession, comme documenté dans CLAUDE.md § Authentification
    # externe. GLPI_URL pointe le fichier apirest.php, pas l'interface web (ex :
    # https://glpi.exemple.local/apirest.php).
    GLPI_URL: Optional[str] = None
    GLPI_APP_TOKEN: Optional[str] = None
    GLPI_USER_TOKEN: Optional[str] = None

    # vCenter Server (13/08/2026, intégration vSphere/ESXi) — lecture seule, pyVmomi. Un seul
    # point de connexion (vCenter, pas d'ESXi standalone dans ce parc) qui agrège tous les
    # vim.HostSystem qu'il gère, même esprit que "MERAKI_ORGANIZATION_ID absent = toutes les
    # organisations visibles par la clé" ci-dessus. Compte de service en rôle "Read-only" côté
    # vCenter — jamais d'écriture. Alimente Asset.cpe_list (matching CVE hyperviseur, cf.
    # services/vsphere_matcher.py) ; l'inventaire VM par hôte reste informatif (Asset.hardware),
    # aucune VM n'est créée comme Asset dans cette passe.
    VCENTER_URL: Optional[str] = None
    VCENTER_USER: Optional[str] = None
    VCENTER_PASSWORD: Optional[str] = None
    # true (défaut) = vérification TLS standard. À passer à false si vCenter présente un
    # certificat auto-signé — quasi systématique en on-prem, même logique que PRTG_VERIFY_TLS.
    VCENTER_VERIFY_TLS: bool = True

    # App
    # Tâches lancées au démarrage du backend (corrélation CVE puis cycle de patch
    # check). Activées par défaut : c'est le comportement attendu en production,
    # où un redémarrage doit rattraper ce qui a été manqué pendant l'arrêt.
    # Les passer à false permet de **redémarrer le backend sans effet de bord sur
    # les données** — utile en développement, où un simple rechargement de code
    # créait des vulnérabilités et basculait des statuts, rendant illisibles les
    # écarts de chiffres constatés par l'utilisateur (session 21/07/2026).
    STARTUP_MATCHING: bool = True
    STARTUP_PATCH_CHECK: bool = True

    SECRET_KEY: str = "changeme"
    DEBUG: bool = False

    # Authentification (30/07/2026). Bootstrap : si la table `users` est vide au
    # démarrage et que ces deux variables sont renseignées, le premier compte admin
    # est créé automatiquement (must_change_password=true) — cf. main.py::lifespan.
    # À retirer de `.env` après la première connexion (cf. CHECKLIST_DOCKER.md).
    BOOTSTRAP_ADMIN_EMAIL: Optional[str] = None
    BOOTSTRAP_ADMIN_PASSWORD: Optional[str] = None
    # Cookie de session `Secure` : nécessite HTTPS. Aucun TLS dans docker-compose.yml
    # actuellement (déploiement HTTP interne) — à passer à true si un reverse-proxy
    # TLS est ajouté devant l'app.
    COOKIE_SECURE: bool = False

    # Jeton partagé pour les appels internes worker → backend (07/08/2026) — les
    # tâches Celery (patch_check_periodic, run_cpe_matching_for_asset_task)
    # déclenchent POST /api/patch-check/run via HTTP plutôt qu'un appel direct au
    # service (état du cycle en mémoire côté process `backend`, cf.
    # tasks/scheduled_tasks.py), mais cette route exige une session utilisateur
    # valide — inexistante côté worker. Optionnel : si absent, ces déclenchements
    # échouent proprement (401, retry Celery) sans rien casser d'autre. Jamais
    # envoyé au navigateur, jamais dans les logs en clair — cf. auth_deps.py::
    # require_page_or_internal.
    INTERNAL_API_TOKEN: Optional[str] = None

    class Config:
        env_file = ".env"


settings = Settings()


# Fail-fast : refuser de démarrer avec un secret laissé à sa valeur par défaut
# "changeme" (`.env` non chargé, mauvais montage, variable oubliée). Sans ce
# garde-fou, l'app démarrerait silencieusement avec un secret prévisible — le cas
# le plus grave pour SECRET_KEY, d'où dérive la clé Fernet qui chiffre les mots de
# passe SSH stockés en base (services/crypto.py) : un secret prévisible annule ce
# chiffrement. Mieux vaut un échec bruyant au démarrage qu'une sécurité illusoire.
_defaulted = [
    name for name in ("SECRET_KEY", "DB_PASSWORD")
    if getattr(settings, name) == "changeme"
]
if _defaulted:
    raise RuntimeError(
        f"Secret(s) non configuré(s), valeur par défaut 'changeme' détectée : "
        f"{', '.join(_defaulted)}. Renseigner ces variables dans .env avant de démarrer."
    )
