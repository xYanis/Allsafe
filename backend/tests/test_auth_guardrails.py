"""
tests/test_auth_guardrails.py
Authentification (services/auth.py, auth_deps.py, main.py) :
- hash/verify de mot de passe (bcrypt) fait un aller-retour correct et rejette un mauvais
  mot de passe ou un hash malformé sans lever d'exception,
- verrou anti-bruteforce : les seuils par email et par IP déclenchent bien is_locked_out,
- garde-fou anti-régression : toute route /api/* (hors liste blanche explicite) doit porter
  require_auth ou require_admin dans ses dépendances résolues — empêche un futur router
  monté dans main.py sans dependencies= par oubli.

Tests unitaires purs, sans base de données ni serveur HTTP (mêmes conventions que
test_incidents_guardrails.py) : `session`/`count_recent_failures` mockés.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

import services.auth as auth_module
from auth_deps import require_agent
from services.auth import (
    LOCKOUT_MAX_PER_EMAIL,
    LOCKOUT_MAX_PER_IP,
    MAX_CONCURRENT_SESSIONS,
    hash_password,
    verify_password,
)


class TestPasswordHashing:
    def test_roundtrip(self):
        hashed = hash_password("un-mot-de-passe-bien-solide")
        assert verify_password("un-mot-de-passe-bien-solide", hashed)

    def test_wrong_password_rejected(self):
        hashed = hash_password("un-mot-de-passe-bien-solide")
        assert not verify_password("autre-chose", hashed)

    def test_malformed_hash_does_not_raise(self):
        assert not verify_password("x", "pas-un-hash-bcrypt")


class TestBruteForceLockout:
    async def test_not_locked_below_both_thresholds(self):
        with patch.object(auth_module, "count_recent_failures",
                           AsyncMock(side_effect=[LOCKOUT_MAX_PER_EMAIL - 1, LOCKOUT_MAX_PER_IP - 1])):
            assert not await auth_module.is_locked_out(MagicMock(), "a@b.c", "1.2.3.4")

    async def test_locked_at_email_threshold(self):
        with patch.object(auth_module, "count_recent_failures", AsyncMock(return_value=LOCKOUT_MAX_PER_EMAIL)):
            assert await auth_module.is_locked_out(MagicMock(), "a@b.c", "1.2.3.4")

    async def test_locked_at_ip_threshold_even_if_email_below(self):
        with patch.object(auth_module, "count_recent_failures",
                           AsyncMock(side_effect=[LOCKOUT_MAX_PER_EMAIL - 1, LOCKOUT_MAX_PER_IP])):
            assert await auth_module.is_locked_out(MagicMock(), "a@b.c", "1.2.3.4")


class TestPasswordResetLockout:
    """`/forgot-password` (18/08/2026, cf. audit/AUDIT_SECURITE.md #20) — n'avait
    initialement aucun verrou ni traçabilité, contrairement à /login. Verrou par IP
    uniquement (pas par email, cf. docstring `is_password_reset_locked_out`)."""

    async def test_not_locked_below_threshold(self):
        with patch.object(auth_module, "count_recent_failures", AsyncMock(return_value=LOCKOUT_MAX_PER_IP - 1)):
            assert not await auth_module.is_password_reset_locked_out(MagicMock(), "1.2.3.4")

    async def test_locked_at_ip_threshold(self):
        with patch.object(auth_module, "count_recent_failures", AsyncMock(return_value=LOCKOUT_MAX_PER_IP)):
            assert await auth_module.is_password_reset_locked_out(MagicMock(), "1.2.3.4")

    async def test_no_ip_never_locked(self):
        # Pas d'IP résolue (cas extrême) : rien à limiter, court-circuité avant tout
        # appel à count_recent_failures (pas d'exception sur ip_address=None).
        assert not await auth_module.is_password_reset_locked_out(MagicMock(), None)


class TestConcurrentSessionLimit:
    """Plafond de connexions simultanées (12/08/2026, demande utilisateur) — le login
    (routers/auth.py) refuse une nouvelle session dès que count_active_sessions() atteint
    MAX_CONCURRENT_SESSIONS, tous comptes confondus."""

    async def test_count_active_sessions_returns_scalar(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 3
        mock_session.execute = AsyncMock(return_value=mock_result)
        assert await auth_module.count_active_sessions(mock_session) == 3

    def test_limit_is_five(self):
        # Valeur métier explicite demandée par l'utilisateur — un test qui échoue si
        # quelqu'un la change par erreur en modifiant la constante seule.
        assert MAX_CONCURRENT_SESSIONS == 5


class TestRequireAgent:
    """require_agent (12/08/2026, module Sécurité > Agents) — même idiome que require_auth
    mais résout l'en-tête X-Agent-Token plutôt que le cookie de session."""

    async def test_missing_header_rejected(self):
        request = MagicMock()
        request.headers.get.return_value = None
        with pytest.raises(HTTPException) as exc:
            await require_agent(request, MagicMock())
        assert exc.value.status_code == 401

    async def test_unknown_token_rejected(self):
        request = MagicMock()
        request.headers.get.return_value = "some-token"
        session = MagicMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=result)
        with pytest.raises(HTTPException) as exc:
            await require_agent(request, session)
        assert exc.value.status_code == 401

    async def test_revoked_agent_rejected(self):
        request = MagicMock()
        request.headers.get.return_value = "some-token"
        revoked_agent = MagicMock(status="revoked")
        session = MagicMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = revoked_agent
        session.execute = AsyncMock(return_value=result)
        session.commit = AsyncMock()
        with pytest.raises(HTTPException) as exc:
            await require_agent(request, session)
        assert exc.value.status_code == 401

    async def test_enrolled_agent_accepted_and_last_seen_updated(self):
        request = MagicMock()
        request.headers.get.return_value = "some-token"
        agent = MagicMock(status="enrolled", last_seen_at=None)
        session = MagicMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = agent
        session.execute = AsyncMock(return_value=result)
        session.commit = AsyncMock()
        returned = await require_agent(request, session)
        assert returned is agent
        assert agent.last_seen_at is not None
        session.commit.assert_awaited_once()


class TestAllApiRoutesAreProtected:
    """Filet de sécurité : un router/une route ajoutée à main.py sans require_auth (ou
    require_admin) resterait ouverte par simple oubli — ce test l'empêche. Trois routes
    sont légitimement publiques au sens FastAPI (aucun `Depends` d'auth du tout, protégées
    par une vérification applicative interne à la place) : /login (formulaire de connexion),
    POST /connections (journal d'accès, doit rester joignable même avant toute connexion,
    cf. routers/connections.py), et POST /agents/enroll (protégé par le jeton d'enrôlement
    à usage unique dans le corps de requête, pas par un `Depends` — cf. routers/agents.py).
    POST /agents/checkin, lui, N'EST PAS public : protégé par `require_agent` (en-tête
    X-Agent-Token), une identité non-humaine distincte de `require_auth`/`require_admin` —
    couvert séparément par `test_agents_checkin_requires_agent_auth` ci-dessous."""

    PUBLIC_ROUTES = {
        ("GET", "/api/health"), ("POST", "/api/auth/login"), ("POST", "/api/connections"),
        ("POST", "/api/agents/enroll"),
        # /forgot-password (18/08/2026) : public comme /login (utilisateur pas encore
        # authentifié) — protégé par son propre verrou anti-spam par IP et sa journalisation
        # (is_password_reset_locked_out/record_audit), pas par un Depends() d'auth, cf.
        # routers/auth.py.
        ("POST", "/api/auth/forgot-password"),
        # Distribution des paquets agent (13/08/2026, cf. routers/agents.py docstring) —
        # interrogées par des scripts tournant sur les postes eux-mêmes (tâche planifiée/GPO),
        # sans session utilisateur possible : intentionnellement публic, même raisonnement que
        # /enroll. Manquaient de cette liste depuis leur création — invisible tant que cette
        # classe de tests était vide (cf. `_api_routes`), découvert en la faisant tourner pour
        # de vrai.
        ("GET", "/api/agents/latest/version"), ("GET", "/api/agents/latest/windows"),
        ("GET", "/api/agents/latest/linux"), ("GET", "/api/agents/latest/windows-exe"),
    }

    @staticmethod
    def _resolved_dependency_calls(route) -> set:
        # `route.dependant.dependencies` (18/08/2026, cf. audit/AUDIT_SECURITE.md — trouvé
        # en faisant tourner cette suite pour de vrai, pas en la relisant) : sur FastAPI
        # 0.140.0, ne contient QUE les dépendances déclarées sur la route elle-même (Depends()
        # explicite, ou `dependencies=[...]` posé directement sur le décorateur @router.xxx).
        # Les `dependencies=` passées à `app.include_router(...)` (main.py) — la façon dont la
        # quasi-totalité des routers de ce projet posent require_auth/require_admin/
        # require_page(...) — ne sont PLUS fusionnées ici (changement de comportement interne
        # vs. versions FastAPI plus anciennes, où route.dependant.dependencies contenait déjà
        # tout). Sans le repli `_router_level_dependants` posé par `_api_routes` ci-dessous,
        # TOUTE cette classe de tests devenait silencieusement vide (`app.routes` ne contient
        # plus les routes /api/* aplaties non plus, cf. `_api_routes`) — 0 route inspectée,
        # donc chaque assertion passait par vacuité sans jamais rien vérifier. Détecté
        # uniquement en exécutant la suite en conditions réelles : un test qui compare un
        # ensemble trouvé à un ensemble attendu
        # (`test_assets_write_and_scan_routes_require_admin_read_stays_open`) est ce qui a fait
        # remonter le problème — les tests "pour chaque route protégée, vérifier X" restent
        # vacuously true sur un ensemble vide, invisibles sans ce genre de comparaison.
        seen = set()
        stack = list(route.dependant.dependencies) + list(getattr(route, "_router_level_dependants", ()))
        while stack:
            dep = stack.pop()
            if dep.call in seen:
                continue
            seen.add(dep.call)
            stack.extend(dep.dependencies)
        return seen

    def _api_routes(self, app):
        # `get_dependant` (fonction interne FastAPI, celle qu'il utilise lui-même pour
        # résoudre les dépendances d'une route) reconstruit un `Dependant` complet pour chaque
        # dépendance de routeur — nécessaire pour `require_page(...)`, une factory qui renvoie
        # une closure `_dep` dont le PROPRE paramètre par défaut est `Depends(require_auth)` :
        # sans ce niveau de résolution supplémentaire, seule la closure elle-même apparaîtrait
        # dans `calls`, jamais `require_auth` qu'elle encapsule.
        from fastapi.dependencies.utils import get_dependant

        for included in app.routes:
            if type(included).__name__ != "_IncludedRouter":
                # Routes posées directement sur `app` (docs/openapi, pas de router inclus) —
                # aucune de ce projet n'est sous /api/*, ignorées comme avant.
                continue
            ctx = included.include_context
            prefix = ctx.prefix or ""
            router_level_dependants = [
                get_dependant(path=prefix, call=d.dependency) for d in ctx.dependencies
            ]
            for route in included.original_router.routes:
                path = prefix + getattr(route, "path", "")
                if not hasattr(route, "dependant") or not path.startswith("/api/"):
                    continue
                route._router_level_dependants = router_level_dependants
                for method in route.methods - {"HEAD", "OPTIONS"}:
                    yield route, method, path

    @staticmethod
    def _is_protected(calls: set) -> bool:
        from auth_deps import require_admin, require_admin_or_internal, require_agent, require_auth

        if calls & {require_auth, require_admin, require_agent, require_admin_or_internal}:
            return True
        # require_page_or_internal(...) (17/08/2026) — factory qui renvoie une NOUVELLE
        # closure `_dep` à chaque appel (comme require_page), impossible à comparer par
        # identité à une référence unique. Contrairement à require_page, sa propre logique
        # d'auth est réimplémentée en ligne (pas de Depends(require_auth) en paramètre,
        # cf. sa docstring "Corps dupliqué plutôt que composé") : `get_dependant` ne peut
        # rien y trouver de plus à résoudre, la closure elle-même doit être reconnue par nom.
        return any(getattr(c, "__qualname__", "").startswith("require_page_or_internal.<locals>") for c in calls)

    def test_every_api_route_requires_auth_or_admin(self):
        from main import app

        unprotected = []
        for route, method, path in self._api_routes(app):
            if (method, path) in self.PUBLIC_ROUTES:
                continue
            calls = self._resolved_dependency_calls(route)
            if not self._is_protected(calls):
                unprotected.append(f"{method} {path}")

        assert not unprotected, f"Routes /api/* sans protection reconnue : {unprotected}"

    def test_agents_checkin_requires_agent_auth(self):
        # /checkin doit porter spécifiquement require_agent (pas seulement "une auth
        # quelconque") — une régression qui le ferait passer sous require_auth par erreur
        # laisserait n'importe quel compte humain pousser un check-in au nom d'un agent.
        from auth_deps import require_agent
        from main import app

        for route, method, path in self._api_routes(app):
            if path == "/api/agents/checkin":
                assert require_agent in self._resolved_dependency_calls(route), \
                    f"{method} {path} doit porter require_agent"

    def test_agents_management_routes_require_admin_except_list(self):
        # Gestion des jetons + révocation/suppression : admin uniquement. GET /agents,
        # GET /{agent_id} et GET /{agent_id}/checkins (lecture) restent ouverts à tout
        # compte ayant accès à la page Sécurité > Agents (require_page), pas réservés
        # admin — cf. routers/agents.py. GET /pending et POST /checkin portent une
        # identité agent (require_agent), pas humaine — couverts séparément
        # (test_agents_checkin_requires_agent_auth ci-dessous pour /checkin). POST /enroll
        # et GET /latest/* sont publics (cf. PUBLIC_ROUTES) — élargi le 18/08/2026 après
        # avoir fait tourner cette suite pour de vrai : /latest/* en manquait, invisible
        # tant que cette classe de tests était silencieusement vide.
        from auth_deps import require_admin
        from main import app

        page_only_paths = {
            ("GET", "/api/agents"), ("GET", "/api/agents/{agent_id}"),
            ("GET", "/api/agents/{agent_id}/checkins"),
            # /history (19/08/2026) : même require_page("/agents") que les trois ci-dessus,
            # manquait de cette liste depuis son ajout (route jamais couverte par ce test
            # jusqu'ici, découvert en le faisant tourner pour de vrai).
            ("GET", "/api/agents/history"),
            # /security-events/count (19/08/2026, cf. docs/AGENT_DETECTION.md) : require_auth
            # seul (pas require_page), même exception que routers/security.py::events_count —
            # le badge nav doit rester visible à tout connecté, pas seulement admin. Le nom
            # "page_only_paths" est un peu impropre ici (pas de require_page en jeu), mais
            # cette branche ne vérifie que l'absence de require_admin, ce qui est exactement
            # ce qu'on veut pour cette route.
            ("GET", "/api/agents/security-events/count"),
        }
        non_admin_agent_paths = {
            ("POST", "/api/agents/enroll"), ("POST", "/api/agents/checkin"), ("GET", "/api/agents/pending"),
        }

        for route, method, path in self._api_routes(app):
            if not path.startswith("/api/agents"):
                continue
            if (method, path) in self.PUBLIC_ROUTES or (method, path) in non_admin_agent_paths:
                continue
            calls = self._resolved_dependency_calls(route)
            if (method, path) in page_only_paths:
                assert require_admin not in calls, f"{method} {path} ne devrait pas exiger admin (lecture partagée)"
            else:
                assert require_admin in calls, f"{method} {path} doit être réservé au rôle admin"

    def test_connections_and_security_admin_only_endpoints(self):
        # GET /connections (lecture du journal) et tout /security sauf le compteur
        # (badge visible à tout utilisateur connecté) doivent porter require_admin.
        from auth_deps import require_admin
        from main import app

        admin_only_paths = {("GET", "/api/connections"), ("GET", "/api/connections/users")}
        authed_not_admin = {("GET", "/api/security/events/count")}

        for route, method, path in self._api_routes(app):
            if not (path.startswith("/api/connections") or path.startswith("/api/security")):
                continue
            calls = self._resolved_dependency_calls(route)
            if (method, path) in authed_not_admin:
                assert require_admin not in calls, f"{method} {path} ne devrait pas exiger admin (badge partagé)"
            elif (method, path) in admin_only_paths or path.startswith("/api/security"):
                assert require_admin in calls, f"{method} {path} doit être réservé au rôle admin"

    def test_analysts_write_requires_admin_read_stays_open(self):
        # Registre d'analystes (30/07/2026, déplacé dans Administration) : la lecture
        # reste ouverte à tout connecté (dropdowns partout), l'écriture est admin-only.
        from auth_deps import require_admin
        from main import app

        for route, method, path in self._api_routes(app):
            if not path.startswith("/api/analysts"):
                continue
            calls = self._resolved_dependency_calls(route)
            if method == "GET":
                assert require_admin not in calls, f"{method} {path} ne devrait pas exiger admin (lecture partagée)"
            else:
                assert require_admin in calls, f"{method} {path} doit être réservé au rôle admin"

    def test_assets_write_and_scan_routes_require_admin_read_stays_open(self):
        # 18/08/2026, cf. audit/AUDIT_SECURITE.md #14 — assets.router n'avait jusqu'ici
        # aucune restriction de rôle au-delà de require_auth : n'importe quel compte connecté
        # pouvait créer/modifier/supprimer un actif, déclencher un scan SSH/WinRM/agent, ou
        # les checks réseau/switch/web (SSRF via Asset.url non validé, sonde SSH via
        # ip_address+identifiants libres, déclenchement de scan agent contournant
        # POST /agents/{id}/request-scan déjà réservé admin). Les GET restent ouverts à tout
        # compte connecté (décision actée, cf. CLAUDE.md § limite assumée — lus en cross-
        # référence par Dashboard/Incidents/Rapports/Veille).
        from auth_deps import require_admin
        from main import app

        write_and_scan_paths = {
            ("POST", "/api/assets"),
            ("PUT", "/api/assets/{asset_id}"),
            ("DELETE", "/api/assets/{asset_id}"),
            ("POST", "/api/assets/{asset_id}/scan"),
            ("POST", "/api/assets/network-protocol-check/run"),
            ("POST", "/api/assets/switch-hardening/run"),
            ("POST", "/api/assets/web-hardening/run"),
        }

        found = set()
        for route, method, path in self._api_routes(app):
            if not path.startswith("/api/assets"):
                continue
            calls = self._resolved_dependency_calls(route)
            if (method, path) in write_and_scan_paths:
                found.add((method, path))
                assert require_admin in calls, f"{method} {path} doit être réservé au rôle admin"
            elif method == "GET":
                assert require_admin not in calls, f"{method} {path} ne devrait pas exiger admin (lecture partagée)"

        assert found == write_and_scan_paths, f"Routes attendues non trouvées : {write_and_scan_paths - found}"
