# Audit de sécurité — CBR / CyberVuln

> Revue défensive du code (lecture seule), 24/07/2026. Classée par priorité.
> Chaque entrée : où, pourquoi, correctif concret. Cocher au fur et à mesure.
>
> ⚠️ **Rappel architectural périmé** : la ligne ci-dessous disait vrai le 24/07/2026, plus
> depuis le 30/07/2026 — une vraie authentification existe désormais (email/mot de passe,
> bcrypt, session par cookie HttpOnly, RBAC admin/analyst, cf. CLAUDE.md § Authentification).
> Gardée telle quelle pour ne pas réécrire l'historique des entrées #1-#8 ci-dessous, qui
> restent correctes pour leur contexte d'origine. Cf. § Revue du 10/08/2026 plus bas pour
> ce que l'authentification change (et ne change pas) au tableau de risques.
>
> ~~Rappel architectural : **aucune authentification** sur l'API (réseau interne de
> confiance supposé, cf. CLAUDE.md). C'est assumé, mais c'est ce qui fait passer le
> SSRF #1 de « moyen » à « élevé » — rien ne filtre avant d'atteindre l'endpoint.~~

---

## 🔴 #1 — SSRF via les sources de veille (ÉLEVÉ, seul exploitable à distance sans creds)

**Où** : `backend/routers/watch.py:450` (`create_watch_source`) + `backend/services/watch_fetcher.py:461` (`_fetch_feed`)

**Problème** : le champ `url` est accepté sans validation de schéma ni d'hôte, puis
requêté côté serveur avec `follow_redirects=True`. Sans auth, n'importe qui sur le
réseau crée une source pointant vers `http://127.0.0.1:6379` (Redis), le WinRM d'un
autre serveur du parc, ou `http://169.254.169.254/…` (métadonnées cloud). Contenu XML
valide → stocké + affiché (exfiltration) ; sinon SSRF aveugle (scan de ports interne).

**Correctif** : valider l'URL à la création **et** à la mise à jour, et re-vérifier
après chaque redirection plutôt que `follow_redirects=True` aveugle.

```python
# backend/services/net_guard.py  (nouveau — partagé avec rss_fetcher/nvd si besoin)
import ipaddress, socket
from urllib.parse import urlparse

def validate_public_url(url: str) -> str:
    """Rejette tout ce qui n'est pas http(s) vers un hôte public routable.
    Lève ValueError sinon. À rappeler après chaque redirection."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise ValueError("Schéma non autorisé (http/https uniquement)")
    if not p.hostname:
        raise ValueError("Hôte manquant")
    # Résolution DNS → rejet des plages non publiques (anti-DNS-rebinding basique)
    for family, _, _, _, sockaddr in socket.getaddrinfo(p.hostname, None):
        ip = ipaddress.ip_address(sockaddr[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            raise ValueError(f"Adresse non routable interdite : {ip}")
    return url
```

```python
# routers/watch.py — create_watch_source ET update_watch_source
from services.net_guard import validate_public_url
try:
    validate_public_url(data.url.strip())
except ValueError as e:
    raise HTTPException(400, f"URL refusée : {e}")
```

```python
# services/watch_fetcher.py:463 — remplacer follow_redirects=True
async with httpx.AsyncClient(timeout=30, follow_redirects=False, headers={...}) as client:
    resp = await client.get(feed["url"])
    # suivre les redirections à la main en re-validant chaque hop
    hops = 0
    while resp.is_redirect and hops < 5:
        nxt = str(resp.next_request.url)
        validate_public_url(nxt)      # bloque une redirection vers l'interne
        resp = await client.get(nxt)
        hops += 1
    resp.raise_for_status()
```

- [x] `net_guard.validate_public_url` créé (27/07/2026, `backend/services/net_guard.py`)
- [x] Appelé dans `create_watch_source` **et** `update_watch_source` — testé : URL interne
      (`http://127.0.0.1:6379/`) rejetée en 400, URL publique acceptée
- [x] Redirections re-validées dans `_fetch_feed` (`follow_redirects=False` + boucle de
      re-validation par hop) — testé : sync veille toujours fonctionnelle (22 flux, 0 erreur)

---

## 🟠 #2 — Vérification de clé d'hôte SSH désactivée (MOYEN)

**Où** : `backend/services/asset_scanner.py:247` + `backend/services/patch_checker.py:709`

**Problème** : `known_hosts=None` désactive toute vérification de l'identité du serveur
SSH. Un attaquant en MITM (VLAN partagé, ARP spoofing) se fait passer pour la cible :
si l'actif s'authentifie par **mot de passe** (`scan_password_encrypted`), le mot de
passe SSH lui est livré ; sinon il injecte de faux relevés de paquets (fausse détection
de patch). Contredit le modèle « lecture seule fiable ».

**Correctif** : known_hosts persistant (TOFU au 1er scan, pinning ensuite). Fichier monté
en volume à côté de `keys/`.

```python
# les deux fichiers — remplacer known_hosts=None
KNOWN_HOSTS = settings.SSH_KNOWN_HOSTS or "/app/keys/known_hosts"
connect_kwargs = dict(username=ssh_user, known_hosts=KNOWN_HOSTS, connect_timeout=15)
```
```python
# config.py
SSH_KNOWN_HOSTS: Optional[str] = None   # défaut résolu à /app/keys/known_hosts
```
- Créer `keys/known_hosts` (peut être vide au départ), monté déjà en `:ro` — le passer
  en `rw` le temps du premier apprentissage, ou pré-remplir via `ssh-keyscan`.
- Alternative pragmatique si TOFU trop lourd : garder `known_hosts=None` mais **interdire
  l'auth par mot de passe** (clé uniquement), ce qui supprime la fuite de credentials.

- [x] `known_hosts` pointé sur un fichier persistant, TOFU implémenté dans
      `backend/services/ssh_trust.py` (`connect_trusted`), branché dans `asset_scanner.py`
      **et** `patch_checker.py` (27/07/2026)
- [x] `keys/known_hosts` créé, peuplé automatiquement au premier contact (pas de
      pré-remplissage `ssh-keyscan` nécessaire)
- [x] Volume `./keys` repassé en écriture (`docker-compose.yml`, services `backend`+`worker`)
- Testé en conditions réelles contre `gitlab.aer.loc` : premier contact → apprentissage +
  pin ; second scan → clé pinnée acceptée sans réapprentissage ; clé substituée par une
  autre clé valide → connexion rejetée (`Host key is not trusted`) **sans** écraser
  l'entrée pinnée.

---

## 🟠 #3 — Bind LDAP en clair (MOYEN)

**Où** : `backend/services/asset_importer.py:122-135`

**Problème** : `ldap://` + `authentication=ldap3.SIMPLE`, sans `use_ssl` ni `start_tls()`.
Le mot de passe du compte de service AD transite en clair à chaque import (quotidien +
manuel). Compte lecture seule, mais compte de domaine valide, réutilisable en reconnaissance.

**Correctif** :
```python
# config.py
AD_USE_TLS: bool = True

# asset_importer.py — __init__ / _connect
self.server = ldap3.Server(settings.AD_SERVER, get_info=ldap3.ALL,
                           use_ssl=settings.AD_USE_TLS, connect_timeout=10)
conn = ldap3.Connection(self.server, user=settings.AD_USER,
                        password=settings.AD_PASSWORD,
                        authentication=ldap3.SIMPLE, auto_bind=True)
if not settings.AD_USE_TLS:  # repli si le DC n'expose que StartTLS sur 389
    conn.start_tls()
```
- Passer `AD_SERVER` en `ldaps://…:636` dans `.env` / `.env.example`.

- [x] `AD_USE_TLS` ajouté (27/07/2026, défaut **`False`** plutôt que `True` — choix
      délibéré différent de la proposition initiale : StartTLS sur le `ldap://` déjà
      configuré (389, sans changer port/URL) plutôt que TLS implicite (`ldaps://`, 636)
      dont on ne sait pas si le DC l'expose. Toujours chiffré, juste un mécanisme plus
      sûr par défaut. Passer à `True` + `AD_SERVER=ldaps://...:636` si le DC le permet.
- [ ] `.env` **non** basculé en `ldaps://` (repli StartTLS actif à la place, cf. ci-dessus)
- Testé contre le vrai contrôleur de domaine (`tintamarre.aer.loc`) : import AD toujours
  fonctionnel après activation de StartTLS (`windows_found:1, errors:0`).

---

## 🟠 #4 — Parseur XML non durci sur flux distants (MOYEN)

**Où** : `backend/services/watch_fetcher.py:481` + `backend/services/rss_fetcher.py:175`

**Problème** : `ET.fromstring(resp.content)` de la stdlib sur du contenu de sources
**ajoutables par l'utilisateur**. Combiné au SSRF (#1), une source malveillante renvoie
un XML à expansion d'entités → DoS mémoire/CPU du backend. (Pas de lecture de fichier :
ElementTree ne résout pas les entités externes par défaut — mais le DoS reste ouvert.)

**Correctif** : drop-in `defusedxml`.
```python
# requirements.txt
defusedxml==0.7.1

# watch_fetcher.py + rss_fetcher.py — remplacer l'import
from defusedxml.ElementTree import fromstring as ET_fromstring
# puis ET.fromstring(...) → ET_fromstring(...)
```
- [x] `defusedxml` ajouté à `requirements.txt` (27/07/2026)
- [x] Import remplacé dans les 2 fichiers — testé : sync veille toujours fonctionnelle
      (22 flux, 824 items, 0 erreur)

---

## 🟡 #5 — Aucun `.gitignore` (FAIBLE mais à faire AVANT tout `git init`)

**Problème** : pas de repo git aujourd'hui, mais un premier `git init && git add .`
committerait `.env` (secrets en clair) et `keys/id_ed25519`. CLAUDE.md l'interdit, rien
ne le fait respecter techniquement.

**Correctif** — créer `.gitignore` à la racine :
```gitignore
.env
keys/
__pycache__/
*.pyc
frontend/node_modules/
frontend/dist/
```
- [ ] `.gitignore` créé **avant** le premier `git init`

---

## 🟡 #6 — Secrets par défaut « changeme » (FAIBLE)

**Où** : `backend/config.py:13` (`DB_PASSWORD`) et `:59` (`SECRET_KEY`)

**Problème** : si `.env` n'est pas chargé (erreur de montage), l'app démarre
silencieusement avec `SECRET_KEY="changeme"` → clé Fernet prévisible, déchiffrement des
mots de passe SSH stockés.

**Correctif** — échouer bruyamment plutôt que démarrer avec un secret prévisible :
```python
# config.py — après settings = Settings()
if settings.SECRET_KEY == "changeme" or settings.DB_PASSWORD == "changeme":
    raise RuntimeError("SECRET_KEY / DB_PASSWORD non configurés (valeur par défaut détectée)")
```
- [x] Garde-fou au démarrage ajouté (24/07/2026, `config.py`) — refuse de démarrer si `SECRET_KEY` ou
      `DB_PASSWORD` valent `changeme` ; message listant la/les variable(s) fautive(s). Testé : déclenche
      avec `changeme`, passe avec les vraies valeurs.
- [x] **Rôle applicatif à privilèges réduits** (24/07/2026, hors des 6 initiaux) — l'app tourne en
      `cbr_app` (DML only, NOSUPERUSER) au lieu du superuser `cybervuln` (`backend/db/app_role.sql`,
      `APP_DB_*`). Vérifié : `CREATE`/`DROP`/`DELETE security_events`/superuser refusés. Complète la
      déception DB (traces ineffaçables). Cf. `docs/ARCHITECTURE.md § Rôle applicatif`.
- [x] **Déception DB** (24/07/2026) — honeypots (vues/rôles leurres, honeytokens) → `security_events` +
      bannière Dashboard (`backend/db/deception_setup.sql`). Cf. `docs/ARCHITECTURE.md § Déception`.

---

## ℹ️ Info / hygiène (pas de code, mais à traiter)

- [x] **`DB_PASSWORD` roté** (24/07/2026) : `Cyb3rVuln_2026!` → 40 car. aléatoires alphanumériques
      (`ALTER ROLE` PostgreSQL + `.env`, services applicatifs recréés, ancien mdp vérifié rejeté).
      Alphanumérique volontairement : `config.py` construit `DATABASE_URL` en f-string sans URL-encoding.
- [x] **`AD_PASSWORD`/`WINRM_PASSWORD` rotés** (10/08/2026, côté AD par l'utilisateur — compte
      de domaine `AER\cybervuln`, un seul mot de passe pour LDAP et WinRM sur tout le parc, pas
      seulement DEPLOYAPP d'où le changement a été fait). `.env` mis à jour, `backend`/`worker`
      redémarrés pour charger les nouvelles valeurs. Vérifié en conditions réelles : import AD
      (71 machines, 0 erreur) et scan WinRM (DEPLOYAPP, reachable) tous deux fonctionnels après
      rotation. `SECRET_KEY` **non changé** (le roter invalide le mot de passe SSH déjà chiffré
      d'1 actif, cf. `crypto.py` — le re-saisir après si un jour on le fait).
- [ ] **WinRM en `http://…:5985` + NTLM** (`patch_checker.py:244`) : le transport `ntlm`
      chiffre la charge au niveau message (creds pas en clair), mais exposé au NTLM relay.
      Passer en 5986/HTTPS si l'AD le permet. Priorité basse.
- [x] **`cryptography` ajouté à `requirements.txt`** (27/07/2026, pin `==49.0.0` — version
      déjà installée en transitif dans l'image, épinglée telle quelle).
- [x] **`pip-audit` / `npm audit` passés** (27/07/2026). Trouvailles hors des 6 points initiaux :
      - [x] Backend **corrigé le même jour** : `starlette==0.38.6` et `python-multipart==0.0.12`
        (transitifs de `fastapi==0.115.0`) avaient plusieurs CVE. Bump `fastapi` → `0.140.0`
        (`requirements.txt`), qui tire `starlette` → `1.3.1` (aucun plafond de version dans
        `fastapi`'s `Requires-Dist: starlette>=0.46.0`) et `python-multipart` → `0.0.32`.
        `pydantic` 2.13.4 déjà compatible (`fastapi` exige `>=2.9.0`), aucun bump nécessaire.
        `python-multipart` n'est même pas utilisé dans le code (aucun `UploadFile`/`Form`) — risque
        nul sur ce paquet. Testé après bump : `pip-audit` propre, tous les endpoints/CORS/export CSV
        (StreamingResponse) et le fork Celery (`cap_drop: ALL`) toujours fonctionnels.
      - [ ] Frontend **non corrigé, laissé ouvert** : `react-router-dom@6.30.4` (CVE modérée,
        redirection ouverte) — pas de correctif dans la branche 6.x, nécessite v7 (breaking, pas
        validé sans accord explicite). `esbuild`/`vite` (dev uniquement, CVE modérée sur le serveur
        de dev) — fix nécessite `vite@8` (breaking, `npm audit fix --force`).

---

## 🔴 #7 — Injection de formule CSV/Excel dans les exports (ÉLEVÉ sur le rapport auditeur NIS 2)

**Où** : `backend/routers/watch.py:427-440` (`export_watch_items`, colonnes Titre/URL/Source/
Décision) + `backend/routers/reports.py` (backlog CSV, rapport hebdo veille/surveillance/CVE).

**Problème** : les cellules CSV étaient écrites brutes (`writer.writerow([w.title, w.url, ...])`),
sans neutraliser les valeurs commençant par `=`, `+`, `-`, `@`. Excel/LibreOffice interprètent
ces cellules comme des formules à l'ouverture (DDE compris). `w.title`/`w.url` viennent de flux
RSS/Atom **externes**, y compris les sources personnalisées ajoutables sans code (`WatchSource`,
même point d'entrée que le SSRF #1) : une source malveillante ou compromise peut publier un item
dont le titre est une formule piégée. L'endpoint le plus exposé est justement celui *« destiné au
rapport auditeur NIS 2 »* — le document remis à un tiers externe, ouvert sans méfiance.

Pas un doublon de #1 : #1 empêche d'atteindre un hôte interne (SSRF réseau), ça n'empêche pas un
flux public malveillant/compromis d'empoisonner le contenu de l'export une fois la source acceptée.

**Correctif** :
```python
# backend/services/csv_safety.py (nouveau)
def csv_safe(value) -> str:
    s = "" if value is None else str(value)
    return f"'{s}" if s and s[0] in ("=", "+", "-", "@", "\t", "\r") else s
```
Appliqué à tous les champs texte libre des 3 exports (titre/URL/source/décision en veille,
notes/validated_by en CVE, value en surveillance) — pas aux champs contraints (statut, dates,
CVE ID, sévérité, scores).

- [x] `backend/services/csv_safety.py` créé (27/07/2026)
- [x] Appliqué dans `routers/watch.py` (`export_watch_items`) et `routers/reports.py` (backlog
      CSV + rapport hebdo, 3 types)
- [x] Testé en conditions réelles après redémarrage backend+worker : les 3 exports (`/api/reports/csv`,
      `/api/watch/export`, `/api/reports/weekly/{id}/csv`) renvoient toujours 200 avec contenu
      correct, aucune régression (BOM UTF-8, en-têtes, accents FR intacts).

---

## 🟡 #8 — Passage `bandit` (SAST), backend (27/07/2026)

> `bandit -r backend/` (dans le conteneur, `pip install bandit` à la volée). 9 signalements,
> la plupart faux positifs déjà vérifiés dans le code (`subprocess.run` de `backup.py` en liste
> sans `shell=True` ni entrée utilisateur ; `try/except/pass` bénins sur du parsing de date).
> Deux corrigés ci-dessous, aucun autre nouveau.

**`B108` — cache Debian Security Tracker en dur sur `/tmp`** (`backend/services/debian_tracker.py:33`) :
`CACHE_PATH.write_bytes(...)` suit un symlink existant si un attaquant en pré-crée un à ce chemin
fixe (`/tmp` partagé). Risque faible (suppose déjà l'exécution de code dans le conteneur) mais
correctif trivial : déplacé vers `/app/cache/` (répertoire propre à l'appli, pas de tiers), création
du dossier avant écriture (`CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)`).
- [x] Corrigé et testé (téléchargement réel confirmé, fichier écrit dans `/app/cache/`)

**`B324` — `hashlib.sha1()` sans `usedforsecurity=False`** (`backend/services/watch_fetcher.py:277`,
`_stable_url`) : usage non cryptographique (clé de dédup d'un item de veille sans URL propre), faux
positif fonctionnel — silencié pour que bandit arrête de le (re)signaler.
- [x] Corrigé (`hashlib.sha1(raw.encode(), usedforsecurity=False)`)

**`B405` — import `xml.etree.ElementTree`** (`rss_fetcher.py:15`, `watch_fetcher.py:16`) : import
gardé pour les types (`ET.Element`) et `ET.ParseError` uniquement — le parsing réel du contenu
distant passe déjà par `defusedxml.fromstring` (correctif #4). Pas une vraie faille, juste bandit qui
ne distingue pas l'usage ; annoté `# nosec B405` avec justification en commentaire plutôt que
retravaillé, pour ne pas complexifier le code pour un faux positif documenté.
- [x] Annoté dans les 2 fichiers

- [x] Testé en conditions réelles après redémarrage backend+worker : sync veille (22 flux, 0 erreur),
      téléchargement + écriture cache tracker Debian confirmés. Re-passage `bandit` : `B108`/`B324`
      disparus, 5 signalements restants tous déjà couverts par les vérifications ci-dessus.

---

## 🐳 Docker / conteneurs (revue du 27/07/2026)

> `docker-compose.yml` + `backend/Dockerfile` + `frontend/Dockerfile`. Rien de critique,
> mais le setup actuel est clairement **orienté dev**, pas durci pour tourner exposé.

- **🟠 Conteneurs backend/frontend en root** — aucun `USER` dans les deux Dockerfiles.
  Une RCE dans l'app (faille future, dépendance compromise) donne root dans le conteneur.
  Correctif : `RUN useradd -m app && chown -R app /app` + `USER app` en fin de Dockerfile
  (vérifier que le port 8000/3000 reste bindable en non-root — oui, ports > 1024).
  - [x] Backend passé en utilisateur non-root (10/08/2026) — `useradd -u 1000`, `USER app`
        (`backend/Dockerfile`, partagé par `backend`/`worker`/`beat`). UID 1000 choisi pour
        matcher la propriété déjà en place sur les bind mounts (`./backend`, `./keys` —
        1000:1000 côté hôte WSL2/drvfs, permissifs `777`). Les 4 volumes nommés déjà peuplés
        en usage réel (`backups`/`documents`/`incident_attachments`/`audit_attachments`,
        `root:root` par défaut) ont dû être réappropriés séparément (`docker run --rm -v
        <volume>:/data alpine chown -R 1000:1000 /data`) — un `chown` dans le Dockerfile ne
        les couvre pas, ils sont montés PAR-DESSUS l'image au démarrage. Vérifié en
        conditions réelles après rebuild+recréation des 3 conteneurs : `id` confirme
        `uid=1000(app)` sur les trois, sauvegarde manuelle déclenchée avec succès (nouveau
        `.dump` créé par le worker), upload + suppression d'un document de test réussis.
  - [x] Frontend passé en utilisateur non-root (10/08/2026) — les **deux** stages du
        `frontend/Dockerfile` :
        - `dev` (Vite, celui réellement actif) : `USER node`, déjà présent dans l'image
          officielle `node:20-alpine` (UID 1000). Anonyme `node_modules` régénéré propre
          (`docker compose up -d -V frontend`, `-V`/`--renew-anon-volumes` — sinon l'ancien
          volume anonyme, peuplé en root par les conteneurs précédents, aurait survécu au
          changement d'utilisateur). Vérifié : `id` confirme `uid=1000(node)`, page servie
          (`200`), proxy `/api` fonctionnel, HMR toujours actif après modification d'un fichier.
        - `prod` (nginx, pas encore utilisé — cf. bascule prévue sous 2 semaines) : `USER
          nginx`, déjà présent dans l'image officielle `nginx:1.27-alpine` (UID 101).
          Chemins réappropriés (`/usr/share/nginx/html`, `/var/cache/nginx`,
          `/etc/nginx/conf.d`, `/var/log/nginx`) + fichier pid déplacé sous `/tmp` (`/run`
          reste root-only). ⚠️ Deux essais infructueux avant le bon correctif, gardés en
          mémoire pour ne pas les rejouer : `pid` posé en double via `CMD -g "... pid
          /tmp/nginx.pid;"` en plus de celui déjà dans `nginx.conf` → nginx refuse de
          démarrer (« "pid" directive is duplicate ») ; `sed` visant `/var/run/nginx.pid`
          alors que l'image utilise en réalité `/run/nginx.pid` (`/var/run` n'en est qu'un
          symlink, le texte du fichier ne le contient pas) → aucun remplacement, échec
          silencieux du `sed`, permission refusée persistante. Corrigé en modifiant
          directement `/etc/nginx/nginx.conf` par un `sed` sur motif POSIX
          (`[[:space:]]`, pas `\s` — non supporté par le `sed` BusyBox d'Alpine) capturant
          toute la directive `pid ...;` quel que soit le chemin d'origine. Vérifié en
          conditions réelles : build de l'image + conteneur lancé isolément (port 3001, sans
          toucher au `frontend` dev déjà en service) → `id` confirme `uid=101(nginx)`, `200`
          sur `/`, proxy `/api/health` fonctionnel, conteneur de test supprimé après coup.

- **🟠 Serveurs de dev exposés tels quels** — `uvicorn --reload` et `npm run dev` (serveur
  de dev Vite) ne sont pas conçus pour tourner en continu/exposés au réseau. Le serveur de
  dev Vite a une CVE ouverte (cf. `npm audit` plus haut : lecture de réponse arbitraire par
  n'importe quel site). Ports `8000`/`3000` bindés sur `0.0.0.0` (donc accessibles à tout le
  réseau interne, pas seulement localhost) — cohérent avec l'absence d'auth déjà assumée
  dans CLAUDE.md, mais à garder en tête. Pas de vrai correctif sans introduire un vrai
  build de prod (`vite build` + serveur statique, `uvicorn` sans `--reload`) — hors
  scope tant que c'est un outil interne en développement actif.
  - [ ] Décider si/quand un mode "prod" (sans reload/dev server) est nécessaire

- **🟡 `./keys` monté en écriture (backend + worker)** — nécessaire pour le TOFU SSH (#2
  ci-dessus), mais expose aussi la clé privée `id_ed25519` en écriture alors qu'elle n'a
  besoin que d'être lue. Compromis accepté pour fermer #2 sans repo git séparé pour
  `known_hosts`. Amélioration possible : séparer `known_hosts` dans un volume nommé Docker
  dédié (écriture) et garder `./keys` en `:ro` pour la clé privée seule.
  - [x] `known_hosts` séparé de la clé privée sur deux montages distincts (10/08/2026) —
        `./keys:/app/keys` repassé en `:ro` (backend + worker), nouveau volume nommé
        `ssh_known_hosts:/app/ssh-state` (rw, seul chemin qui a encore besoin d'écriture)
        pour le seul fichier qui en a besoin (`services/ssh_trust.py::_known_hosts_path`,
        défaut basculé de `/app/keys/known_hosts` à `/app/ssh-state/known_hosts`).
        Contenu existant (1 hôte pinné, `gitlab.aer.loc`) migré vers le nouveau volume
        avant bascule (`docker run --rm -v ... alpine cp ... && chown 1000:1000`) — sans
        cette étape, le pin existant aurait été perdu et le prochain contact aurait
        redéclenché un apprentissage TOFU. `./keys/known_hosts` (hôte) devient un fichier
        mort, gardé tel quel plutôt que supprimé (aucun coût à le laisser, mount `:ro`
        de toute façon). Vérifié en conditions réelles : écriture dans `/app/keys` refusée
        (`Read-only file system`), clé privée toujours lisible, contenu de `known_hosts`
        bien présent sur le nouveau volume, scan SSH réel contre `gitlab.aer.loc` réussi
        **sans** relog "premier contact" (confirme que le pin migré est bien reconnu, pas
        redemandé).

- **🟡 Pas de `.dockerignore`** — `COPY . .` embarque `__pycache__/` (backend, présents
  actuellement) et, côté frontend, écrase potentiellement le `node_modules` fraîchement
  installé dans l'image par celui du contexte de build hôte (sans impact à l'exécution
  grâce au volume anonyme `/app/node_modules`, mais gaspille de l'espace/temps de build).
  - [ ] `.dockerignore` créé (`__pycache__/`, `*.pyc`, `node_modules/`, `dist/`, `.git/`)

- **🟡 Durcissement runtime** — corrigé (27/07/2026) :
  - [x] `security_opt: [no-new-privileges:true]` sur les **6** services
  - [x] `cap_drop: [ALL]` sur les 4 services applicatifs (`backend`, `worker`, `beat`,
        `frontend`) — pas sur `db`/`redis`, dont l'entrypoint officiel a besoin de
        CHOWN/SETUID/SETGID au démarrage (bascule root → utilisateur dédié via `gosu`)
  - [x] `mem_limit`/`cpus` sur les 6 services. Piège rencontré en le faisant : `backend`
        posé d'abord à `1g` puis `3g` restait bloqué indéfiniment sur "Waiting for
        application startup" (ni crash ni `OOMKilled`, juste plafonné) — mesure en
        direct sans limite : le matching CVE synchrone au démarrage (`STARTUP_MATCHING`)
        pique à **~4.6GiB** avant de retomber à ~300MiB une fois terminé. Réglé à `6g`
        (`backend`) / `4g` (`worker`, qui fait les mêmes syncs NVD/patch-check
        volumineuses) avec marge de croissance ; `1g`/`256m`/`512m` sur `db`/`redis`/
        `beat`/`frontend`, bien plus légers en usage réel.
  - [x] Testé de bout en bout après coup : les 6 services `Up`, aucun `OOMKilled`, API/
        frontend/sync veille/fork Celery (pool `ForkPoolWorker`, sensible à `cap_drop`)
        tous fonctionnels.
  - **Piège annexe découvert en cours de route** : Compose construit une image **par
    service** (`cybervuln-backend`, `cybervuln-worker`, `cybervuln-beat`) même quand ils
    partagent le même `build: ./backend` — `docker compose build backend` seul (fait pour
    le fix #4 defusedxml) n'avait pas reconstruit `worker`/`beat`, qui tournaient donc sur
    une image obsolète sans `defusedxml` (`ModuleNotFoundError`, conteneurs en `Exited`).
    Toujours reconstruire (`docker compose build`) ou recréer (`up -d`) les **trois**
    services backend après un changement de `requirements.txt`, pas juste `backend`.

- **🟢 Points déjà corrects** : `db`/`redis` ne publient **aucun port** vers l'hôte
  (accessibles uniquement via le réseau Docker interne) · images `-alpine` minimales ·
  `.env` chargé via `env_file` (jamais copié dans une image, hors du contexte de build de
  `backend/`/`frontend/`) · `depends_on` avec `condition: service_healthy` correct.

---

## ✅ Vérifié conforme (dans le code, pas juste la doc)

Non-intervention SSH/AD strictement lecture seule · **aucune** commande utilisateur
interpolée (commandes SSH/PowerShell = chaînes statiques, pas d'injection) · aucun appel
API Claude · pas d'injection SQL/LDAP · chiffrement Fernet correct (AES-CBC+HMAC, clé
dérivée de `SECRET_KEY`, jamais renvoyée par l'API) · CORS restreint à localhost ·
`DEBUG=false` par défaut · XSS frontend couvert (DOMPurify avant `dangerouslySetInnerHTML`
dans `MarkdownNote.jsx`).

**Ordre conseillé** : #1 → #2 → #5 (avant git init) → #3 → #4 → #6 → #7 → #8.

**État au 27/07/2026** : #1, #2, #3, #4, #6, #7, #8 corrigés et testés en conditions réelles.
Seul **#5 reste volontairement en attente** (pas de repo git pour l'instant) — à faire
juste avant le premier `git init`.

---

## Revue du 10/08/2026 — après l'introduction de l'authentification réelle

> Nouveau tour de code (lecture seule), pas un simple diff depuis le 27/07/2026 : beaucoup
> construit depuis (auth réelle 30/07, uploads Documents/Incidents/Audits, WithSecure/
> Meraki/PRTG, RBAC par page). Priorité donnée à ce qui n'a jamais été audité. Aucun
> correctif appliqué à ce stade — proposés ci-dessous, à valider avant implémentation.

**Ce que l'authentification change (et ne change pas) au tableau du 24/07** : le SSRF #1
et l'injection CSV #7 restaient exploitables par n'importe qui sur le réseau ; ce n'est
plus vrai (il faut désormais une session valide) — mais les deux restent corrects à
traiter, une source de veille malveillante reste possible **depuis un compte analyst
légitime compromis ou malveillant**, pas seulement un tiers anonyme. Le reste (#2-#6, #8)
est inchangé par l'auth.

### 🟠 #9 — IP falsifiable via `X-Forwarded-For` (MOYEN, casse deux garde-fous)

**Où** : `frontend/nginx.conf:16` (`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`,
build de prod) **et** `frontend/vite.config.js:22-23` (serveur de dev, celui réellement en
service au moment de cette revue) + `backend/routers/auth.py:_client_ip` +
`backend/routers/connections.py:18-22`

⚠️ Le serveur de dev est **pire** que nginx sur ce point précis : il ne se contente pas
d'ajouter, il **priorise** l'en-tête `x-forwarded-for` envoyé par le client lui-même
(`req.headers['x-forwarded-for'] || req.socket.remoteAddress`) — un attaquant n'a même
pas besoin d'un en-tête déjà présent à faire déborder, il lui suffit d'en envoyer un.

**Problème** : `$proxy_add_x_forwarded_for` **ajoute** `$remote_addr` à la fin d'un éventuel
`X-Forwarded-For` déjà présent dans la requête du client, il ne le remplace pas. Le code
backend lit `.split(",")[0]` — le **premier** élément, donc celui que le client a fourni
lui-même s'il en a envoyé un, pas l'IP réelle ajoutée par nginx en dernier. Un client qui
envoie `X-Forwarded-For: 1.2.3.4` se fait passer pour `1.2.3.4` aux yeux du backend. Deux
garde-fous reposent là-dessus :
- Le verrou anti-bruteforce par IP (`LOCKOUT_MAX_PER_IP=20`, `services/auth.py`) — un
  attaquant qui fait varier l'en-tête à chaque tentative ne se fait jamais bloquer par IP
  (le verrou par email tenté, lui, reste intact).
- La piste d'audit (`auth_audit_logs.ip_address`, `sessions.ip_address`,
  `ConnectionLog.ip`) — falsifiable, ce qui mine la traçabilité NIS 2 que tout le reste de
  l'app prend soin de préserver (cf. CLAUDE.md).

**Correctif** — un seul reverse-proxy (nginx) entre le client et le backend : pas besoin
de préserver une chaîne, juste écraser plutôt qu'ajouter.
```nginx
# frontend/nginx.conf
proxy_set_header X-Forwarded-For $remote_addr;   # écrase, n'ajoute plus
```
```js
// frontend/vite.config.js — ignorer l'en-tête client, ne garder que le socket réel
const clientIp = req.socket?.remoteAddress || 'unknown'
```
Optionnel, défense en profondeur : côté backend, ignorer `X-Forwarded-For` si la requête
ne vient pas de nginx (adresse source hors du réseau Docker interne) — inutile tant que
`backend`/`8000` reste borné à `127.0.0.1` (cf. tour du 03/08/2026).

- [x] `nginx.conf` corrigé (écrase au lieu d'ajouter) — 10/08/2026
- [x] `vite.config.js` corrigé (ignore l'en-tête client, socket réel uniquement) — 10/08/2026,
      celui réellement actif en dev
- [x] Vérifié en conditions réelles (10/08/2026) : `POST /api/connections` avec un
      `X-Forwarded-For` falsifié (`6.6.6.6`) enregistre bien l'adresse socket réelle,
      pas la valeur envoyée par le client — testé avant/après correctif (le "avant"
      confirmait l'exploitabilité, le "après" confirme le correctif)

---

### 🟠 #10 — `must_change_password` non appliqué côté serveur (MOYEN)

**Où** : `frontend/src/components/ProtectedRoute.jsx` (seul endroit qui applique la règle)

**Problème** : le compte bootstrap (`BOOTSTRAP_ADMIN_EMAIL`/`PASSWORD`, mot de passe fort
mais **en clair dans `.env`**, censé être changé à la première connexion) — comme tout
compte créé par un admin avec `force_password_reset` — n'est bloqué que par un écran React
(`ForcedPasswordChange`). Rien côté API ne vérifie ce flag : un appel direct (`curl`, script,
ou simplement fermer/contourner le composant) avec les identifiants provisoires donne un
accès complet et **permanent** à l'API, y compris si le mot de passe n'est jamais changé.
Le contrôle d'accès existe, mais uniquement dans la couche qui peut être contournée par
définition (le client) — même famille d'erreur que l'ancien sélecteur "Je suis…" retiré le
30/07/2026 pour cette exacte raison (masquage visuel sans valeur de sécurité, cf. CLAUDE.md).

**Correctif** — vérifier le flag dans `require_auth` (ou une variante dédiée), en
laissant passer uniquement les routes nécessaires pour changer le mot de passe :
```python
# auth_deps.py — require_auth
ALLOWED_WHILE_MUST_CHANGE = {("POST", "/api/auth/change-password"),
                              ("POST", "/api/auth/logout"), ("GET", "/api/auth/me")}

async def require_auth(request: Request, session: AsyncSession = Depends(get_session)) -> User:
    ...
    if user.must_change_password and (request.method, request.url.path) not in ALLOWED_WHILE_MUST_CHANGE:
        raise HTTPException(403, "Changement de mot de passe requis avant de continuer.")
    return user
```
- [x] Garde-fou serveur ajouté (10/08/2026, `auth_deps.py::require_auth`)
- [x] Testé en conditions réelles : compte de test temporaire `must_change_password=true`
      créé → `GET /api/assets` refusé en 403, `GET /api/auth/me` et
      `POST /api/auth/change-password` acceptés en 200, `GET /api/assets` de nouveau
      accepté en 200 une fois le mot de passe changé. Compte de test supprimé après coup.

---

### 🟡 #11 — Aucun en-tête de sécurité de réponse (FAIBLE À MOYEN selon upload)

**Où** : `backend/main.py` (aucune middleware d'en-têtes)

**Problème** : ni `X-Content-Type-Options: nosniff`, ni `X-Frame-Options`/
`Content-Security-Policy`. Les documents/pièces jointes (Documentation, Incidents, Audits)
ne valident que les **premiers octets** (signature magique, cf. `document_storage.py`) —
un fichier qui commence par un en-tête PNG/PDF valide mais contient du HTML/JS ensuite,
servi en `Content-Disposition: inline` (PDF/PNG/JPEG), pourrait dans certains navigateurs
anciens/en mode de compatibilité être re-sniffé comme HTML au lieu du type déclaré. Impact
limité (navigateurs modernes respectent déjà le `Content-Type` explicite posé par l'API),
mais correctif quasi gratuit.

**Correctif** :
```python
# main.py — juste après CORSMiddleware
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response
```
- [x] Middleware ajouté (10/08/2026, `main.py::security_headers`)
- [x] Testé : `curl -I /api/health` renvoie bien `x-content-type-options: nosniff` et
      `x-frame-options: DENY`

---

### 🟡 #12 — Comparaison non constante du jeton interne (FAIBLE)

**Où** : `backend/auth_deps.py::require_page_or_internal` — `token == settings.INTERNAL_API_TOKEN`

**Problème** : comparaison de chaînes standard Python, pas à temps constant — vulnérable en
théorie à une attaque temporelle pour deviner `INTERNAL_API_TOKEN` octet par octet. Risque
réel faible (jeton partagé `worker`↔`backend` en interne, jamais exposé au navigateur), mais
correctif trivial.

**Correctif** :
```python
import hmac
if settings.INTERNAL_API_TOKEN and hmac.compare_digest(token or "", settings.INTERNAL_API_TOKEN):
    return None
```
- [x] Corrigé (10/08/2026, `hmac.compare_digest`, `auth_deps.py::require_page_or_internal`)

---

### 🟢 Reconfirmé — items du 27/07/2026 toujours ouverts, rien de nouveau

Ces trois points de la revue Docker (§ ci-dessus) n'ont pas bougé, un rappel suffit plutôt
qu'une nouvelle entrée : **conteneurs backend/frontend en root** (pas de `USER` dans les
Dockerfiles), **serveurs de dev exposés** (`uvicorn --reload`/`vite dev`, assumé tant que
l'outil reste en développement actif), **pas de `.dockerignore`**.

### ✅ Reconfirmé conforme sur le nouveau périmètre

RBAC (`require_page`/`require_admin`) posé de façon cohérente et documentée sur les 20
routers de `main.py`, aucun oubli constaté · uploads (Documents/Incidents/Audits) : nom de
fichier jamais utilisé comme chemin réel, toujours renommé en UUID, signature magique
vérifiée, taille plafonnée · aucune fuite de secret (clés API WithSecure/Meraki/PRTG) dans
une réponse API ou un log · clients API sortants (WithSecure/Meraki) en `verify=True` par
défaut ; l'exception PRTG (`PRTG_VERIFY_TLS=false`, CA interne non reconnue par le
conteneur) reste documentée et assumée, pas une régression · pas d'endpoint GET qui modifie
un état (CSRF déjà couvert par `SameSite=Lax` + CORS restreint, pas besoin d'un jeton CSRF
dédié pour ce modèle de menace) · aucune injection SQL trouvée sur le nouveau périmètre
(WithSecure/Meraki/PRTG/Audits/Documents/Crises) · mots de passe : bcrypt correct, minimum
16 caractères imposé **côté serveur** (pas seulement le formulaire), verrou anti-bruteforce
par email ET IP (IP faussable, cf. #9).

**Ordre conseillé** : #9 → #10 → #11 → #12.

**État au 10/08/2026** : #9, #10, #11, #12 corrigés et testés en conditions réelles le jour
même (choix explicite de l'utilisateur, les 4 proposés ont été retenus).

---

## Fuzzing (10/08/2026) — parseurs internes + API en conditions réelles

> Demande explicite ("le fuzzing ça te parle ?"), scope validé avec l'utilisateur : parseurs
> internes en profondeur (`hypothesis`), API elle-même restreinte à **lecture seule** (GET
> uniquement) pour ne jamais risquer d'abîmer les vraies données du parc.

### Fuzzing par propriétés (hypothesis) — parseurs internes

`hypothesis==6.165.2` ajouté à `requirements.txt` (n'entraîne aucune mise à jour forcée de
`pytest`, vérifié avant d'ajouter — contrairement à `schemathesis`, cf. plus bas). 3 nouveaux
fichiers dans `backend/tests/`, 17 tests, tous verts :

- `test_net_guard_fuzz.py` — `services/net_guard.py` (garde-fou SSRF, #1). Propriété centrale :
  pour n'importe quelle IP générée aléatoirement (v4/v6, y compris IPv4-mappée type
  `::ffff:127.0.0.1`), le verdict accepté/rejeté correspond toujours exactement à
  `ipaddress.*.is_private/is_loopback/etc`. Complété par des cas connus de contournement SSRF
  testés en dur contre le vrai `socket.getaddrinfo` (décimal `2130706433`, hexadécimal
  `0x7f000001`, octal `0177.0.0.1`, forme courte `127.1`, IPv4-mappée IPv6) : **tous rejetés
  correctement** — `net_guard.py` résout d'abord via `getaddrinfo` (qui normalise ces formes)
  puis classifie le résultat, ce qui immunise contre ce contournement par construction, pas
  par chance.
- `test_csv_safety_fuzz.py` — `services/csv_safety.py` (#7). Le premier caractère du résultat
  n'est jamais un déclencheur de formule, quelle que soit l'entrée.
- `test_document_storage_fuzz.py` — `services/document_storage.py`. Contenu/nom de fichier
  arbitraires : jamais de crash hors `ValueError`, invariant de signature respecté si accepté.

**Aucun bug trouvé dans ces trois services** — confirme leur robustesse plutôt qu'un échec du
fuzzing (500 exemples générés par propriété).

### Fuzzing de l'API (schemathesis) — GET uniquement, contre l'environnement réel

`schemathesis` **volontairement non ajouté** à `requirements.txt` : tirerait `pytest` vers la
9.x (testé via `pip install --dry-run`), un saut majeur qui aurait pu casser les 166 tests
existants sans bénéfice pour un outil qu'on utilise ponctuellement. Exécuté à la place dans un
conteneur `python:3.12-slim` jetable sur le réseau Docker du projet, génère ses cas depuis le
schéma OpenAPI déjà exposé par FastAPI (`/openapi.json`, zéro configuration par endpoint) :

```bash
docker run --rm --network cybervuln_default python:3.12-slim bash -c "
  pip install --quiet schemathesis==4.24.3
  schemathesis run http://backend:8000/openapi.json \
    --url http://backend:8000 \
    --header 'Cookie: cbr_session=<token>' \
    --include-method GET --phases coverage --checks not_a_server_error
"
```

**🔴 Trouvé et corrigé — 500 au lieu de 404 sur ID malformé (79 endpoints concernés)** :
n'importe quel `GET /api/{router}/{id}/...` avec un `id` qui n'est pas un UUID syntaxiquement
valide (ex. `/api/documents/0/download`) faisait planter `session.get(Model, id)` avec une
`sqlalchemy.exc.DBAPIError` (asyncpg `DataError`) non interceptée → 500 avec trace complète.
Confirmé sur `vulnerabilities/{id}/other-instances`, `vulnerabilities/{id}/status-history`,
`assets/{id}/packages`, `assets/{id}/pending-updates`, `audits/{id}`, `documents/{id}/download`
— 79 occurrences de `session.get(...)` dans les routers au total, très probablement bien
d'autres routes touchées. **Correctif global plutôt que 79 correctifs locaux** (`main.py`,
`@app.exception_handler(DBAPIError)`) : la vraie exception asyncpg vit dans
`exc.orig.__cause__` (SQLAlchemy la wrappe deux fois pour ce dialecte), ne traite que le cas
`asyncpg.exceptions.DataError` (mauvais format), relève tel quel toute autre `DBAPIError`
(contrainte violée, connexion perdue...) pour ne pas masquer un vrai 500. Vérifié en
conditions réelles : les 6 endpoints ci-dessus renvoient désormais `404
{"detail":"Ressource introuvable (identifiant invalide)."}` ; un appel valide (`GET
/api/assets`) et la suite de tests complète (166) inchangés après coup.
- [x] Handler ajouté et testé (10/08/2026)

**🟠 Constaté et mitigé le jour même — le backend entier avait cessé de répondre pendant plus
de 2 minutes** (y compris `/api/health`, aucune dépendance DB) lors du premier run
schemathesis **concurrent** (`-w auto`, plusieurs workers en parallèle) — nécessité d'un
redémarrage manuel pour restaurer le service. **Non reproduit en séquentiel** (`-w 1`)
au-delà de brefs ralentissements (~13s, auto-résolus). `database.py` utilise `NullPool`
(poolclass) donc **aucune limite de connexions concurrentes côté application** — chaque
requête ouvre une connexion PostgreSQL neuve (`max_connections=100` côté serveur). Une
rafale de requêtes concurrentes (fuzzer, mais aussi un pic de trafic légitime) peut saturer
ce plafond et mettre en file d'attente/geler des requêtes sans rapport, y compris
`/api/health`.

**Décision (10/08/2026, demande explicite : "5 connexions simultanées")** : sémaphore
`asyncio.Semaphore(DB_MAX_CONCURRENT_SESSIONS)` (défaut 5, `config.py`) posé dans
`database.py::get_session` — utilisé par les **162 routes** de l'API (cf. `routers/`), le
vrai chemin qu'emprunte une rafale de requêtes HTTP externes. `NullPool` **conservé tel
quel**, jamais touché : un sémaphore ne retient ni ne réutilise aucune connexion entre deux
requêtes (contrairement à un pool classique type `QueuePool`), il limite juste combien de
requêtes peuvent en détenir une **en même temps** — donc pleinement compatible avec la
contrainte Celery (nouvelle boucle asyncio à chaque `asyncio.run()`) qui avait motivé
`NullPool` à l'origine. Les `SessionLocal()` ouverts directement dans `services/` (tâches
de fond, Celery — jamais des dizaines de requêtes concurrentes déclenchées de l'extérieur,
le scénario réellement observé) restent volontairement hors de ce plafond.

Vérifié en conditions réelles : 40 requêtes concurrentes vers `GET /api/assets` traitées
par vagues d'environ 5 (temps de complétion en palier : 2,2s → 17s, pas toutes en même
temps) ; `GET /api/health` reste à `200` en continu **pendant toute la rafale** (15 sondes,
aucun timeout) — contrairement à l'incident d'origine. Suite de tests complète (166)
inchangée, `worker`/`beat` toujours sains après coup (ne consomment jamais `get_session`,
confirmé par recherche dans `services/`/`tasks/`).

- [x] Sémaphore ajouté (`database.py`, `config.py::DB_MAX_CONCURRENT_SESSIONS=5`) — 10/08/2026
- [x] Testé en conditions réelles : rafale de 40 requêtes mises en file d'attente,
      `/api/health` jamais indisponible pendant le test, 166 tests toujours verts
