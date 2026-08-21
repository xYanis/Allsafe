# Audit de sécurité — Allsafe (ex-CBR/CyberVuln)

> Fichier unique (19/08/2026, demande explicite — "on en a trop aujourd'hui") : fusionne les
> 4 revues distinctes menées entre le 24/07/2026 et le 18/08/2026, jusqu'ici dans 4 fichiers
> séparés (`AUDIT_SECURITE_1.md` à `_4.md`, désormais supprimés). Contenu inchangé, ordre
> chronologique conservé, **numérotation des findings inchangée** (#1 à #37, continue d'une
> revue à l'autre) — seuls les titres de section de tête de chaque revue sont passés en `##`
> pour s'insérer dans un seul document. Toutes les références `cf. audit/AUDIT_SECURITE_N.md`
> dans le code pointent désormais vers ce fichier unique, `#N` inchangé.
>
> **État global au 19/08/2026 : les 37 findings numérotés sont clos** (corrigés et — sauf
> mention contraire — vérifiés en conditions réelles), à l'exception de #5 (attente
> délibérée, sans objet une fois le repo git initialisé) et de deux décisions actées sans
> changement de code (§ Revue du 18/08/2026 (3), #28 et la note `severity IS NULL`).

---

## Revue du 24/07/2026 — première revue défensive

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

### 🔴 #1 — SSRF via les sources de veille (ÉLEVÉ, seul exploitable à distance sans creds)

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

### 🟠 #2 — Vérification de clé d'hôte SSH désactivée (MOYEN)

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

### 🟠 #3 — Bind LDAP en clair (MOYEN)

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

### 🟠 #4 — Parseur XML non durci sur flux distants (MOYEN)

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

### 🟡 #5 — Aucun `.gitignore` (FAIBLE mais à faire AVANT tout `git init`)

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

### 🟡 #6 — Secrets par défaut « changeme » (FAIBLE)

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

### ℹ️ Info / hygiène (pas de code, mais à traiter)

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
      - [x] Frontend **refermé le 18/08/2026** (§ Revue du 18/08/2026 (2) ci-dessous) : mise à jour
        de routine (`react-router-dom@7.18.2`, `vite@7.3.6`), `npm audit` renvoie désormais 0
        vulnérabilité — plus rien à corriger sur ce point.

---

### 🔴 #7 — Injection de formule CSV/Excel dans les exports (ÉLEVÉ sur le rapport auditeur NIS 2)

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

### 🟡 #8 — Passage `bandit` (SAST), backend (27/07/2026)

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

### 🐳 Docker / conteneurs (revue du 27/07/2026)

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
        **Repassé en multi-stage le 18/08/2026** (§ Revue du 18/08/2026 (2), #32) — `gcc`/
        `libldap2-dev`/`libsasl2-dev` (nécessaires seulement à `pip install`) retirés de
        l'image finale.
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

### ✅ Vérifié conforme (dans le code, pas juste la doc) — 24/07/2026

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
- [x] **Complété le 18/08/2026** (§ Revue du 18/08/2026 (2), #33) — ce middleware ne couvre
      que les réponses proxées via `/api/`, pas les fichiers statiques (`index.html`,
      bundles JS/CSS) servis directement par nginx pour `location /` : mêmes deux en-têtes
      ajoutés là aussi, scopés à cette location pour ne pas dupliquer ceux du backend sur
      `/api/`.

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

### ✅ Reconfirmé conforme sur le nouveau périmètre — 10/08/2026

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

⚠️ **NOTE — RBAC "aucun oubli constaté" invalidée le 18/08/2026** : la conclusion ci-dessus
tenait le 10/08/2026, mais `assets.router` a reçu de nouveaux endpoints d'écriture entre le
07 et le 17/08/2026 sans reprendre le RBAC déjà en place ailleurs — cf. #14 (§ Revue du
18/08/2026 (2)), la vraie prochaine revue formelle à avoir trouvé cette régression.

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
existants sans bénéfice pour un outil qu'on utilise ponctuellement (le saut vers `pytest` 9 a
finalement eu lieu le 18/08/2026 pour une tout autre raison, cf. #29 § Revue du 18/08/2026 (3)
— vérifié en conditions réelles ce jour-là, sans casse). Exécuté à la place dans un
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
      (relevé à 15 le 14/08/2026, cf. CLAUDE.md — 5 saturait dès qu'un 2e onglet/utilisateur
      était actif, sans rapport avec un problème de sécurité)
- [x] Testé en conditions réelles : rafale de 40 requêtes mises en file d'attente,
      `/api/health` jamais indisponible pendant le test, 166 tests toujours verts

---

## Revue du 18/08/2026 (2) — module Agents, CI, mot de passe oublié

> Revue défensive du code (lecture + exploitation réelle contre les conteneurs Docker déjà
> en service), 18/08/2026. Fait suite à la revue du 10/08/2026 ci-dessus — ne couvre QUE ce
> qui a été ajouté depuis : module Agents (12-18/08), mise à jour auto + GUI Tauri de l'agent
> (18/08), politiques de scan planifié (17/08), intégrations GLPI/KEV/maturité d'exploit
> (11-17/08), mot de passe oublié (18/08), pipeline de signature CI (18/08).
>
> Méthodologie : 6 revues parallèles, chacune sur un périmètre distinct, avec exploitation
> réelle quand c'était possible (comptes/jetons/agents de test créés puis supprimés,
> conteneurs jamais laissés dans un état modifié). Numérotation reprise à la suite de la
> revue du 10/08/2026 (dernier numéro utilisé : #12).
>
> **Correctifs appliqués le 19/08/2026** (pas le jour même de cette revue, contrairement aux
> revues précédentes) — session de correctifs dédiée, cf. entrées `[x]` ci-dessous et
> `STATUS.md` § 19/08/2026 pour le détail (dont deux bugs trouvés en cours de correctif,
> pas dans le périmètre initialement audité : #16 déplacé avant la consommation du jeton,
> et le filtre du bandeau "depuis votre dernière visite" qui ne reconnaissait pas le nouveau
> libellé `validated_by` d'#34).

### 🔴 #13 — Mise à jour automatique de l'agent : exécution d'un `.msi` non vérifié (CRITIQUE)

**Où** : `agent/src/install.rs` (`apply_update`), rejoué à l'identique dans
`agent/deploy/update-agent.ps1` (script recommandé pour le déploiement de parc).

**Problème** : `apply_update()` télécharge les octets bruts d'un `.msi` depuis
`GET {server}/api/agents/latest/windows`, les écrit dans `%TEMP%` puis lance directement
`msiexec /i <tmp> /qn`. **Aucune vérification de signature Authenticode ni d'empreinte**
entre le téléchargement et l'exécution — confirmé par grep exhaustif (`signature|verify|
osslsigncode|Authenticode`) sur tout le crate Rust : zéro résultat dans `install.rs`/
`gui.rs`. La signature Authenticode ajoutée en CI (`.gitlab-ci.yml::build-agent`, cf. #25-27
plus bas) ne sert qu'à éviter le bandeau UAC "Éditeur inconnu" côté utilisateur — jamais
consommée par l'agent lui-même. `require_elevated()` est bien rappelé avant l'installation
(l'élévation admin est réelle), ce qui signifie que le fichier non vérifié s'installe
**avec des droits administrateur confirmés**.

**Scénario d'exploit** : n'importe qui en position de se faire passer pour `{server}` —
MITM réseau local (le champ serveur est nativement en HTTP par défaut, cf. #17), spoofing
DNS, ou compromission du vrai backend Allsafe/CI — répond avec un `.msi` arbitraire →
exécution de code arbitraire en admin sur chaque poste qui clique "Mettre à jour", ou sur
**tout le parc** via la tâche planifiée GPO documentée comme méthode de déploiement
recommandée. Chaîne d'approvisionnement classique sur un agent privilégié.

**Correctif** :
- Vérifier la signature Authenticode du `.msi` téléchargé **avant** `msiexec /i` (crate
  `windows` → `WinVerifyTrust`, ou `signtool verify /pa /v <fichier>` en subprocess),
  comparer le Subject au certificat Allsafe distribué par GPO (cf. `docs/AGENTS.md` §
  Signature).
- Alternative moins coûteuse : endpoint séparé servant un hash SHA-256 attendu (signé ou
  servi en HTTPS avec pinning), comparé avant exécution.
- Forcer `https://` sur CET appel précis, indépendamment de #17.

- [x] **Correctif retenu (19/08/2026) : SHA-256, pas Authenticode** — le certificat de
      signature CI est aujourd'hui auto-signé (cf. #25-27), non vérifiable par une chaîne
      de confiance standard tant que la distribution GPO du `.cer` (§ Signature,
      `docs/AGENTS.md`) n'est pas faite. `GET /latest/version` publie désormais
      `sha256_windows`/`sha256_linux` (empreinte du paquet actuellement publié,
      `routers/agents.py::latest_agent_version`), comparée par `apply_update()` (Rust) et
      `update-agent.ps1`/`.sh` au SHA-256 réel du fichier téléchargé avant tout
      `msiexec /i`/`dpkg -i` — refuse l'installation si absent ou différent. Protège contre
      un MITM qui altère le paquet sans contrôler aussi la réponse `/latest/version`
      (transport HTTPS) ; ne protège **pas** contre un backend totalement compromis (qui
      publierait un hash correspondant à son propre paquet malveillant) — seule une vraie
      signature vérifiée le ferait, cf. `docs/AGENTS.md` § Signature pour le suivi.
- [x] Même vérification ajoutée côté `update-agent.ps1`/`.sh` (les deux scripts de
      déploiement — jamais supprimés, restent la méthode d'installation recommandée)
- [ ] **HTTPS non forcé sur ce chemin** (décision explicite, cf. #17 ci-dessous) — le check
      SHA-256 seul ne bloque pas un MITM actif tant que le serveur de prod reste en HTTP

---

### 🔴 #14 — `routers/assets.py` : aucune restriction de rôle sur les endpoints d'écriture (ÉLEVÉ)

**Où** : `backend/routers/assets.py` — `create_asset`, `update_asset`,
`network-protocol-check/run`, `switch-hardening/run`, `web-hardening/run`, et la branche
agent de `scan_asset_endpoint`. `assets.router` est monté avec `dependencies=_authed`
seul (`main.py:224`) — **aucun** `require_admin`/`require_page`, contrairement à la quasi-
totalité des autres routers d'écriture du projet. La revue du 10/08/2026 notait "RBAC posé
de façon cohérente... aucun oubli constaté" — ce n'est plus vrai depuis les endpoints
ajoutés le 07-17/08. Racine commune trouvée indépendamment sous **trois angles distincts**
par deux audits séparés (confirmation croisée) :

**A) SSRF via `Asset.url` non validé** (`services/web_hardening.py`, `check_website`,
`httpx...get(url, follow_redirects=True)`) : `net_guard.validate_public_url` (créé
justement pour ce cas, cf. #1) n'est appelé nulle part sur ce chemin.
N'importe quel compte connecté — y compris un `analyst` restreint via `allowed_pages` (la
restriction ne couvre justement pas `/api/assets`, décision déjà actée) — peut créer un
actif `asset_type="website", url="http://127.0.0.1:6379/"` (ou une IP de métadonnées cloud,
ou un service interne du parc) puis déclencher `POST /assets/web-hardening/run` : le
backend fait le fetch, restitue en-têtes/cookies/version TLS dans `web_compliance`. SSRF
aveugle exploitable pour scanner le réseau interne — même faille que #1, sur un point
d'entrée créé après coup sans reprendre le garde-fou déjà écrit.

**B) Sonde réseau interne via `ip_address`/identifiants libres** (`network_protocol_check.py`,
`switch_hardening.py`) : un actif `asset_type="network"` avec `ip_address` = une cible
interne quelconque et `scan_username`/`scan_password` fournis par l'appelant transforme le
backend en sonde SSH — le détail d'erreur de connexion renvoyé (`switch_hardening.py`)
permet de tester des couples identifiant/mot de passe contre des hôtes internes.

**C) Déclenchement non autorisé de scan agent** — trouvé indépendamment par deux audits :
`POST /assets/{id}/scan` (branche `collection_method=="agent"`) pose
`agent.pending_scan_requested_at` — exactement l'action que `POST /agents/{id}/request-scan`
réserve explicitement à `require_admin`. Tout compte connecté peut la déclencher via cette
voie parallèle. Impact limité (lecture seule côté agent) mais incohérence réelle de contrôle
d'accès.

**Correctif** — restreindre l'écriture/le scan sur les actifs à `require_admin` (ou une
permission dédiée si un accès `analyst` non-admin doit rester possible, à trancher avec
l'utilisateur — pas un oubli technique mais un choix de modèle de permission) :
```python
# routers/assets.py
from auth_deps import require_admin, require_auth
from models import User

@router.post("", status_code=201, dependencies=[Depends(require_admin)])
@router.put("/{asset_id}", dependencies=[Depends(require_admin)])
@router.post("/network-protocol-check/run", dependencies=[Depends(require_admin)])
@router.post("/switch-hardening/run", dependencies=[Depends(require_admin)])
@router.post("/web-hardening/run", dependencies=[Depends(require_admin)])

@router.post("/{asset_id}/scan")
async def scan_asset_endpoint(..., user: User = Depends(require_auth)):
    ...
    if asset.collection_method == "agent":
        if user.role != "admin":
            raise HTTPException(403, "Demande de scan agent réservée aux administrateurs.")
```
Et reprendre le correctif SSRF déjà écrit pour #1 (`validate_public_url`) sur `create_asset`/
`update_asset` (URL) + revalidation par hop dans `web_hardening.py::check_website`
(`follow_redirects=False` + boucle).

- [x] **Décision retenue (19/08/2026, arbitrée avec l'utilisateur) : `require_admin` sur
      la totalité des endpoints d'écriture/scan**, y compris `scan_asset_endpoint` en
      entier (pas seulement la branche agent comme proposé ci-dessus) et `delete_asset`
      (pas listé par cette revue, même trou trouvé et corrigé au passage)
- [x] `validate_public_url` branché sur la création/mise à jour d'un actif `website`
- [x] Revalidation des redirections dans `web_hardening.py` (`follow_redirects=False` +
      boucle de re-validation par hop)
- [x] `require_admin` posé sur create/update/delete/scan d'actif + les 3 endpoints de
      durcissement réseau/switch/web
- [x] Frontend aligné (`Assets.jsx`/`Durcissement.jsx`) : boutons masqués/désactivés pour
      un compte non-admin, évite le 403 sec
- [x] Test anti-régression ajouté (`test_auth_guardrails.py`)
- [ ] Nettoyage des actifs `website` déjà en base créés avant le correctif — pas fait,
      à vérifier manuellement si pertinent

---

### 🔴 #15 — Race condition (TOCTOU) sur `max_uses` des jetons d'enrôlement agent (ÉLEVÉ)

**Où** : `backend/routers/agents.py` (`enroll_agent`) — lecture de `use_count` puis
écriture différée (`token.use_count += 1`, commit plus tard), sans verrou de ligne ni
contrainte atomique.

**Reproduit en conditions réelles** : 15 requêtes `POST /api/agents/enroll` concurrentes
avec le **même** jeton `max_uses=1` → **15 identités agent valides créées** (15×201), toutes
avec un credential fonctionnel. `GET /enrollment-tokens` affiche ensuite `use_count: 1` —
**l'audit trail lui-même est faux**, l'admin croit qu'un seul poste a consommé le jeton.

**Aggravant testé séparément** — même test avec un jeton lié à un `asset_id` précis
(`max_uses=1` obligatoire pour ce cas) → 10 agents distincts rattachés au **même actif
réel**. Chacun peut ensuite `POST /checkin` avec un hostname/paquets/hardware arbitraires,
appliqués tels quels par `apply_scan_result` (aucune vérification de correspondance, cf.
#16). **Casse aussi une fonctionnalité déjà livrée** : `POST /assets/{id}/scan` sur cet
actif renvoie désormais un `500` reproductible (`MultipleResultsFound`, le code suppose 0
ou 1 agent enrôlé par actif).

**Correctif** — `UPDATE ... WHERE use_count < max_uses ... RETURNING` en une seule requête
atomique (verrouille la ligne côté Postgres, sérialise les requêtes concurrentes) :
```python
# routers/agents.py — enroll_agent
result = await session.execute(
    update(AgentEnrollmentToken)
    .where(AgentEnrollmentToken.token_hash == token_hash,
           AgentEnrollmentToken.use_count < AgentEnrollmentToken.max_uses,
           AgentEnrollmentToken.expires_at >= now)
    .values(use_count=AgentEnrollmentToken.use_count + 1)
    .returning(AgentEnrollmentToken)
)
token = result.scalar_one_or_none()
if token is None:
    # distinguer invalide/expiré/épuisé SANS ré-écrire la ligne (juste pour le message)
    ...
```

- [x] `UPDATE ... RETURNING` atomique en remplacement du lire-puis-écrire (19/08/2026)
- [x] Testé via la suite de tests (pas rejoué le scénario 15 requêtes concurrentes en
      conditions réelles cette fois — corrigé par une garantie Postgres structurelle, pas
      un correctif applicatif fragile)
- [x] Agents/actifs de test générés pendant cet audit déjà supprimés (fait, vérifié)

---

### 🟠 #16 — `apply_scan_result` fait confiance sans réserve au hostname/paquets déclarés par l'agent (MOYEN)

**Où** : `backend/services/asset_scanner.py::apply_scan_result` + `routers/agents.py`
(branche `asset_id` déjà fourni par le jeton).

**Problème** : rien ne vérifie que le hostname déclaré par l'agent correspond à l'actif visé
par un jeton lié à un `asset_id` précis. Combiné à #15 (ou à une simple interception réseau
du jeton), un tiers peut se faire délivrer un credential pour cet actif précis et lui faire
porter n'importe quel hostname/paquets/hardware/compliance — persistés tels quels, y compris
le renommage de l'actif.

**Correctif** — a minima journaliser l'écart plutôt que le silence total :
```python
if asset.hostname and data.hostname.strip().lower() != asset.hostname.strip().lower():
    logger.warning("Enrôlement agent : hostname déclaré (%s) != actif ciblé (%s, id=%s)",
                    data.hostname, asset.hostname, asset.id)
```

- [x] **Durci au-delà du correctif proposé (19/08/2026)** : mismatch hostname/actif ciblé
      **rejeté (403)**, pas seulement journalisé — un agent légitime connaît forcément son
      propre hostname, un mismatch est un signal fort de jeton détourné. Vérifié **avant**
      de consommer une utilisation du jeton (#15) : le faire après aurait grillé le jeton
      sur un simple typo, bug attrapé et corrigé avant livraison.

---

### 🟠 #17 — Aucune contrainte HTTPS sur les communications agent↔serveur (MOYEN, aggrave #13)

**Où** : `agent/src/api.rs` (`enroll`/`pending`/`checkin`), `agent/src/install.rs`
(`check_update`/`apply_update`).

**Problème** : `server` est une chaîne libre, aucune vérification de schéma — `http://`
accepté aussi bien que `https://` (l'UI d'installation et les scripts de déploiement le
proposent même par défaut en HTTP). En clair, transitent : le jeton d'enrôlement (une fois),
le `X-Agent-Token` (à chaque check-in), et surtout le `.msi` de mise à jour (#13) — un MITM
sur le réseau interne (même classe que le SSH #2 déjà corrigé : ARP spoofing/VLAN partagé)
suffit à les capturer/substituer.

**Correctif** :
```rust
// agent/src/api.rs — en tête de enroll()/pending()/checkin(), et install.rs pour l'update
if !server.starts_with("https://") {
    anyhow::bail!("le serveur Allsafe doit être en HTTPS (http:// refusé)");
}
```
Si HTTP doit rester toléré à court terme (pas de reverse-proxy TLS en place aujourd'hui),
documenter le risque dans `docs/AGENTS.md` comme le fait déjà `CLAUDE.md` pour WinRM/LDAP —
mais forcer HTTPS au minimum sur le chemin de mise à jour (#13), qui est le plus critique.

- [x] **Décision explicite (19/08/2026) : avertissement non bloquant, pas de blocage
      strict** — le serveur de prod tourne encore en HTTP aujourd'hui (`COOKIE_SECURE=false`,
      aucun reverse-proxy TLS en place, cf. CHECKLIST_DOCKER.md) : bloquer aurait cassé la
      mise à jour en conditions réelles. `warn_if_not_https()` (Rust) affiche un avertissement
      sur `check_update`/`apply_update` sans interrompre l'appel — combiné au check SHA-256
      (#13), un MITM actif peut réécrire hash et `.msi` dans la même requête HTTP tant que ce
      n'est qu'un avertissement. **À repasser en blocage strict au déploiement du
      reverse-proxy TLS**, documenté dans `docs/AGENTS.md`.
- [ ] Décision sur le reste des appels (enroll/pending/checkin) — pas d'avertissement non
      plus pour l'instant, même raisonnement

---

### 🟡 #18 — `agent.json`/`enroll-defaults.json` sans restriction de permissions sous Windows (FAIBLE à MOYEN)

**Où** : `agent/src/config.rs` (`restrict_permissions`, no-op sous `#[cfg(not(unix))]` —
la version Linux fait un vrai `chmod 600`) + `agent/src/daemon.rs::bootstrap_from_defaults`
(lit `enroll-defaults.json` sans jamais en restreindre les permissions).

**Problème** : déjà documenté comme limite MVP assumée (`docs/AGENTS.md`), mais jamais
évalué avec un scénario concret. `%ProgramData%\allsafe-agent\agent.json` contient le
credential en clair — sous des ACL par défaut Windows correctement héritées, un utilisateur
standard ne devrait pas pouvoir le lire, mais rien dans le code ne le garantit (contrairement
à Linux). Plus grave pour `enroll-defaults.json` (jeton **bulk réutilisable**, pensé pour
être embarqué dans une image de déploiement) : jamais protégé, et combiné à #15, un seul
jeton extrait d'une image suffit à générer un nombre illimité d'identités.

**Correctif** — restreindre l'ACL de `%ProgramData%\allsafe-agent` à `SYSTEM`+`Administrators`
à la création (`icacls` invoqué depuis `install.rs`, ou crate `windows-acl`), à planifier
avant tout déploiement de parc au-delà d'un poste de test isolé.

- [x] ACL explicite posée sur `%ProgramData%\allsafe-agent` (19/08/2026, `icacls` invoqué
      depuis `config.rs::restrict_permissions`, SID bien connu `*S-1-5-32-544` pour
      Administrators plutôt que le nom du groupe — indépendant de la langue d'installation
      Windows ; SYSTEM + Administrators, best-effort/non bloquant si `icacls` échoue)
- [ ] `enroll-defaults.json` (répertoire d'installation, pas `%ProgramData%`) — pas couvert,
      risque jugé disproportionné par rapport au gain (restreindre l'ACL de tout le dossier
      d'installation pourrait empêcher un utilisateur standard de lancer l'exe en CLI)

---

### 🟠 #19 — Mot de passe oublié : race condition sur la dédup des demandes en attente (MOYEN)

**Où** : `backend/routers/auth.py::forgot_password` — vérification puis insertion non
atomique, aucune contrainte unique en base (`schema_patches.sql` ne pose que des index
non-uniques sur `password_reset_requests`).

**Reproduit en conditions réelles** : 15 requêtes concurrentes sur le même compte → **2
lignes `pending`** au lieu d'1 (confirmé en base). Casse le garde-fou annoncé par le
commentaire ("un utilisateur qui reclique ne doit pas empiler des doublons") et permet de
flooder le panneau admin sans effort.

**Correctif** :
```sql
CREATE UNIQUE INDEX ux_password_reset_pending ON password_reset_requests(user_id)
WHERE status='pending';
```
+ capturer l'`IntegrityError` côté Python (retomber sur un update), ou `SELECT ... FOR UPDATE`
avant de décider insert/update.

- [x] Contrainte unique partielle ajoutée (`schema_patches.sql::ux_password_reset_pending`,
      19/08/2026 — **pas encore rejouée contre une vraie base**, à faire côté déploiement)
      + `IntegrityError` catchée côté Python, repli sur update via une SAVEPOINT
      (`session.begin_nested()`) pour ne pas invalider la transaction entière

---

### 🟠 #20 — Mot de passe oublié : aucun rate-limiting ni traçabilité (MOYEN)

**Où** : `backend/routers/auth.py::forgot_password` — contrairement à `/login`
(`is_locked_out`/`count_recent_failures`, verrou 5/email + 20/IP en 15 min, **et**
`record_audit` sur chaque tentative y compris email inexistant), cette route n'appelait ni
l'un ni l'autre.

**Testé** : ~90 requêtes envoyées pendant l'audit (76 sur un email valide) →
`auth_audit_logs` sur les 20 dernières minutes : **1** ligne, sans rapport avec ces tests.
Zéro trace. Contredit le principe de traçabilité NIS 2 que le reste de l'app respecte
scrupuleusement (même les emails inexistants sont loggés sur `/login`), et laisse le canal
de timing (#22) exploitable sans aucune détection ni frein.

**Correctif** — réutiliser le verrou par IP de `/login` (ou un compteur dédié) + logger
l'appel dans `auth_audit_logs` (nouvel `event_type`, ex. `PASSWORD_RESET_REQUESTED`) même
sur email inconnu/inactif.

- [x] Verrou anti-spam par IP ajouté (`services/auth.py::is_password_reset_locked_out`,
      réutilise `count_recent_failures`/mêmes seuils que `/login`, 19/08/2026)
- [x] Journalisation dans `auth_audit_logs` (`event_type="PASSWORD_RESET_REQUESTED"`, toute
      tentative y compris email inconnu)

---

### 🟠 #21 — Mot de passe oublié : sessions actives non révoquées après remise à zéro (MOYEN)

**Où** : `backend/routers/users.py::resolve_password_reset_request` — fixe un nouveau mot
de passe + `must_change_password=True`, mais ne touche jamais `sessions`, alors que
`revoke_sessions` (même fichier) fait exactement ce `DELETE` et existe déjà.

**Problème** : un cookie de session volé pour ce compte reste valide après la remise à zéro
— restreint aux 3 routes autorisées tant que `must_change_password` est vrai, **mais**
redevient pleinement valide dès que l'utilisateur légitime change son mot de passe (le flag
repasse à `False` pour toutes les sessions du compte). C'est précisément le scénario que ce
flow est censé couvrir (perte d'appareil, session compromise).

**Correctif** :
```python
# resolve_password_reset_request — après avoir fixé le nouveau mot de passe
await session.execute(delete(UserSession).where(UserSession.user_id == user.id))
```

- [x] Révocation des sessions ajoutée dans `resolve_password_reset_request` (19/08/2026)

---

### 🟡 #22 — Mot de passe oublié : canal de timing mesurable (énumération) (FAIBLE)

**Où** : `backend/routers/auth.py::forgot_password` — le chemin "email inconnu/désactivé"
s'arrête après 1 `SELECT` ; le chemin "compte actif existant" ajoute 1 `SELECT` (dédup) + 1
`INSERT`/`UPDATE` + 1 `COMMIT`.

**Mesuré** : 40 requêtes entrelacées (alternance email inconnu/existant) → moyenne **~245ms
vs ~278ms**, écart reproduit sur deux runs indépendants (22-33ms). Corps et en-têtes de
réponse strictement identiques. Impact réel limité (5 comptes max, outil interne) mais rompt
la garantie explicitement annoncée en commentaire ("le contenu de la réponse ne doit jamais
confirmer qu'une adresse existe").

**Correctif** — égaliser le nombre d'opérations DB entre les deux branches, ou délai
artificiel constant avant de répondre.

- [x] Nombre d'opérations DB égalisé entre les deux branches (19/08/2026) — même requête de
      dédup exécutée dans les deux cas, sur un UUID sentinelle (`_NIL_USER_ID`) côté email
      inconnu plutôt qu'un court-circuit

---

### 🟡 #23 — Mot de passe oublié : race sur double-traitement d'une même demande (FAIBLE)

**Où** : `backend/routers/users.py::resolve_password_reset_request` — pas de
`SELECT ... FOR UPDATE`. Deux admins qui traitent la même demande à la même seconde peuvent
tous deux passer le contrôle `status != "pending"` avant que l'un des deux commite → le
second mot de passe écrase le premier sans erreur pour aucun des deux. Impact faible (5
comptes, nécessite 2 admins actifs simultanément) mais réel.

**Correctif** : `with_for_update()` sur le `SELECT` de la demande.

- [x] Verrou de ligne ajouté sur `resolve`/`dismiss` (19/08/2026)

---

### 🟡 #24 — Mot de passe oublié : aucune limite de taille sur le champ `message` (FAIBLE)

**Où** : `backend/routers/auth.py::ForgotPasswordPayload.message` (sans `max_length`),
aucune middleware de taille de requête dans `main.py`.

**Testé** : payload de 5 Mo accepté en 200 (0,31s) ; la troncature à 2000 caractères
s'applique bien **après** écriture (confirmé en base), mais après que tout le corps ait
déjà été bufferisé/parsé. Pas propre à cette route (`/login` a le même trou), mais l'une des
deux seules routes entièrement publiques.

**Correctif** : `Field(max_length=2000)` sur `message` + limite globale de taille de requête
pour les routes publiques.

- [x] `max_length` posé sur le champ Pydantic (19/08/2026)
- [ ] Limite globale de taille de requête pour les routes publiques — pas fait (`/login` a
      le même trou, hors scope de ce correctif ponctuel)

---

### 🟠 #25 — CI : job de signature non restreint aux branches protégées (MOYEN, sévérité réelle dépend de la config GitLab)

**Où** : `.gitlab-ci.yml` (`build-agent`, `rules: changes: agent/**/*`, aucune condition
sur `$CI_COMMIT_REF_PROTECTED`).

**Problème** : n'importe qui avec un accès push peut créer une branche, modifier ce fichier
(ex. exfiltrer `AGENT_SIGNING_PASSWORD`/le contenu du `.pfx` via une commande détournée) et
déclencher un pipeline touchant `agent/**`. Le job tourne alors avec les secrets de signature
disponibles **si** ces variables ne sont pas marquées "Protected" dans les réglages GitLab —
condition non vérifiable depuis les fichiers du dépôt. Le masquage GitLab ne protège que la
valeur littérale ; un `base64`/`rev` défait le masquage trivialement.

**Correctif** :
```diff
 build-agent:
   rules:
     - changes:
         - agent/**/*
+      if: '$CI_COMMIT_REF_PROTECTED == "true"'
```

- [x] Condition `CI_COMMIT_REF_PROTECTED` ajoutée (19/08/2026)
- [ ] **À vérifier côté toi, Settings > CI/CD > Variables** : `AGENT_SIGNING_PFX` et
      `AGENT_SIGNING_PASSWORD` cochées "Protect variable" ; MR pipelines depuis un fork
      n'exposent pas ces variables

---

### 🟠 #26 — CI : garantie erronée sur la gestion d'échec de la signature (MOYEN)

**Où** : `.gitlab-ci.yml` (commentaire : *"on se fie au code de sortie de `sign` (défaut
`set -e` de GitLab CI)"*) — faux pour un bloc multi-lignes (`- |`) : GitLab CI ne fait du
fail-fast qu'**entre** items de la liste `script:`, pas à l'intérieur d'un seul bloc shell.

**Problème** : si `osslsigncode sign` échoue à mi-chemin (mauvais mot de passe, `.pfx`
corrompu) sans que le script ne s'arrête explicitement, le `mv` suivant peut soit échouer
(heureux hasard, pas un garde-fou voulu), soit — selon le comportement de `osslsigncode` sur
un échec partiel — remplacer le binaire valide par un fichier corrompu, publié tel quel en
artifact, potentiellement avec un job final **vert**.

**Correctif** :
```diff
     - |
       if [ -n "$AGENT_SIGNING_PFX" ]; then
+        set -e
         echo "Signature Authenticode du .exe et du .msi..."
-        osslsigncode sign ... -out .../allsafe-agent-signed.exe
+        if ! osslsigncode sign ... -out .../allsafe-agent-signed.exe; then
+          echo "Échec de la signature (.exe)" >&2; exit 1
+        fi
         mv .../allsafe-agent-signed.exe .../allsafe-agent.exe
-        osslsigncode sign ... -out allsafe-agent-signed.msi
+        if ! osslsigncode sign ... -out allsafe-agent-signed.msi; then
+          echo "Échec de la signature (.msi)" >&2; exit 1
+        fi
         mv allsafe-agent-signed.msi allsafe-agent.msi
```
Corriger aussi le commentaire (retirer la mention du `set -e` implicite, faux).

- [x] `set -e` + vérification explicite du code de sortie ajoutés (19/08/2026)
- [x] Commentaire corrigé

---

### 🟡 #27 — CI : `CI_DEBUG_TRACE` non explicitement interdit (FAIBLE)

**Où** : `.gitlab-ci.yml`, globalement — rien n'active `set -x`/trace aujourd'hui (vérifié,
aucune occurrence), mais rien n'empêche non plus un déclenchement manuel avec
`CI_DEBUG_TRACE=true`, qui rend le masquage des variables moins fiable. Aggrave #25.

**Correctif** : politique GitLab (pas un changement de fichier) — restreindre qui peut
déclencher un pipeline manuel avec variables custom sur ce job.

- [x] Rappel documenté dans `.gitlab-ci.yml` (19/08/2026, à côté du bloc `AGENT_SIGNING_*`)
- [ ] Politique appliquée côté projet GitLab — pas un changement de fichier, à faire dans
      les réglages GitLab eux-mêmes

---

### 🟡 #28 — `GET /assets/lifecycle-since` expose les noms d'actifs supprimés à tout compte authentifié (INFO)

**Où** : `backend/routers/assets.py::assets_lifecycle_since` — même router `_authed` que le
reste de #14, décision déjà actée globalement pour ce router (cross-référencé
Dashboard/Incidents/Reports). Mais cet endpoint expose en plus les **hostnames d'actifs
supprimés** (`AssetDeletionLog`), une donnée qui n'existait nulle part avant et qui reste
visible même pour un analyste sans aucun module autorisé (`since=1970-01-01` renvoie
jusqu'à 100 noms). Pas un bug isolé — cohérent avec la décision globale déjà actée pour ce
router — mais à valider explicitement : l'historique des suppressions doit-il suivre la
même règle que l'état courant des actifs, ou mérite-t-il son propre `require_page` ?

- [x] **Décision prise avec l'utilisateur (19/08/2026)** : laissé ouvert à tout compte
      connecté, cohérent avec la limite déjà assumée sur `/api/assets`/`/api/vulnerabilities`
      (CLAUDE.md) — aucun changement de code, question de modèle de permission tranchée, pas
      un oubli technique.

---

### ✅ Vérifié conforme (testé, pas seulement lu) — 18/08/2026

**Enrôlement agent** : application de l'authentification sur toutes les routes testées en
direct (401 sans session/en-tête sur `/agents`, `/enrollment-tokens`, `/{id}/revoke`,
`/pending`, `/checkin` ; `/latest/version` public comme documenté) · hachage SHA-256 du
credential/jeton (256 bits, même idiome que les sessions utilisateur) · pas d'énumération
via les codes d'erreur de `/enroll` (jeton résolu par égalité de hash, inatteignable sans le
posséder déjà) · pas d'IDOR via le payload de check-in (`hostname`/`os` hors du payload
d'auth) · pas d'injection de commande côté Rust (`Command::new` avec arguments séparés,
`clap` sans interprétation shell) · message d'erreur uniforme agent inconnu/révoqué.

**Politiques de scan** : `require_admin_or_internal` rejette bien une requête sans session
ni jeton (testé en direct) · comparaison du jeton interne en temps constant
(`hmac.compare_digest`, cohérent avec #12) · `check_scan_policies`
appelle l'endpoint via une vraie requête HTTP avec le jeton lu depuis l'environnement ·
aucune requête SQL construite par concaténation dans `scan_policy.py` · `AssetDeletionLog`
inséré dans la même transaction atomique que la suppression (pas d'entrée orpheline
possible) · `GET /assets/lifecycle-since` correctement typé/borné côté Pydantic.

**Intégrations externes** : GLPI/KEV/maturité d'exploit/`kb_build` — hôtes fixes (constantes
codées en dur ou config admin), aucun champ utilisateur ne pilote la cible réseau ⇒ pas de
SSRF sur ces clients spécifiquement · `verify=True` préservé partout · aucun secret (tokens
GLPI) journalisé ou renvoyé en réponse API · aucun `dangerouslySetInnerHTML` sur les champs
GLPI (d'ailleurs non affichés côté frontend aujourd'hui) · `cvss_bte.py` sans appel réseau.

**Mot de passe oublié** : autorisation admin-only testée en direct sur les 4 endpoints
(list/count/resolve/dismiss, 401 sans session, jamais de 404 révélateur) · politique de mot
de passe appliquée côté serveur avant tout hash (pas de contournement possible) · aucun
`dangerouslySetInnerHTML` sur le champ `message` (rendu JSX brut, échappé) · cohérence
`ON DELETE CASCADE` entre `models.py` et `schema_patches.sql` · `GRANT` cohérent avec la
convention systématique du reste du fichier.

**Mise à jour agent / GUI Tauri** : aucune commande Tauri exposée ne construit de commande
shell ou de chemin fichier à partir d'un champ JS libre · `app.js` n'utilise jamais
`innerHTML` (toujours `.textContent`/`.value`) ⇒ pas de vecteur XSS DOM identifié
aujourd'hui · CSP (`default-src 'self'`) sans `unsafe-inline`/`unsafe-eval` pour les scripts
· `require_elevated()` correctement re-vérifié à chaque appel de mise à jour, pas mis en
cache · distribution `/latest/windows`/`/latest/version` : fichier fixe monté en lecture
seule, jamais alimenté par un endpoint d'upload HTTP.

**CI signature** : `AGENT_SIGNING_PFX` toujours traité comme un chemin (variable "File"),
jamais comme contenu inline · bloc `artifacts:` à chemins explicites, pas de glob large ·
raisonnement solide sur l'absence de `osslsigncode verify` en garde-fou (cert auto-signé) ·
dépendance manifeste `Common-Controls` réintroduite (correctif de crash réel,
`TaskDialogIndirect`) sans ajout de privilège · `WebView2Loader.dll` dans le même composant
MSI que l'exe, sans modification d'ACL.

---

**Ordre conseillé** : #13 (RCE, le plus critique) → #14 (SSRF + autorisation, racine
commune à 3 problèmes) → #15 (race jetons agent, casse aussi une fonctionnalité livrée) →
#17 → #16 → #19 → #20 → #21 → #25 → #26 → #18 → #22 → #23 → #24 → #27 → #28.

**État au 19/08/2026** : #13 à #27 corrigés en code ; #28 tranché sans changement de code
(décision de modèle de permission). Cf. § "`cargo check`/`pytest` réellement exécutés" dans
`STATUS.md` pour la vérification effective (255/255 tests verts, `cargo check` propre sur
la cible Windows).

---

## Revue du 18/08/2026 (3) — dépendances & réexamen Docker/infra

> Revue du 18/08/2026, en complément des revues précédentes. Périmètre : dépendances
> Python/Node/Rust (`pip-audit`/`npm audit`/`cargo audit` — ce dernier jamais passé jusqu'ici,
> le crate agent n'existait pas en juillet) + réexamen de `docker-compose.yml`/Dockerfiles/
> `CHECKLIST_DOCKER.md` pour vérifier qu'ils n'ont pas dérivé depuis leur dernière mise à jour
> (13/08/2026). Numérotation reprise à la suite de la revue du 18/08/2026 (2) (dernier numéro : #28).

### 🟡 #29 — `pytest` : CVE sur les répertoires temporaires (FAIBLE, dépendance de test uniquement)

**Où** : `backend/requirements.txt` — `pytest==8.3.3`.

**Trouvé par `pip-audit`** : `PYSEC-2026-1845` / `CVE-2025-71176` (alias `GHSA-6w46-j5rx-g56g`) —
sous UNIX, `pytest` s'appuie sur des répertoires nommés `/tmp/pytest-of-{user}` de façon
prévisible, permettant à un utilisateur local de causer un déni de service ou une élévation
de privilèges. Corrigé en `9.0.3`.

**Impact réel** : nul en production — `pytest` n'est utilisé que pendant les tests (`backend/
tests/`), jamais importé/exécuté par l'app en fonctionnement (`main.py`, aucun import). Le
conteneur `backend`/`worker`/`beat` ne lance jamais de test à l'exécution. Risque théorique
uniquement si quelqu'un lance la suite de tests sur une machine multi-utilisateurs partagée.

**Correctif** : `pytest>=9.0.3` dans `requirements.txt`, revérifier les 166 tests existants
après bump (changement majeur de version, cf. changelog pytest 9).

- [x] `pytest` bumpé à `9.0.3` + `pytest-asyncio` à `1.4.0` (compatibilité, 19/08/2026) —
      **vérifié en conditions réelles : 255/255 tests verts**, aucune régression. Un vrai
      bug de test suite trouvé et corrigé au passage (pas lié au bump lui-même) : FastAPI
      0.140.0 avait changé la structure interne de `app.routes`, rendant silencieusement
      vide toute la classe `TestAllApiRoutesAreProtected` — cf. `STATUS.md` § 19/08/2026
      pour le détail complet.

**Reste du backend (`pip-audit` complet, ~65 paquets directs+transitifs)** : aucune autre
vulnérabilité. Bump `fastapi`→`0.140.0`/`starlette`→`1.6.0` du 27/07 toujours en place et sain.

---

### ✅ Frontend (`npm audit`) — les deux points laissés ouverts en juillet sont refermés

**Rappel du 27/07/2026** (§ Info/hygiène ci-dessus) : `react-router-dom@6.30.4` (CVE modérée,
redirection ouverte, "pas de correctif dans la branche 6.x") et `esbuild`/`vite` (CVE dev
server) avaient été laissés ouverts, un passage en v7/v8 jugé trop risqué sans validation
explicite à l'époque.

**Constaté aujourd'hui** : `react-router-dom` est passé en **7.18.2** et `vite` en **7.3.6**
(mise à jour de routine depuis, sans rapport avec un audit) — `npm audit` renvoie désormais
**0 vulnérabilité** (250 paquets, prod+dev+optional). Rien à corriger, juste à noter que ces
deux items de l'audit d'origine peuvent être cochés `[x]`.

- [x] `react-router-dom`/`vite` mis à jour, `npm audit` propre (constaté, pas une action de
      cette session)

---

### ✅ Rust — `cargo audit` sur le crate `allsafe-agent` (jamais fait, 489 dépendances)

**Résultat** : **0 vulnérabilité** trouvée sur l'arbre complet (base d'avisories RustSec à
jour, 1217 entrées, mise à jour le jour même).

**Avertissements informationnels** (pas des vulnérabilités) : une douzaine de paquets
"non maintenus" (`atk`/`gdk`/`gtk`/`gtk-sys`/`gtk3-macros`/famille `unic-*`) + un problème
d'unsoundness connu sur `glib 0.18.5` (`GHSA-wrw7-89jp-8q8g`, itérateur `VariantStrIter`,
corrigé en `glib>=0.20.0`) — tous liés aux bindings **GTK3/X11**, dépendance transitive du
backend Linux de `tao` (fenêtrage de Tauri).

**Vérifié, pas supposé** : `cargo tree --target x86_64-pc-windows-gnu` (la seule cible
réellement compilée/livrée, cf. `agent/README.md` § Build) ne résout **aucune** de ces
entrées — `gtk`/`glib`/`atk`/`gdk` n'apparaissent que dans la résolution multi-plateforme
par défaut de `Cargo.lock`, jamais dans l'arbre de dépendances effectivement compilé pour
Windows. Ces avertissements ne concernent donc pas le binaire réellement distribué.

- [x] `cargo audit` passé pour la première fois sur `agent/` — aucune action requise
- [x] Confirmé par `cargo tree --target x86_64-pc-windows-gnu` que les paquets GTK3/glib
      signalés ne font pas partie du binaire livré
- [x] **`cargo check --target x86_64-pc-windows-gnu` repassé le 19/08/2026** après les
      correctifs #13-#18 ci-dessus — vert, 0 warning (cf. `STATUS.md`)

---

### 🟡 #32 — L'image backend garde les outils de compilation en production (FAIBLE)

**Où** : `backend/Dockerfile` — `gcc`, `libldap2-dev`, `libsasl2-dev` installés pour compiler
`ldap3`/dépendances natives, jamais retirés après `pip install`. Dockerfile en un seul stage
(pas de `FROM ... AS build` séparé).

**Problème** : confirmé en direct (`docker exec cybervuln-backend-1 which gcc` → présent,
`dpkg -l` liste `gcc-14` complet). Une RCE applicative future (dépendance compromise, faille
métier) donne accès à un compilateur C complet dans le conteneur — facilite la fabrication
d'un exploit sur place plutôt que d'avoir à en apporter un depuis l'extérieur. Gonfle aussi
l'image (surface de CVE du système de base, déjà partiellement traitée par le scan Trivy du
13/08 mais pas éliminée à la racine).

**Correctif** — multi-stage build, ne copier que les artefacts Python installés :
```dockerfile
FROM python:3.12-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    libldap2-dev libsasl2-dev gcc curl gnupg lsb-release \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail \
       https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && echo "deb [signed-by=...] ..." > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends postgresql-client-16 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl procps postgresql-client-16 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /root/.local /home/app/.local
COPY . .
RUN useradd -m -u 1000 -s /bin/bash app && chown -R app:app /app
USER app
ENV PATH=/home/app/.local/bin:$PATH
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```
(`libldap2-dev`/`libsasl2-dev`/`gcc` ne sont nécessaires qu'à la compilation des bindings
`ldap3` — vérifier si des `.so` runtime de libldap/libsasl doivent aussi être copiés dans le
stage final, sans quoi `ldap3` échouerait à l'import).

- [x] Dockerfile backend passé en multi-stage (19/08/2026) — `ldap3` s'avère en réalité **pur
      Python** (vérifié via `requirements.txt`, aucun autre package n'a besoin de libldap/
      libsasl), donc aucun `.so` runtime à recopier ; `gcc`/`*-dev` absents de l'image finale,
      `COPY --chown` inline plutôt qu'un `chown -R` récursif séparé. **`docker compose up
      --build` jamais lancé pour confirmer** (pas de Docker dans l'environnement où ce
      correctif a été écrit) — à valider avant un vrai déploiement.

---

### 🟡 #33 — Aucun en-tête de sécurité sur les fichiers statiques servis par `frontend-prod` (FAIBLE)

**Où** : `frontend/nginx.conf` — le middleware `security_headers` (`X-Content-Type-Options`,
`X-Frame-Options`, cf. #11) ne s'applique qu'aux réponses du **backend**
(proxées via `location /api/`). Les fichiers statiques (`index.html`, bundles JS/CSS) servis
directement par nginx pour `location /` n'ont aucun en-tête de sécurité de réponse.

**Impact** : faible (le SPA est une app interne, pas de contenu tiers hébergé), mais coût de
correction nul.

**Correctif** :
```nginx
# frontend/nginx.conf — dans le bloc server {}
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
```

- [x] En-têtes ajoutés à `nginx.conf` (19/08/2026) — scopés à `location /` (pas au niveau
      `server`), pour ne pas dupliquer/entrer en conflit avec les en-têtes déjà posés par
      le backend sur les réponses `/api/` proxées

---

### ✅ Docker / infra — réexamen de ce qui a changé depuis le 10/08/2026

`CHECKLIST_DOCKER.md` a été entièrement revu et mis à jour le **13/08/2026** (profils
`*-prod`, segmentation réseau `backend_net`/`frontend_net`, retrait de `--reload` de l'image,
scan Trivy avec 2 correctifs appliqués) — plus récent que la dernière revue formelle de
sécurité avant celle-ci et déjà très complet. Relu intégralement + **vérifié en direct** plutôt que
pris pour argent comptant :

- `docker inspect cybervuln-backend-1` : `RestartPolicy=unless-stopped`, `CapDrop=[ALL]`,
  `User=app`, `SecurityOpt=[no-new-privileges:true]`, `Memory=6442450944` (6g) — conforme
  exactement à ce que documentent `docker-compose.yml`/`CHECKLIST_DOCKER.md`.
- `frontend/Dockerfile` (stages `dev`/`prod`) : `USER node`/`USER nginx` confirmés présents,
  cohérents avec le fichier.
- Réseaux : `backend_net`/`frontend_net` bien séparés dans `docker-compose.yml`, `frontend`
  n'est que sur `frontend_net`.
- Tout ce qui reste ouvert dans `CHECKLIST_DOCKER.md` (reverse-proxy/TLS, `COOKIE_SECURE`,
  chiffrement au repos, rootless daemon) est explicitement **bloqué sur le serveur cible de
  déploiement**, pas quelque chose que ce dépôt peut corriger seul — confirmé toujours vrai,
  rien de nouveau à signaler.

**Scripts de déploiement de l'agent** (`agent/deploy/update-agent.ps1`/`.sh`, 17/08/2026) —
lus intégralement : reproduisent le **même défaut déjà documenté** en #13/#17 ci-dessus (téléchargement du paquet sans vérification de signature, HTTP par défaut) — pas un
nouveau problème distinct, juste confirmation que le correctif à apporter à `apply_update()`
doit aussi couvrir ces deux scripts (fait le 19/08/2026, cf. #13). Bonne hygiène par ailleurs : `set -euo pipefail` (script
Linux), contrôle d'élévation avant toute action (les deux), codes de sortie de `msiexec`/
`dpkg` vérifiés explicitement (contrairement au bloc CI de signature, cf. #26).

- [x] Aucune dérive constatée sur `docker-compose.yml`/Dockerfiles depuis le 13/08/2026
- [x] Scripts de déploiement agent confirmés comme rejouant #13/#17 (déjà tracés,
      pas de nouvelle entrée) — les deux corrigés le 19/08/2026

---

### Résumé — Revue du 18/08/2026 (3)

| Zone | Résultat |
|---|---|
| `pip-audit` (backend) | 1 CVE, dépendance de test uniquement (#29) |
| `npm audit` (frontend) | 0 — 2 items de l'audit de juillet refermés par mise à jour de routine |
| `cargo audit` (agent, jamais fait) | 0 vulnérabilité réelle sur 489 dépendances ; avertissements confirmés non applicables au binaire Windows livré |
| Docker/infra | Aucune dérive depuis la revue du 13/08 ; 2 nouveaux points mineurs (#32, #33) |

**Ordre conseillé** : #32 → #33 → #29 (tous FAIBLE, aucune urgence comparée aux findings
de la revue du 18/08/2026 (2)).

**État au 19/08/2026** : #29, #32, #33 corrigés en code — #32 (Dockerfile multi-stage) reste
à valider par un `docker compose up --build` réel, jamais lancé faute de Docker dans
l'environnement du correctif.

---

## Revue du 18/08/2026 (4) — garantie non-intervention & uploads Notes

> Revue du 18/08/2026, en complément des revues précédentes. Périmètre : (1) vérification exhaustive — code + requêtes réelles en
> base — que le partage de `apply_scan_result` entre le scan pull SSH/WinRM et le check-in
> push de l'agent (12/08/2026) n'a pas ouvert de brèche dans la garantie centrale du produit
> ("CRITICAL toujours manuel", états terminaux jamais écrasés, jamais d'écriture sur un
> serveur) ; (2) upload d'images du module Notes (12/08/2026), jamais audité jusqu'ici.
> Numérotation reprise à la suite de la revue du 18/08/2026 (3) (dernier numéro : #33).

### ✅ La garantie centrale du produit tient (vérifié en code ET en base réelle)

`apply_scan_result` (partagé depuis le 12/08 entre le scan pull SSH/WinRM et le check-in
push agent) ne touche **jamais** `Vulnerability.status` lui-même — les deux producteurs
convergent vers la même porte de garde (`patch_checker.py::apply_patch_result`), sans
bypass possible :

- États terminaux (`false_positive`/`patched`/`accepted_risk`) vérifiés **en premier**,
  avant toute autre logique — jamais écrasés automatiquement.
- Décision humaine sur un état non-terminal (`awaiting_fix` annoté) : seule évolution
  automatique permise, vers `patched`.
- `cve.severity == "CRITICAL"` bloque toute bascule automatique, évalué après le bloc
  humain mais avant les 4 branches de bascule — aucune combinaison ne peut faire passer
  un CRITICAL.
- `grep record_status_change(` sur tout `backend/` : exactement 10 sites (6 manuels + 4
  automatiques dans `apply_patch_result`) — le refactor du 12/08 n'a ajouté aucun site de
  mutation non comptabilisé, juste un nouveau déclencheur en amont du même pipeline.
- **Vérifié en base réelle** (SELECT uniquement) : `SELECT ... WHERE severity='CRITICAL'
  AND validated_by LIKE 'Auto%'` sur `vulnerabilities` **et** sur
  `vulnerability_status_history` → **0 ligne** dans les deux cas.
- `web_hardening.py`/`network_protocol_check.py`/`switch_hardening.py`/`network_cli.py` :
  grep exhaustif (`subprocess|os.system|exec_command|.write(|conn.run(|session.run_ps(`)
  → 0 résultat. Les seules commandes réseau envoyées sont une liste fixe de `show ...`
  (lecture), jamais de chaîne dynamique.
- Endpoints bulk (`bulk-patch`/`bulk-awaiting-fix`/`bulk-false-positive`/...) : chacun
  revérifie individuellement les mêmes conditions que son équivalent unitaire (sévérité,
  `still_matches`, `no_fix_available`...) plutôt que de faire confiance à la liste
  transmise — aucun raccourci bulk qui saperait la garde CRITICAL.

**Rien à corriger sur ce point** — la promesse "jamais d'automatisation sur du CRITICAL,
jamais d'écriture sur un serveur" reste intacte après l'introduction de l'agent.

---

### 🟠 #34 — Confiance aveugle aux données auto-déclarées par l'agent pour une bascule automatique non-CRITICAL

**Où** : `backend/services/patch_checker.py::_check_windows_app_patch` (comparaison de
versions installées contre les plages NVD, sans jamais se reconnecter à la machine) +
`backend/services/asset_scanner.py::apply_scan_result` (`asset.installed_packages =
result.get("packages", [])`).

**Problème** : pour un actif scanné par SSH/WinRM, `installed_packages` provient toujours
d'une lecture authentifiée faite par le backend lui-même. Pour un actif en
`collection_method="agent"`, ce même champ vient tel quel de
`AgentCheckinPayload.packages` — un champ **entièrement contrôlé par le binaire posé sur
le poste**, sans aucune vérification indépendante côté serveur (pas de signature, pas de
recoupement). Une CVE HIGH/MEDIUM/LOW peut donc basculer automatiquement en `patched` ou
`false_positive` sur la seule foi d'une version que l'agent choisit de rapporter — un
agent compromis ou buggé produit cette conclusion sans jamais toucher au serveur réel ni
déclencher la garde CRITICAL (qui, elle, tient). Le modèle de confiance implicite (« ce
champ vient toujours d'une lecture backend authentifiée ») ne tient plus pour ce mode de
collecte.

**Constaté en base** : l'actif `DEPLOYAPP` (`collection_method='agent'`) porte des vulns
HIGH déjà `patched`/`validated_by='Auto (patch check)'` via `windows-app-version` — mais
leurs `last_patch_check` précèdent son passage en collecte par agent : aucun incident live
démontré à ce jour, l'exposition est réelle mais pas encore exploitée.

**Correctif** — au choix :
- Exclure `_check_windows_app_patch` pour les actifs `collection_method="agent"` (repli
  sur vérification manuelle) ;
- ou distinguer la provenance dans l'audit trail (`validated_by="Auto (patch check,
  agent-reported)"`) pour que la piste NIS 2 reste honnête sur le niveau de confiance ;
- ou exiger un recoupement (scan WinRM/SSH quand disponible) avant bascule auto sur
  donnée agent seule.

- [x] **Décision retenue (19/08/2026, arbitrée avec l'utilisateur) : garder la bascule
      automatique identique agent/compte de service** (pas d'exclusion — le modèle de
      confiance de l'agent doit rester le même que celui du compte de service, par
      cohérence) + **traçabilité renforcée** : `validated_by="Auto (patch check,
      agent-reported)"` (vs `"Auto (patch check)"` pour un scan pull), constantes
      `AUTO_VALIDATED_BY`/`AUTO_VALIDATED_BY_AGENT`/`AUTO_VALIDATED_BY_LABELS` dans
      `patch_checker.py`, `agent_reported` propagé depuis les 3 sites d'appel
      d'`apply_patch_result` (`routers/patch_check.py`, `run_full_patch_check_cycle`,
      `backfill_auto_patch`). **Le canal est durci en contrepartie** plutôt que le
      contenu : #15 (race jetons) corrigé, #16 (mismatch hostname) rejeté avant
      consommation du jeton, #17 (HTTPS) au moins en avertissement, #35 (throttle/
      troncature) — la donnée elle-même reste non vérifiable dans l'absolu (limite
      assumée de tout modèle par agent), mais l'identité agent↔actif qui la porte l'est.
- [x] **Bug connexe trouvé et corrigé** : le filtre du bandeau "depuis votre dernière
      visite" (`routers/vulnerabilities.py::auto_bascule_summary`) ne cherchait que
      l'ancien libellé exact `validated_by == "Auto (patch check)"` — sans correctif, les
      bascules automatiques sur les actifs agent auraient disparu silencieusement du
      rattrapage. Passé en `validated_by.in_(AUTO_VALIDATED_BY_LABELS)`.
- [x] Point Linux (paquets `dpkg` auto-déclarés pareil, non cité explicitement par cette
      revue) couvert par les mêmes correctifs transverses (#15/#16/#17/#35), pas de trou
      resté ouvert côté OS

---

### 🟡 #35 — Aucune limite de taille/débit sur `POST /checkin` (FAIBLE)

**Où** : `backend/routers/agents.py` (`AgentCheckinPayload.packages`/`compliance`, listes/
dicts non bornés) — contrairement aux scans WinRM/SSH classiques qui tronquent à `[:300]`
(`asset_scanner.py`). Aucun rate-limit par agent, aucune limite de taille de requête HTTP
configurée (uvicorn sans `--limit-max-requests`).

**Problème** : un agent compromis/buggé peut spammer `/checkin` (chaque appel déclenche
une tâche Celery + un cycle de patch check complet) ou envoyer un payload démesuré,
stocké tel quel dans des colonnes JSON.

**Correctif** : plafonner `packages`/`compliance.checks` côté serveur (même `[:300]`),
ajouter un throttle par agent (ex. 1 check-in/minute), limiter la taille du corps HTTP.

- [x] Troncature `[:300]` (packages + `compliance.checks`) ajoutée (19/08/2026)
- [x] Throttle 1 check-in/minute par agent ajouté — basé sur `AgentCheckinLog.checked_in_at`
      le plus récent (pas `Agent.last_seen_at`, déjà réécrit par `require_agent` avant que
      la route ne s'exécute) ; cadence normale (cycle horaire) largement au-dessus du seuil,
      ne gêne ni le cycle planifié ni un scan à la demande

---

### 🟡 Note annexe — `severity IS NULL` contourne la garde CRITICAL par égalité stricte

`cve.severity == "CRITICAL"` est une égalité stricte — une CVE pas encore notée par NVD
(`severity IS NULL`) échapperait mécaniquement à cette garde. Préexistant, sans rapport
avec le partage agent/pull, non exploré en profondeur ici (hors scope de cette revue) —
signalé pour mémoire, à vérifier séparément si des CVE `severity IS NULL` existent
réellement en base et participent au cycle de patch check.

- [ ] **Non vérifié (19/08/2026)** — nécessite une requête SQL contre la vraie base
      (`SELECT COUNT(*) FROM cves WHERE severity IS NULL`), pas d'accès DB dans
      l'environnement où les autres correctifs de cette revue ont été écrits.

---

### 🟠 #36 — Module Notes : aucune suppression des fichiers image sur disque (accumulation illimitée)

**Où** : `backend/routers/notes.py` — aucun endpoint `DELETE /images/{id}`, contrairement
aux trois modules frères (`documents.py`, `incidents.py`, `audits.py`), qui font tous
`os.remove(path)` + `session.delete(...)`.

**Problème** : `NoteImage.subject_id` a `ondelete="CASCADE"` — supprimer un sujet efface
les lignes `note_images` en base, mais **jamais les fichiers sur disque** (aucun
`os.remove` dans tout `notes.py`). Tout compte avec accès `/notes` peut uploader des
images (5 Mo chacune, sans limite de nombre) puis supprimer le sujet en boucle : aucune
n'est jamais récupérée, accumulation illimitée dans le volume `note_images`, sans
mécanisme de purge — à la différence de tous les modules frères déjà audités.

**Correctif** (calqué sur `audits.py`) :
```python
@router.delete("/images/{image_id}", status_code=204)
async def delete_note_image(image_id: str, session: AsyncSession = Depends(get_session)):
    image = await session.get(NoteImage, image_id)
    if not image:
        raise HTTPException(404, "Image introuvable.")
    path = os.path.join(NOTE_IMAGES_ROOT, image.stored_filename)
    if os.path.isfile(path):
        os.remove(path)
    await session.delete(image)
    await session.commit()
```
Et nettoyer les fichiers liés dans `delete_subject` avant `session.delete(subject)` (le
cascade DB ne nettoie pas le disque).

- [x] Endpoint de suppression ajouté (19/08/2026, `DELETE /notes/images/{id}`)
- [x] Nettoyage disque ajouté à `delete_subject` — fait **avant** `session.delete(subject)`
      (le cascade DB efface les lignes `NoteImage`, il faut lister les fichiers avant)
- [ ] Aucune UI de suppression d'image câblée côté frontend (n'existait pas avant non plus
      — les images ne sont référencées qu'inline dans le Markdown, pas de galerie à gérer)

---

### 🟡 #37 — Notes : signature WebP incomplète (FAIBLE, cosmétique)

**Où** : `backend/services/note_images.py` — `".webp": b"RIFF"` ne vérifie que le
préfixe RIFF générique (conteneur partagé avec WAV/AVI), pas la marque `WEBP` à l'offset
8, contrairement aux autres formats du même fichier (PNG/JPEG/GIF, signature complète).

**Impact réel** : faible — un `.wav`/`.avi` renommé `.webp` passerait la validation,
mais serait juste une image cassée à l'affichage (`nosniff` empêche toute
réinterprétation par le navigateur, pas un vecteur XSS).

**Correctif** :
```python
if ext == ".webp" and content[8:12] != b"WEBP":
    raise ValueError("Le contenu du fichier ne correspond pas à un webp valide.")
```

- [x] Vérification `WEBP` à l'offset 8 ajoutée (19/08/2026)

---

### ✅ Vérifié conforme — Notes (le reste du patron upload)

Path traversal (UUID systématique, jamais le nom client, code identique aux modules
frères) · taille plafonnée à 5 Mo côté serveur (même mécanisme) · volume Docker dédié
(`note_images`, séparé des autres modules) · service de l'image gardé par
`require_page("/notes")` au niveau routeur — **testé en direct** : `GET
/api/notes/images/<uuid>/file` sans session → 401, pas de bypass par fichier statique ·
en-têtes anti-sniffing (`nosniff`/`X-Frame-Options`) appliqués globalement, couvrent
aussi cette route · XSS : l'URL d'image vient toujours du serveur (jamais construite à
partir du nom client), rendue via `MarkdownNote.jsx` + DOMPurify.

---

### ⚠️ Incident signalé pendant l'audit Notes

Une commande shell mal formée exécutée par l'agent en charge de cet audit a supprimé par
erreur `cookies.txt` à la racine du projet (hors périmètre de la revue, fichier non suivi
par git). Recréé à l'identique à partir du contenu lu juste avant la suppression, vérifié
ligne à ligne après coup. Le jeton de session qu'il contenait était déjà expiré (aucun
impact pratique). Aucune autre action destructive n'a eu lieu.

---

### Résumé — Revue du 18/08/2026 (4)

| # | Sujet | Sévérité |
|---|---|---|
| — | Garantie CRITICAL/non-intervention après partage agent+pull | ✅ tient, vérifié code+DB |
| #34 | Confiance aveugle aux données agent pour bascule auto non-CRITICAL | 🟠 |
| #35 | Pas de limite taille/débit sur `/checkin` | 🟡 |
| — | `severity IS NULL` contourne la garde CRITICAL (préexistant, non exploré) | 🟡 note |
| #36 | Notes : pas de suppression des fichiers image | 🟠 |
| #37 | Notes : signature WebP incomplète | 🟡 |

**Ordre conseillé** : #34 → #36 → #35 → #37.

**État au 19/08/2026** : #34 à #37 corrigés en code. La note `severity IS NULL` reste
non vérifiée (nécessite un accès DB réel, cf. ci-dessus).

---

## Revue du 21/08/2026 (5) — Analyse Strix (IA, white-box backend/)

Scan statique AI white-box via **Strix v1.5.3** (DeepSeek) sur `backend/` uniquement.
8 agents de découverte + passes SAST (semgrep, gitleaks, trivy) — aucune CVE de dépendance,
aucun RCE, aucune injection SQL/commande. 4 findings confirmés.

### 🟠 #38 — BFLA sauvegardes : tout compte authentifié peut déclencher pg_dump superuser (MEDIUM)

**Où** : `main.py:240` + `routers/backup.py:20-34`

**Problème** : `backup.router` monté avec `_authed` (tout compte connecté) alors que l'intention
documentée dans `main.py:216-218` le réserve aux admins. Tout analyste peut donc déclencher
`POST /api/backup/run` (pg_dump complet en superutilisateur `cybervuln` via Celery) et lister
l'inventaire des sauvegardes (`GET /api/backup/list`). CVSS 5.4 (AV:N/AC:L/PR:L/UI:N).

**Correctif** : une ligne — remplacer `_authed` par `_admin_only` dans `main.py`.

- [x] Corrigé (21/08/2026) : `_admin_only` dans `main.py:240`

### 🟠 #39 — BOLA notes personnelles : aucune propriété par utilisateur (MEDIUM)

**Où** : `routers/notes.py` + `models.py` (`NoteSubject`, `NoteImage`, `NoteTheme`)

**Problème** : le module Notes est documenté « notes personnelles » mais les modèles ne portent
aucune colonne `user_id` / colonne d'appartenance. Tous les handlers résolvent les objets par ID
sans filtrer sur l'utilisateur authentifié — tout compte avec accès `/notes` peut lire, modifier
et supprimer les notes et images de tous les utilisateurs. CVSS 5.4 (AV:N/AC:L/PR:L/UI:N,
CWE-639).

**Correctif** : ajouter une FK `user_id` sur `NoteSubject`/`NoteImage`/`NoteTheme` (+ patch SQL),
filtrer toutes les requêtes par l'utilisateur de session. Effort : moyen.

- [x] Corrigé (21/08/2026) : `user_id` sur les 3 tables, contrainte `UNIQUE(name, user_id)`
  (remplace `UNIQUE(name)` global), backfill vers le 1er admin, filtrage dans tous les handlers.
  404 en cas d'accès cross-user (ne révèle pas l'existence des objets d'autrui).

### 🟠 #40 — Forgery `risk_score` hors-bornes (MEDIUM)

**Où** : `routers/vulnerabilities.py:198-203` (`VulnUpdate`)

**Problème** : `risk_score: Optional[float]` sans borne — un compte non-admin peut passer
`risk_score=999` ou une valeur négative, corrompant le tri du dashboard. CVSS 4.3 (CWE-863).

Note : la possibilité pour un analyste de passer à un état terminal (`patched`/`false_positive`/
`accepted_risk`) sur des vulns HIGH/MEDIUM/LOW est **intentionnelle** (cf. CLAUDE.md § 1). Le
problème ici est la corruption du score numérique, pas les transitions de statut.

**Correctif** : `Field(ge=0, le=10)` sur `risk_score`.

- [x] Corrigé (21/08/2026) : `Field(ge=0, le=10)` dans `VulnUpdate`

### 🟡 #41 — Injection de formules CSV : 4 colonnes résiduelles non neutralisées (FAIBLE)

**Où** : `routers/watch.py:433,440` + `routers/reports.py:433,454`

**Problème** : le neutraliseur `csv_safe` (#7, 27/07/2026) couvre la majorité des colonnes mais
4 ont été oubliées : `themes` et « Actifs concernés » dans l'export veille (`watch.py`),
`matched_identities` et `asset_name` dans les rapports hebdo (`reports.py`). Une valeur
`=HYPERLINK(...)` dans un thème ou un nom d'actif atteint un tableur. CVSS 3.5 (CWE-1236).

- [x] Corrigé (21/08/2026) : 4 colonnes enveloppées dans `csv_safe()`

### Résumé — Revue du 21/08/2026 (5)

| # | Sujet | Sévérité |
|---|---|---|
| #38 | BFLA backup — tout compte peut déclencher pg_dump | 🟠 |
| #39 | BOLA notes — aucune propriété par utilisateur | 🟠 |
| #40 | Forgery `risk_score` hors-bornes | 🟠 |
| #41 | CSV injection résiduelle — 4 colonnes manquantes | 🟡 |

**État au 21/08/2026** : #38, #39, #40, #41 corrigés en code. `schema_patches.sql` appliqué en conditions réelles (même session).

---

## Revue du 21/08/2026 (6) — Scan Strix frontend (`frontend/src/`)

> Scan white-box Strix v1.5.3, modèle DeepSeek, ciblé sur `frontend/src/` séparément (le scan global
> plante en WSL2 — TUI Bubble Tea incompatible avec ce terminal). 1 finding confirmé.

### 🟠 #42 — XSS stocké dans l'export PDF (MEDIUM)

**Où** : `frontend/src/components/ReportMarkdown.jsx::exportPdf`

**Problème** : `exportPdf()` convertit le markdown d'un rapport (incident, audit, archive
hebdomadaire) en HTML sans échapper les caractères spéciaux, puis l'écrit via `document.write`
dans un popup same-origin. Un analyste peut insérer `<img src=x onerror=...>` dans un texte de
rapport (annotations d'incident, résumé d'audit, etc.) — stocké en base, exécuté dans la session
de tout utilisateur qui exporte ce rapport. CVSS 7.3 (AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N,
CWE-79, Stored XSS) — exfiltration de session et actions en nom d'autrui sur une plateforme NIS 2.
DOMPurify était déjà installé (`^3.4.12`) mais non utilisé dans ce chemin.

**Correctif** : échapper les caractères spéciaux HTML (`<>&"'`) en amont du parser markdown dans
`inline()`, puis passer le HTML assemblé dans `DOMPurify.sanitize()` en filet de sécurité.

- [x] Corrigé (21/08/2026) : `import DOMPurify from 'dompurify'` ajouté ; `escapeHtml()` posé
  avant `colorizeHtml()` dans la fonction `inline` ; `DOMPurify.sanitize()` sur `bodyHtml` avant
  le `document.write`. La sortie React à l'écran (`renderMd`) est inchangée — elle passe déjà
  par des nœuds JSX, jamais par `innerHTML`.

### Résumé — Revue du 21/08/2026 (6)

| # | Sujet | Sévérité |
|---|---|---|
| #42 | XSS stocké — export PDF `exportPdf()` sans échappement | 🟠 |

**État au 21/08/2026** : #42 corrigé en code.

---

## Ce qui reste ouvert, tous périmètres confondus (21/08/2026)

- **#5** — `.gitignore` : sans objet aujourd'hui (repo git déjà initialisé avec `.gitignore`
  en place depuis longtemps), entrée gardée pour l'historique.
- **Décision Docker/prod** (§ Docker 27/07/2026) : mode "prod" sans reload/dev server —
  toujours pas tranché, dépend du calendrier de passage en production.
- **`.dockerignore`** — jamais créé.
- **`ux_password_reset_pending`** (#19) — index créé dans `schema_patches.sql`, jamais
  rejoué contre une vraie base.
- **`docker compose up --build`** (#32) — Dockerfile backend multi-stage jamais buildé en
  conditions réelles.
- **`severity IS NULL`** (note, Revue du 18/08/2026 (4)) — nécessite une requête SQL réelle.
- **Frontend** (`Assets.jsx`/`Durcissement.jsx`, #14) — boutons masqués pour un compte
  non-admin jamais testés au navigateur.
- **Réglages GitLab** (#25/#27) — variables "Protected" + restriction des déclenchements
  manuels, à faire côté Settings, pas dans un fichier.
- **Redistribution des binaires agent** reconstruits avec les correctifs #13/#18 aux postes
  déjà enrôlés — pas fait automatiquement, à planifier selon le processus habituel
  (`docs/AGENTS.md` § Mise à jour).
~~**`schema_patches.sql` notes**~~ — appliqué en conditions réelles (21/08/2026, même session).
