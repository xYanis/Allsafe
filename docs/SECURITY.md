# SECURITY.md
## Charger uniquement pour les tâches liées à la sécurité, SSH, AD ou l'anonymisation

---

## Anonymisation Claude API — Détail complet

### Mapping OS générique (dans claude_analyzer.py)
```python
OS_GENERIC_MAP = {
    "windows server 2022": "Windows Server (recent)",
    "windows server 2019": "Windows Server (recent)",
    "windows server 2016": "Windows Server (older)",
    "windows server 2012": "Windows Server (legacy)",
    "ubuntu 22.04": "Ubuntu Linux LTS (recent)",
    "ubuntu 20.04": "Ubuntu Linux LTS",
    "debian 12": "Debian Linux (recent)",
    "debian 11": "Debian Linux (stable)",
    "rhel 9": "RHEL-based Linux (recent)",
    "rhel 8": "RHEL-based Linux",
    "cisco ios": "Network OS (Cisco)",
}
```

### Tags autorisés vers l'API Claude
Préfixes acceptés : `zone:`, `criticite:`, `usage:`, `env:`, `role:`
Bloqués : tout tag contenant `ip-`, `hostname`, `fqdn`, `asset-id`

### anonymization_log retourné à chaque appel
```json
{
  "hostname_sent": false,
  "ip_sent": false,
  "os_sent_as": "Windows Server (recent)",
  "asset_type_sent_as": "Serveur de production",
  "tags_filtered": 2
}
```

---

## Active Directory — Compte de service

- Droits : lecture seule sur l'OU Servers
- Attributs lus : cn, dNSHostName, operatingSystem, operatingSystemVersion, lastLogonTimestamp
- Aucune modification possible avec ce compte
- **Connexion chiffrée** (`AD_USE_TLS`, session 27/07/2026 — audit `audit/AUDIT_SECURITE.md` #3) :
  `services/asset_importer.py` n'ouvrait auparavant aucune session TLS, le bind SIMPLE envoyait le
  mot de passe du compte de service **en clair** à chaque import. Défaut `AD_USE_TLS=False` = StartTLS
  sur le `ldap://` déjà configuré (port 389, aucun changement d'URL nécessaire) — choix délibérément
  différent de la proposition initiale de l'audit (`ldaps://` implicite par défaut), car on ne sait
  pas à l'avance si le DC expose le port 636. Passer à `AD_USE_TLS=True` + `AD_SERVER=ldaps://...:636`
  si le contrôleur de domaine le permet. Toujours chiffré dans les deux cas, seul le mécanisme change.
  Testé contre le DC réel (`tintamarre.aer.loc`) : import fonctionnel après activation.

## SSH Linux — Compte de service

- Utilisateur : svc-cybervuln sans sudo
- Authentification : clé Ed25519 dédiée (./keys/id_ed25519)
- **Vérification de la clé d'hôte — TOFU** (`services/ssh_trust.py`, session 27/07/2026 — audit #2) :
  `known_hosts=None` désactivait toute vérification de l'identité du serveur SSH, exposant à un MITM
  sur le VLAN (vol du mot de passe SSH si authentification par mot de passe, ou injection de faux
  relevés de paquets sinon). `connect_trusted()` remplace l'appel direct à `asyncssh.connect` :
  premier contact avec un hôte → sa clé est apprise et pinnée dans `keys/known_hosts` (fichier
  persistant, volume `./keys` désormais monté en écriture, cf. `docs/ARCHITECTURE.md` § Docker) ;
  tout contact suivant avec une clé **différente** → connexion **rejetée**, jamais de réapprentissage
  silencieux (un changement de clé légitime — réinstallation du serveur — doit être traité par un
  humain, pas absorbé automatiquement). Testé en direct contre `gitlab.aer.loc` : apprentissage au
  premier scan, acceptation au second, rejet d'une fausse clé substituée sans écraser le pin.
- Commandes autorisées (lecture seule uniquement) — liste complète, `services/asset_scanner.py` +
  `services/patch_checker.py` :
  - `hostname -f`, `hostname -I` (fiabilité + IP)
  - `cat /etc/os-release` (PRETTY_NAME, VERSION_ID)
  - `dpkg -l` / `dpkg-query -W` / `rpm -qa` / `rpm -q` (paquets installés + patch check)
  - `LC_ALL=C lscpu` (CPU — `LC_ALL=C` force la sortie en anglais quelle que soit la locale du
    serveur, cf. `docs/FRONTEND.md`), `nproc` (cœurs), `free -b` (RAM — `free -g` jusqu'au 27/07/2026,
    qui tronquait en Go entiers ; `-b` + conversion Python arrondie donne la décimale, cf. Inventaire),
    `df -BG` (disques)
  - `uname -m` (architecture 32/64 bits, session 03/07/2026 — cf. `docs/ARCHITECTURE.md`)
  - `cat /sys/class/net/*/address` (MAC), `ss -tuln` (ports en écoute)
  - `uname -r` (version noyau en cours d'exécution — patch check uniquement, cf. ci-dessous)
  - `grep ... /etc/login.defs`, `sudo -n sshd -T` (durcissement CIS-like, session 27/07/2026 — cf.
    `docs/ARCHITECTURE.md` § Durcissement / conformité ; `sudo -n` échoue silencieusement sans hang si
    NOPASSWD n'est pas configuré, remonte "indéterminé" plutôt que de faire échouer le scan)
- Aucune commande d'écriture ou d'exécution distante. Jamais.
- **Statut détection Linux** (session 02/07/2026) : `check_patch_linux()` compare la version installée
  aux versions corrigées du **Debian Security Tracker** (actifs Debian — fiable y compris backports et
  noyau), avec fallback sur les plages NVD pour les autres distros — même bascule automatique que
  Windows. Le téléchargement du tracker (JSON public) n'envoie aucune donnée du parc. Détail dans
  `docs/MATCHING.md` § Patch checker.

**Exception — identifiants par machine (phase de test)** : le compte de service partagé ci-dessus
reste la cible à terme. En attendant le déploiement de clés SSH par machine, le formulaire "Ajouter
un actif" a deux champs optionnels *Utilisateur SSH* / *Mot de passe SSH*, stockés sur l'actif :
- `scan_username` en clair (non sensible)
- `scan_password` chiffré (`services/crypto.py`, Fernet dérivé de `SECRET_KEY`) — **jamais renvoyé
  par l'API**, ni en clair ni chiffré (write-only ; `GET /api/assets` n'expose que `has_scan_password: bool`)

`POST /api/assets/{id}/scan` accepte aussi un corps ponctuel `{username, password}` (dépannage sans
toucher l'actif, jamais persisté ni journalisé) — prioritaire sur les identifiants stockés, eux-mêmes
prioritaires sur la clé SSH partagée. Toujours lecture seule, toujours limité aux mêmes commandes
ci-dessus, quel que soit le mode d'authentification utilisé.

Changer `SECRET_KEY` invalide tous les mots de passe déjà chiffrés en base — à fixer définitivement
avant d'enregistrer de vraies données (actuellement en phase de test).

---

## Bascule automatique du statut de vulnérabilité — limites de fiabilité

Depuis l'ajout du patch check automatique, CyberVuln peut basculer une vuln en `patched` sans validation
humaine — **uniquement pour les CVE non-CRITICAL** (règle complète dans `CLAUDE.md` § Non-intervention).
Le SSH/WinRM reste strictement lecture seule dans tous les cas ; seul le statut *dans CyberVuln* change.

Cette bascule automatique reste un signal probable, pas une preuve :
- Windows : `patch_detected = true` dès qu'**un seul** KB de la liste est trouvé installé (voulu — chaque
  CVE a un KB différent par version d'OS, un serveur ne peut avoir que celui qui correspond à sa build).
- La liste de KB vient d'une regex sur les références NVD (peut capter un KB non pertinent mentionné dans
  une page de contexte) ou de l'API MSRC (fallback + `kb_os_hint` informatif comparant le produit MSRC à
  l'OS déclaré de l'actif — n'affecte jamais `patch_detected`, affichage seul dans la modale patch check).
- Aucune vérification de la version réelle du binaire vulnérable — seule la présence du KB est contrôlée.

Recommandation : auditer ponctuellement quelques vulns auto-basculées (bouton "🔍 Patch check" disponible
directement dans le tableau "Vulnérabilités traitées") avant de s'appuyer dessus pour un rapport de conformité.

---

## SSRF — sources de veille personnalisées (session 27/07/2026)

`WatchSource.url` (source RSS/Atom ajoutée par l'utilisateur, `docs/VEILLE.md` § 10.1) était acceptée
sans validation puis requêtée côté serveur avec `follow_redirects=True` — sans authentification sur
l'API, n'importe qui sur le réseau pouvait pointer une source vers `127.0.0.1`, le VLAN interne, ou les
métadonnées cloud (exfiltration si contenu XML valide, sinon scan de ports interne aveugle). Corrigé
par `backend/services/net_guard.py` (`validate_public_url`) : rejette tout hôte non public routable
(privé/loopback/lien-local/réservé/multicast), appelé à la création **et** à la modification d'une
source, et re-appelé à **chaque redirection** dans `watch_fetcher.py` (`follow_redirects=False` +
boucle manuelle de re-validation, 5 hops max) — sans ça, une source publique légitime redirigeant vers
l'interne aurait quand même exposé la faille. Testé : URL interne → 400 à la création, sync veille
toujours fonctionnelle sur les sources réelles.
