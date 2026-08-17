# ARCHITECTURE.md
## Charger uniquement pour les tâches liées à la BDD, Docker ou l'API

---

## 🗄️ Schéma base de données

### Table `cves`
```sql
id          UUID PRIMARY KEY
cve_id      VARCHAR UNIQUE        -- CVE-2025-21298
description TEXT
published   TIMESTAMP WITH TZ
modified    TIMESTAMP WITH TZ
cvss_score  FLOAT                 -- CVSS v3 (fallback v2)
cvss_vector VARCHAR
epss_score  FLOAT
severity    VARCHAR               -- CRITICAL / HIGH / MEDIUM / LOW
references  JSONB                 -- URLs enrichies (NVD + CERT-FR)
cpe         JSONB                 -- CPE affectés
source      VARCHAR               -- nvd / cert-fr / exploit-db / github
raw_data    JSONB
```

### Table `assets`
```sql
id                  UUID PRIMARY KEY
name                VARCHAR
hostname            VARCHAR UNIQUE   -- Clé de déduplication (casse insensible)
ip_address          VARCHAR          -- Pas INET (incompatible asyncpg)
os                  VARCHAR
os_version          VARCHAR
asset_type          VARCHAR          -- server / workstation / network
tags                JSONB            -- {env, source, criticite, zone, kernel, arch}
cpe_list            JSONB            -- CPE pour le matching CVE
source              VARCHAR          -- active_directory / ssh / csv / manual / meraki
last_scan           TIMESTAMP WITH TZ
status              VARCHAR          -- active / inactive
installed_packages  JSONB            -- [{name, version}] — dernier scan (module Inventaire), lecture seule
last_scan_result    JSONB            -- Fiabilité déclaré vs détecté (hostname/os/version) du dernier scan
hardware            JSONB            -- {cpu, arch, cores, ram_gb, ip, mac, open_ports: [int], disks: [{name, total_gb, free_gb}]} — module Inventaire
scan_username           VARCHAR      -- Identifiant SSH par machine — phase de test (cf. section ci-dessous)
scan_password_encrypted VARCHAR      -- Mot de passe chiffré (Fernet), jamais renvoyé par l'API
```

**Scan read-only d'actif** (`services/asset_scanner.py`, `POST /api/assets/{id}/scan`) : vérifie la
fiabilité des infos déclarées et collecte applications + specs matérielles en une seule connexion
WinRM/SSH. Le compte de service n'a **pas les droits WMI/CIM** (`Get-WmiObject`/`Get-CimInstance`/
`systeminfo` → accès refusé) — CPU vient du registre (`HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0`),
RAM d'un appel natif `GlobalMemoryStatusEx` (P/Invoke kernel32.dll, contourne WMI), disques de
`[System.IO.DriveInfo]` (.NET, contourne WMI aussi), adresse(s) MAC de
`[System.Net.NetworkInformation.NetworkInterface]` (.NET, contourne WMI également — `getmac.exe` ET
`Get-NetAdapter` ont été testés et refusés "Accès refusé" pour ce compte), IP(s) via la même API
.NET (`GetIPProperties().UnicastAddresses`, IPv4 uniquement). Côté Linux, MAC lue directement dans
`/sys/class/net/*/address`, IP via `hostname -I` (SSH, aucun droit spécial). Toujours lecture
seule, jamais d'écriture.

L'IP détectée est exposée à deux endroits : dans `hardware.ip` (JSONB, affichée dans la modale
specs matérielles d'**Inventaire**, entre "Disques" et "Adresse MAC"), et comparée à l'IP déclarée
via `ip_match`/`detected.ip_address` (affichée dans la modale "Fiabilité des infos déclarées"
d'**Actifs**, au même titre que hostname/OS/version) — les deux viennent du même relevé réseau,
juste présentés différemment selon la vue (patrimoine vs sécurité).

**Ports TCP en écoute** (`hardware.open_ports`, liste d'int) : affichés sous "Adresse MAC" dans la
modale Inventaire. Windows via `[System.Net.NetworkInformation.IPGlobalProperties]::GetActiveTcpListeners()`
(.NET, contourne WMI comme le reste) ; Linux via `ss -tuln` (SSH, aucun droit root requis pour
lister sans les PID). Purement informatif, lecture seule — aucune tentative de connexion, juste la
liste des sockets en écoute déjà exposée par l'OS.

**Architecture 32/64 bits** (`hardware.arch`, session 03/07/2026) : Windows via `$env:PROCESSOR_ARCHITECTURE`
(variable d'environnement — `AMD64`/`x86`/`ARM64`, contourne WMI comme le reste) ; Linux via `uname -m`
(SSH — `x86_64`/`aarch64`/`i686`...). Normalisé en libellé lisible par `_format_arch()`
(`services/asset_scanner.py`) — ex. `"64 bits (x64)"`, `"32 bits (x86)"` — valeur brute conservée si
non reconnue plutôt que masquée. Affiché dans les modales specs matérielles d'Actifs et Inventaire, et
en colonne dans le tableau Inventaire (cf. `docs/FRONTEND.md`).

**Durcissement / conformité — bloc `compliance`** (session 27/07/2026, checks CIS-like en lecture
seule) : ajouté au résultat de `scan_asset()` (`_build_result()`), **pas de nouvelle colonne** — vit
dans le JSON `last_scan_result` déjà générique, donc exposé automatiquement par les routes existantes
(`GET /assets`, `GET /{id}/packages`) sans changement de route. Forme : `{"checks": [{"id", "label",
"status": "ok"|"warn"|"unknown", "detail"}]}`.
- **Linux** (`_build_compliance_linux`, nouvelles commandes SSH dans `_scan_linux`) : `PASS_MAX_DAYS`/
  `PASS_MIN_LEN` (`/etc/login.defs`, world-readable) ; `PermitRootLogin`/`PasswordAuthentication`
  (`sudo -n sshd -T`, souvent sans droits suffisants → `"unknown"`, jamais d'échec du scan) ; ports à
  risque (dérivé de `hardware.open_ports` déjà collecté, aucune commande supplémentaire).
- **Windows** (`_build_compliance_windows`, ajouts dans le même `$ps_script` unique — toujours pas de
  WMI/CIM) : `net accounts` (politique de mot de passe — texte localisé, cf. § piège ci-dessous) ;
  RDP/NLA, SMBv1, pare-feu via lecture registre pure (`HKLM:\SYSTEM\CurrentControlSet\...`).
- `"unknown"` (icône « — ») signifie **droits insuffisants en lecture seule**, jamais une
  non-conformité — à ne pas confondre avec `"warn"`.

**Paquets installés ↔ vulnérabilités déjà connues** (session 27/07/2026,
`services/cpe_matcher.py § get_installed_package_vulnerabilities`) : pour chaque paquet de
`asset.installed_packages`, expose les CVE déjà matchées et non résolues (statuts open/in_progress/
awaiting_fix/accepted_risk — pas patched/false_positive, résolus). **Ne relance pas** un matching
contre tout le référentiel (coûteux, cf. § matching CPE ci-dessus) : croise seulement les
vulnérabilités déjà en base pour cet actif. Exposé via `vuln_count`/`severity`/`cve_ids` ajoutés à
chaque paquet dans `GET /assets/{id}/packages` et `POST /assets/{id}/scan`.

⚠️ **Ne fonctionne que pour Linux.** `_package_candidates()` dérive un nom de produit CPE depuis un
nom de paquet Debian/RPM (`libssh2-1` → `libssh2`) — les noms d'applications Windows (registre, texte
libre : `"PuTTY release 0.81 (64-bit)"`) n'ont pas de règle de dérivation fiable équivalente. Un
heuristique naïf ("premier mot avant le numéro de version") donnerait par exemple "microsoft" pour
"Microsoft Edge" (l'éditeur, pas le produit — faux positifs garantis sur toute CVE dont le produit
CPE vaut aussi "microsoft"). Non implémenté volontairement — cf. `STATUS.md` § Points ouverts pour la
solution envisagée (table de correspondance nom affiché → produit CPE, réglable sans code).

**Identifiants SSH par machine (Linux, phase de test)** : le formulaire "Ajouter un actif"
(`Assets.jsx`) a deux champs optionnels *Utilisateur SSH* / *Mot de passe SSH*. Si renseignés, ils
sont stockés sur l'actif — `scan_username` en clair (non sensible), `scan_password` chiffré
(`services/crypto.py`, Fernet dérivé de `SECRET_KEY`) dans `scan_password_encrypted`. Champ
write-only : `GET /api/assets` ne renvoie jamais le mot de passe (déchiffré ou chiffré), seulement
`has_scan_password: bool` et `scan_username` (pour préremplir le formulaire d'édition — laisser le
mot de passe vide en édition = on conserve celui déjà enregistré).

`POST /api/assets/{id}/scan` accepte toujours un corps optionnel `{username, password}` pour un
dépannage ponctuel qui ne touche pas l'actif (prioritaire sur les identifiants stockés). Ordre de
priorité dans `_scan_linux()` : `creds` de la requête > `scan_username`/`scan_password_encrypted` de
l'actif > clé SSH partagée du parc (`SSH_USER`/`SSH_KEY_PATH`). Jamais utilisé côté Windows (compte
WinRM partagé uniquement).

⚠️ **Choix explicite de phase de test** (l'utilisateur a écarté le stockage par défaut au profit
d'identifiants par machine, en attendant de déployer une clé SSH par machine à terme) — voir
`STATUS.md` pour l'historique de la décision. `SECRET_KEY` doit être fixée avant toute donnée réelle
en base : la changer invalide tous les mots de passe déjà chiffrés.

**Note taille de commande WinRM** : le script PowerShell du scan Windows est encodé en base64 et
passé via `powershell -encodedcommand` dans un `cmd.exe` — limite dure d'environ 8191 caractères.
Le P/Invoke `GlobalMemoryStatusEx` a été réécrit sous forme compacte (noms de champs/méthode
raccourcis, structure C# en une ligne) après un dépassement (`La ligne de commande est trop
longue`) causé par l'ajout de la détection MAC + IP.

**Dépassement reconfirmé le 27/07/2026** en ajoutant les contrôles de durcissement (§ Durcissement /
conformité ci-dessous) : le budget avait encore été consommé par un bloc de commentaire explicatif
placé **à l'intérieur** de la chaîne `ps_script` (donc transmis avec le script, sans aucun bénéfice
d'exécution). Script raccourci — alias `gp`/`-ea 0` (au lieu de `Get-ItemProperty`/
`-ErrorAction SilentlyContinue`), variables PowerShell internes en mono-lettre (`$di`, `$na`, `$fw`…,
sans impact côté Python qui ne lit que les clés du `[PSCustomObject]` final), préfixe de registre
`HKLM:\SYSTEM\CurrentControlSet` factorisé dans `$cc`. **Piège de mesure** : la taille du script telle
qu'elle apparaît dans le fichier source Python (avec `\\` littéraux) n'est pas la taille réellement
transmise — Python résout `\\` en `\` à l'exécution. Mesurer via `ast` (valeur résolue du nœud), pas
un regex naïf sur le texte du fichier, sous peine de surestimer d'environ 15%. Marge actuelle,
mesurée ainsi : **8048/8191 caractères encodés** (143 de marge) — à revérifier avec la même méthode
avant tout nouvel ajout au script.

**Correction automatique au scan** (`routers/assets.py`, `POST /{id}/scan`) : le scan fait foi sur ce
qui est déclaré à la création. Si le hostname détecté diffère de celui déclaré, `hostname` **et**
`name` (affiché partout dans l'UI) sont alignés automatiquement sur la valeur détectée — utile pour un
actif ajouté à la main avec un nom saisi sans vérification (ex: nom de l'utilisateur ayant rempli le
formulaire, pas le nom réel de la machine). `IntegrityError` gérée si un autre actif porte déjà ce
hostname (correction abandonnée, reste du scan conservé). Même logique pour `os_version` (toujours
alignée sur le `VERSION_ID` détecté) ; `os` (champ court, ex. "Debian") n'est rempli que s'il était
vide, pour ne jamais écraser un libellé court par le `PRETTY_NAME` complet ("Debian GNU/Linux 12
(bookworm)").

**`collection_method="vsphere_api"` (13/08/2026, intégration vSphere/ESXi)** : troisième valeur à
côté de `service_account`/`agent` (cf. `docs/AGENTS.md`), posée par `services/vsphere_matcher.py`
sur les hôtes ESXi importés/enrichis via vCenter. Contrairement aux deux autres, aucun cycle
périodique ne filtre encore dessus (il n'existe pas de cycle SSH/WinRM automatique sur tout le
parc — seul le clic manuel "Scanner" ou le push agent déclenchent un scan) : ce qui compte
réellement, c'est le garde-fou posé sur `POST /api/assets/{id}/scan`
(`routers/assets.py::scan_asset_endpoint`) qui refuse désormais (400) tout scan SSH/WinRM sur un
actif dont `collection_method != "service_account"` — sans ce garde-fou, cliquer "Scanner" sur un
hôte ESXi ouvrirait une vraie session SSH avec des commandes pensées pour Debian/RHEL contre le
shell BusyBox d'ESXi, et écraserait silencieusement le `cpe_list` fiable posé par la sync vSphere.

**`Asset.created_at` (13/08/2026, badge « Nouveau » sur Actifs)** : `server_default=func.now()`,
posé au niveau DB pour rester correct même sur une insertion hors SQLAlchemy. Les 441 actifs déjà
en base au moment de la migration ont été rétrodatés à une date sentinelle (`2020-01-01`, cf.
`schema_patches.sql`) — sans ça, `ADD COLUMN ... DEFAULT now()` les aurait tous datés du jour de la
migration, affichant "Nouveau" sur tout le parc pendant 24h, l'exact opposé de l'intention du
badge. Conséquence assumée : un actif créé le jour même mais **avant** cette migration (ex. le
premier hôte ESXi importé lors du test vSphere, cf. § ci-dessus) reste rétrodaté lui aussi — pas de
badge dessus malgré une création réellement récente, aucun moyen de distinguer les deux cas après
coup sans une vraie date d'origine perdue.

### Table `network_status` (session 04/08/2026)
```sql
id                UUID PRIMARY KEY
asset_id          UUID FK → assets (CASCADE)
source            VARCHAR          -- "meraki" | "prtg" aujourd'hui ; extensible à d'autres sondes
status            VARCHAR          -- online / offline / alerting / dormant (vocabulaire partagé,
                                    -- chaque source normalise son propre vocabulaire vers celui-ci)
last_reported_at  TIMESTAMP WITH TZ
metrics           JSONB            -- Meraki: {serial, model, product_type, public_ip} ; PRTG:
                                    -- {objid, group, probe, raw_status, raw_status_code} — champ
                                    -- libre pour scaler vers d'autres métriques (bande passante,
                                    -- CPU...) plus tard sans nouvelle migration
updated_at        TIMESTAMP WITH TZ
UNIQUE (asset_id, source)
```
État réseau remonté par une sonde externe — reprend l'idée PRTG évoquée le 31/07/2026, d'abord
comblée par Cisco Meraki (`services/meraki_client.py` : lecture seule, clé API en en-tête
`X-Cisco-Meraki-API-Key`, aucune écriture côté Meraki ; `services/meraki_matcher.py` : rapprochement
par hostname/nom aux `Asset` existants), puis PRTG lui-même codé le même jour à la suite
(`services/prtg_client.py` : lecture seule, API cœur PRTG Network Monitor — pas Multiboard, qui
sert à agréger des widgets visuels entre instances —, token API en paramètre de requête
`apitoken` ; `services/prtg_matcher.py` : rapprochement par host/hostname/nom, code numérique
`status_raw` normalisé vers le vocabulaire partagé — pas le libellé texte `status`, constaté
**localisé selon la langue de l'interface PRTG** ("OK" au lieu de "Up" sur le serveur testé,
configuré en français) et donc impropre à un mapping codé en dur sur des libellés anglais). Une ligne par `(asset_id, source)`, mise à jour en place à
chaque cycle — pas un historique, même esprit que `Asset.last_scan_result`. Un même actif peut
avoir une ligne par source ; `GET /api/assets` retient la plus récemment mise à jour des deux pour
son champ `network_status` (pas une source figée en dur, cf. `routers/assets.py::list_assets`).

**`import_new_assets`** côté PRTG (`sync_network_status(..., import_new_assets=True)`, `POST
/api/prtg/run?import_new_assets=true`, décision revue en session après un premier essai qui a
laissé 343 devices invisibles) : même mécanique que Meraki (`asset_type="network"`,
`source="prtg"`), avec une exclusion propre à PRTG — `prtg_matcher.py::_is_prtg_internal` écarte
structurellement (host vide ou loopback `127.0.0.1`, pas une liste de noms) les objets internes à
la plateforme PRTG elle-même (sonde, serveur central) : ce ne sont pas des équipements du réseau
surveillé. Vérifié en conditions réelles (04/08/2026) avant activation : sur les 343 devices non
rapprochés, aucun ne partage un nom normalisé ou une IP exacte avec un `Asset` déjà en base
(Meraki ou AD/SSH) — le rapprochement exact existant suffit à éviter les vrais doublons, y compris
pour des devices au nom proche mais physiquement distincts (ex. "Routeur Bellevigny" vs
"AP_Bellevigny", même site, IP différentes). Résultat : 339 `Asset` créés (343 moins les 4 objets
PRTG internes), parc Allsafe passé de 142 à 481 actifs.

**`hardware.prtg_icon` (17/08/2026)** — colonne `icon` ajoutée à `DEVICE_COLUMNS`
(`services/prtg_client.py`) : nom de fichier de l'icône assignée au device côté PRTG
(`vendors_Cisco.png`, `Device_WLAN.png`, `vendors_synology.png`...). Vérifié en conditions
réelles avant d'écrire le moindre code (`devicetype`/`hosttype`/`deviceicon` testés en même
temps, introuvables sur cette version de PRTG — seul `icon` existe). Stockée dans
`Asset.hardware`, même précédent que `vendor_hint` (création **et** rafraîchissement à chaque
cycle, `prtg_matcher.py::sync_network_status`). Consommée côté frontend par
`utils/assetCategory.js::PRTG_ICON_CATEGORY_LABELS` pour une catégorie plus précise que le
générique "Équipement réseau" (Colonne Catégorie de Durcissement.jsx/Assets.jsx/Inventaire.jsx)
— reflète tel quel l'icône choisie côté PRTG (auto-assignée ou posée manuellement par l'admin
PRTG), Allsafe ne vérifie ni ne déduit rien de plus : un device nommé "AP_TPLINK_..." peut par
exemple porter l'icône Cisco si c'est ce qui a été configuré côté PRTG, sans que ce soit une
erreur d'Allsafe.

**`import_new_assets`** côté Meraki (`sync_network_status(..., import_new_assets=True)`, `POST
/api/meraki/run?import_new_assets=true`) : contrairement à `withsecure_matcher.py` (n'enrichit que
des serveurs déjà importés via AD/SSH, jamais de création), crée un `Asset`
(`asset_type="network"`, `source="meraki"`, `hostname` NULL — pas de DNS pour un boîtier réseau et
la colonne est UNIQUE) pour chaque équipement Meraki sans correspondance. Défaut `False` : un
cycle planifié ne doit jamais créer d'actifs silencieusement sans qu'on le demande explicitement à
chaque appel. Vérifié en conditions réelles (04/08/2026) : la clé API peut voir **plusieurs
organisations Meraki distinctes** (2 constatées, 48 + 22 équipements) — `get_device_statuses()`
les agrège toutes par défaut, sauf `MERAKI_ORGANIZATION_ID` renseigné. 70 équipements importés au
premier essai (bornes Wi-Fi + pare-feux MX67C), parc Allsafe passé de 72 à 142 actifs ; ces actifs
réseau n'ont ni OS ni paquets installés, donc jamais de CVE matchée dessus.

### Intégration vSphere / ESXi (13/08/2026)

Plus-value distincte du reste des sondes réseau ci-dessus : Meraki/PRTG ne font que du statut en
ligne/hors ligne, l'intégration vSphere alimente le **matching CVE** de l'hyperviseur lui-même —
compromission d'un ESXi = accès à toutes les VM qu'il héberge (cf. campagnes ransomware ESXiArgs
2023 sur ESXi non patchés). Topologie confirmée avec l'utilisateur : ESXi géré par **vCenter
Server**, pas d'hôtes standalone — `services/vsphere_client.py` (pyVmomi, lecture seule) ouvre un
seul point de connexion vCenter qui agrège tous les `vim.HostSystem` qu'il gère, même esprit que
`MERAKI_ORGANIZATION_ID` absent = "toutes les organisations visibles par la clé". pyVmomi est
synchrone (comme `pywinrm`) — toujours appelé via `run_in_executor`, jamais directement dans une
coroutine.

`services/vsphere_matcher.py::sync_esxi_hosts(import_new_assets=False)` : rapprochement par
hostname/nom (même ordre que Meraki/PRTG), création optionnelle d'un `Asset`
(`asset_type="server"` — pas de nouvelle valeur, un hôte ESXi se comporte comme un serveur pour
tous les consommateurs en aval qui comptent ; `source="vsphere"`, `collection_method="vsphere_api"`,
cf. § ci-dessus). Pour chaque hôte matché (nouveau ou existant) : `hardware` mis à jour (vendor,
modèle, UUID, CPU, RAM, `esxi_build`, `esxi_vms` — inventaire VM **informatif uniquement**, aucune
VM n'est créée comme `Asset` ni rapprochée d'un actif existant dans cette passe, extension
naturelle mais hors scope), puis CPE posé directement (`_build_cpe("esxi", version)` —
`CPE_MAP_ESXI` ajouté à `services/asset_importer.py`, même forme que la branche Linux existante :
version en composant séparé, 8 composants après la base comme documenté pour l'incident
CVE-2022-30190) et `run_cpe_matching_for_asset_task.apply_async(...)` déclenché après commit —
il n'existe pas de scan SSH/WinRM de l'hôte ESXi lui-même à travers lequel router ce CPE, contrairement
à un serveur classique (`apply_scan_result`).

**Durcissement ESXi** (13/08/2026, `services/vsphere_hardening.py`) — ajouté à la suite,
initialement laissé hors scope puis demandé par l'utilisateur en miroir du durcissement
switches ci-dessous. Contrairement aux switches, **aucun SSH sur l'hôte** : tout est lu via
l'API vSphere déjà utilisée pour l'inventaire (`vsphere_client.py::_hardening_facts`,
`host.config.lockdownMode`/`host.config.service.service`/`host.config.dateTimeInfo.ntpConfig`/
options avancées `Syslog.global.logHost` et `Security.AccountLockFailures` via
`configManager.advancedOption.QueryOptions`). 5 checks : `lockdown_mode`, `ssh_service`
(le service SSH lui-même actif est le finding, pas un moyen d'y accéder), `ntp_configured`,
`syslog_configured`, `account_lockout`. Écrit dans `Asset.last_scan_result.compliance.checks`
— **pas** `network_compliance` : un hôte ESXi est `asset_type="server"`, `Durcissement.jsx::
checksFor()` route déjà tout actif non-network vers ce champ, aucun changement frontend
nécessaire pour l'affichage. Écrasement complet à chaque sync (pas de fusion comme
`switch_hardening.py`) : un hôte ESXi n'a qu'un seul producteur de `last_scan_result` (cette
sync — le scan SSH/WinRM classique y est bloqué par le garde-fou de `scan_asset_endpoint`,
cf. § ci-dessus), pas de risque d'écraser les données d'un autre producteur. Remédiation
(`hardeningRemediation.js`) : nouvelle famille `esxi`, sélectionnée par `os === "VMware ESXi"`
(pas par `assetType`, qui vaut `"server"` comme un serveur classique) — commandes
`esxcli`/`vim-cmd`, jamais exécutées par Allsafe. Vérifié en conditions réelles (13/08/2026,
`ESX3.aer.loc`) : Lockdown Mode désactivé et syslog distant vide remontés comme avertissements
réels, NTP/SSH/verrouillage de compte conformes.

`POST /api/vsphere/run?import_new_assets=`, `GET /api/vsphere/status` — déclenchement manuel
uniquement, même précédent que Meraki/PRTG/GLPI (cf. § Planning Celery Beat).

**`GET /api/integrations/status`** (14/08/2026, `routers/integrations.py`, page Paramètres >
Intégrations) : agrège en un seul appel le statut de NVD/GitHub/AD/SSH/WithSecure/Meraki/PRTG/GLPI/
vSphere — `{configured: bool}` dérivé de la présence des variables `.env` correspondantes (jamais leur
valeur), `last_synced_at` lu directement dans `sync_state` (mêmes clés que les endpoints `/status`
ci-dessus — `withsecure_missing_updates`/`meraki_network_status`/`prtg_network_status`/
`glpi_inventory`/`vsphere_esxi`/`nvd`). Ouvert à tout connecté (`dependencies=_authed`, comme les
routers `withsecure`/`meraki`/`prtg`/`glpi`/`vsphere` eux-mêmes) — aucun secret exposé, juste
configuré/non configuré + une date.

### Durcissement switches Cisco (13/08/2026)

Angle retenu pour le réseau après évaluation avec l'utilisateur : la plus-value CVE/firmware côté
switch est faible et peu fiable (matching CPE par marque/firmware nettement moins standardisé que
Debian/Windows) — l'angle retenu est le **durcissement de configuration**, même mécanisme que les
checks CIS-like déjà en place pour serveurs/postes (`asset_scanner.py`), qui produit des findings
concrets et actionnables. Parc réseau confirmé majoritairement Cisco IOS/IOS-XE : les checks ne
visent pas une abstraction multi-vendor, un équipement d'une autre marque retombe simplement sur
des checks `"unknown"`.

`services/network_cli.py` : driver SSH **interactif** (`asyncssh`, `conn.create_process()` avec
pty, `services/ssh_trust.py::connect_trusted` pour le TOFU — même credentials que le SSH Linux
existant, `Asset.scan_username`/`scan_password_encrypted`, aucun nouveau modèle) — nécessaire car
Cisco IOS/IOS-XE ne supporte pas de façon fiable l'exec non-interactif à la `conn.run(cmd)` utilisé
pour Linux. Une seule session par actif, lecture jusqu'à un prompt détecté par regex (best-effort —
un vendor au prompt très différent retombe sur un timeout, jamais une exception qui remonte brute).

`services/switch_hardening.py` (`POST /api/assets/switch-hardening/run`) : cible
`asset_type="network"` **avec `scan_username` renseigné** (opt-in — tous les actifs réseau ne sont
pas des switches Cisco administrables en SSH, filtré directement en SQL). 8 checks à partir de 7
lectures `show running-config | include/section ...` : `telnet_disabled`/`console_vty_timeout`
(parsées depuis une même lecture `section line`, stanzas VTY), `snmp_default_community`
(`public`/`private`), `password_encryption`, `aaa_authentication`, `banner_motd`,
`syslog_configured`, `ntp_configured`. Toute sortie commençant par `%` (droits insuffisants,
commande rejetée) → check `"unknown"`, jamais une erreur bloquante.

⚠️ **Prérequis de provisioning** : `show running-config` exige le mode privilégié IOS (prompt `#`).
Un compte `scan_username` limité au mode utilisateur (`>`) donnera des checks `"unknown"` sur toute
la ligne — pas un bug, un prérequis côté compte switch (accès niveau 15 via AAA sur la session SSH).

⚠️ **Fusion, jamais écrasement, de `Asset.network_compliance`** : `network_protocol_check.py` (test
TCP passif Telnet/HTTP, non credentialed) écrase `network_compliance` en entier
(`asset.network_compliance = result`). Un même switch peut être suivi à la fois par PRTG/Meraki
(donc passer par ce test TCP) et avoir des identifiants SSH (donc passer aussi par le durcissement
ci-dessus) — `switch_hardening.py` fusionne par `id` dans l'existant pour que les deux jeux de
checks cohabitent. Asymétrie assumée : si `network_protocol_check.py` tourne *après* le
durcissement sur le même actif, il écrase toujours tout — non corrigé de ce côté-là dans cette
passe. Contrairement à `network_protocol_check.py` (jamais credentialed), ce service met aussi à
jour `Asset.last_scan` — une vraie session SSH authentifiée mérite un "dernier scan".

Rendu frontend : les checks switches utilisent la même forme `{"id","label","status","detail"}` que
partout ailleurs, affichés sans changement de route (`Durcissement.jsx` lit déjà
`network_compliance.checks` pour `asset_type="network"`). Seule adaptation nécessaire : le
catalogue de remédiation (`frontend/src/utils/hardeningRemediation.js`) ne distinguait que les
familles `windows`/`linux` par regex sur `os` — un `os` de switch (modèle Meraki/PRTG, version IOS)
ne matche ni l'une ni l'autre. Nouvelle famille `network`, sélectionnée par `assetType` (prop
threadée depuis `Durcissement.jsx` → `ComplianceChecklist` → `categoryFor`/`remediationFor`) plutôt
que par une regex sur `os`, qui n'a pas de sens pour un actif réseau.

Déclenchement manuel uniquement (`POST /api/assets/switch-hardening/run`), même précédent que
Meraki/PRTG/GLPI/vSphere.

### Table `vulnerabilities`
```sql
id                  UUID PRIMARY KEY
asset_id            UUID FK → assets
cve_id              UUID FK → cves
status              VARCHAR   -- open / in_progress / patched / accepted_risk / awaiting_fix / false_positive
risk_score          FLOAT     -- cvss × epss × criticite (0-10)
detected_at         TIMESTAMP WITH TZ
patched_at          TIMESTAMP WITH TZ
awaiting_fix_at     TIMESTAMP WITH TZ  -- date de passage en "awaiting_fix"
false_positive_at   TIMESTAMP WITH TZ  -- date de passage en "false_positive"
accepted_risk_until TIMESTAMP WITH TZ  -- date de revue obligatoire si status="accepted_risk" (session 27/07/2026)
validated_by        VARCHAR   -- analyste ayant validé (dropdown) — null si "Auto (patch check)" a basculé
notes               TEXT      -- aussi utilisé comme annotation/justification pour awaiting_fix/false_positive
ai_analysis         JSONB     -- Résultat Claude anonymisé
last_patch_check    TIMESTAMP WITH TZ  -- NULL = jamais vérifié (éligible au check auto/manuel)
patch_check_result  JSONB     -- Dernier rapport patch_checker (patch_detected, kb_checked, kb_os_hint...)
```

Deux statuts au-delà du cycle classique open → patched (cf. `docs/FRONTEND.md` § Dashboard) :
- **`awaiting_fix`** — vulnérabilité réelle mais sans correctif éditeur/distro disponible pour
  l'instant (annotation obligatoire). Reste éligible au patch check autonome — bascule automatiquement
  en `patched` dès qu'un correctif est détecté, sans repasser par `open`.
- **`false_positive`** — la CVE ne concerne en réalité pas l'actif (erreur de matching CPE/mots-clés,
  cf. `docs/MATCHING.md`). État terminal comme `patched`, mais volontairement **exclu** du patch check
  autonome (rien à revérifier, la CVE n'a jamais été le sujet).
- **`accepted_risk`** (justification/date de revue obligatoires depuis le 27/07/2026) — le risque est
  assumé plutôt que corrigé. `notes`/`validated_by`/`accepted_risk_until` requis à la transition
  (`PATCH /{id}` et `POST /bulk-accepted-risk`, 400 sinon). État terminal comme les deux précédents,
  mais avec une nuance : `accepted_risk_until` alimente un champ calculé **jamais stocké**,
  `review_overdue` (`accepted_risk_until < now()`), exposé par `GET /api/vulnerabilities` — **la date
  de revue ne rouvre jamais la vuln automatiquement**, elle ne fait qu'afficher un badge ⚠, exactement
  comme `sla_exceeded` sur la Veille (`routers/watch.py`). Un humain doit requalifier manuellement.

**Important** : `last_patch_check` et `patch_check_result` sont remis à `NULL` dès que `status` repasse à
`open` / `in_progress` (voir `routers/vulnerabilities.py`) — sans ça, le rattrapage
(`backfill_auto_patch`) rebasculerait instantanément une vuln réouverte en `patched` sur la base d'un
ancien résultat, sans relancer de vrai contrôle. **Exception** : passer en `awaiting_fix` conserve ces
deux champs (contexte technique utile en plus de l'annotation, et préserve le rythme de
`RECHECK_INTERVAL` plutôt que de forcer un recheck immédiat).

### Table `vulnerability_status_history` (session 27/07/2026)

```sql
id                UUID PRIMARY KEY
vulnerability_id  UUID FK → vulnerabilities (ON DELETE CASCADE)
old_status        VARCHAR   -- NULL possible (non utilisé aujourd'hui)
new_status        VARCHAR NOT NULL
changed_at        TIMESTAMP WITH TZ NOT NULL  -- posé explicitement par record_status_change(), pas un défaut ORM
validated_by      VARCHAR   -- analyste, ou "Auto (patch check)"
notes             TEXT
```

Jamais écrasée, jamais supprimée (sauf cascade si la vuln elle-même est supprimée). **Prospective, pas
rétroactive** : ne couvre que les transitions survenues à partir de sa mise en service — motivée par un
incident où une réouverture/rebascule sans piste d'audit a compliqué un diagnostic.

Alimentée par un unique helper, `services/vuln_history.py` (`record_status_change(session, vuln_id,
old_status, new_status, validated_by=None, notes=None)` — no-op si `old_status == new_status`),
appelé aux **9 points** qui modifient `Vulnerability.status` dans tout le backend (sweep exhaustif
vérifié par grep) :
- Les 6 endpoints de `routers/vulnerabilities.py` : `PATCH /{id}`, `bulk-patch`, `bulk-awaiting-fix`,
  `bulk-accepted-risk`, `bulk-false-positive`, `bulk-validate`.
- Le point de passage unique de la bascule **automatique**, `apply_patch_result()`
  (`services/patch_checker.py`) — les 3 branches patched/awaiting_fix/false_positive. Cette fonction a
  gagné un 4ᵉ paramètre `session` à cette occasion (elle ne l'avait pas avant, `record_status_change`
  en a besoin pour `session.add()`) ; ses 3 appelants (`backfill_auto_patch`,
  `run_startup_patch_checks`, `routers/patch_check.py:check_patch_for_vuln`) le transmettent tous.

Exposée par `GET /api/vulnerabilities/{id}/status-history` (tri `changed_at DESC`).

⚠️ **Une table créée après `app_role.sql` n'hérite d'aucun droit pour `cbr_app`** (rôle applicatif à
privilèges réduits, cf. § Rôle applicatif ci-dessous) — sans un `GRANT SELECT, INSERT, UPDATE, DELETE`
explicite (posé dans le même `schema_patches.sql`), l'app aurait planté en `permission denied` au
premier `INSERT`. Réflexe à reproduire pour toute future nouvelle table.

### Table `feeds`
```sql
id              UUID PRIMARY KEY
name            VARCHAR
url             VARCHAR UNIQUE
feed_type       VARCHAR   -- rss / atom / nvd_api
active          BOOLEAN
last_fetch      TIMESTAMP WITH TZ
fetch_interval  INTEGER   -- minutes
```

### Table `watch_items`
Détail complet du module (workflow, sources, thèmes, SLA) dans `docs/VEILLE.md` — schéma ci-dessous à
titre de référence rapide.
```sql
id            UUID PRIMARY KEY
source        VARCHAR NOT NULL   -- cert-fr-avis, zataz, ransomware-live, ou un slug de WatchSource
source_label  VARCHAR            -- libellé affiché ("CERT-FR Avis", "Ransomware.live"...)
title         VARCHAR NOT NULL
url           VARCHAR UNIQUE     -- clé de déduplication
summary       TEXT
published_at  TIMESTAMP WITH TZ  -- date de publication source
received_at   TIMESTAMP WITH TZ  -- date d'import Allsafe
severity      VARCHAR            -- critical / important / informational
status        VARCHAR            -- new / in_review / treated / not_applicable
reviewed_by   VARCHAR
reviewed_at   TIMESTAMP WITH TZ
decision      TEXT
linked_cve_id VARCHAR
cve_ids_found JSONB              -- CVE-IDs détectés automatiquement dans le contenu
themes        JSONB              -- Cyber, Admin, Réseau, Hardware, Software, Données, Fuite de
                                  -- données, Réglementation, Ransomware, APT, Vulnérabilité, IA
country       VARCHAR            -- ISO 3166-1 alpha-2 (FR, US…) — onglet Fuite de données uniquement,
                                  -- depuis l'API pour ransomware.live, défaut FR pour les trackers
                                  -- dédiés français, NULL sinon
```

### Table `watch_sources`
Sources RSS/Atom ajoutées dynamiquement par l'utilisateur — depuis Fuite de données ou Veille
technologique, sans toucher au code (`services/watch_fetcher.py` reste la seule liste des sources
codées en dur). Détail dans `docs/VEILLE.md`.
```sql
id         UUID PRIMARY KEY
name       VARCHAR NOT NULL      -- libellé affiché ("Mon flux perso")
slug       VARCHAR UNIQUE NOT NULL  -- dérivé du nom (ASCII, accents translittérés), = watch_items.source
url        VARCHAR NOT NULL      -- URL du flux RSS/Atom
feed_type  VARCHAR               -- rss / atom
category   VARCHAR               -- general (Veille technologique) / leak (Fuite de données) —
                                  -- routage d'affichage uniquement, la collecte ne distingue pas
country    VARCHAR               -- pays par défaut assigné aux items de ce flux (optionnel)
enabled    BOOLEAN
created_at TIMESTAMP WITH TZ
```

### Table `sync_state`
Horodatage de la dernière exécution d'une tâche de synchronisation récurrente — une ligne par clé de
tâche (`key`), pas une table par tâche : la 2e tâche à en avoir eu besoin (matching CPE, après la
veille, session 20/07/2026) était le signal qu'il ne fallait pas dupliquer le modèle une 3e fois (cf.
principe "penser scalable", `CLAUDE.md`). Mise à jour aussi bien par le déclenchement manuel (bouton UI)
que par le cycle automatique (Celery beat pour `watch`, démarrage de l'app pour `cpe_match`) — lue au
chargement de page pour afficher la date de dernière synchronisation sans dépendre d'un clic dans la
session en cours.
```sql
key            VARCHAR PRIMARY KEY   -- "watch" | "cpe_match" | "nvd"
last_synced_at TIMESTAMP WITH TZ
```
Clé `"nvd"` (session 20/07/2026) : curseur de la sync NVD incrémentale, avance uniquement après un run
complet sans erreur — cf. § Incident sync NVD ci-dessous, une confiance aveugle en `MAX(CVE.modified)`
recalculé à chaque appel permettait à un run interrompu de perdre silencieusement des CVE.

Lue via `GET /api/watch/sync-status` (clé `watch`, cf. `docs/VEILLE.md`) et `GET /api/sync/match-status`
(clé `cpe_match`).

### Table `kb_builds` (session 21/07/2026)

Cache permanent KB Microsoft → numéro(s) de build OS, alimenté à la demande par
`services/kb_build.py` depuis le titre de l'article support.microsoft.com.

| Colonne | Type | Rôle |
|---|---|---|
| `kb` | String (PK) | Numéro de KB sans préfixe, ex. `"4489899"` |
| `builds` | JSON | `["17763.379"]` — liste car un KB couvre parfois plusieurs branches |
| `title` | String | Titre brut de l'article, traçabilité pour l'analyste |
| `found` | Boolean | `False` = article sans build (mises à jour .NET/Defender…), ne pas retenter |
| `fetched_at` | DateTime | Horodatage de récupération |

**Pourquoi un cache permanent** : le couple KB→build est immuable une fois publié, et
support.microsoft.com rate-limite agressivement. Une CVE peut porter 14 KB et un actif plusieurs
milliers de CVE — sans cache, inexploitable. Un échec réseau n'est jamais mis en cache (retenté plus
tard), contrairement à un article réellement dépourvu de build. Détail du signal et de son usage
dans `docs/MATCHING.md` § Signal 2bis.

### Table `watched_identities`
Identités de l'entreprise à surveiller — module Surveillance Identités (CyberVeille). `name`/`domain` :
aucune collecte propre, croisées avec les `watch_items` déjà agrégés (sources leak uniquement).
`ip`/`ip_range` (session 20/07/2026) : mécanisme différent, vérifiées contre des listes de blocage
tierces (`services/ip_watch.py`) — une IP n'apparaît jamais dans le texte des sources de fuite. Dans
tous les cas 100% gratuit, aucune clé API. Liste éditable dans l'interface. Détail dans `docs/VEILLE.md`
§ 9bis/9ter.
```sql
id         UUID PRIMARY KEY
value      VARCHAR NOT NULL      -- "AER" | "aer.fr" | "203.0.113.10" | "203.0.113.0/24" (normalisés :
                                  -- domaine en minuscules, IP/CIDR canonisés via le module `ipaddress`)
kind       VARCHAR NOT NULL      -- name | domain | ip | ip_range
enabled    BOOLEAN
created_at TIMESTAMP WITH TZ
```

### Table `analysts` (session 29/07/2026)
Registre des analystes, remplace la liste `ANALYSTS` codée en dur (`frontend/src/components/
ValidateDropdown.jsx`) utilisée partout comme menu déroulant d'attribution. **Pas une
authentification** : aucun mot de passe, aucune session serveur. Gérée depuis Administration
(onglet « Analystes », `AdministrationSecurity.jsx` — déplacé de Paramètres le 30/07/2026) — distinct
des comptes `users` ci-dessous, pas de fusion (décision reconfirmée après usage réel). Lecture
(`GET /api/analysts`) ouverte à tout utilisateur connecté, écriture réservée `admin` (cf. § Protection
des routes ci-dessous) — avant ce déplacement, n'importe quel compte pouvait modifier ce registre.
```sql
id          UUID PRIMARY KEY
name        VARCHAR NOT NULL UNIQUE
created_at  TIMESTAMPTZ
```

### Authentification (`users`, `sessions`, `auth_audit_logs`, session 30/07/2026)

Remplace le module Bastion (sélecteur « Je suis… », `visible_modules`, retiré le même jour — sans
rapport avec le nouveau placeholder « Bastion » du module Sécurité, réintroduit la même session pour
un futur accès jump host aux serveurs critiques, cf. `frontend/src/pages/Bastion.jsx`) —
authentification réelle : compte email/mot de passe (politique centralisée dans
`services/auth.py::validate_password_strength` depuis le 14/08/2026 — **16 caractères minimum +
majuscule + minuscule + chiffre + caractère spécial**, avant dupliquée en deux endroits avec juste
une longueur minimale), session par cookie
**HttpOnly** (`SameSite=Lax`, `Secure` piloté par `COOKIE_SECURE`), RBAC **binaire**
(`admin`/`analyst`, une simple colonne `CHECK`, pas de table `roles` séparée — deux valeurs ne
justifient pas cette abstraction). Mot de passe hashé avec `bcrypt`. Champ mot de passe avec bascule
afficher/masquer (`frontend/src/components/PasswordInput.jsx`, réutilisé sur Login, changement forcé
et création de compte).

```sql
-- users
id                    UUID PRIMARY KEY
email                 VARCHAR NOT NULL UNIQUE
full_name             VARCHAR NOT NULL
password_hash         VARCHAR NOT NULL
role                  VARCHAR NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin','analyst'))
is_active             BOOLEAN NOT NULL DEFAULT true
must_change_password  BOOLEAN NOT NULL DEFAULT false
created_at            TIMESTAMPTZ
updated_at            TIMESTAMPTZ

-- sessions — le cookie ne porte qu'un token aléatoire opaque (secrets.token_urlsafe) ;
-- seul son hash SHA-256 est stocké ici, jamais le token en clair.
id                  UUID PRIMARY KEY
user_id             UUID REFERENCES users(id) ON DELETE CASCADE
session_token_hash  VARCHAR NOT NULL UNIQUE
ip_address          VARCHAR
user_agent          TEXT
expires_at          TIMESTAMPTZ NOT NULL   -- 8h glissantes, plafond absolu 7j depuis created_at
created_at          TIMESTAMPTZ

-- auth_audit_logs — trace toutes les tentatives (y compris email inexistant, sinon le
-- comptage anti-bruteforce par email n'a aucun sens). Index sur (email_attempt, created_at)
-- et (ip_address, created_at) pour ce comptage.
id            UUID PRIMARY KEY
event_type    VARCHAR NOT NULL   -- LOGIN_SUCCESS | LOGIN_FAILED | LOGOUT | PASSWORD_CHANGED |
                                 -- EMAIL_CHANGED | SESSION_REVOKED (14/08/2026)
user_id       UUID REFERENCES users(id) ON DELETE SET NULL
email_attempt VARCHAR
ip_address    VARCHAR
user_agent    TEXT
details       JSONB
created_at    TIMESTAMPTZ
```

**Protection des routes** : `dependencies=[Depends(require_auth)]` posé explicitement sur chaque
`app.include_router(...)` dans `main.py` (pas de middleware global — reste visible dans
`app.routes`/OpenAPI, garde-fou testé par `tests/test_auth_guardrails.py`). `/api/health` et
`POST /api/auth/login` sont les deux seules routes publiques. `GET /api/connections`,
`GET/POST /api/security/events*` (sauf `/events/count`, badge partagé à tout utilisateur connecté)
et `/api/users` exigent en plus `require_admin` — ferme un trou hérité de l'ancien verrou côté client
d'`AdministrationSecurity.jsx` (mot de passe en clair dans le bundle JS, sans aucune vérification
serveur). `POST /api/connections` reste volontairement public : c'est le journal d'accès
(`ConnectionTracker`, `frontend/src/App.jsx`), qui doit capter les visites même avant toute connexion.
`POST/PATCH/DELETE /api/analysts` exigent aussi `require_admin` (30/07/2026, `GET` reste ouvert) —
même logique de fermeture d'un accès jusque-là trop large (n'importe quel compte pouvait modifier ce
registre).

**Anti-bruteforce** : `services/auth.py::is_locked_out` compte les `LOGIN_FAILED` des 15 dernières
minutes, seuils 5 par email tenté et 20 par IP (protège aussi contre l'énumération d'emails valides
depuis un même poste). Message d'erreur générique identique dans tous les cas (mauvais mot de passe,
compte inexistant ou désactivé) — pas d'énumération de comptes par le contenu de la réponse.

**Bootstrap** : si la table `users` est vide au démarrage et que `BOOTSTRAP_ADMIN_EMAIL`/
`BOOTSTRAP_ADMIN_PASSWORD` sont renseignés, `main.py::lifespan` crée le premier admin
(`must_change_password=true`) — idempotent, pas de fail-fast si absent (juste un `logger.warning`,
pour ne pas casser un environnement de dev sans auth encore configurée).

**Registre `analysts` inchangé** : les comptes `users` ci-dessus servent à se connecter, le registre
`analysts` ci-dessus continue d'alimenter les dropdowns d'attribution (`validated_by`...) — deux
registres distincts, pas de fusion pour cette phase (cf. STATUS.md).

**Self-service sur son propre compte** (14/08/2026, `routers/auth.py`, tous `Depends(require_auth)`
sur son propre `user`, jamais sur un `user_id` de chemin — contrairement à `routers/users.py` qui
opère sur n'importe quel compte mais est réservé admin) :
- `PATCH /api/auth/change-email` — body `{current_password, new_email}`. Vérifie le mot de passe
  actuel (même garde que `change-password`, un email de connexion est sensible) et l'unicité du
  nouvel email. Journalise `EMAIL_CHANGED` (`details.new_email`).
- `GET /api/auth/sessions` — sessions actives du compte connecté, `is_current` calculé en comparant
  le hash du cookie de la requête à `session_token_hash` de chaque ligne (`services/auth.py::_hash_token`,
  importé malgré le prefixe `_` — même module, pas d'API publique à préserver).
- `DELETE /api/auth/sessions/{id}` — révoque une session du compte connecté (404 si elle appartient à
  un autre compte). Refuse (400) de révoquer la session courante — message renvoyant vers
  `POST /api/auth/logout`, pour éviter la confusion "je clique révoquer et je me déconnecte moi-même
  sans comprendre pourquoi". Journalise `SESSION_REVOKED`.

Pendant de `POST /api/users/{id}/revoke-sessions` (`routers/users.py`, admin, sur un *autre* compte) —
les deux mécanismes coexistent, aucune fusion : l'un pour soi-même sans droits admin, l'autre pour
gérer les comptes des autres.

### Déception / honeypots DB (`security_events`, session 24/07/2026)

Couche de **détection** (pas de prévention) : des objets leurres qu'**aucun code d'Allsafe ne
référence** sont plantés dans la base ; tout accès à l'un d'eux = intrusion (zéro faux positif).
Tout est dans `backend/db/deception_setup.sql` (idempotent, à rejouer sur toute base — comme les
`ALTER` manuels, `create_all` ne crée que la table `security_events`, jamais les vues/fonctions/rôles).

- **`security_events`** (table réelle, modèle `SecurityEvent`) : journal des accès leurres.
  Colonnes `source` (honey_read | honey_write | decoy_role), `object_name`, `operation`, `db_user`,
  `client_addr` (inet), `detail` (jsonb), `acknowledged`/`ack_by`/`ack_at`.
- **Vues leurres** `api_keys` / `app_users` / `ssh_credentials_backup` / `admin_tokens` : chacune est
  une **vue adossée à une fonction `SECURITY DEFINER`** qui journalise **à la lecture** (SELECT — pas
  de trigger SELECT natif, d'où l'astuce vue+fonction) et renvoie des **honeytokens** (fausses creds
  crédibles, self-hosted, aucun callback externe). Triggers `INSTEAD OF` pour journaliser aussi les
  écritures (avalées silencieusement). `GRANT ... TO PUBLIC` : l'app (`cybervuln`) n'y touche jamais,
  donc toute lecture s'y trahit — y compris une réutilisation des creds app volées.
- **Rôles leurres** `admin`/`root`/`dba`/`backup`/`postgres_admin` : mot de passe aléatoire inconnu,
  aucun droit sur les tables réelles, seulement sur les vues leurres. `log_connections=on`
  (via `ALTER SYSTEM`, persiste dans `postgresql.auto.conf`) trace les connexions pour la forensique.
- **Alerte** : `GET /api/security/events/count` (nombre seul, sans détail), `GET /api/security/events?unack_only=`,
  `POST /api/security/events/{id}/ack`, `POST /api/security/events/ack-all`. La sidebar (`Layout.jsx`)
  poll `count` (~30 s) et affiche un **badge rouge (nombre) sur l'item Paramètres** quand il y a des
  alertes non acquittées (masqué en Présentation). Le **détail reste derrière le mot de passe** :
  Paramètres > Sécurité > Administration > onglet « Base de données » (`AdministrationSecurity.jsx`).
  Le badge disparaît une fois les événements acquittés là-bas.

⚠️ **Ne jamais référencer un objet leurre dans le code de l'app** (ça créerait des faux positifs).

### Rôle applicatif à privilèges réduits (`cbr_app`, session 24/07/2026)

L'app ne tourne plus avec le superuser `cybervuln` mais avec **`cbr_app`** (LOGIN, NOSUPERUSER,
NOCREATEDB, NOCREATEROLE) — cf. `backend/db/app_role.sql` (idempotent). `cybervuln` reste réservé à
l'admin/init/migrations/déception.

- **Config** : `config.py` construit `DATABASE_URL` depuis `APP_DB_USER`/`APP_DB_PASSWORD` s'ils sont
  définis, sinon repli sur `DB_USER`/`DB_PASSWORD` (rétrocompatible → rollback = vider les APP_DB_*).
  Docker : le service `db` garde `DB_USER` (superuser) pour l'init + le healthcheck ; seuls
  backend/worker/beat consomment `APP_DB_*`.
- **Droits `cbr_app`** : `SELECT/INSERT/UPDATE/DELETE` sur les tables applicatives + `USAGE` séquences.
  Sur `security_events` : **SELECT + UPDATE(acknowledged, ack_by, ack_at) uniquement** — pas d'INSERT
  (les événements naissent des fonctions SECURITY DEFINER), **pas de DELETE** → un attaquant avec les
  creds app **ne peut plus effacer les traces de déception** (la « limite assumée » du § précédent est
  levée). `ALTER DEFAULT PRIVILEGES` accorde le DML à cbr_app sur les futures tables créées par l'owner.
- **Vérifié** : cbr_app ne peut ni `CREATE TABLE`, ni `DROP`, ni `DELETE FROM security_events`, ni agir
  en superuser ; DML complet OK sur les tables réelles ; l'app démarre normalement.

⚠️ **Conséquence sur le schéma** : `create_all` (init_db) n'émet aucun DDL sur une base **existante**
(checkfirst), donc cbr_app suffit. Mais une **nouvelle table de modèle** doit être créée par l'owner
(`cybervuln`) **avant** le déploiement, sinon le démarrage échoue (permission refusée sur CREATE). Cohérent
avec la convention « pas de migration auto, ALTER manuels par l'admin ».

### Verrou DDL — event trigger (`backend/db/ddl_guard.sql`, session 24/07/2026)

Défense active en profondeur : un **event trigger** `ddl_command_start` (`guard_ddl()`) **bloque ET
journalise** toute commande DDL (CREATE / ALTER / DROP / GRANT…) lancée par un rôle **non whitelisté**.

- **Whitelist = `session_user IN ('cybervuln')`** (le superuser d'admin/migrations). `session_user` =
  rôle réellement authentifié, insensible à `SET ROLE`/SECURITY DEFINER. Tout autre rôle (cbr_app, rôles
  leurres, rôle compromis) → `RAISE EXCEPTION` (bloque) + événement `security_events` (source `ddl_attempt`).
- **Journalisation AUTONOME via `dblink`** : le `RAISE EXCEPTION` annule la transaction — un simple INSERT
  serait annulé avec elle. `dblink_exec` ouvre une connexion séparée (locale, trust `127.0.0.1`) qui
  committe le log indépendamment. `dblink` est **révoqué de PUBLIC** (sinon un rôle compromis pourrait
  s'en servir pour du mouvement latéral) — réservé au superuser via la fonction SECURITY DEFINER.
- `RAISE WARNING` en doublon dans le log serveur (2e canal hors base).
- **Limite native** : les event triggers ne couvrent pas les objets **partagés** (rôles, tablespaces,
  `ALTER SYSTEM`) — l'essentiel (schéma + objets leurres) est protégé.
- **Console** : ces événements apparaissent dans Paramètres > Sécurité > Administration > Base de données
  (type « DDL bloquée », violet) et incrémentent le badge Paramètres.

⚠️ **Interaction avec cbr_app / déploiement à neuf** : le trigger bloque le DDL de cbr_app. Sur une base
**existante** create_all n'émet aucun DDL → aucun souci. Mais sur une base **vierge**, il faut créer le
schéma **avec `cybervuln`** d'abord : laisser `APP_DB_*` vide au premier démarrage (l'app se rabat sur
`DB_USER=cybervuln`, whitelisté, et create_all bâtit le schéma), puis renseigner `APP_DB_USER=cbr_app`.
Ordre de pose des scripts sur base neuve : schéma (cybervuln) → `app_role.sql` → `deception_setup.sql` →
`ddl_guard.sql` → `schema_patches.sql` (peut être rejoué à tout moment, idempotent).

### `backend/db/schema_patches.sql` (session 27/07/2026)

`create_all` ne modifie jamais une table existante (seulement les tables absentes) — pas d'Alembic
dans ce projet. Ce fichier centralise les `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (et désormais les
`CREATE TABLE IF NOT EXISTS`) au lieu de les exécuter à la main sans trace (comme les deux `ALTER` du
22/07/2026, non versionnés). **À exécuter avec le rôle superuser `cybervuln`**, jamais `cbr_app`
(bloqué par le verrou DDL ci-dessus). Contient aujourd'hui `vulnerabilities.accepted_risk_until` et la
table `vulnerability_status_history` (+ son `GRANT` pour `cbr_app`, cf. § Table
`vulnerability_status_history`) — à faire grossir au fil des sessions plutôt que créer un nouveau
fichier à chaque colonne/table.

Contient aussi, depuis le 28/07/2026, deux `CREATE INDEX IF NOT EXISTS` (`idx_cves_published` sur
`cves.published`, `idx_vulnerabilities_status` sur `vulnerabilities.status`) — aucune des deux colonnes
n'était indexée malgré des endpoints interrogés en continu par le Dashboard (`GET /patch-check/status`
toutes les 3s, `GET /stats`), qui faisaient un scan séquentiel des ~270k `vulnerabilities`/~181k `cves`
à chaque appel. `/api/health` lui-même en était affecté (plusieurs secondes de latence sous charge
normale). Effet mesuré : `/api/health` de plusieurs secondes à ~2ms. **N'accélère pas** les 3 endpoints
"candidats" de `routers/vulnerabilities.py` (`awaiting-fix`/`false-positive`/`critical-review`) — leur
pagination trie par `vulnerabilities.id`, un ordre sans rapport avec ces filtres, cf.
`project_ad_widening_scale_incident` en mémoire pour le détail de ce chantier resté ouvert.

---

## 🐳 Services Docker

| Service | Image | Port | Rôle |
|---------|-------|------|------|
| db | postgres:16-alpine | 5432 | Base de données |
| redis | redis:7-alpine | 6379 | File Celery + cache |
| backend | ./backend | 8000 | API FastAPI |
| worker | ./backend | — | Celery Worker |
| beat | ./backend | — | Celery Beat (scheduler) |
| frontend | ./frontend (stage `dev`) | 3000 | React — Vite dev server, HMR |
| frontend-prod | ./frontend (stage `prod`) | 3000 | React — build Vite + nginx, profil Compose `prod` (opt-in) |

**Rotation des logs** (27/07/2026, sur les 6 services principaux) : `json-file` sans limite grossit
indéfiniment par défaut — vérifié sur cet hôte (`docker inspect ... LogConfig` vide, pas de
`daemon.json` global). Sur un outil qui tourne en continu (sync NVD/veille toutes les heures, patch
check toutes les 6h, tout ça loggé), rien ne purgeait jamais les logs. `max-size: 10m` / `max-file: 5`
= 50 Mo max par service.

**Build de production du frontend** (27/07/2026) — jusque-là le frontend tournait en mode Vite dev
(`npm run dev`) même dans ce qui sert de déploiement principal : pas de minification, tooling de dev
actif en continu. `frontend/Dockerfile` est maintenant multi-stage :
- `dev` (défaut, service `frontend`) : comportement inchangé, HMR, sources montées en direct.
- `build` : stage intermédiaire, jamais lancé directement (`npm run build`).
- `prod` (service `frontend-prod`) : nginx sert le build Vite minifié, `frontend/nginx.conf` reproduit
  le proxy `/api` → backend et le forwarding `X-Forwarded-For`/`X-Real-IP` du `vite.config.js` dev —
  sans ça, `routers/connections.py` journaliserait l'IP du conteneur nginx au lieu du vrai client.

**HMR silencieusement cassé sous WSL2 (28/07/2026)** — le dépôt vit sous `/mnt/c/...` (chemin Windows
monté dans WSL2). Le watcher natif de Vite (chokidar/inotify) ne voit pas les écritures faites sur ce
type de montage : des éditions de pages restaient invisibles dans le navigateur — fichier à jour sur le
disque **et** dans le conteneur (bind mount correct), mais jamais recompilé/rechargé, sans la moindre
erreur visible. Repéré en testant `Assets.jsx`/`Inventaire.jsx` en conditions réelles, confirmé en
comparant le DOM rendu au contenu du fichier monté. `frontend/vite.config.js` a `server.watch:
{ usePolling: true, interval: 300 }` depuis — seul un `docker compose restart frontend` faisait
apparaître les changements avant ce correctif. Coût : un peu de CPU (polling au lieu d'événements),
acceptable pour un service de dev.

⚠️ **`target: dev` fixé explicitement** sur le service `frontend` dans `docker-compose.yml` : sans
lui, Docker construit par défaut le **dernier** stage du `Dockerfile` (`prod`), ce qui basculerait
silencieusement l'environnement de développement vers un build figé sans HMR au prochain rebuild.

**`frontend-prod` derrière un profil Compose** (`profiles: ["prod"]`), pas un `docker-compose.prod.yml`
séparé — un second fichier aurait exigé de bien gérer la fusion YAML entre fichiers (les listes comme
`volumes`/`healthcheck` se **concatènent** par défaut entre fichiers Compose, elles ne se remplacent
pas), source d'erreurs subtiles. Un service à part entière dans le même fichier est sans équivoque.
`docker compose up` seul ne le démarre jamais (profil inactif) ; **nommer** le service suffit à le
démarrer (`docker compose up -d frontend-prod`), pas besoin de `--profile prod`. Les deux services
occupent le même port hôte (3000) — à utiliser l'un ou l'autre, jamais ensemble.

Vérifié en conditions réelles (27/07/2026) : build + conteneur nginx lancé isolément (port de test
3001, réseau Docker du projet) — page servie, routes SPA inconnues retombent bien sur `index.html`
(pas de 404 au rechargement sur `/vulnerabilities`), proxy `/api/health` fonctionnel, `X-Forwarded-For`
correctement transmis et retrouvé dans `connection_logs` (testé avec une IP factice, nettoyée après
coup).

Volume `./keys` monté **en écriture** (`rw`, plus `:ro`) dans backend et worker depuis le 27/07/2026 —
nécessaire pour que `services/ssh_trust.py` puisse écrire `keys/known_hosts` (TOFU SSH, cf.
`docs/SECURITY.md`). Compromis assumé : la clé privée `id_ed25519` est donc aussi accessible en
écriture (elle n'a besoin que d'être lue) ; amélioration possible plus tard : séparer `known_hosts`
sur un volume dédié.

⚠️ **Compose construit une image par service**, même quand plusieurs services partagent le même
`build: ./backend` (`backend`/`worker`/`beat` ⇒ `cybervuln-backend`/`cybervuln-worker`/
`cybervuln-beat`, trois images distinctes). Après un changement de `requirements.txt` ou du
`Dockerfile`, **toujours** `docker compose build backend worker beat` **ensemble** — reconstruire
`backend` seul laisse les deux autres sur l'ancienne image (`ModuleNotFoundError` au démarrage,
constaté deux fois le 27/07/2026).

**Durcissement runtime** (session 27/07/2026) — `no-new-privileges` sur les 6 services ; `cap_drop:
[ALL]` sur `backend`/`worker`/`beat`/`frontend` uniquement (pas `db`/`redis` : leur entrypoint officiel
a besoin de capacités root — CHOWN/SETUID/SETGID — pour basculer vers un utilisateur dédié au
démarrage, même sur un volume déjà initialisé) ; `mem_limit`/`cpus` sur les 6.

⚠️ **`mem_limit` trop bas = blocage silencieux, pas un crash.** `backend` posé d'abord à `1g` puis `3g`
restait figé indéfiniment sur "Waiting for application startup" (ni erreur, ni `OOMKilled` signalé).
Cause : `STARTUP_MATCHING` (matching CVE synchrone au démarrage) pique à **~4.6GiB** avant de retomber
à ~300MiB une fois terminé — jamais mesuré avant de poser une limite. Valeurs actuelles : `backend`
`6g`/2 CPU, `worker` `6g`/1.5 CPU, `db` `1g`, `redis` `256m`, `beat` `256m`, `frontend` `512m`. À
revoir à la hausse si le référentiel CVE grossit significativement — remesurer sans limite
(`docker stats`) plutôt que d'augmenter au hasard.

⚠️ **`worker` OOMKilled le 27/07/2026** en déportant le matching CPE par actif sur Celery (cf. §
matching CPE ci-dessous) : deux tâches de matching concurrentes (~4.6GiB **chacune**, même calcul que
`STARTUP_MATCHING`) ont dépassé `mem_limit: 4g`. Cause profonde :
`multiprocessing.cpu_count()` (utilisé par Celery pour dimensionner son pool de fork) lit les CPU du
**host** (14 ici), pas le quota `cpus:` du conteneur — sans le savoir, plusieurs process de fork
tournaient en parallèle. `worker_prefetch_multiplier=1` (`tasks/scheduled_tasks.py`) limitait déjà la
réservation à une tâche par process, mais ne servait à rien tant qu'il y avait plusieurs process.
Corrigé : `--concurrency=1` explicite dans la commande du service `worker` (`docker-compose.yml`) +
`mem_limit` remonté à `6g`. Le même piège s'appliquerait à toute future tâche CPU-bound ajoutée au
worker sans revérifier cette valeur.

**Matching CPE par actif déporté sur Celery** (session 27/07/2026) — `POST /assets/{id}/scan` (et
`create_asset`/`update_asset`) appelaient `run_cpe_matching_for_asset()` de façon **bloquante** avant
de répondre : mesuré à ~30s pour un actif avec ~950 CVE déjà rattachées (parcourt tout le référentiel
CVE), rendant chaque scan perceptiblement lent côté UI. Un premier essai avec `asyncio.create_task`
dans le process API s'est révélé insuffisant : le calcul est **CPU-bound**, pas de l'I/O —
`create_task` partage la même boucle événementielle qu'uvicorn et la bloque quand même pour
**toute l'API**, pas seulement le scan concerné (backend mesuré à 99% CPU). Déporté sur le worker
Celery (`tasks.scheduled_tasks.run_cpe_matching_for_asset_task`, dispatché via `.apply_async(args=...,
queue='default')` — **pas** `.delay()` seul, qui publie sur la queue Celery par défaut `celery`,
jamais consommée par ce worker qui n'écoute que `default`). Résultat : `POST /assets/{id}/scan`
répond en ~1-3s au lieu de 34-60s ; les nouvelles vulnérabilités éventuellement révélées par le scan
n'apparaissent que quelques secondes plus tard (matching asynchrone), pas instantanément.

### Healthchecks sur les 6 services (session 27/07/2026)

Jusque-là seuls `db`/`redis` en avaient. Les 4 autres :

| Service | Test | Pourquoi |
|---------|------|----------|
| `backend` | `curl -f http://127.0.0.1:8000/api/health` | Endpoint déjà existant, jamais câblé en healthcheck |
| `worker` | `celery ... inspect ping --timeout 10` | Vérifie que le worker répond **via le broker Redis**, pas juste que le process existe (un worker déconnecté du broker resterait "running" sans ce détail) |
| `beat` | `pgrep -f 'celery.*beat'` | Pas d'endpoint HTTP — beat ne fait que planifier. Nécessite `procps` (ajouté au `Dockerfile`) |
| `frontend` | `wget --spider -q http://127.0.0.1:3000/` | Vite écoute déjà sur ce port en dev |

`start_period` généreux sur `backend` (120s) : `STARTUP_MATCHING`/`STARTUP_PATCH_CHECK` peuvent
prendre plus d'une minute, sans quoi Docker compterait des échecs "unhealthy" pendant un démarrage
pourtant normal.

⚠️ **Piège réel rencontré en testant** : `http://localhost:8000/...` (ou `:3000`) échoue par
intermittence avec `Connection refused` alors que le serveur tourne bien. Cause : `/etc/hosts` dans
les images Debian/Alpine résout `localhost` en `::1` (IPv6) **avant** `127.0.0.1` (IPv4) ; uvicorn et
Vite (`--host 0.0.0.0`) n'écoutent qu'en IPv4. `curl`/`wget` tentent l'adresse IPv6 en premier → échec
silencieux. Fix : `127.0.0.1` explicite dans les deux healthchecks, jamais `localhost`. Reproductible
en une commande : `docker compose exec frontend wget --spider http://localhost:3000/` échoue,
`http://127.0.0.1:3000/` réussit.

### Sauvegarde PostgreSQL (`services/backup.py`, session 27/07/2026)

Volume nommé `backups`, monté sur `backend` (lecture, `GET /api/backup/list`) et `worker` (écriture,
exécution du dump). `pg_dump` déclenché **toujours côté worker** via la tâche Celery
`tasks.scheduled_tasks.backup_database` — y compris le déclenchement manuel
(`POST /api/backup/run` enqueue la même tâche plutôt que d'exécuter pg_dump dans le process API), même
raisonnement que le matching CPE ci-dessus : ne jamais bloquer l'API le temps du dump.

**Client PostgreSQL 16, pas le paquet Debian générique** : `postgresql-client` sur Debian bookworm
(base de l'image `python:3.12-slim`) installe la v15, plus ancienne que le serveur (`postgres:16-alpine`)
— `pg_dump` doit être **au moins** de la version du serveur, jamais plus ancien. Le `Dockerfile` ajoute
le dépôt officiel PGDG (clé + `apt.postgresql.org`) pour installer `postgresql-client-16` exactement.
Conséquence : un changement de version majeure de l'image `db` (`postgres:17-alpine` par exemple)
nécessite de mettre à jour ce paquet en parallèle.

**Format `-Fc` (custom)** : compressé, restauration sélective possible (`pg_restore -l fichier.dump`
pour lister le contenu, `pg_restore --table=nom -d cybervuln fichier.dump` pour ne restaurer qu'une
table) — contrairement à un dump SQL texte brut (`-Fp`) qu'il faut rejouer intégralement.

**Rétention** : `BACKUP_RETENTION_DAYS` (défaut 14, `.env`) — les dumps plus anciens sont supprimés
**après** un dump réussi seulement (jamais après un échec, pour ne pas perdre la dernière sauvegarde
valide en même temps que celle qui a échoué). Planning : tous les jours à 4h (`docker-compose.yml`
§ Celery Beat ci-dessous), après les syncs nocturnes de 3h/minuit.

**Restaurer une sauvegarde** (procédure manuelle, jamais automatisée — un restore écrase des données
réelles, geste qui doit rester un choix humain explicite) :
```bash
# Lister le contenu d'un dump sans rien modifier
docker compose exec worker pg_restore -l /app/backups/cybervuln-20260727-130704.dump

# Restaurer intégralement sur une base neuve (jamais directement sur `cybervuln` en production)
docker compose exec db createdb -U cybervuln cybervuln_restore_test
docker compose exec worker pg_restore -h db -U cybervuln -d cybervuln_restore_test \
  /app/backups/cybervuln-20260727-130704.dump

# Ne restaurer qu'une seule table (ex: après une erreur manuelle sur `vulnerabilities`)
docker compose exec worker pg_restore -h db -U cybervuln -d cybervuln \
  --table=vulnerabilities --clean /app/backups/cybervuln-20260727-130704.dump
```
Vérifié en conditions réelles le 27/07/2026 : dump de 124 Mo sur la base réelle (~162k CVE), structure
validée via `pg_restore -l` (156 entrées de TOC), purge de rétention testée avec un faux fichier
antidaté.

---

## 🖥️ Prérequis matériels — serveur de production

Demandé le 12/08/2026 — préconisations pour la (les) VM qui hébergeront `docker compose up` en
continu. Dimensionnées confortablement mais **réalistes pour une demande de VM sur infra de
virtualisation existante** (VMware/Proxmox/Hyper-V, pas un serveur physique dédié) — premier jet trop
généreux pour une seule VM, recalibré le même jour après retour de l'utilisateur ("jamais mon
entreprise pourra me donner ce genre de serveur"), **puis doublé** le même jour encore une fois
précisé qu'une bascule complète en cas de panne (VM secondaire prête à prendre le relai) est prévue —
cf. § Réplication / bascule ci-dessous pour la topologie exacte et ce qui manque encore côté logiciel.

Les specs par VM ci-dessous **ne changent pas** avec la réplication (chaque nœud a besoin des mêmes
ressources, il tourne la même stack complète) — c'est le *nombre* de VM qui double, pas leur taille
individuelle. Beaucoup plus facile à faire approuver comme "deux VM standard, primaire + secours" que
comme "une VM deux fois plus grosse".

**vCPU — 8.** Les limites `cpus:` déjà posées sur les conteneurs (§ ci-dessus) totalisent à elles
seules **6,5 vCPU** rien que pour satisfaire leurs plafonds actuels (`backend` 2, `worker` 1.5, `db`
1, `redis`/`beat`/`frontend` 0.5 chacun) — 8 laisse une marge raisonnable pour l'OS hôte et les pics,
sans être un luxe. Le matching CPE (double boucle actif × CVE), les cycles de patch check, et
désormais les check-in d'agents (chaque check-in déclenche un matching CPE + un cycle de patch check
sur l'actif concerné, cf. `docs/AGENTS.md`) sont tous CPU-bound — le coût réel croît avec le nombre
d'actifs suivis, qui va grossir avec le déploiement de l'agent sur le parc de postes. Avantage d'une
VM : un vCPU insuffisant se corrige par un resize à chaud depuis la console de virtualisation, pas un
nouvel achat matériel à re-justifier.

**RAM — 32 Go recommandés, 16 Go possible avec mitigation.** Les `mem_limit` actuels totalisent déjà
**14 Go** (`backend` 6g, `worker` 6g, `db` 1g, `redis`/`beat` 256m chacun, `frontend` 512m) — et
`worker` a déjà été OOMKilled une fois en conditions réelles avant d'être remonté à 6g (§ ci-dessus,
`STARTUP_MATCHING` pique à ~4,6 GiB). Le double des plafonds actuels donne une marge confortable
(cache disque PostgreSQL, absorption de la croissance du parc) sans sur-dimensionner.

⚠️ **Si 16 Go est le plafond réel imposé par l'entreprise** (demandé le 12/08/2026) : c'est jouable,
mais serré — ne reste que ~2 Go pour l'hôte lui-même une fois les plafonds conteneurs actuels
soustraits, sans aucune marge pour en remonter un plus tard. Le risque n'est pas l'usage courant (le
backend mesuré en fonctionnement normal tourne à ~160 Mo, cf. § Performance plus bas dans ce
document) mais les **pics simultanés** (ex. sync NVD + matching CPE en même temps) — c'est exactement
ce qui avait déjà provoqué l'OOM initial. Mitigation recommandée plutôt que de compter sur la chance :
- **Swap sur la VM** (8-16 Go) + `memswap_limit` posé sur `backend`/`worker` en plus de `mem_limit`
  dans `docker-compose.yml` (ex. `mem_limit: 6g` / `memswap_limit: 8g`) — un conteneur qui dépasse
  peut déborder temporairement sur le swap au lieu d'être tué (`OOMKilled`), dégradé en performance
  le temps du pic plutôt qu'en panne. Ne protège que si `memswap_limit` est explicitement posé
  au-delà de `mem_limit` — Docker désactive le swap du conteneur par défaut sinon.
- Surveiller `docker stats` en conditions réelles après mise en prod plutôt que de se fier aux
  plafonds actuels (calibrés une fois sur la machine de développement, jamais réévalués depuis).
- Revisiter le budget RAM assez tôt si le parc d'agents grossit significativement — 16 Go laisse peu
  de marge de croissance, contrairement à 32 Go.

**Disque — 500 Go, sur un datastore/tier SSD (pas HDD).** Le tier de stockage compte plus que la
taille brute : PostgreSQL est sensible à la latence d'écriture (transactions fréquentes — historique
de statut, journal d'accès, synchronisations NVD/EPSS/veille horaires), un datastore mécanique
dégraderait tout le reste. Pas besoin de demander du RAID en plus au niveau de la VM — la plupart des
clusters de virtualisation d'entreprise ont déjà de la redondance au niveau du datastore/SAN
sous-jacent, redondant avec une demande explicite. La base fait actuellement ~1 Go mais grossit avec
les pièces jointes (incidents/audits/documents, jusqu'à 10 Mo chacune), les rapports, et la
sauvegarde quotidienne `pg_dump` (rétention 14 jours, `BACKUP_RETENTION_DAYS`) — 500 Go laisse des
années de marge même à ce rythme.

**Réseau — à revoir avant d'exposer le serveur aux agents/utilisateurs du parc.** Aujourd'hui le
backend (port 8000) est bindé `127.0.0.1` uniquement (durcissement du 03/08/2026) et seul le serveur
de dev Vite (port 3000, `npm run dev`, HMR actif) est exposé sur le réseau — pas approprié pour un
vrai serveur de production, indépendamment de sa taille. Le service `frontend-prod` existe déjà et a
été vérifié en conditions réelles (27/07/2026, cf. § ci-dessus : build nginx minifié, proxy `/api`
fonctionnel, `X-Forwarded-For` correctement transmis) — il suffit de le démarrer
(`docker compose up -d frontend-prod`) à la place du service `frontend` (dev) sur la VM de
production. **Il manque encore le TLS** : ni `frontend` (Vite dev) ni `frontend-prod` (nginx) ne
terminent HTTPS aujourd'hui — `COOKIE_SECURE=false` dans `.env.example` le confirme explicitement
("true seulement derrière un reverse-proxy TLS"). À poser avant la mise en prod (reverse proxy TLS
devant `frontend-prod`, ou configuration nginx directement dans `frontend/nginx.conf`) — sinon les
identifiants de session et les credentials d'agents circuleraient en clair sur le réseau du parc.

**OS — VM Linux (Debian/Ubuntu Server LTS), Docker Engine natif, pas Docker Desktop/WSL2.**
L'environnement de développement actuel (Windows + WSL2 + Docker Desktop) a déjà produit plusieurs
incidents opérationnels réels sans lien avec le code de l'application : un hang complet du daemon
Docker (session antérieure, cf. entrée correspondante plus bas dans ce fichier) et un deadlock de
~25 min entre deux conteneurs de build partageant un cache monté en bind (`.cargo-cache`, session du
12/08/2026, cf. `docs/AGENTS.md`) — tous deux liés à la fiabilité du verrouillage de fichiers sur les
montages bind WSL2, pas à Allsafe lui-même. Une VM Linux dédiée exécutant Docker Engine directement
élimine toute cette classe de problème — c'est déjà ce qu'implique le choix d'une VM sur l'infra de
virtualisation plutôt que de continuer sur la machine de développement.

### Réplication / bascule (VM secondaire) — ⚠️ pas encore construit, hardware seul ne suffit pas

Topologie demandée : deux VM identiques (8 vCPU / 32 Go / 500 Go SSD chacune), la seconde prête à
prendre le relai en cas de panne de la première. **Provisionner la deuxième VM ne suffit pas** —
`docker-compose.yml` aujourd'hui n'a aucune notion de "primaire"/"secondaire", tout tourne sur un
seul hôte fixe. Ce qu'il reste réellement à construire avant qu'une bascule fonctionne :

1. **Réplication PostgreSQL en streaming** (`db`, seul état qui compte vraiment — Redis ne se
   réplique pas et n'en a pas besoin : la file Celery est éphémère, une file vide au redémarrage
   relance simplement le prochain cycle planifié sans perte de données métier). Config standard
   PostgreSQL (utilisateur de réplication, `pg_hba.conf`/`postgresql.conf`, `pg_basebackup` initial
   puis flux WAL continu) — l'image `postgres:16-alpine` le supporte nativement, mais rien n'est
   configuré aujourd'hui dans ce projet.
2. **Volumes applicatifs à synchroniser vers le secondaire** (pas seulement la base) : pièces jointes
   incidents/audits/documents, sauvegardes `pg_dump`, clé SSH + `known_hosts` TOFU
   (`services/ssh_trust.py`) — sans ça, la bascule perdrait ces fichiers même avec la base à jour.
3. **Décision bascule manuelle vs automatique.** Manuelle (promouvoir le standby, démarrer sa stack
   Docker, repointer le DNS/reverse-proxy) : simple à mettre en place, RTO de quelques minutes,
   suffisant pour un premier palier. Automatique (Patroni/repmgr + un load-balancer qui détecte la
   panne) : RTO quasi nul, mais un vrai chantier d'infra à part entière — à ne considérer qu'une fois
   le palier manuel en place et éprouvé.
4. **Le reverse-proxy/TLS (§ Réseau ci-dessus) doit pointer vers le nœud actif**, pas être codé en dur
   sur l'IP de la VM primaire — sinon la bascule bouge la base mais laisse les utilisateurs/agents
   connectés à un nœud mort.

Recommandation : provisionner les deux VM maintenant (le dimensionnement ne change rien à l'ordre des
étapes), mais traiter la réplication comme un chantier logiciel séparé après la mise en prod initiale
sur la VM primaire seule — pas un prérequis bloquant au premier déploiement.

**Avant la mise en production** : penser à remonter les `mem_limit`/`cpus` du `docker-compose.yml`
pour profiter de la nouvelle VM (les valeurs actuelles sont calibrées pour la machine de
développement, pas pour laisser filer la consommation sur un serveur dédié) — remesurer avec
`docker stats` plutôt qu'augmenter au hasard, même règle que la mise en garde déjà posée plus haut
dans ce document.

---

## 📡 Endpoints API complets

```
GET  /api/health
GET  /api/stats?asset_id=uuid1,uuid2   -- KPI globaux, ou restreints à un/plusieurs actifs (CSV) si fourni
                                        -- (filtre "Actifs" du dashboard — cf. docs/FRONTEND.md)

GET  /api/cves?page=&severity=&search=&per_page=&matched_only=&days=
                                    -- matched_only=true par défaut ; days filtre sur `published`
                                    -- (pas `modified`) — une CVE publiée hors fenêtre n'apparaît pas
                                    -- même récemment mise à jour par NVD, ni via `search`
GET  /api/cves/{cve_id}

GET  /api/assets                   -- inclut vuln_count (tous statuts), package_count, hardware,
                                    -- last_scan_result, network_status (session 04/08/2026 :
                                    -- {status, last_reported_at, source} ou null si jamais rapproché
                                    -- d'un équipement Meraki — une seule requête groupée pour toute
                                    -- la liste, cf. table network_status ci-dessus)
                                    -- ⚠️ open_vuln_count (11/08/2026, bug réel corrigé) : distinct de
                                    -- vuln_count, filtré status="open" strict — même agrégat groupé
                                    -- server-side sur tout le parc. Assets.jsx recalculait ce compte
                                    -- côté client depuis une liste plafonnée à 200 lignes triée par
                                    -- score sur tout le parc, faux pour la quasi-totalité des actifs
                                    -- (cf. STATUS.md § Tour complet).
POST /api/assets                   -- ajout manuel (source="manual") ; dérive cpe_list depuis OS/Version
                                    -- si vide, puis lance le matching CVE pour cet actif (cf. MATCHING.md)
PUT  /api/assets/{id}               -- idem : re-dérive cpe_list + relance le matching si nécessaire
                                     -- + recalculate_scores_for_asset() si `tags` a changé (session
                                     -- 27/07/2026) — sinon un changement de `tags.criticite` reste
                                     -- invisible sur risk_score tant qu'un scan/sync NVD ne
                                     -- redéclenche pas un recalcul (cf. `docs/MATCHING.md` § Scoring)
DEL  /api/assets/{id}               -- cascade : supprime aussi les vulnérabilités liées (pas de ON DELETE CASCADE en DB)
POST /api/assets/{id}/scan          -- scan read-only WinRM/SSH (fiabilité + apps + hardware) ; corrige
                                    -- hostname/name/os_version si écart détecté ; reconstruit cpe_list
                                    -- depuis l'OS détecté et relance le matching CVE. 400 si
                                    -- collection_method != "service_account" (13/08/2026 — un actif
                                    -- agent/vsphere_api n'est pas scanné par ce chemin, cf. § vSphere)
GET  /api/assets/{id}/packages      -- applications installées + hardware, depuis le dernier scan (sans en relancer un)
POST /api/assets/network-protocol-check/run  -- test TCP passif Telnet/HTTP sur asset_type="network"
                                    -- (switches/pare-feux PRTG/Meraki), lecture seule, écrit
                                    -- Asset.network_compliance (cf. services/network_protocol_check.py)
POST /api/assets/switch-hardening/run  -- durcissement Cisco IOS/IOS-XE (SSH credentialed, lecture
                                    -- seule, 13/08/2026) sur asset_type="network" + scan_username
                                    -- défini ; fusionne dans Asset.network_compliance (ne l'écrase
                                    -- pas) et met à jour Asset.last_scan (cf. § Durcissement switches)

GET  /api/vulnerabilities?asset_id=&status=&severity=&validated_by=&search=&max_age_years=&sort_by=&sort_dir=&page=
                                    -- status : open / in_progress / patched / accepted_risk /
                                    -- awaiting_fix / awaiting_fix_partial / false_positive
                                    -- search (session 24/07/2026) : recherche sur l'identifiant CVE
                                    -- (CVE.cve_id ILIKE %search%). Cible une CVE précise sans dépendre du
                                    -- tri/plafond des listes du Dashboard (une CVE LOW auto-patchée est hors
                                    -- des premières pages triées par score). Utilisé par : le champ de
                                    -- recherche CVE de Vulnerabilities.jsx, la recherche SERVEUR de la
                                    -- section "Vulnérabilités traitées" du Dashboard, et le clic d'une CVE
                                    -- de bascule (cloche 🔔 / bandeau) qui ouvre son justificatif en modale
                                    -- max_age_years (session 20/07/2026) : masque les CVE publiées il y a
                                    -- plus de N ans — filtre d'affichage réversible uniquement (checkbox
                                    -- "Masquer les CVE > 2 ans" sur Vulnerabilities.jsx), ne touche jamais
                                    -- à la collecte/au matching — cf. incident CVE-2022-30190 : couper à
                                    -- la collecte aurait recréé le trou qu'on venait de combler
                                    -- réponse (_vuln_dict) inclut aussi patch_check_details (session
                                    -- 21/07/2026) : texte du dernier patch check, justifie un `patched`
                                    -- + asset.criticite (session 04/08/2026, asset.tags.criticite,
                                    -- même donnée que la page Actifs) + resolved_elsewhere_count/
                                    -- patched_elsewhere_count (session 04/08/2026) : combien
                                    -- d'instances de la même CVE sont déjà dans un état terminal sur
                                    -- d'autres actifs — une seule requête GROUP BY par page affichée,
                                    -- jamais une par ligne. Alimente le badge "Correctif déjà
                                    -- appliqué ailleurs" (Vulnerabilities.jsx/Dashboard.jsx) et le
                                    -- filtre dédié du Dashboard
POST /api/vulnerabilities
PATCH /api/vulnerabilities/{id}    body: {status, validated_by, notes, risk_score, accepted_risk_until}
                                    -- accepted_risk_until (session 27/07/2026) : requis (400 sinon,
                                    -- comme notes/validated_by) quand status="accepted_risk"

GET  /api/vulnerabilities/awaiting-fix-candidates
                                    -- CVE ouvertes sans correctif publié par la distro
                                    -- (`no_fix_available`, statut « open » du tracker Debian pour
                                    -- TOUS les paquets concernés — les cas mixtes sont exclus par
                                    -- construction). En pratique surtout des CRITICAL, les autres
                                    -- sévérités étant déjà basculées automatiquement.
POST /api/vulnerabilities/bulk-awaiting-fix     body: {vuln_ids, validated_by, notes}
                                    -- passage groupé en `awaiting_fix` ; annotation ET analyste
                                    -- obligatoires (400 sinon), chaque id revérifié côté serveur
GET  /api/vulnerabilities/false-positive-candidates
                                    -- CVE ouvertes ne concernant pas réellement l'actif, 2 motifs
                                    -- objectifs : `matching_invalide` (le rattachement ne serait plus
                                    -- créé par les règles actuelles) et `produit_absent` (aucun paquet
                                    -- visé n'est installé). Liste seulement, ne modifie rien.
POST /api/vulnerabilities/bulk-false-positive   body: {vuln_ids, validated_by, notes}
                                    -- qualification groupée en `false_positive` ; annotation ET
                                    -- analyste obligatoires (400 sinon), chaque id revérifié côté
                                    -- serveur avant application
GET  /api/vulnerabilities/critical-review-candidates
                                    -- CVE CRITICAL ouvertes avec un signal de patch check positif
                                    -- (patch_detected ou date_heuristic), triées signal formel puis
                                    -- ancienneté > 1 an — ne bascule rien, liste seulement (session
                                    -- 21/07/2026, cf. STATUS.md)
POST /api/vulnerabilities/bulk-validate    body: {vuln_ids, validated_by}
                                    -- valide en masse des CRITICAL déjà signalés par critical-review-
                                    -- candidates — revérifie côté serveur (CRITICAL + signal positif)
                                    -- avant bascule, ignore sinon (renvoyé dans `skipped`)
POST /api/vulnerabilities/bulk-patch        body: {vuln_ids, validated_by, notes?}
                                    -- même geste que le "✓ Corrigé" unitaire, répété sur la sélection —
                                    -- aucune restriction de sévérité, action manuelle explicite comme
                                    -- ligne par ligne (à ne pas confondre avec bulk-validate ci-dessus).
                                    -- `notes` optionnel (22/07/2026, cf. STATUS.md) : contrairement à
                                    -- bulk-false-positive/bulk-awaiting-fix, l'annotation reste facultative
POST /api/vulnerabilities/bulk-accepted-risk    body: {vuln_ids, validated_by, notes, accepted_risk_until}
                                    -- passage groupé en `accepted_risk` (session 27/07/2026) ; les 3
                                    -- champs sont obligatoires (400 sinon). Aucune restriction de
                                    -- sévérité/signal technique (comme bulk-patch) : décision humaine
                                    -- pure, pas de liste de "candidats" objective possible pour ce statut
GET  /api/vulnerabilities/{id}/status-history
                                    -- historique des transitions de statut (session 27/07/2026),
                                    -- tri changed_at DESC — prospectif, cf. table
                                    -- vulnerability_status_history ci-dessus
GET  /api/vulnerabilities/{id}/other-instances
                                    -- autres instances de la même CVE sur d'autres actifs (session
                                    -- 04/08/2026, demande explicite : retrouver le diagnostic/la
                                    -- justification déjà posés ailleurs sans redemander les mêmes
                                    -- infos sur la CVE). Résolues (patched/false_positive/
                                    -- accepted_risk) en premier, chacune avec validated_by/notes/
                                    -- patch_check_details. Lecture seule, pas de pagination (le
                                    -- nombre d'actifs par CVE reste borné à la taille du parc)
GET  /api/vulnerabilities/auto-bascule-summary  ?since=<ISO>
                                    -- vulns basculées AUTOMATIQUEMENT (validated_by="Auto (patch
                                    -- check)") en patched/false_positive depuis `since` — jamais les
                                    -- validations manuelles. Alimente le bandeau "depuis votre
                                    -- dernière visite" du Dashboard (22/07/2026) : le cycle autonome
                                    -- tourne aussi la nuit (toutes les 6h), sans authentification
                                    -- `since` vient du localStorage client, pas d'une session serveur

GET  /api/reports/weekly           ?kind=cve|veille|surveillance&asset_id=uuid1,uuid2
                                    -- archives hebdomadaires figées, plus récente d'abord.
                                    -- sans asset_id : rapports du parc entier uniquement (sinon
                                    -- chaque semaine apparaîtrait autant de fois qu'il y a d'actifs)
                                    -- `complete=false` = semaine encore en cours à la génération
GET  /api/reports/weekly/{id}      -- rapport figé complet (summary markdown + stats + activity)
POST /api/reports/weekly/generate  ?kind=cve&iso_year=&iso_week=&asset_id=&force=&generated_by=
                                    -- `asset_id` limite le rapport à un actif ; absent = tout le parc
                                    -- sans année/semaine : dernière semaine ISO complète (idem tâche
                                    -- planifiée). `created=false` = rapport déjà figé, non réécrit.
                                    -- 501 si le contenu du type demandé n'est pas encore implémenté
GET  /api/reports/weekly/{id}/csv  -- export CSV de l'activité figée (depuis le snapshot, jamais
                                    -- depuis l'état courant de la base)

POST /api/analysis/cve             body: {cve_id, asset_id}

POST /api/remediation/recommend    body: {vuln_id}
POST /api/remediation/script       body: {vuln_id}
GET  /api/remediation/{vuln_id}

GET  /api/reports/csv?asset_id=uuid1,uuid2   -- backlog courant (status != patched), CSV filtrable par actif
GET  /api/reports/inventory/pdf              -- export PDF du module Inventaire (session 28/07/2026,
                                              -- cf. § Export PDF Inventaire) : tableau récapitulatif de
                                              -- tous les actifs + détail des apps par actif. Pas de
                                              -- filtre asset_id (contrairement au CSV ci-dessus) — export
                                              -- global uniquement, cohérent avec le bouton frontend.
POST /api/reports/executive-summary          body: {period_days, asset_id} — les deux optionnels ;
                                              -- period_days ajoute une section "Ce qui a été fait"
                                              -- (corrigées/en attente/faux positifs/détectées sur la
                                              -- période) en plus de l'état actuel (cf. MATCHING.md
                                              -- pour le détail des statuts awaiting_fix/false_positive)

POST /api/sync/nvd?days=7
POST /api/sync/nvd/{cve_id}         -- rattrapage ponctuel d'une CVE précise, ignore le curseur incrémental (cf. § Incident)
POST /api/sync/nvd-backfill         -- rattrapage complet des CVE NVD applicables aux CPE du parc (fetch_by_cpe), peut prendre plusieurs minutes
POST /api/sync/assets
POST /api/sync/match                -- réponse inclut `synced_at` (cf. table `sync_state`, clé `cpe_match`)
GET  /api/sync/match-status          -- {"last_synced_at"} — lu au chargement page Dashboard (bouton "Matching CVE")
GET  /api/sync/status/{task_id}

POST /api/patch-check/{vuln_id}?force=    -- check read-only unique ; auto-bascule patched si non-CRITICAL (cf. CLAUDE.md)
                                    -- si le dernier contrôle date de moins de MIN_RECHECK_GAP (30s,
                                    -- session 21/07/2026), renvoie ce résultat en cache (`cached: true`,
                                    -- `cached_age_seconds`) sans resolliciter l'actif — force=true l'ignore
GET  /api/patch-check/status       -- current / last_completed / checked / pending / running / assets /
                                    -- started_at / last_cycle_status / last_cycle_at — pour polling dashboard
                                    -- ("pending" inclut open/in_progress/awaiting_fix jamais vérifiés
                                    -- ou dont le dernier check date de plus de RECHECK_INTERVAL, 24h).
                                    -- ⚠️ "running" (11/08/2026, bug corrigé) est le SEUL signal fiable
                                    -- de cycle actif — "pending" est un décompte de backlog, quasi
                                    -- toujours > 0 sur un vrai parc, ne pas le réutiliser comme signal
                                    -- d'activité (cf. docs/FRONTEND.md § tour visuel)
GET  /api/patch-check/asset-completions  ?since=<ISO>  -- pendant de auto-bascule-summary ci-dessous, mais
                                    -- pour la notification "actif terminé" du Dashboard (11/08/2026) :
                                    -- actifs ayant fini une passe de contrôle depuis `since`, avec
                                    -- checked_count/auto_bascule_count. Table dédiée
                                    -- (patch_check_asset_completions, sans FK sur asset_id — snapshot
                                    -- texte, survit à la suppression de l'actif), écrite une fois par
                                    -- actif par services/patch_checker.py::record_asset_completion.
                                    -- Endpoint séparé de auto-bascule-summary à dessein (fusion faite
                                    -- côté frontend seulement, cf. docs/FRONTEND.md) : ce dernier
                                    -- alimente aussi le bandeau "depuis votre dernière visite" et
                                    -- WelcomeOverlay, tous deux écrits pour un format de ligne CVE
POST /api/patch-check/run?force=   -- relance le cycle complet (rattrapage + check des vulns jamais/plus
                                    -- assez récemment vérifiées), tâche de fond, protégé contre
                                    -- l'exécution concurrente
                                    -- force=true (session 21/07/2026) : efface d'abord last_patch_check
                                    -- sur toutes les vulns ouvertes pour lever le garde-fou
                                    -- RECHECK_INTERVAL (24h) — à utiliser après l'amélioration d'un
                                    -- signal de détection, sinon le stock déjà contrôlé garde un
                                    -- résultat calculé par l'ancienne logique. Ne touche ni les
                                    -- statuts, ni les validateurs, ni les rapports déjà stockés.

GET  /api/connections               -- 500 dernières connexions IP tracées. Réservé admin (30/07/2026)
POST /api/connections               -- PUBLIC (journal d'accès, cf. § Authentification ci-dessus)

GET  /api/watch?...                 -- module Veille cyber NIS 2 + Fuite de données, détail complet dans docs/VEILLE.md
GET  /api/watch/sync-status         -- {"last_synced_at"} — cf. table `sync_state`, clé `watch` ; réponse de
                                     -- POST /api/watch/sync inclut aussi `synced_at`
POST /api/watch/recompute-themes    -- recalcule `themes` de tous les items déjà en base (règles actuelles) —
                                     -- à relancer après ajout/modif d'un thème ou mot-clé, cf. docs/VEILLE.md § 3
GET  /api/watch/profile             -- profil de veille : termes enregistrés + suggestions issues de
                                    -- l'inventaire (OS des actifs + applications installées), chacune
                                    -- portant les actifs où elle a été vue et un `selected`
PUT  /api/watch/profile             body: {items: [{kind: os|software, value, origin}]}
                                    -- remplace le profil complet (la modale envoie l'état final des
                                    -- cases cochées, pas un diff)
GET  /api/watch?profile_only=true   -- ne garde que les éléments correspondant au profil. Pagination
                                    -- calculée en Python (correspondance textuelle, non exprimable
                                    -- en SQL) — `total` reste exact
GET  /api/watch/leak-sources        -- slugs à traiter comme "fuite" (natives + WatchSource category=leak)
GET  /api/watch/sources?category=   -- liste des sources personnalisées (WatchSource), filtrable general|leak
POST /api/watch/sources             body: {name, url, feed_type, category, country}
PATCH /api/watch/sources/{id}       -- édition (nom/url/format/pays/enabled) ; category non modifiable après création
DEL  /api/watch/sources/{id}        -- arrête la collecte future, conserve les items déjà importés

GET  /api/identities                -- identités surveillées (Surveillance Identités), cf. docs/VEILLE.md
POST /api/identities                body: {value, kind} — kind : name | domain | ip | ip_range
                                     -- (ip/ip_range validés + normalisés via le module `ipaddress`, 400 si invalide)
DEL  /api/identities/{id}
GET  /api/identities/matches        -- {total, items[], identities_count, ip_total, ip_matches[]} —
                                     -- items : fuites mentionnant name/domain (croisement texte à la volée)
                                     -- ip_matches : IP/plages sur des listes de blocage tierces (cf. VEILLE.md § 9ter)

GET  /api/backup/list               -- sauvegardes présentes sur le volume, la plus récente d'abord
POST /api/backup/run                -- déclenche un pg_dump immédiat sur le worker (enqueue Celery,
                                     -- ne bloque jamais l'API) — suivre via GET /api/sync/status/{task_id}

GET  /api/security/events?unack_only=&limit=   -- journal des accès aux objets leurres (déception DB),
                                     -- le plus récent d'abord. Réservé admin
GET  /api/security/events/count     -- {unacknowledged, latest} — compteur léger pour la bannière
                                     -- Dashboard, ouvert à tout connecté (le détail reste admin)
POST /api/security/events/{id}/ack        body: {ack_by?}   -- réservé admin, n'efface jamais la ligne
POST /api/security/events/ack-all         body: {ack_by?}   -- réservé admin

POST /api/withsecure/run            -- sync manuelle EDR/EPP → Vulnerability (missing-updates Windows
                                     -- uniquement, lecture seule). "withsecure_not_configured" si
                                     -- WITHSECURE_API_CLIENT_ID/SECRET absents de .env
GET  /api/withsecure/status         -- {"last_synced_at"}, même mécanisme que /api/sync/match-status

POST /api/meraki/run?import_new_assets=   -- sync manuelle équipements Meraki → NetworkStatus
                                     -- (état en ligne/hors ligne), lecture seule côté Meraki.
                                     -- "meraki_not_configured" si MERAKI_API_KEY absente de .env.
                                     -- import_new_assets=true (défaut false, session 04/08/2026) :
                                     -- crée un Asset (asset_type="network", source="meraki") pour
                                     -- chaque équipement sans correspondance, au lieu de le laisser
                                     -- invisible — cf. table network_status ci-dessus
GET  /api/meraki/status             -- {"last_synced_at"}, même mécanisme que /api/withsecure/status

POST /api/vsphere/run?import_new_assets=  -- sync manuelle hôtes ESXi (via vCenter) → Asset + CPE
                                     -- vSphere/ESXi, lecture seule côté vCenter (13/08/2026).
                                     -- "vsphere_not_configured" si VCENTER_URL/USER/PASSWORD absents
                                     -- de .env. import_new_assets=true (défaut false) : crée un Asset
                                     -- (asset_type="server", source="vsphere",
                                     -- collection_method="vsphere_api") pour chaque hôte sans
                                     -- correspondance — cf. § Intégration vSphere / ESXi ci-dessus
GET  /api/vsphere/status            -- {"last_synced_at"}, même mécanisme que /api/meraki/status

GET  /api/incidents?status=&severity=&category=&requires_notification=&overdue_only=&asset_id=&q=&page=&per_page=
                                     -- registre incidents (module Incidents, cf. docs/INCIDENTS.md)
GET  /api/incidents/nis2/pending-count    -- {overdue, imminent} — jalons NIS 2 non envoyés,
                                     -- dépassés ou < 24h ; badge sidebar
GET  /api/incidents/export          -- export CSV auditeur (registre complet)
GET  /api/incidents/prefill?source_type=&source_id=
                                     -- lecture seule, préremplit la modale de création — ne crée
                                     -- jamais rien. source_type : security_event | vulnerability |
                                     -- watch_item | audit_finding (03/08/2026, module Audits)
GET    /api/incidents/notification-contacts
POST   /api/incidents/notification-contacts     body: {name, role?, email?, phone?, website_url?, categories?, notes?}
PATCH  /api/incidents/notification-contacts/{id}
DEL    /api/incidents/notification-contacts/{id}
GET    /api/incidents/{id}
DEL    /api/incidents/{id}
POST   /api/incidents                body: {title, category, severity, status?, detected_at?, aware_at,
                                     -- reported_by, affected_asset_ids?, security_event_id?,
                                     -- vulnerability_id?, watch_item_id?, audit_finding_id?}
                                     -- ⚠️ requires_notification/*_sent_at absents du schéma : Pydantic
                                     -- les ignore silencieusement, seuls les endpoints dédiés
                                     -- ci-dessous peuvent les poser
PATCH  /api/incidents/{id}           body: {title?, description?, category?, severity?, status?,
                                     -- detected_at?, reported_by?, affected_asset_ids?, completed_response_steps?}
GET    /api/incidents/{id}/timeline
GET    /api/incidents/{id}/report    -- markdown généré à la demande, jamais persisté (docs/INCIDENTS.md § 7)
POST   /api/incidents/{id}/notes                    body: {author, notes}
POST   /api/incidents/{id}/qualify-notification     body: {analyst, justification}   -- justification obligatoire
POST   /api/incidents/{id}/unqualify-notification   body: {analyst, reason}
POST   /api/incidents/{id}/aware-at                 body: {new_aware_at, analyst, recompute?}
                                     -- verrouillé (409) dès qu'un jalon a été marqué envoyé
POST   /api/incidents/{id}/milestones/{milestone}/mark-sent   body: {sent_by, sent_at?, note?}
GET    /api/incidents/{id}/attachments
POST   /api/incidents/{id}/attachments    multipart: {file, uploaded_by, milestone?}   -- PDF 5 Mo max
GET    /api/incidents/{id}/attachments/{attachment_id}/download
DEL    /api/incidents/{id}/attachments/{attachment_id}

GET    /api/crises/contacts
POST   /api/crises/contacts          body: {name, role?, email?, phone?, website_url?, notes?}
PATCH  /api/crises/contacts/{id}
DEL    /api/crises/contacts/{id}
GET    /api/crises?status=&q=
GET    /api/crises/{id}
POST   /api/crises                   body: {title, description?, activated_by}   -- statut toujours "active"
PATCH  /api/crises/{id}              body: {title?, description?, completed_crisis_steps?}
DEL    /api/crises/{id}              -- incidents liés repassent crisis_id=NULL (ON DELETE SET NULL),
                                     -- jamais supprimés
GET    /api/crises/{id}/timeline
POST   /api/crises/{id}/stand-down          body: {analyst, justification}
POST   /api/crises/{id}/roles               body: {role, analyst_name, by}
DEL    /api/crises/{id}/roles/{role}?by=
POST   /api/crises/{id}/incidents           body: {incident_id, by}
DEL    /api/crises/{id}/incidents/{incident_id}?by=
POST   /api/crises/{id}/decisions           body: {author, content}
POST   /api/crises/{id}/communications      body: {author, content, audience}   -- audience: interne|externe

GET    /api/analysts                -- registre des analystes (session 29/07/2026, cf. models.py::Analyst)
                                     -- remplace la liste ANALYSTS codée en dur. Ouvert à tout connecté
POST   /api/analysts                body: {name}   -- réservé admin (30/07/2026)
PATCH  /api/analysts/{id}           body: {name?}  -- réservé admin
DEL    /api/analysts/{id}                          -- réservé admin

GET    /api/organization-roles      -- registre « Rôles » (poste -> personne -> email), résout
                                     -- service_name/service_color et reports_to_name/position à
                                     -- la lecture. Ouvert à tout connecté
POST   /api/organization-roles      body: {position, name, email?, service_id?, reports_to_id?}
                                     -- réservé admin ; reports_to_id protégé contre les cycles
PATCH  /api/organization-roles/{id}  body: {position?, name?, email?, service_id?, clear_service?,
                                     -- reports_to_id?, clear_reports_to?}   -- réservé admin
DEL    /api/organization-roles/{id}                -- réservé admin

GET    /api/services                -- registre Services/départements (RH, DSI...), ouvert à tout connecté
POST   /api/services                body: {name, color, icon?}    -- réservé admin
PATCH  /api/services/{id}           body: {name?, color?, icon?}  -- réservé admin
DEL    /api/services/{id}                          -- réservé admin, détache les postes rattachés (SET NULL)

GET    /api/document-types          -- module Documentation, registre ouvert des types (PSSI, chartes...)
POST   /api/document-types          body: {name}    -- réservé admin
PATCH  /api/document-types/{id}     body: {name?}   -- réservé admin
DEL    /api/document-types/{id}                     -- réservé admin ; 409 si des documents y sont rattachés
GET    /api/documents?document_type_id=       -- fichiers uploadés, plus récent d'abord (= l'historique)
POST   /api/documents               multipart: {file, document_type_id, uploaded_by, notes?}
                                     -- réservé admin ; PDF/Word/Excel/PNG/JPEG, 10 Mo max,
                                     -- signature de fichier vérifiée
GET    /api/documents/{id}/download            -- Content-Disposition inline pour PDF/PNG/JPEG, sinon attachment
DEL    /api/documents/{id}                             -- réservé admin

GET    /api/windows-app-mappings    -- correspondance nom d'appli Windows -> produit CPE, ouvert à tout connecté
POST   /api/windows-app-mappings    body: {pattern, cpe_product, cpe_vendor?}   -- réservé admin, 409 si motif déjà mappé
PATCH  /api/windows-app-mappings/{id}
DEL    /api/windows-app-mappings/{id}                  -- réservé admin

POST /api/auth/login                body: {email, password} -- PUBLIC. Verrou anti-bruteforce,
                                     -- pose le cookie de session HttpOnly. Message d'erreur générique
                                     -- (401) qu'il s'agisse d'un mauvais mot de passe ou d'un compte
                                     -- inexistant. 429 si verrou anti-bruteforce déclenché.
POST /api/auth/logout               -- supprime la session serveur + efface le cookie
GET  /api/auth/me                   -- utilisateur courant (id/email/full_name/role/must_change_password)
POST /api/auth/change-password      body: {current_password, new_password}
                                     -- validate_password_strength() : 16 car. + majuscule/minuscule/
                                     -- chiffre/spécial (14/08/2026, cf. § Authentification ci-dessus)
PATCH  /api/auth/change-email       body: {current_password, new_email}   -- 14/08/2026, self-service
GET    /api/auth/sessions           -- sessions actives du compte connecté, is_current inclus
DEL    /api/auth/sessions/{id}      -- 400 si c'est la session courante (utiliser /logout à la place)

GET    /api/users                   -- réservé admin. CRUD des comptes (session 30/07/2026)
POST   /api/users                   body: {email, full_name, password, role}
PATCH  /api/users/{id}              body: {email?, full_name?, role?, is_active?, force_password_reset?}
                                     -- email modifiable (30/07/2026, contrôle d'unicité serveur) —
                                     -- si le compte modifié est celui de l'admin connecté, le
                                     -- frontend doit rafraîchir AuthContext (cf. FRONTEND.md)
DEL    /api/users/{id}
POST   /api/users/{id}/revoke-sessions  -- invalide toutes les sessions actives de ce compte

GET    /api/audits?status=&type=&q=&page=&per_page=    -- module Audits (03/08/2026, cf. docs/AUDITS.md)
                                     -- réponse par audit : findings_total/findings_by_severity/
                                     -- findings_open/findings_unretested_closed (compteurs agrégés)
GET    /api/audits/findings?asset_id=          -- findings d'un actif, alimente sa fiche (ScanResultModal.jsx)
GET    /api/audits/findings/open-unretested-count      -- {count} : findings ouverts sur un audit
                                     -- `termine`, jamais retestés — badge Dashboard
POST   /api/audits                  body: {title, type, methodology?, referential?, conducted_by?,
                                     -- started_at?, ended_at?, asset_ids?}   -- statut initial "cadrage"
GET    /api/audits/{id}
PATCH  /api/audits/{id}             body: {title?, type?, methodology?, referential?, status?,
                                     -- conducted_by?, started_at?, ended_at?, executive_summary?}
                                     -- ⚠️ status="cadrage"/"autorise" rejetés (400) : l'autorisation ne
                                     -- passe que par POST .../authorize ; toute transition tant que
                                     -- l'audit est "cadrage" est bloquée (403)
DEL    /api/audits/{id}             -- cascade findings/historique/pièces jointes
POST   /api/audits/{id}/authorize   body: {scope, rules_of_engagement, authorized_by, authorized_at}
                                     -- garde-fou central : 409 si déjà autorisé (champs immuables),
                                     -- 400 si un champ est vide. Passe le statut à "autorise"
POST   /api/audits/{id}/assets/{asset_id}     -- lie un actif déjà connu d'Allsafe (pas de saisie libre)
DEL    /api/audits/{id}/assets/{asset_id}
GET    /api/audits/{id}/findings
POST   /api/audits/{id}/findings    body: {author, title, severity, description?, cvss_vector?,
                                     -- cvss_score?, cwe_id?, owasp_ref?, affected_asset_id?,
                                     -- affected_component?, cve_id?, proof_of_concept?, impact?,
                                     -- recommendation?, status?, mitre_techniques?, discovered_at?}
                                     -- 403 si l'audit est encore "cadrage" (garde-fou central du module)
PATCH  /api/audits/{id}/findings/{finding_id}    -- `author` requis si `status` change (traçabilité
                                     -- de la transition dans audit_finding_history)
DEL    /api/audits/{id}/findings/{finding_id}
POST   /api/audits/{id}/findings/{finding_id}/retest   body: {retest_result, retested_by, retested_at?}
GET    /api/audits/{id}/findings/{finding_id}/history
GET    /api/audits/{id}/attachments            -- mandat(s) écrit(s) de l'audit
POST   /api/audits/{id}/attachments            multipart: {file, uploaded_by}   -- PDF/PNG/JPEG, 5 Mo max
GET    /api/audits/{id}/findings/{finding_id}/attachments   -- preuves du finding (captures d'écran)
POST   /api/audits/{id}/findings/{finding_id}/attachments   multipart: {file, uploaded_by}
GET    /api/audits/{id}/attachments/{attachment_id}/download  -- sert mandat ou preuve indifféremment
DEL    /api/audits/{id}/attachments/{attachment_id}
GET    /api/audits/{id}/report      -- markdown généré à la demande, jamais persisté (cf. incidents)
```

---

## 🔌 Connexion base de données — `NullPool`

`database.py` utilise `poolclass=NullPool` (pas de pool de connexions persistant). Nécessaire car les
tâches Celery (`nvd_fetcher`, `rss_fetcher`, `watch_fetcher`, `patch_checker`) ouvrent chacune une
boucle asyncio différente via `asyncio.run(...)`. Un pool de connexions persistant survit à la fermeture
de la boucle qui l'a créé et provoque `cannot perform operation: another operation is in progress` en
cascade dès qu'une connexion est réutilisée depuis une nouvelle boucle — bug rencontré en production
(sync NVD passée de 682 créées/0 erreur à 0 créée/2300 erreurs après un simple incident réseau NVD).
Coût : une connexion Postgres ouverte par requête plutôt que réutilisée — négligeable vu le volume
(80 VM, usage interne).

**Note** : `backend/routers.py` (fichier plat à la racine) a été supprimé — c'était du code mort jamais
importé (`main.py` importe le package `backend/routers/`, qui prend le dessus sur un fichier de même nom).

---

## 🔍 Contrôle automatique des correctifs (patch check)

Au démarrage du backend (`main.py` → `lifespan`), un cycle tourne en tâche de fond (non bloquant) :

1. **Rattrapage** (`backfill_auto_patch`) — réapplique la règle de bascule aux vulns déjà contrôlées
   dont le résultat n'a jamais été réconcilié (DB uniquement, aucun appel réseau serveur).
2. **Contrôle** (`run_startup_patch_checks`) — vérifie séquentiellement (WinRM/SSH read-only) les vulns
   jamais contrôlées (`last_patch_check IS NULL`).

Règle (détail complet dans `CLAUDE.md` § Non-intervention) :
- **CRITICAL** → signalement seul, l'analyste valide manuellement (jamais de bascule automatique).
- **HIGH / MEDIUM / LOW** → bascule automatique en `patched` si `patch_detected: true`
  (`validated_by = "Auto (patch check)"`).

Le même cycle est réutilisable manuellement via `POST /api/patch-check/run` (bouton "Patch check global"
sur le dashboard) — protégé par un verrou (`_cycle_running`) contre l'exécution concurrente.

L'avancement en direct (machine en cours d'analyse, dernier résultat, restant à vérifier) est exposé via
`GET /api/patch-check/status`, avec un horodatage `checked_at` par complétion pour permettre au frontend
de dédupliquer précisément deux vérifications successives d'une même vuln (ex : réouverte puis re-checkée).

**Cycle vraiment autonome — `RECHECK_INTERVAL`** : une vuln déjà contrôlée est revérifiée automatiquement
après 24h (pas seulement si jamais contrôlée) — sans ça, un correctif appliqué après le premier check
(Linux notamment, cf. Debian Security Tracker ci-dessous) ne serait plus jamais revu. Le cycle tourne
aussi tout seul via la tâche Celery `patch_check_periodic` (toutes les 6h, cf. planning ci-dessous), qui
déclenche `POST /api/patch-check/run` **via HTTP vers le process `backend`** plutôt que d'appeler le
service directement depuis le `worker` — l'état d'avancement (`_cycle_running`, `_current_check`) vit en
mémoire dans le process FastAPI unique, l'invoquer depuis un autre process casserait le suivi et le
verrou anti-concurrence.

**Détection Windows vs Linux** : Windows compare les KB installés (Event Log + WMI + PSWindowsUpdate) aux
KB associés à la CVE (NVD + API MSRC). Linux compare la version de paquet installée (`dpkg-query`) à la
version corrigée du **Debian Security Tracker** (fiable y compris backports et noyau — NVD ne publie que
les versions corrigées *amont*, que Debian ne suit pas forcément), avec repli sur les plages de versions
NVD pour les distros non-Debian ou CVE inconnues du tracker. Détail complet (comparaison de version,
piège Secure Boot, limites) dans `docs/MATCHING.md` § Patch checker.

---

**Actifs concernés par un élément de veille** (`watch_items.asset_ids`, 22/07/2026) : liste d'UUID en
JSON, renseignée à la main par l'analyste dans la modale de traitement (Veille technologique). Même
approche que `themes`/`cve_ids_found` plutôt qu'une table de liaison — quelques actifs par item, sur
des items traités un par un.
- Les **noms ne sont pas stockés** : ils sont résolus à la lecture depuis `assets` (`_asset_names`,
  une seule requête pour toute la page), donc un actif renommé l'est partout et un actif supprimé
  disparaît simplement de la liste au lieu de laisser un nom fantôme.
- `PATCH /api/watch/{id}` **filtre les ids inexistants** avant écriture : un actif supprimé entre
  l'ouverture de la modale et l'enregistrement ne doit pas se retrouver en base.
- `asset_ids: null` (champ absent) laisse la sélection inchangée, `[]` l'efface — sans cette
  distinction, tout PATCH partiel (changer le statut seul) effacerait les actifs.
- Repris dans l'export CSV du registre et dans le rapport hebdomadaire de veille (colonne
  « Actifs concernés » de la section « Décisions consignées »).

⚠️ **Colonne ajoutée sur une base existante** (pas de migration automatique) :
```sql
ALTER TABLE watch_items ADD COLUMN IF NOT EXISTS asset_ids JSON DEFAULT '[]'::json;
```

### Table `watch_profile`
```sql
id         UUID PRIMARY KEY
kind       VARCHAR NOT NULL   -- os | software | application | firewall | saas | hardware
                                --   (PROFILE_CATEGORIES, services/watch_profile.py — seule source
                                --   de vérité, extensible sans migration : `kind` est un String libre)
value      VARCHAR NOT NULL   -- "Debian", "openssl"…
origin     VARCHAR            -- inventory (proposé depuis le parc) | manual
enabled    BOOLEAN
created_at TIMESTAMP WITH TZ
UNIQUE (kind, value)
```
Profil de veille — **marque** les éléments concernant le parc, ne filtre jamais la collecte ni le
registre NIS 2. Table créée automatiquement (`create_all`), aucun `ALTER` manuel. Détail et choix de
conception : `docs/VEILLE.md` § Profil de veille.

### Table `reports`
```sql
id           UUID PRIMARY KEY
kind         VARCHAR NOT NULL   -- cve / veille / surveillance
label        VARCHAR NOT NULL   -- "S30/2026"
iso_year     INTEGER NOT NULL   -- année ISO (peut différer de l'année de period_start)
iso_week     INTEGER NOT NULL
period_start TIMESTAMP WITH TZ  -- lundi 00:00 UTC (inclus)
period_end   TIMESTAMP WITH TZ  -- lundi suivant 00:00 UTC (exclu)
generated_at TIMESTAMP WITH TZ
generated_by VARCHAR            -- "Auto (hebdomadaire)" / "Manuel"
summary      TEXT               -- markdown figé
stats        JSONB              -- KPI figés
activity     JSONB              -- {patched, awaiting_fix, false_positive, detected}
asset_id     UUID FK → assets   -- NULL = tout le parc, sinon rapport d'un actif
asset_label  VARCHAR            -- nom figé de l'actif (survit à un renommage/suppression)
UNIQUE (kind, iso_year, iso_week, COALESCE(asset_id, '000…000'))
```
Rapport hebdomadaire **figé** — cf. § Rapports hebdomadaires ci-dessous.

⚠️ `COALESCE` dans l'index unique et non un `UNIQUE` simple : en SQL deux `NULL` sont distincts, donc
une contrainte portant directement sur `asset_id` n'empêcherait pas d'empiler plusieurs rapports
globaux pour la même semaine.

⚠️ **Colonnes ajoutées le 22/07/2026 sur une base existante** — il n'y a pas de système de migration
(`create_all` ne modifie jamais une table déjà créée). Sur une base antérieure, appliquer à la main :
```sql
ALTER TABLE reports ADD COLUMN IF NOT EXISTS asset_id UUID REFERENCES assets(id) ON DELETE CASCADE;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS asset_label VARCHAR;
ALTER TABLE reports DROP CONSTRAINT IF EXISTS uq_report_kind_week;
CREATE UNIQUE INDEX IF NOT EXISTS uq_report_kind_week_asset
  ON reports (kind, iso_year, iso_week, COALESCE(asset_id, '00000000-0000-0000-0000-000000000000'::uuid));
```

## ⏱️ Planning Celery Beat

| Tâche | Fréquence | Description |
|-------|-----------|-------------|
| `sync_nvd_recent` | Toutes les 4h | CVE NVD des 24 dernières heures (curseur incrémental, cf. ci-dessous) |
| `sync_nvd_critical` | Quotidien à 3h | Filet de sécurité CRITICAL+HIGH — balayage 45j **indépendant** du curseur (`since_override`, cf. incident ci-dessous) |
| `sync_rss_feeds` | Toutes les heures à H+5 | CERT-FR, Exploit-DB, GitHub |
| `sync_watch_feeds` | Toutes les heures à H+10 | CyberVeille — sources natives + personnalisées (cf. `docs/VEILLE.md`) |
| `sync_epss` | Quotidien à 3h30 | Scores EPSS (export FIRST.org complet, pas d'API incrémentale) |
| `sync_kev` | Quotidien à 3h45 | Catalogue CISA KEV (`cves.kev`/`kev_date_added`/`kev_ransomware`) |
| `backup_database` | Quotidien à 4h | Sauvegarde PostgreSQL `pg_dump` (cf. § Sauvegarde ci-dessus), après les syncs nocturnes |
| `sync_withsecure` | Quotidien à 5h30 | Correctifs manquants CVE/CVSS Windows (WithSecure Elements) |
| `exploit-maturity-sync-weekly` | Dimanche à 5h45 | Métadonnées Metasploit (`cves.msf_module`/`msf_best_rank`) |
| `generate_weekly_reports_task` | Lundi à 7h | Rapports hebdomadaires figés de la semaine ISO écoulée (cf. § ci-dessous) |
| `scan-policy-check-hourly` | Toutes les heures pile | Vérifie les 4 `ScanPolicy` (critique/haute/moyenne/faible) et déclenche celles dont l'heure/le jour correspond (cf. § Politiques de scan planifié ci-dessous) |
| `cpe-match-daily` | Quotidien à 22h | Matching CVE global (`POST /api/sync/match`), s'ajoute au démarrage backend et au bouton manuel |

⚠️ **`run_cpe_matching` (croisement CVE × actifs) n'est PAS planifié** malgré ce qu'affirmait cette
table jusqu'au 17/08/2026 ("après chaque sync NVD") — c'est faux dans le code, aucune tâche
`scheduled_tasks.py` ne l'appelle après une sync NVD. Ses seuls déclencheurs : démarrage du backend
(`main.py::_startup_matching`), bouton manuel (`POST /api/sync/match`), après un scan/import d'actif
(`run_cpe_matching_for_asset_task`, événementiel), et désormais `cpe-match-daily` ci-dessus.

Meraki / PRTG / GLPI / vSphere / durcissement switches : déclenchement **manuel uniquement**
(`POST .../run`), jamais dans ce planning — précédent délibéré, une intégration n'y entre qu'après
avoir fait ses preuves manuellement (seul WithSecure a suivi ce chemin jusqu'ici, cf.
`sync_withsecure` planifiée quotidiennement après une phase manuelle).

### Politiques de scan planifié par criticité (17/08/2026, `models.py::ScanPolicy`)

4 lignes fixes (une par valeur de `asset.tags.criticite` : critique/haute/moyenne/faible), éditables
depuis Paramètres > Intégrations (`GET`/`PATCH /api/scan-policies`, réservé admin en écriture).
Chacune porte `enabled`/`frequency` (`daily`/`weekly`)/`hour`/`weekday` (0=lundi..6=dimanche, utilisé
seulement si hebdomadaire). Seedées par défaut (`db/schema_patches.sql`) sur la demande initiale :
critique en quotidien minuit, le reste en hebdomadaire dimanche minuit — librement réajustables
ensuite.

Déclenchement (`services/scan_policy.py::run_scan_for_criticite`) : scanne séquentiellement (même
précédent que `patch_checker.py` — pas de session partagée entre coroutines concurrentes, prudence
vis-à-vis des ~80 serveurs on-premise) tous les actifs `collection_method="service_account"` du
groupe, puis lance le durcissement web (`run_all_website_checks(asset_ids=...)`) des sites web du
même groupe. Reproduit exactement l'enchaînement de l'endpoint manuel `POST /assets/{id}/scan`
(`scan_asset` → `apply_scan_result`, qui déclenche lui-même matching CPE + patch check pour
l'actif) — **jamais appelé depuis un worker Celery** : `apply_scan_result` lance le patch check via
`asyncio.create_task()` sur la boucle de l'appelant, qui serait annulée à la fin d'une tâche Celery
`asyncio.run()`. Le poller horaire `check_scan_policies` (`scan-policy-check-hourly` ci-dessus)
déclenche donc `POST /scan-policies/{criticite}/run-now` (process `backend`, `X-Internal-Token`,
`auth_deps.py::require_admin_or_internal`) plutôt que le service directement — même schéma que
`cpe-match-daily`/l'ancien `patch_check_periodic`.

**Périmètre** : uniquement les serveurs `service_account` et les sites web. Les équipements réseau
(Meraki/PRTG) restent 100% manuels (règle ci-dessus). Les actifs agent (checkin, non pilotables sur
planning) ont un simple signal de fraîcheur côté frontend (`Durcissement.jsx`) — badge d'avertissement
si le dernier checkin dépasse le délai attendu pour leur groupe, dérivé de `ScanPolicy.frequency`.

**Patch check** : `patch-check-periodic` (ancien cycle global toutes les 6h, tous actifs confondus)
a été retiré — la revérification de patch se déclenche maintenant via la cascade existante après
chaque scan d'actif (`apply_scan_result` → `run_full_patch_check_cycle`), au rythme de la politique
de son groupe de criticité. Décision explicite de l'utilisateur malgré la baisse de fréquence pour
haute/moyenne/faible (`RECHECK_INTERVAL` 24h → effectivement 7 jours, cf. `STATUS.md`) ; pour
critique, aucun changement réel (déjà revérifié quotidiennement).

### Rapports hebdomadaires figés (`services/weekly_report.py`, table `reports`)

Un rapport couvre une **semaine ISO complète** (lundi 00:00 → lundi suivant 00:00 exclu) et n'est plus
recalculé ensuite : `summary` (markdown), `stats` et `activity` sont stockés tels quels. Un rapport
recalculé à l'ouverture afficherait les chiffres d'aujourd'hui sous une étiquette S30 — inutilisable
pour un audit NIS 2.

- **Lundi et non dimanche soir** : la semaine doit être close, sinon le rapport est tronqué.
- **Semaine ISO, pas calendaire** : `datetime.fromisocalendar`, `iso_year` stocké explicitement — le
  2029-12-31 appartient à la semaine 1 de 2030.
- **Un rapport global + un par actif**, chaque semaine. Générer les rapports par actif d'avance
  plutôt qu'à la demande est un choix de **fidélité** : la requête d'activité s'appuie sur les
  horodatages de clôture, et rouvrir une vulnérabilité efface le sien (`update_vulnerability`) — elle
  disparaîtrait alors du rapport de la semaine où elle avait été clôturée. Seule une génération à
  temps capture la semaine telle qu'elle était. Coût mesuré : ~0,25 s par rapport (~20 s/semaine pour
  80 actifs) ; une semaine calme pèse ~100 octets, la semaine exceptionnelle du 20/07 (5304
  corrections) 114 ko.
- **Une seule table pour les 3 rapports** (`Report.kind` = `cve`/`veille`/`surveillance`), même
  raisonnement que `sync_state` : la mécanique hebdo est identique, seul le contenu diffère.
  **Les trois contenus sont branchés** : `cve` (`build_summary_payload`, routers/reports.py),
  `veille` (`build_veille_payload`, services/watch_report.py) et `surveillance`
  (`build_surveillance_payload`, services/identity_report.py). Un 4e rapport = un `build_*_payload()`
  + une branche dans `generate_report`, sans toucher à la table, aux endpoints, au planning ni au
  frontend (`WeeklyArchives.jsx` est générique).
- **Tous les rapports ne se déclinent pas par actif** (`ASSET_SCOPED_KINDS = ("cve",)`) : le registre
  de veille et la surveillance d'identités ne sont pas rattachés au parc — les décliner produirait N
  copies identiques. `POST /weekly/generate?kind=veille&asset_id=…` renvoie 400.
- **Rapport de surveillance** (`services/identity_report.py`) : périmètre surveillé, publications de
  fuite analysées sur la semaine, correspondances trouvées, adresses IP figurant sur une liste de
  blocage. Réutilise le moteur de correspondance de `routers/identities.py` (import local) — deux
  logiques de matching finiraient par diverger, et l'écran contredirait le rapport.
  ⚠️ **Le volet IP n'est pas rétroactif** : les listes publiques (IPsum, Blocklist.de, Feodo Tracker)
  ne publient que leur état courant, sans historique. Ce volet reflète l'instant de la génération, pas
  la semaine — le rendu le dit explicitement pour ne pas laisser croire à un relevé historique.
  Un rapport sans correspondance a de la valeur : il prouve que le périmètre a été surveillé, ce
  qu'une absence de rapport ne prouve pas. Zéro identité surveillée n'est donc pas « rien à
  signaler » mais une surveillance non configurée (niveau MODÉRÉ, pas FAIBLE).
- **Rapport de veille** (`services/watch_report.py`) : volume collecté, éléments traités, respect du
  SLA 48 h sur les critiques, répartition par sévérité/source/thème, décisions consignées, et stock
  restant toutes semaines confondues (un rapport qui ne montrerait que sa semaine masquerait une dette
  qui s'accumule). Exclut les sources « fuite de données », comme l'écran Veille technologique.
  ⚠️ Deux fenêtres distinctes à ne pas confondre : **reçus** (`received_at`) = volume à traiter,
  **traités** (`reviewed_at`) = travail réellement fait, qui porte souvent sur des semaines
  antérieures. Les confondre fausse le taux de traitement dès qu'un élément est traité en différé.
- **Contrainte d'unicité** `(kind, iso_year, iso_week)` : la régénération écrase la ligne au lieu
  d'empiler des doublons.
- **Exception au gel** : un rapport dont `generated_at < period_end` a été généré en cours de semaine,
  donc incomplet — il est régénéré automatiquement au passage suivant. Sans cette règle, un rapport
  S30 généré manuellement un mercredi resterait tronqué pour toujours (la tâche du lundi le sauterait,
  voyant qu'un rapport S30 existe déjà). Une fois la semaine close, seul `force=true` réécrit.
- Le calcul est partagé avec le rapport à la demande via `build_summary_payload()`
  (`routers/reports.py`) — une seule façon de calculer ces chiffres, sinon l'archive et l'écran
  divergent. `_activity_during_period` accepte une borne `until` pour ça.

### Export PDF Inventaire (`services/inventory_export.py`, session 28/07/2026)

`GET /api/reports/inventory/pdf` — premier export PDF réel du projet (`reportlab`, nouvelle dépendance
`requirements.txt` ; les rapports hebdomadaires ci-dessus ne génèrent que du CSV malgré la mention
"export PDF/CSV" du tableau des modules dans `CLAUDE.md`, à corriger si/quand un vrai export PDF leur
est ajouté un jour — ce n'est pas encore le cas).

- **Tableau récapitulatif unique**, un actif par ligne (nom, OS, CPU, architecture, cœurs, RAM,
  disques, nombre d'applications), format paysage pour la largeur.
- **La colonne "Apps" ne porte que le nombre exact**, jamais la liste. Un appendice détaillant les
  applications (nom + version) par actif a existé le 28/07/2026 puis a été **retiré le jour même à la
  demande de l'utilisateur** : il gonflait le document (17 pages et 35 Ko pour seulement 2 actifs
  réellement scannés, sur un parc de 72) sans servir l'usage visé. Le détail reste consultable à
  l'écran (`PackagesModal`, Inventaire.jsx). Ne pas le réintroduire sans demande explicite.
  Document actuel : 3 pages, ~9 Ko pour 72 actifs.
- **Toujours global, pas de filtre `asset_id`** (contrairement à `GET /reports/csv`) — cohérent avec le
  bouton frontend unique d'`Inventaire.jsx`, pas de sélecteur d'actifs sur cette page.
- **Bloqué en mode Présentation côté frontend** (pas de garde serveur) : contrairement au CSV, dont le
  texte est redigé côté client après téléchargement (`redactText`, `Reports.jsx`), un PDF déjà généré
  ne peut pas être anonymisé après coup facilement — le bouton renvoie une erreur explicite plutôt que
  de risquer d'exposer noms d'actifs/IP réels pendant une démo.
- Testé en conditions réelles sur les 72 actifs du parc : PDF valide, 3 pages, ~9 Ko, comptes exacts
  vérifiés (`DEPLOYAPP` 87, `gitlab.aer.loc` 300).

### Sync NVD incrémentale (`run_nvd_sync(..., incremental=True)`)

Par défaut, si des CVE existent déjà en base, `run_nvd_sync` interroge NVD par **date de
modification** (`lastModStartDate`/`lastModEndDate` depuis un curseur persisté) plutôt que par date
de publication sur toute la fenêtre `days` — évite de retélécharger ce qui est déjà connu à chaque
appel. `days` ne sert que de secours si la base est vide (tout premier import, aucun curseur enregistré).

Gain mesuré : sync "7 jours" passée de **73s / 2271 CVE récupérées** (première fois) à
**~1.5s / 2 CVE** (appel suivant, rien de nouveau depuis). Utilisé par le bouton "Actualiser"
(dropdown 7/15 jours) de la page CVE.

**Important** : après avoir modifié `nvd_fetcher.py`, redémarrer le service **`worker`** (Celery),
pas seulement `backend` — le worker ne recharge pas le code à chaud (contrairement à `uvicorn --reload`).

#### ⚠️ Incident (20/07/2026) — CVE manquantes malgré une base "à jour"

Signalé par l'utilisateur : `CVE-2022-30190` (Follina) absente pour un actif Windows Server 2019,
alors que NVD la liste explicitement comme applicable à ce produit. Investigation → **~4750 CVE
manquantes pour ce seul CPE (98%)**, malgré une base dont la CVE la plus récente datait du jour même.
Trois bugs distincts, empilés :

1. **Curseur incrémental corruptible par un run partiel.** Avant fix, `since` était dérivé de
   `MAX(CVE.modified)` recalculé en base à chaque appel — si un run s'interrompait en cours de
   pagination (timeout, 503 NVD), ce qui avait déjà été commité devenait la nouvelle référence pour
   le run suivant, qui repartait de là **sans jamais revenir sur la portion manquée**. Perte
   silencieuse, permanente, sans erreur visible.
   **Fix** : curseur explicite en base (table `sync_state`, clé `"nvd"`) qui n'avance qu'après un run
   **complet sans exception**, avec `INCREMENTAL_OVERLAP = 3 jours` de recouvrement par précaution
   supplémentaire à chaque lecture.
2. **Le filet de sécurité quotidien (`sync_nvd_critical`) ne rattrapait jamais rien.** Il appelait
   `run_nvd_sync(days=30, severity_filter=[...])` sans désactiver le mode incrémental — `days=30`
   était donc silencieusement ignoré (ne sert qu'en repli base-vide), le rendant strictement
   identique à la sync des 4h qu'il était censé compléter.
   **Fix** : nouveau paramètre `since_override` sur `run_nvd_sync` — balaie NVD par date de
   modification depuis un point explicite (45 jours), **indépendamment** du curseur canonique, sans
   jamais l'avancer (ce n'est qu'une 2e chance, pas la source de vérité).
3. **CPE générés malformés** (`services/asset_importer.py::_build_cpe`) — un composant `:*` en trop
   (12 composants au lieu des 11 de la norme CPE 2.3) rendait le CPE rejeté (404) par toute requête
   NVD directe, bien que toléré par le matching interne (comparaison composant par composant,
   tronquée à `min(len(asset_parts), len(cve_parts))`, donc insensible à un excès de longueur).
   Deuxième défaut sur les CPE Windows spécifiquement : le composant *version* répétait l'année déjà
   présente dans le nom du produit (`windows_server_2019:2019:...`) au lieu de `-` (convention NVD
   pour ce cas) — restreignait fortement les résultats d'une recherche NVD par CPE, sans affecter le
   matching interne (qui traite `-` et une valeur littérale comme wildcard des deux côtés).

**Rattrapage** : `POST /api/sync/nvd/{cve_id}` (une CVE précise, filet de rattrapage ponctuel,
ignore le curseur) et `POST /api/sync/nvd-backfill` (toutes les CVE NVD applicables aux CPE
réellement présents sur le parc — utilise `fetch_by_cpe`, jusque-là jamais appelée dans le code).
Mesure finale : **0 CVE manquante** pour Windows Server 2019 et Debian 12 (les 2 CPE du parc de
test), vérifié par comparaison directe avec NVD. Conséquence attendue et normale après le fix :
un ré-matching (`POST /api/sync/match`) a fait apparaître des centaines de vulnérabilités CRITICAL/
HIGH précédemment invisibles sur les actifs concernés — pas une régression, la vraie photo qui
manquait jusque-là.

**Suite directe de l'incident** : en validant CVE-2022-30190 sur l'actif concerné, découverte d'un
2e défaut, dans le patch checker cette fois — un correctif Windows ancien absorbé par une mise à jour
cumulative récente n'est jamais détecté par un check basé sur le numéro de KB. Fix (comparaison
build/révision OS) détaillé dans `docs/MATCHING.md` § Détection Windows.

---

## 🧪 Tests (session 27/07/2026)

Premiers tests automatisés du projet — jusque-là zéro test, malgré plusieurs incidents réels de
corruption de données déjà documentés dans `STATUS.md` (28 lignes rebasculées le 21/07, 3 lignes
`validated_by` effacées le 27/07). Portée volontairement ciblée sur le code le plus sensible plutôt
qu'une couverture large : les garde-fous de `apply_patch_result` (règle de sévérité CRITICAL, états
terminaux jamais écrasés, décision humaine sur `awaiting_fix`/`awaiting_fix_partial`) et une
régression directe de l'incident du 27/07 (branche manquante dans `update_vulnerability`).

**Lancer les tests** :
```bash
docker compose exec backend pytest -v
```

**Aucune base de données requise** — choix délibéré pour rester rapide et sans aucun risque sur les
données réelles :
- `services/patch_checker.py` : `Vulnerability`/`CVE` instanciés en mémoire (jamais persistés),
  `session` mockée (`MagicMock`) — `apply_patch_result` ne fait que muter l'objet Python passé en
  argument, testable sans DB. `_check_debian_tracker` est une fonction pure (snapshot/fixes en dur),
  le paramètre `cve` qu'elle reçoit n'est même pas utilisé dans son corps.
- `routers/vulnerabilities.py` : `update_vulnerability` appelée directement comme une fonction Python
  asynchrone (pas de serveur HTTP, pas de `TestClient`) — un décorateur FastAPI (`@router.patch(...)`)
  n'enveloppe pas la fonction, l'appeler directement revient exactement au même comportement qu'un
  vrai appel HTTP. `session` mockée avec `get`/`commit` en `AsyncMock` (asynchrones sur une vraie
  `AsyncSession`) et `add` en `MagicMock` simple (synchrone, sinon avertissement "jamais awaited").

**Fichiers** : `backend/tests/test_patch_checker_guardrails.py`,
`backend/tests/test_vulnerabilities_status_transitions.py`. Config `backend/pytest.ini`
(`asyncio_mode = auto`, `pythonpath = .` — nécessaire, `models`/`routers.*`/`services.*` s'importent
en absolu comme dans le reste du code, jamais préfixés `backend.`).

**Hors périmètre pour l'instant** : aucun test end-to-end via HTTP réel, aucun test touchant
effectivement PostgreSQL (matching CPE, patch check Windows/Linux réel, migrations). Une vraie base
de test (`cybervuln_test`, ou conteneur éphémère) serait nécessaire pour ça — non montée le 27/07/2026,
la priorité étant de couvrir en premier le code déjà responsable de deux incidents réels plutôt que
d'investir dans l'infrastructure avant d'avoir le premier test qui marche.
