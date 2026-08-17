# MATCHING.md
## Charger pour les tâches : cpe_matcher.py, scoring.py, remediation.py, patch_checker.py,
## cvss_bte.py, kev_fetcher.py, exploit_maturity_fetcher.py

---

## Principe fondamental — périmètre du parc

**CyberVuln n'analyse que les CVE qui concernent le parc informatique.**

- La base stocke toutes les CVEs NVD (pour pouvoir matcher à l'avenir)
- Mais l'interface, les stats, et les rapports n'exposent **que les CVEs liées à au moins un actif** via la table `vulnerabilities`
- `GET /api/cves` a `matched_only=true` par défaut → filtre automatique
- `GET /api/stats` compte uniquement les CVEs du parc (not total NVD)

Raison : afficher 7 000+ CVEs sans rapport avec le parc est du bruit, pas de l'information.

---

## CPE Matcher — cpe_matcher.py

### Logique de matching (trois niveaux)
```
Pour chaque actif :
  asset.cpe_list = ["cpe:2.3:o:microsoft:windows_server_2019:2019:*"]   ← OS uniquement
  asset.installed_packages = [{"name": "libssh2-1:amd64", "version": "1.10.0-3+b1"}, ...]
  keywords dérivés = ["windows server 2019", "windows server", ...]

Pour chaque CVE :
  Si cve.cpe non vide → matching CPE composant par composant (asset.cpe_list, prioritaire)
                         OU matching produit (asset.installed_packages)
  Si cve.cpe vide     → matching par mots-clés (mot entier) dans description (fallback)

Matching CPE composant par composant (_cpe_matches) :
  Splitte les deux CPE sur ":" et compare part/vendor/product/version un par un
  (pas en préfixe de la chaîne entière — cf. bug ci-dessous). Un composant
  "*"/"-"/absent matche n'importe quoi ; le composant version tolère le padding
  zéro implicite ("12" == "12.0", ex : Debian 12 vs "debian_linux:12.0" côté NVD).

Matching par paquets installés (_package_candidates / _cve_product_index,
session 02/07/2026) : asset.cpe_list ne contenant que l'OS, une CVE qui ne porte
qu'un CPE applicatif ("a:libssh2:libssh2") sans CPE OS associé — l'immense
majorité des CVE de bibliothèques Linux — ne matchait jamais aucun actif tant
que ce chemin n'existait pas. Voir § "Bugs de matching corrigés" pour le détail.
Réutilisé le 27/07/2026 par get_installed_package_vulnerabilities() pour croiser
(sans nouveau matching) les paquets installés d'un actif avec ses vulnérabilités
déjà en base — fonctionne pour Linux (noms dérivables par règles), pas Windows
(noms d'appli en texte libre du registre, aucune règle fiable équivalente ;
cf. docs/ARCHITECTURE.md § get_installed_package_vulnerabilities). Chantier
prochain identifié : une table de correspondance nom affiché → produit CPE,
éditable sans code (même principe que WatchSource, cf. § ci-dessous).

Matching mots-clés (fallback NVD sans CPE) :
  keywords extraits de asset.os + asset.os_version + asset.cpe_list, avec
  correspondance de MOT ENTIER (\b) — pas de sous-chaîne. Le nom d'OS seul
  ("debian", "windows"...) n'est jamais un keyword à lui seul (trop générique,
  cf. bug ci-dessous) ; seule la combinaison avec la version, ou un couple
  vendor+produit dérivé du CPE, est utilisée.

Si match → créer entrée vulnerabilities (éviter les doublons)
```

### Bugs de matching corrigés (session 02/07/2026)

Rapportés par l'utilisateur sur son premier actif Linux réel ("hortholary", Debian 12) : 3 CVE
matchées à tort ou avec un patch check inexploitable.

**1. Faux positif mots-clés — "debian" en sous-chaîne (CVE-2026-11852/11853, "Debusine")**
`_keywords_from_asset()` ajoutait le nom d'OS nu ("debian") comme keyword dès que `asset.os_version`
était vide. `_keyword_matches()` faisait un test de sous-chaîne brut → matchait "Debusine... a
**Debian**-based distribution" (un outil *pour* Debian, sans rapport avec un paquet Debian). Même
classe de bug que le fix `apt`/`rce` de `watch_fetcher.py` (cf. STATUS.md, session veille).
**Fix** : le nom d'OS seul n'est plus jamais ajouté comme keyword (seule la combinaison OS+version,
ou les couples vendor+produit dérivés du CPE de l'actif, sont gardés) ; `_keyword_matches()` passe en
correspondance de mot entier (`\b`).

**2. Comparaison CPE par préfixe de chaîne globale, pas par composant (CVE-2026-31431)**
`_cpe_matches()` comparait `asset_prefix.startswith(cve_prefix)` sur la chaîne CPE entière après
suppression des `*` finaux. `"...debian_linux:12.0".startswith("...debian_linux:12")` est vrai — mais
seulement parce que "12" est littéralement un préfixe de caractères de "12.0", sans aucune notion de
frontière de composant. Un actif "Debian 1" aurait matché tout aussi bien "Debian 12", "Debian 120",
etc. **Fix** : comparaison composant par composant (voir ci-dessus). Le match Debian 12 / CVE noyau
reste positif après fix (légitime : NVD liste bien `debian_linux:12.0` comme vulnérable) — la
correction supprime la classe de bug sans changer ce résultat précis.

**3. Extraction de paquets bruyante pour les CVE noyau (patch_checker.py, cf. section dédiée
ci-dessous)** — conséquence indirecte du point 2 : une fois la CVE noyau correctement matchée,
`_extract_packages_from_cpe()` remontait des dizaines de produits commerciaux tiers sans rapport
(Arista CloudVision, RedHat OpenShift, SUSE Manager...) au lieu de reconnaître qu'aucun paquet
dpkg/rpm réel ne correspond à un CVE noyau générique.

**5. CPE dégénéré `-:-:-` matchant tout le parc (CVE-2017-13091 à 13097, session 21/07/2026)**
NVD publie pour certaines CVE un CPE sans vendeur ni produit : `cpe:2.3:o:-:-:-:*:*:*:*:*:*:*`. En
sémantique CPE, `-` signifie "non applicable / non renseigné" — mais `_cpe_matches` le traitait comme
un joker au même titre que `*`, si bien que ce CPE matchait **tous les actifs**, quel que soit leur
OS. Symptôme : les 7 CVE du standard IEEE P1735 (chiffrement d'IP de circuits électroniques, aucun
rapport avec un serveur) rattachées à la fois à un Windows Server et à un Debian.
**Fix** : `_cpe_matches` ignore désormais tout CPE dépourvu à la fois de vendeur et de produit — il
n'identifie rien, donc ne peut légitimement désigner aucun actif. Garde-fou symétrique côté actif.
**Vérifié sans perte de vrai positif** : simulation sur les 5561 vulnérabilités existantes, exactement
14 cesseraient de matcher — toutes `open`, toutes issues de ces 7 CVE, aucun cas mixte (aucune CVE ne
combine un CPE dégénéré avec un vrai CPE), et aucune vuln `patched`/`false_positive` touchée.

**4. CVE de bibliothèque invisible faute de matching par paquet (CVE-2026-55200, session
02/07/2026)** — `libssh2` réellement installé (`libssh2-1:amd64` 1.10.0) sur "hortholary", en
version vulnérable, mais `cpe_matcher.py` ne comparait que `asset.cpe_list` (OS uniquement) aux CVE
— jamais `asset.installed_packages`. Toute CVE ne portant qu'un CPE applicatif sans CPE OS associé
(la majorité des CVE de bibliothèques Linux : libssh2, libxml2, openssl, gnutls, libexpat...) était
donc structurellement invisible. **Fix** : nouveau chemin de matching produit installé → CPE
applicatif (`_package_candidates`, `_cve_product_index`) — cf. § Matching par paquets installés
ci-dessus. Piège rencontré : le nom de paquet stocké porte le suffixe multi-arch Debian
(`libssh2-1:amd64`), à retirer avant les autres normalisations (soname, préfixe `lib`) sans quoi
aucun candidat utile n'est généré. Validé en réel : 1 → 46 vulnérabilités détectées sur
"hortholary", dont 20 déjà auto-basculées `patched` par le cycle existant sans action manuelle.

### Déclenchement
- Après chaque sync_nvd_recent (Celery)
- Après chaque run_asset_import
- Manuel via POST /api/sync/match (bouton "Matching CVE" du Dashboard)
- Automatique au démarrage du backend (`main.py` → `_startup_matching`)

Chaque exécution du matching global (`run_cpe_matching()`, pas `_for_asset`) horodate sa complétion en
base (table `sync_state`, clé `cpe_match`, session 20/07/2026, cf. `docs/ARCHITECTURE.md`) — lu via
`GET /api/sync/match-status` pour afficher "Dernière sync : jj/mm/aaaa hh:mm" sous le bouton "Matching
CVE", sans dépendre d'un clic manuel dans la session en cours (le matching tourne aussi tout seul au
démarrage de l'app).
- **Ajout manuel d'actif** (`POST /api/assets`, `PUT /api/assets/{id}`) et **scan read-only**
  (`POST /api/assets/{id}/scan`) : `run_cpe_matching_for_asset()` rejoué après coup — **plus en appel
  synchrone bloquant depuis le 27/07/2026**, déporté sur le worker Celery
  (`tasks.scheduled_tasks.run_cpe_matching_for_asset_task.apply_async(..., queue='default')`). Mesuré
  à ~30s pour un actif avec ~950 CVE déjà rattachées (parcourt tout le référentiel) — un appel direct
  ou même un `asyncio.create_task` dans le process API bloquait toute la boucle événementielle
  FastAPI (calcul CPU-bound), pas seulement la requête concernée. Cf. `docs/ARCHITECTURE.md` §
  matching CPE par actif déporté sur Celery pour le détail et le piège de routage de queue rencontré.
  Conséquence pratique : les nouvelles vulnérabilités révélées par un scan/ajout n'apparaissent que
  quelques secondes plus tard, pas dans la réponse HTTP elle-même.

### Construction du CPE pour un actif (`_build_cpe()`, `services/asset_importer.py`)
Un actif **sans `cpe_list`** ne matche jamais aucune CVE (bug rencontré : un actif ajouté à la main
via "Ajouter un actif" restait à 0 CVE indéfiniment, `cpe_list` vide par défaut). `_build_cpe(os_name,
os_version)` dérive un CPE depuis un mapping OS → vendeur/produit (Windows Server 2012-2022, Ubuntu,
Debian, CentOS, RHEL, Rocky, Alma) :
- **À la création/modification manuelle** (`routers/assets.py`) : dérivé depuis les champs OS/Version
  déclarés par l'utilisateur, si `cpe_list` est vide
- **Après un scan réussi** : reconstruit depuis l'OS **détecté** (`/etc/os-release` PRETTY_NAME +
  VERSION_ID côté Linux, plus fiable qu'un champ générique tapé à la main type "Linux" sans distro
  précise — ex : un actif déclaré "Debian" sans version ne matche rien tant qu'un scan n'a pas
  détecté "Debian GNU/Linux 12 (bookworm)" → CPE `debian_linux:12` reconstruit automatiquement)
- Si l'OS/version ne correspond à aucune entrée du mapping (ex: OS générique "Linux" sans nom de
  distro), `_build_cpe()` renvoie `None` et aucun CPE n'est créé — scanner l'actif ou préciser la
  distro exacte (Ubuntu/Debian/CentOS/RHEL/Rocky/Alma) dans le formulaire résout le problème

**Bugs de format corrigés (session 20/07/2026, incident CVE-2022-30190 manquante — cf.
`docs/ARCHITECTURE.md` § Incident)** — les deux passaient inaperçus car le matching interne
(`_cpe_matches`, comparaison composant par composant tronquée + tolérance wildcard sur `*`/`-`/vide)
les tolère très bien ; seule une requête NVD **directe** par CPE (backfill, vérification manuelle) les
révèle :
- Un composant `:*` en trop (12 composants au lieu des 11 de la norme CPE 2.3) rendait le CPE
  généré invalide pour NVD (404 direct), bien qu'accepté silencieusement par le matching local.
- Pour les OS Windows dont le produit embarque déjà la version (`windows_server_2019`), le composant
  *version* du CPE répétait l'année (`:2019:`) au lieu de `-` (convention NVD) — restreignait
  fortement une recherche NVD par CPE exact, sans effet sur le matching local (qui traite `-` et une
  valeur littérale comme wildcard des deux côtés).

### Règles
- Ne pas créer de doublon (vérifier asset_id + cve_id avant INSERT)
- Calculer risk_score à la création via scoring.py
- Status initial : open

### Limites NVD connues
- ~41% des CVEs NVD ont un CPE renseigné (les autres sont enrichis plusieurs jours/semaines après publication)
- Les CVEs Microsoft (MSRC) ont quasi toujours leur CPE → couverture correcte pour Windows Server
- Le fallback mots-clés capture les rares CVEs sans CPE qui mentionnent explicitement l'OS

---

## Patch checker — patch_checker.py

Vérifie (lecture seule, WinRM/SSH) si un correctif semble appliqué. Windows et Linux suivent
maintenant la même logique de bascule automatique (session 02/07/2026 — avant cette session, Linux
ne retournait jamais `patch_detected: true`, cf. STATUS.md).

### Validité du rattachement — vérifiée avant tout signal Windows/Linux (session 22/07/2026)

`check_patch()` (dispatcher commun) appelle `still_matches(asset, cve)` **avant** de dispatcher vers
Windows ou Linux — même fonction que `GET /false-positive-candidates`
(`services/cpe_matcher.py`, § Bugs de matching corrigés).

**Le bug que ça corrige** : sans ce contrôle, un rattachement déjà identifié comme artefact de
matching (CPE dégénéré `-:-:-`, cf. § Bugs de matching corrigés) tombait quand même dans les branches
Windows/Linux normales. Celles-ci ne trouvent logiquement ni KB ni paquet pertinent pour une CVE qui
ne concerne réellement rien — et répondaient un générique *"Vérification manuelle requise"*, sans
jamais dire que le rattachement lui-même était en cause. Deux bouts de code calculaient chacun une
partie de la vérité (« ce rattachement est invalide » d'un côté, « aucun KB/paquet trouvé » de
l'autre) sans jamais se croiser. Repéré sur `CVE-2017-13091`/`DEPLOYAPP` : le bouton "Patch check"
n'apportait aucune indication sur la raison pour laquelle cette ligne figurait parmi les candidats
faux positif, alors que cette raison était calculée depuis longtemps ailleurs.

**Effet** : `not_applicable: true` avec une justification explicite, consommé par
`apply_patch_result` exactement comme "produit absent" (`check_patch_linux`) — même règle de
sévérité (CRITICAL signalé seulement, HIGH/MEDIUM/LOW basculé automatiquement en `false_positive`).
Vérifié en réel : `CVE-2017-13091`/DEPLOYAPP (HIGH, dernière vuln ouverte du parc) auto-basculée en
`false_positive` avec justification, et une CVE légitimement matchée (`CVE-2022-30190`) toujours
correctement évaluée (`build_verdict: true`) — pas de régression.

### Détection Windows (check_patch_windows) — trois signaux combinés

**Signal 1 — KB** (historique) : cherche les numéros KB de la CVE (références NVD + API MSRC) dans
trois sources WinRM read-only — journal `Microsoft-Windows-WindowsUpdateClient` (Event ID 19),
`Win32_QuickFixEngineering`, et `Get-WUHistory` (module PSWindowsUpdate, si présent). Un seul KB
présent suffit (chaque KB de la liste cible une version Windows différente).

**Droits réels du compte de service, testés en conditions réelles (session 20/07/2026)** :
`Get-WmiObject -Class Win32_QuickFixEngineering` **et** `Get-HotFix` renvoient tous deux "Accès
refusé" (droits WMI/DCOM insuffisants, même limite que `asset_scanner.py`) — seul le **journal
d'événements** (`Get-WinEvent`, Event Log Readers suffit) fonctionne réellement pour ce compte. Les
deux autres sources restent dans le code en best-effort (n'affectent jamais la détection si elles
échouent, cf. leur propre `try {} catch {}`) au cas où un déploiement futur ait un compte avec plus de
droits, mais ne pas s'attendre à ce qu'elles apportent quoi que ce soit ici.

**Prérequis distinct, en amont de tout ça (précisé le 28/07/2026)** : « Event Log Readers » ne suffit
qu'une fois la session WinRM déjà ouverte. Ouvrir la session elle-même exige en plus que le compte
`WINRM_USER` soit membre du groupe local **« Remote Management Users »** sur la machine cible — sans
ça, échec dès la connexion (« identifiants rejetés »), avant même d'atteindre le PowerShell ci-dessus.
Repéré sur le parc élargi le 28/07/2026 : le compte fonctionnait sur `DEPLOYAPP` (provisionné
manuellement à l'origine) mais pas sur le reste des serveurs importés depuis `OU=Serveur`, jamais
provisionnés. Aucun des deux groupes ne requiert l'admin local — cf. STATUS.md pour le détail GPO.

**Limite découverte en usage réel (incident CVE-2022-30190/Follina, session 20/07/2026)** : Windows
Server fonctionne en mises à jour **cumulatives** — un KB ancien absorbé par une CU plus récente
n'apparaît plus **jamais** dans aucune des trois sources ci-dessus, même sur un système entièrement à
jour. Faux négatif quasi systématique pour toute CVE dont le correctif date de plusieurs mois/années,
justement le cas de la plupart des CVE Windows Server 2019 fraîchement importées (cf. `docs/ARCHITECTURE.md`
§ Incident sync NVD) — un actif réellement patché aurait été signalé "non corrigé" en boucle.

**Signal 2 — build/révision OS** (ajouté suite à l'incident) : lit `CurrentBuildNumber`/`UBR` par
registre (`HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, même technique sans droits WMI/DCOM
que `asset_scanner.py`), formé en version comparable `10.0.{build}.{UBR}` (ex : `10.0.17763.9020`).
Comparé aux plages de version vulnérables que NVD fournit par CPE **OS** (`versionEndExcluding` etc.,
type `"o"` plutôt que `"a"` — `_extract_version_constraints(cve, product, part="o")`, généralisation
de la fonction déjà utilisée côté paquets applicatifs Linux) via `_version_patched()` (même
comparateur numérique que la voie 2 Linux). Insensible à la supersession par CU, contrairement au
signal 1 — un build supérieur au seuil NVD prouve le correctif inclus, peu importe le nom du KB
d'origine.

**Signal 2bis — build corrigé publié par Microsoft** (`services/kb_build.py`, session 21/07/2026) —
comble le trou du signal 2 sur les CVE anciennes. Le seuil de build vient du **titre de l'article
support.microsoft.com** du KB (`"March 12, 2019—KB4489899 (OS Build 17763.379)"`), puis est comparé
au build installé exactement comme le signal 2.

**Pourquoi cette source** : c'est la seule trouvée qui expose un build pour ces CVE. Vérifié en
conditions réelles (21/07/2026), tout le reste est vide —
- NVD : `configurations` réduit à `{"vulnerable": true}`, aucun `versionEndExcluding`
- MSRC sug v2 (`affectedProduct`) : `affectedBinaries` vide
- MSRC CVRF v3 : `AffectedFiles` vide
- Registre CBS de la machine (`Component Based Servicing\Packages`) : les vieux KB sont purgés par
  le nettoyage Windows, et les entrées restantes n'ont aucun horodatage exploitable

**Même niveau de certitude que le signal 2**, donc **alimente `patch_detected` et l'auto-bascule**
(non-CRITICAL) — contrairement au signal 3 ci-dessous : c'est une comparaison de version objective,
et les CU Windows étant strictement cumulatives, un build installé supérieur au build du correctif
contient forcément ce correctif.

**Filtrage par branche d'OS, indispensable** : une CVE Windows liste un KB par version d'OS (ex.
CVE-2019-0697 → KB4489868 pour Windows 10 1803/branche `17134`, KB4489899 pour Windows Server
2019/branche `17763`). `resolve_fixed_build` ne retient que le KB dont la branche correspond au build
installé — comparer à la mauvaise branche donnerait un verdict faux.

**Placé après le signal 2** dans l'ordre de priorité : pur ajout, ne change aucun verdict déjà rendu
par NVD (et l'appel réseau est même sauté quand NVD tranche déjà).

**Limite connue** : certains types de mise à jour n'exposent aucun build dans le titre de leur
article — **Servicing Stack Updates (SSU)** et **Secure Boot DBX** notamment ("Security update for
Secure Boot DBX", "Servicing stack update for Windows 10, version 1809"). Ces KB sont mis en cache
avec `found=false` pour ne pas être retentés indéfiniment ; les CVE qui n'ont que ce type de KB
restent sans verdict ferme et retombent sur le signal 3 (date). Constaté : 53 KB dans ce cas sur le
parc de test.

**Coût réseau maîtrisé** (support.microsoft.com rate-limite agressivement — constaté) :
- cache permanent en base (table `kb_builds`) : le couple KB→build est immuable, récupéré une fois
  pour toute la vie de l'installation ; un échec réseau n'est **pas** mis en cache (retenté plus tard),
  contrairement à un article réellement sans build
- appels réseau sérialisés avec délai (`_FETCH_DELAY_SECONDS = 3s`)
- les KB sont réordonnés avant résolution (`_order_kbs_by_os`) pour tester d'abord celui que MSRC
  associe à l'OS de l'actif — le bon KB est trouvé au 1er essai au lieu d'en interroger jusqu'à 14
- mesuré sur le parc réel : ~150 KB distincts pour ~2700 CVE Windows ouvertes (le nombre de KB
  sature, un LCU par Patch Tuesday étant partagé par toutes les CVE du mois), soit ~7 min de réseau
  une seule fois

**Signal 3 — repli par date** (ajouté après le signal 2, pour les CVE sans plage de version
exploitable ni côté NVD ni côté MSRC — cas fréquent pour les CVE 2019-2021, moins standardisées que
les récentes, ex : CVE-2020-1467/CVE-2019-1365/etc.) : compare une date de référence du correctif à
la date de l'événement Windows Update le plus récent (`TimeCreated` du même Event ID 19 que le signal
1 — aucun appel WinRM supplémentaire). Les CU étant strictement cumulatives dans le temps, une mise à
jour installée après la sortie du correctif l'inclut forcément.

Date de référence, par ordre de préférence (`date_heuristic_source` indique laquelle a servi) :
1. **`releaseDate` MSRC** (`msrc_release`) — date de sortie *réelle* du KB associé à la CVE, la plus
   précise disponible (déjà récupérée via `fetch_msrc_kb_products`, aucun appel supplémentaire).
2. **`cve.published`** (`cve_published`) — repli si MSRC n'a rien retourné pour cette CVE. Moins
   précis : la date de publication NVD peut différer de quelques jours de la sortie réelle du
   correctif, même pour du Patch Tuesday coordonné.

**Purement indicatif** — n'alimente jamais `patch_detected` ni l'auto-bascule (même pour
HIGH/MEDIUM/LOW), affiché dans `details`/`date_heuristic`/`date_heuristic_reference` uniquement pour
aider l'analyste à juger. Depuis l'ajout du signal 2bis (21/07/2026), il n'apparaît plus que lorsque
**ni** NVD **ni** l'article KB Microsoft ne donnent de seuil de build — cas devenu rare.

**Priorité** : le verdict build/révision (signal 2) l'emporte dès qu'il est exploitable (constraint
NVD disponible pour ce produit CPE) ; repli sur le signal KB sinon (`build_verdict is None`), avec le
signal 3 affiché en complément informatif quand ni l'un ni l'autre n'est concluant. Validé
en conditions réelles : CVE-2022-30190 sur un actif Windows Server 2019 dont le build installé
(`10.0.17763.9020`) dépasse largement le seuil NVD (`10.0.17763.3046`) — `patch_detected: true` malgré
les 12 KB de juin 2022 tous "non trouvés", auto-bascule en `patched` (sévérité HIGH, non-critique).

### Détection Linux (check_patch_linux) — deux voies par ordre de priorité

**Voie 1 — Debian Security Tracker** (`services/debian_tracker.py`, session 02/07/2026) — actifs
Debian uniquement (release déduite du CPE `debian_linux:12` → bookworm, ou de `os_version`) :
1. Télécharge le JSON public du tracker (https://security-tracker.debian.org/tracker/data/json,
   11,6 Mo gzip, ~2 s) — cache disque 24h dans le conteneur, index mémoire restreint aux CVE
   demandées. Aucune donnée du parc n'est envoyée (même profil réseau que la sync NVD).
2. Le tracker donne la version *Debian* du paquet source qui corrige la CVE par release (ex :
   CVE-2026-31431 → `linux 6.1.170-1` pour bookworm) — c'est LA réponse au problème des backports :
   NVD publie les versions amont, Debian corrige sans changer le numéro amont, mais le tracker
   référence la version du paquet Debian réellement installable.
3. `dpkg-query -W` (SSH read-only) relève tous les binaires installés + leur paquet source ;
   comparaison avec `deb_version_compare()` (sémantique dpkg complète : epoch, `~`, révisions —
   validée contre le vrai dpkg, 361 comparaisons, 0 écart, implémentée en local pour éviter des
   allers-retours SSH supplémentaires)
   - **Piège Secure Boot** : sur Debian amd64 le noyau installé vient du paquet source
     `linux-signed-amd64`, pas de `linux` référencé par le tracker — les sources `X-signed[-arch]`
     sont normalisées vers `X`, sans quoi une machine non patchée serait déclarée "non affectée"
     (bug réel attrapé au premier test)
4. Verdicts : version installée ≥ version corrigée → `True` (auto-bascule HIGH/MEDIUM/LOW) ; <
   → `False` ; paquet source non installé → `True` avec note "non affecté" ; statut tracker
   `open` (pas de correctif Debian publié) + paquet installé → `False`
5. Cas noyau : si le paquet corrigé est installé mais que `uname -r` tourne encore sur une version
   antérieure → note "redémarrage requis" (le verdict reste `True`, cohérent avec Windows où le KB
   installé suffit)

**Voie 2 — plages NVD** (fallback : distros non-Debian, ou CVE inconnue du tracker) :
1. Extrait les noms de paquets applicatifs depuis les CPE "a:" de la CVE (`_extract_packages_from_cpe`)
   - **Exception CVE noyau** : si la CVE porte aussi un CPE `cpe:2.3:o:linux:linux_kernel`, les CPE
     "a:" sont ignorés (ce sont des produits commerciaux tiers embarquant leur propre noyau — cf.
     bug matching #3 ci-dessus). Un vendor-allowlist basé sur l'OS de l'actif casserait le cas normal
     (un CVE openssl/curl/apache n'a jamais "debian" comme vendor CPE, toujours le vendor amont) —
     la présence du CPE noyau est le signal retenu à la place.
2. Relève la version installée via `dpkg -l` / `rpm -q` en SSH read-only
3. Compare à la plage de versions vulnérables NVD (`versionStartIncluding/Excluding`,
   `versionEndIncluding/Excluding`, extraites de `cve.raw_data.configurations`) via une comparaison
   numérique best-effort (`_compare_versions` — ignore l'epoch dpkg et les suffixes non numériques
   type `~beta`/`+deb12u2`)
4. **Aucun paquet visé installé → `not_applicable`, jamais `patched`** (session 21/07/2026).
   La CVE ne s'applique pas : le produit n'est pas là. Ce n'est **pas** un correctif appliqué —
   annoncer "corrigé" pour un logiciel absent fausserait la piste d'audit (NIS 2). Le résultat porte
   `not_applicable: true` + `not_applicable_reason`, `patch_detected` reste `None`, et **aucune
   bascule automatique n'a lieu** : ces lignes deviennent des candidats faux positif, qualifiés par
   un analyste (annotation + nom obligatoires, cf. `/api/vulnerabilities/false-positive-candidates`)
   **pour les CRITICAL uniquement** — les HIGH/MEDIUM/LOW sont qualifiées automatiquement en
   `false_positive` par `apply_patch_result`, exactement comme `patch_detected: true` les bascule en
   `patched` (même règle de sévérité, cf. CLAUDE.md). La raison est recopiée dans `notes`.
   Les deux voies suivent la même règle depuis cette session. **Garde-fou** : un relevé vide (`flat`
   sans aucune entrée) signifie une collecte ratée, pas une machine sans paquets — renvoie `None`
   explicitement, sans quoi tout serait déclaré non applicable à tort.
   *Historique* : avant ce changement, la voie 1 basculait ces cas en `patched` (206 lignes en base),
   et la voie 2 renvoyait `None` (des dizaines de vulns bloquées en "à traiter"). Les 206 ne sont pas
   rétro-corrigées automatiquement, `patched` étant un état terminal.
5. `patch_detected = True` seulement si **toutes** les plages exploitables indiquent une version hors
   vulnérable ; `False` si au moins une plage indique encore vulnérable ; `None` si aucune plage
   exploitable (CVE sans CPE, ou CVE noyau — comparaison manuelle requise)

**Limite de la voie 2, assumée** : ne détecte pas un correctif backporté par la distro sans
changement du numéro de version amont — limite structurelle du modèle CPE NVD, résolue pour Debian
par la voie 1. Ubuntu a un équivalent (API JSON par CVE sur ubuntu.com/security), non implémenté à
ce jour (parc Linux de test = Debian).

### Identifiants SSH utilisés
Même ordre de priorité que `asset_scanner.py` : identifiants stockés sur l'actif
(`scan_username`/`scan_password_encrypted`, phase de test) **avant** la clé SSH partagée du parc
(`SSH_USER`/`SSH_KEY_PATH`). **Bug corrigé** : la version précédente utilisait toujours le compte de
service partagé, ignorant les identifiants par machine — d'où un `Permission denied for user
svc-cybervuln` sur tout actif configuré avec ses propres identifiants (cas réel : "hortholary").

### Cycle autonome (recheck)
- `RECHECK_INTERVAL = 24h` (`patch_checker.py`) : une vuln déjà contrôlée est revérifiée
  automatiquement après ce délai, pas seulement si elle n'a jamais été contrôlée — sans ça, un
  correctif appliqué après le premier check (résultat `None` ou `False`) ne serait plus jamais
  revu automatiquement.
- Tâche Celery `patch_check_periodic` (`tasks/scheduled_tasks.py`, beat toutes les 6h, H+20) —
  déclenche `POST /api/patch-check/run` **côté process `backend`** plutôt que d'appeler le service
  directement depuis le `worker` : l'état d'avancement (`_cycle_running`, `_current_check`, suivi par
  le polling du dashboard) vit en mémoire dans le process FastAPI unique — l'invoquer depuis le
  `worker` créerait un état parallèle invisible et sans verrou anti-concurrence avec un cycle déjà en
  cours (démarrage ou bouton manuel).

### Relevé mis en cache par actif (session 21/07/2026 — perf)

**Incident** : sur un parc avec un historique NVD important (plusieurs milliers de CVE par actif),
le cycle autonome n'avançait presque plus — `check_patch_windows`/`check_patch_linux` rouvraient une
session WinRM/SSH et rejouaient un relevé coûteux **par CVE**, alors que ce relevé (KB installés,
build OS, paquets dpkg/rpm installés) est strictement identique pour toutes les CVE d'un même actif
dans un même cycle. Le scan complet du journal Windows Update (`Get-WinEvent`, seule source
réellement fonctionnelle pour ce compte de service, cf. ci-dessus) est l'opération la plus coûteuse
de cette redondance.

**Fix** : `_fetch_windows_patch_snapshot(asset)` / `_fetch_linux_package_snapshot(asset)` — un seul
appel WinRM/SSH par actif, résultat mis en cache par l'appelant (`snapshot` optionnel sur
`check_patch`/`check_patch_windows`/`check_patch_linux`) et réutilisé pour toutes les CVE de cet actif
dans le même cycle. `run_startup_patch_checks` regroupe désormais les vulns par actif avant de
boucler. Cache `msrc_cache` par CVE (indépendant de l'actif) partagé sur tout le cycle — utile dès
qu'une même CVE touche plusieurs serveurs (pertinent pour le parc cible de 80 VM). Si un relevé
échoue (actif injoignable), l'échec est détecté une fois pour tout le lot plutôt qu'un timeout WinRM
par CVE.

Le bouton "Patch check" unitaire (`POST /api/patch-check/{vuln_id}`) n'utilise pas ce cache par
défaut — il appelle `check_patch(asset, cve)` sans `snapshot`, qui en fait un frais à la volée
(comportement inchangé, cf. `MIN_RECHECK_GAP` ci-dessous pour son propre cache, à ne pas confondre).

### Cache court terme du check unitaire (`MIN_RECHECK_GAP`, session 21/07/2026)

`MIN_RECHECK_GAP = 30s` — si le dernier contrôle d'une vuln date de moins de ce délai, `POST
/api/patch-check/{vuln_id}` renvoie le `patch_check_result` déjà en base (`cached: true`,
`cached_age_seconds`) sans ressolliciter l'actif, sauf `force=true`. Différent de `RECHECK_INTERVAL`
(24h, cycle autonome) : ce cache évite un aller-retour WinRM/SSH redondant pour un simple double-clic
ou une modale rouverte juste après, pas une politique de fraîcheur de fond.

---

## Scoring — scoring.py

### Formule
```python
risk_score = min(cvss_score * epss_score * multiplicateur, 10.0)

multiplicateurs = {
    "haute":   1.5,
    "moyenne": 1.0,
    "faible":  0.7,
}
# criticite extraite de asset.tags["criticite"] (défaut: "moyenne")
```

### Exemples
```
CVE 9.8 × EPSS 0.85 × haute 1.5   = 12.5 → plafonné à 10.0
CVE 7.5 × EPSS 0.12 × moyenne 1.0 = 0.9
CVE 5.0 × EPSS 0.05 × faible 0.7  = 0.175
```

### Criticité métier — enfin branchée à l'UI (session 27/07/2026)

La formule ci-dessus existait depuis longtemps, mais rien ne permettait de régler `asset.tags["criticite"]`
avant le 27/07/2026 : ni endpoint dédié, ni champ dans le formulaire d'actif — tous les actifs
restaient donc figés sur le défaut `"moyenne"` (×1.0). Correctif purement un branchement, pas une
nouvelle logique de scoring :
- `frontend/src/pages/Assets.jsx` (`AssetFormModal`) : `<select>` Haute/Moyenne/Faible, payload
  `tags: { ...asset.tags, criticite }` — **merge**, jamais un remplacement du dict `tags` complet
  (`PUT /assets/{id}` écrase tout ce qui est envoyé dans `tags`).
- `routers/assets.py` (`update_asset`) : appelle désormais `recalculate_scores_for_asset()` (déjà
  définie dans `scoring.py`, jamais invoquée depuis cette route) si `tags` a changé — sans cet appel,
  changer la criticité n'a aucun effet visible sur `risk_score` tant qu'un scan ou une sync NVD ne
  redéclenche pas un recalcul.
- Badge `CriticiteBadge.jsx` (nouveau composant, calqué sur `SeverityBadge.jsx`) dans le tableau
  `Assets.jsx`.

Vérifié isolément (`calculate_risk_score(9.8, 0.5, "haute")` = 7.35 = 4.9 × 1.5) ; l'effet de bout en
bout sur les scores réels du parc n'a pas pu être observé en direct — l'EPSS est à 0/absent pour les
CVE actuellement liées aux deux actifs de test, ce qui annule le produit quelle que soit la criticité
(caractéristique du jeu de données, pas un bug).

---

## Exploitation active — kev_fetcher.py / exploit_maturity_fetcher.py

Deux signaux gratuits ajoutés le 17/08/2026, équivalents de ce que fait Cyberwatch (référence
explicite de l'utilisateur : CVSS-B, CVSS-BTE, EPSS, "maturité d'exploit — rouge = présent dans
Metasploit"). Tous deux ne créent jamais de CVE, n'en mettent à jour que celles déjà en base
(`cves.cve_id`) — même principe qu'`epss_fetcher.py`.

- **KEV** (`kev_fetcher.py`) — catalogue CISA "Known Exploited Vulnerabilities" : un **fait
  constaté**, pas une prédiction (contrairement à l'EPSS). Source publique gratuite sans clé,
  export JSON complet régénéré au fil de l'eau. Deux passes bulk UPDATE (réinitialise les CVE
  retirées du catalogue avant d'appliquer le feed courant, cf. docstring du fichier).
  `cves.kev`/`kev_date_added`/`kev_ransomware`. Sync quotidienne (Celery beat, 3h45).
- **Maturité d'exploit** (`exploit_maturity_fetcher.py`) — présence dans le framework
  Metasploit (fichier de métadonnées public du dépôt, BSD-3-Clause). Read-only, threat intel
  publique : seuls le nom du module, les CVE référencées et le rang de fiabilité natif du
  framework (`rank`, 0=manual à 600=excellent) sont extraits — aucun code d'exploitation
  téléchargé ni exécuté (cf. CLAUDE.md §1). `cves.msf_module`/`msf_best_rank`/`msf_module_count`.
  Sync hebdomadaire (dimanche 5h45) — le catalogue de modules évolue lentement, pas de valeur à
  reparser ~11 Mo chaque jour.

Les deux exposent un filtre booléen sur `GET /cves` et `GET /vulnerabilities` (`kev`/
`msf_module`, index partiels `idx_cves_kev`/`idx_cves_msf_module`) et un badge partagé côté
frontend (`components/ExploitBadge.jsx`, cf. `docs/FRONTEND.md`). Déclenchement manuel :
`POST /api/sync/kev` / `POST /api/sync/exploit-maturity` (même forme que `/epss`).

## CVSS-BTE — cvss_bte.py

Score CVSS v3.1 **Temporal + Environnemental réel**, par `(CVE, actif)` — donc porté par
`Vulnerability.cvss_bte`/`cvss_bte_vector`, pas par `CVE` (contrairement à `cvss_score`,
générique et identique pour tout le monde). **Coexiste avec `risk_score` sans le remplacer** —
formules distinctes, calculées côte à côte dans les mêmes fonctions de recalcul (`scoring.py`,
pas un second passage sur le parc, cf. commentaire sur `_RESCORE_LOAD_OPTIONS`).

Calcul via la librairie `cvss` (Red Hat Product Security, LGPLv3+) plutôt qu'une
réimplémentation main de l'arrondi CVSS v3.1 (`round_up`), source connue de bugs subtils.

Périmètre volontairement limité à **Temporal (E/RL/RC) + Environmental Requirements
(CR/IR/AR)** — pas de Modified Base Metrics (MAV/MAC/...), non dérivables automatiquement de ce
qu'Allsafe connaît d'un actif. Dérivation automatique (`compute_cvss_bte`) :

| Métrique | Source | Règle |
|---|---|---|
| E (Exploit Code Maturity) | `CVE.kev`/`msf_module` | `kev` → `H` ; sinon `msf_module` → `F` (un module intégré à un framework majeur correspond à la définition CVSS de "Functional exploit code available", indépendamment de son `rank` de fiabilité) ; sinon `X` |
| RL (Remediation Level) | `Vulnerability.status` | `awaiting_fix`/`awaiting_fix_partial` (aucun correctif publié, cf. CLAUDE.md §1) → `U` ; sinon `X` |
| RC (Report Confidence) | — | toujours `C` (CVE publiées par NVD, source confirmée) — même multiplicateur que `X` (1.0), gardé explicite pour la traçabilité du vecteur |
| CR/IR/AR | `asset.tags["criticite"]` | `haute→H`, `moyenne→M`, `faible→L`, défaut `X` — même dimension métier que `risk_score` (§ Criticité métier ci-dessus), réutilisée sur les 3 axes plutôt que d'inventer 3 réglages séparés |

`None` si `CVE.cvss_vector` est absent ou n'est pas un vecteur v3.0/3.1 (`CVSS:3.`) — CVE notée
en v2 seulement, la lib `cvss` ne couvre pas ce cas ici (même repli que `risk_score` sur
`cvss_score is None`).

Recalculé automatiquement à chaque sync KEV/maturité d'exploit (les deux appellent
`recalculate_all_scores()` en fin de fonction, `E` en dépend directement) et à chaque
`/rescore`/scan d'actif/sync CVE ciblée, comme `risk_score`. Exposé par l'API
(`GET /vulnerabilities`, `sort_by=cvss_bte`) sans colonne dédiée dans le tableau pour l'instant —
même traitement que `risk_score`, qui n'en a pas non plus (sert uniquement au tri par défaut).

---

## Correctifs — remediation.py

⚠️ CyberVuln propose uniquement. L'analyste décide et applique.

### Niveau 1 — Recommandation textuelle (MVP)
Prompt Claude anonymisé → retourne JSON :
```json
{
  "steps": ["Étape 1", "Étape 2", "Étape 3"],
  "kb_or_package": "KB5034441 / nginx 1.24.0",
  "verification_cmd": "Get-HotFix -Id KB5034441",
  "reboot_required": true,
  "estimated_effort": "30 min"
}
```

### Niveau 2 — Script généré (V1)
- Windows → PowerShell
- Linux → Bash
- Toujours avec : vérif pré-patch, application, vérif post-patch
- Avertissement systématique : "Tester en recette avant prod"
- Retourne : PATCHED / ALREADY_PATCHED / FAILED

### Workflow complet end-to-end
```
NVD sync → cpe_matcher → scoring → vulnerabilities (open)
                                         ↓
                              Analyste voit dans dashboard
                                         ↓
                              Clique "Analyser IA" → claude_analyzer
                                         ↓
                              Clique "Correctif" → remediation
                                         ↓
                              Lit, valide, teste en recette
                                         ↓
                              Applique manuellement sur serveur
                                         ↓
                    patch_checker (SSH/WinRM read-only) détecte le correctif
                                         ↓
                        ┌────────────────┴────────────────┐
                        ↓                                  ↓
              CVE CRITICAL                        CVE HIGH/MEDIUM/LOW
                        ↓                                  ↓
        Signalement seul, l'analyste             Bascule automatique en
        marque "patched" manuellement            "patched" (validated_by =
                                                  "Auto (patch check)")
```

**Deux issues alternatives** (session 02/07/2026, cf. `docs/FRONTEND.md` § Dashboard) — au lieu du
correctif appliqué puis détecté ci-dessus :
- **`awaiting_fix`** (bouton "⏳ En attente", annotation obligatoire) — pas de correctif éditeur/distro
  disponible pour l'instant (ex: CVE publiée mais pas encore backportée par Debian). Reste dans le
  cycle de patch check autonome, bascule en `patched` dès qu'un correctif sort.
- **`false_positive`** (bouton "🚫 Faux positif", annotation obligatoire) — la CVE ne concerne en
  réalité pas l'actif (erreur de matching, cf. § Bugs de matching corrigés ci-dessus). État terminal,
  exclu du patch check autonome.

Voir CLAUDE.md § Non-intervention sur les serveurs pour la règle exacte —
dans tous les cas, aucune commande n'est jamais exécutée sur le serveur
lui-même, seule la bascule de statut dans CyberVuln diffère selon la sévérité.
