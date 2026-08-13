# Encyclopédie des Vulnérabilités de Sécurité

Ce document liste les vulnérabilités identifiées dans l'outil de gestion des vulnérabilités, ainsi qu'une liste complémentaire de défauts de sécurité critiques fréquemment rencontrés (basés sur l'OWASP et les standards de sécurité).

## 1. Vulnérabilités identifiées (issues de la capture d'écran)

Toutes ces vulnérabilités sont classées avec une sévérité **CRITIQUE**.

| Référence | Nom du défaut de sécurité |
| :--- | :--- |
| WSTG-INPV-19 | Server-Side Request Forgery |
| WSTG-INPV-13 | Buffer Overflow and Format-String Injection |
| WSTG-INPV-12 | Command Injection |
| WSTG-INPV-11 | Code Injection |
| WSTG-INPV-08 | SSI Injection |
| WSTG-INPV-06 | LDAP Injection |
| WSTG-INPV-05 | SQL Injection |
| WSTG-ATHZ-03 | Privilege Escalation |
| WSTG-ATHZ-02 | Bypassing Authorization Schema |
| WSTG-ATHZ-01 | Directory Traversal File Include |
| WSTG-ATHN-02 | Default Credentials |
| Vuln-SMB-CVE-2017-7494 | Vulnerability to Samba remote code execution |
| Vuln-IIS-buffer-overflow | IIS buffer overflow vulnerability |
| Vuln-Apache-Struts-CVE-2017-5638| Vulnerability to Apache Struts remote code execution |
| Telnet-port | Insecure Telnet protocol |
| SMBv1_custom | SMBv1 (custom) |
| SMBv1 | Dangerous protocol SMBv1 enabled |
| rsync-port | Insecure rsync protocol |
| OWASP-2025-A07 (critical) | Authentication Failures |
| OWASP-2025-A05 (critical) | Injection |

---

## 2. Vulnérabilités complémentaires (Ajouts suggérés)

Pour compléter cette encyclopédie, voici d'autres vulnérabilités majeures (issues des standards OWASP WSTG, du Top 10 OWASP et des audits classiques) qui sont généralement surveillées et qui complètent logiquement votre liste actuelle :

### Filles de test OWASP (WSTG) manquantes courantes :
*   **WSTG-INPV-01 / 02** : Cross-Site Scripting (XSS) - *Injection de scripts côté client (Reflected / Stored).*
*   **WSTG-INPV-07** : XML External Entity (XXE) Injection - *Exploitation de parseurs XML mal configurés pour lire des fichiers locaux.*
*   **WSTG-ATHZ-04** : Insecure Direct Object References (IDOR) - *Accès non autorisé à des objets directs via manipulation de paramètres.*
*   **WSTG-ATHN-01** : Weak Password Policy - *Politique de mots de passe trop faible ou absente.*
*   **WSTG-SESS-01 / 02** : Bypassing Session Management Schema / Weak Session ID - *Failles liées à la gestion des sessions utilisateurs.*

### Top 10 OWASP (Catégories critiques à ajouter) :
*   **OWASP-A01** : Broken Access Control - *Défaillance du contrôle d'accès (souvent la faille la plus critique sur les applications modernes).*
*   **OWASP-A02** : Cryptographic Failures - *Stockage ou transmission en clair de données sensibles (ex: mots de passe non hashés).*
*   **OWASP-A06** : Vulnerable and Outdated Components - *Utilisation de bibliothèques ou frameworks obsolètes avec des CVE connues.*
*   **OWASP-A08** : Software and Data Integrity Failures - *Failles d'intégrité (ex: mises à jour logicielles non signées, désérialisation non sécurisée).*

### Protocoles non sécurisés fréquents (pour la partie réseau/infrastructure) :
*   **FTP-port (21)** : Insecure FTP protocol - *Transmission d'identifiants et de données en clair.*
*   **HTTP-port (80)** : Insecure HTTP protocol - *Absence de chiffrement TLS, permettant l'interception du trafic.*
*   **SNMPv1/v2c** : Insecure SNMP protocol - *Communautés (mots de passe) transmises en clair sur le réseau.*

---

## 3. Compléments (12/08/2026 — étoffage demandé, en vue du découpage agent/sonde)

Chaque entrée porte une étiquette de faisabilité, cohérente avec la distinction actée avec
l'utilisateur (cf. discussion agent vs sonde BAS) :
- 🔍 **Détection passive** — constatable sans rien exécuter d'actif (lecture de config, banner,
  clé de registre, version installée...). Éligible à l'agent poste ou au scan centralisé existant.
- ⚔️ **Test actif / exploitation** — nécessite d'envoyer une charge, de tenter une authentification,
  ou d'exploiter réellement la faille pour la confirmer. Jamais automatisé sur le parc en prod —
  réservé au futur module Sécurité (sonde BAS/Red Team, autorisation écrite obligatoire, même
  garde-fou que le module Audits).

### 3.1 WSTG — chapitres non encore couverts

*   **WSTG-INFO (Information Gathering)** 🔍 — fingerprinting techno (headers serveur, `X-Powered-By`),
    fichiers/chemins sensibles exposés (`.git/`, `.env`, `/backup`, `robots.txt` trop bavard),
    énumération de sous-domaines, commentaires HTML/JS laissant fuiter des infos internes.
*   **WSTG-CONF (Configuration and Deployment Management)** 🔍 — méthodes HTTP dangereuses activées
    (`PUT`/`DELETE`/`TRACE`), en-têtes de sécurité absents (`Content-Security-Policy`,
    `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`), CORS trop permissif
    (`Access-Control-Allow-Origin: *` avec credentials), pages d'admin exposées sans restriction IP.
*   **WSTG-IDNT (Identity Management)** 🔍/⚔️ — énumération de comptes via message d'erreur différent
    (login/mot de passe oublié révélant si l'email existe) [⚔️ à confirmer activement], politique de
    création de compte trop permissive.
*   **WSTG-ATHN (Authentication) — compléments** :
    *   **WSTG-ATHN-03** ⚔️ Testing for Weak Lock Out Mechanism — absence de verrou anti-bruteforce
        ou verrou contournable (déjà couvert côté Allsafe lui-même, cf. `services/auth.py`).
    *   **WSTG-ATHN-04** ⚔️ Testing for Bypassing Authentication Schema.
    *   **WSTG-ATHN-06** 🔍 Testing for Browser Cache Weaknesses — données sensibles mises en cache
        côté navigateur après déconnexion.
    *   **WSTG-ATHN-07** ⚔️ Testing for Weak Password Change or Reset Functionalities.
    *   **WSTG-ATHN-08** ⚔️ Testing for Weaker Authentication in Alternative Channel (API mobile,
        legacy endpoint contournant le MFA du portail principal).
*   **WSTG-ATHZ — compléments** :
    *   **WSTG-ATHZ-04** ⚔️ Insecure Direct Object References (IDOR) — déjà listé en §2, confirmé ici.
*   **WSTG-SESS (Session Management) — compléments** :
    *   **WSTG-SESS-03** 🔍 Cookies absents des attributs `Secure`/`HttpOnly`/`SameSite`.
    *   **WSTG-SESS-05** ⚔️ Cross-Site Request Forgery (CSRF).
    *   **WSTG-SESS-06** 🔍 Absence d'expiration de session / timeout trop long.
    *   **WSTG-SESS-09** ⚔️ Session Puzzling (réutilisation incohérente de variables de session).
*   **WSTG-INPV — compléments** (au-delà de SQLi/XSS/LDAP/SSI/Command/Code Injection déjà listés) :
    *   **WSTG-INPV-03/04** ⚔️ HTTP Verb Tampering / HTTP Parameter Pollution.
    *   **WSTG-INPV-09** ⚔️ XPath Injection.
    *   **WSTG-INPV-14** ⚔️ Incubated Vulnerability (chaîne d'injections en plusieurs étapes).
    *   **WSTG-INPV-15** ⚔️ HTTP Splitting/Smuggling.
    *   **WSTG-INPV-16** ⚔️ HTTP Incoming Requests (déni de service applicatif via requêtes
        malformées) — hors périmètre non-intervention, à ne jamais tester en prod.
    *   NoSQL Injection ⚔️ (MongoDB, CouchDB... — variante moderne de SQLi, pas dans le WSTG classique).
    *   Mass Assignment / Over-posting ⚔️ — champs protégés modifiables via un payload API non filtré.
    *   Server-Side Template Injection (SSTI) ⚔️ — moteurs de templates (Jinja2, Twig...) exécutant
        du code via une entrée utilisateur non échappée.
    *   GraphQL — introspection activée en prod 🔍, requêtes en profondeur non limitées (déni de
        service) ⚔️, absence de contrôle d'autorisation par champ ⚔️.
*   **WSTG-ERRH (Error Handling)** 🔍 — stack traces/messages d'erreur détaillés exposés en prod
    (chemins serveur, requêtes SQL, version de framework).
*   **WSTG-CRYP (Cryptography)** 🔍 — TLS 1.0/1.1 encore acceptés, suites de chiffrement faibles
    (RC4, 3DES, export-grade), certificat auto-signé ou expiré en prod, absence de HSTS,
    algorithmes de hash de mot de passe obsolètes (MD5/SHA1 non salés).
*   **WSTG-BUSL (Business Logic)** ⚔️ — contournement de workflow (validation d'étape sautée),
    manipulation de prix/quantité côté client, réutilisation abusive de coupon/jeton à usage unique.
*   **WSTG-CLNT (Client-Side)** ⚔️ — DOM-based XSS, `postMessage` sans vérification d'origine,
    Clickjacking (absence de `X-Frame-Options`/`frame-ancestors`), CSS injection, WebSocket sans
    validation d'origine.
*   **WSTG-APIT (API Testing)** 🔍/⚔️ — versionnement d'API non déprécié proprement (ancienne version
    vulnérable encore accessible) 🔍, rate limiting absent ⚔️, JWT avec `alg: none` accepté ou secret
    faible/prévisible ⚔️, clé API en dur côté client (mobile/JS) 🔍.

### 3.2 OWASP Top 10:2021 — catégories restantes

*   **A03:2021** — déjà couvert (Injection, référencé ici sous OWASP-2025-A05).
*   **A04:2021 — Insecure Design** 🔍/⚔️ — absence de threat modeling constatable indirectement
    (fonctionnalité sensible sans contrôle métier prévu dès la conception, pas juste un bug
    d'implémentation).
*   **A07:2021** — déjà couvert (Authentication Failures, référencé ici sous OWASP-2025-A07).
*   **A09:2021 — Security Logging and Monitoring Failures** 🔍 — absence de journalisation des
    échecs d'authentification/actions sensibles, logs non protégés en écriture (falsifiables),
    absence d'alerting sur activité anormale.
*   **A10:2021 — Server-Side Request Forgery (SSRF)** — déjà listé en §1 (WSTG-INPV-19).

### 3.3 OWASP API Security Top 10 (2023) — pertinent dès qu'une app expose une API REST/GraphQL

*   **API1** ⚔️ Broken Object Level Authorization (BOLA) — variante API de l'IDOR, la plus fréquente
    en pratique sur les API REST.
*   **API2** ⚔️ Broken Authentication.
*   **API3** ⚔️ Broken Object Property Level Authorization (excès de champs exposés/modifiables).
*   **API4** ⚔️ Unrestricted Resource Consumption (absence de pagination/rate limiting → déni de
    service applicatif).
*   **API5** ⚔️ Broken Function Level Authorization (endpoint admin accessible à un rôle standard).
*   **API6** 🔍 Unrestricted Access to Sensitive Business Flows.
*   **API7** ⚔️ Server-Side Request Forgery (spécifique aux intégrations API tierces).
*   **API8** 🔍 Security Misconfiguration (CORS, verbes HTTP, en-têtes — recoupe WSTG-CONF).
*   **API9** 🔍 Improper Inventory Management (API "fantômes" non documentées/oubliées, encore actives).
*   **API10** ⚔️ Unsafe Consumption of APIs tierces (confiance aveugle dans une réponse externe).

### 3.4 Active Directory — égarements spécifiques (pertinent ici : parc majoritairement Windows Server joint AD)

*   **Kerberoasting** ⚔️ — extraction de tickets de service (TGS) chiffrés avec le hash du compte de
    service pour craquage hors-ligne ; détectable passivement 🔍 en repérant les comptes de service
    avec SPN et mot de passe non-géré par gMSA/LAPS.
*   **AS-REP Roasting** ⚔️ (exploitation) / 🔍 (détection passive : comptes avec pré-authentification
    Kerberos désactivée, `DONT_REQ_PREAUTH`).
*   **Délégation Kerberos non contrainte/contrainte mal configurée** 🔍 — détectable en lisant les
    attributs `userAccountControl`/`msDS-AllowedToDelegateTo`, chemin d'escalade classique vers
    Domain Admin.
*   **DCSync / droits de réplication excessifs** 🔍 — comptes non-admin disposant de
    `Replicating Directory Changes` sur le domaine (permet d'extraire tous les hashs NTLM).
*   **LAPS absent ou mot de passe administrateur local partagé** 🔍 — mouvement latéral trivial si
    un seul poste est compromis.
*   **SMB signing / LDAP signing non requis** 🔍 — expose au relais NTLM (déjà partiellement couvert
    côté durcissement CIS-like existant pour SMBv1/NTLM, à étendre explicitement à la signature).
*   **AdminSDHolder/ACL du domaine mal restrictives** 🔍 — droits `GenericAll`/`WriteDACL` accordés
    à des groupes trop larges sur des objets sensibles (chemins d'attaque type BloodHound).
*   **Golden/Silver Ticket — surface d'exposition** 🔍 — âge du mot de passe du compte KRBTGT (une
    rotation ancienne élargit la fenêtre d'exploitation en cas de compromission passée).
*   **Zerologon (CVE-2020-1472)** ⚔️/🔍 — vérifiable passivement via la présence du correctif
    (patch level du DC) sans avoir à exploiter la faille.
*   **PrintNightmare (CVE-2021-34527)** 🔍 — Print Spooler actif sur un contrôleur de domaine (ne
    devrait jamais l'être) + niveau de correctif.
*   **Comptes avec `Password Never Expires` ou `PasswordNotRequired`** 🔍.
*   **Groupe "Utilisateurs du domaine" avec droits locaux administrateur sur des postes** 🔍.

### 3.5 Protocoles et services réseau non sécurisés — compléments

*   **LDAP non chiffré (389) vs LDAPS (636)** 🔍 — déjà géré côté configuration AD du produit
    lui-même (`AD_USE_TLS`), pertinent aussi comme *finding* sur les actifs scannés.
*   **SMTP en clair sans STARTTLS, relais ouvert** 🔍/⚔️.
*   **POP3/IMAP en clair (110/143) au lieu de POP3S/IMAPS (995/993)** 🔍.
*   **NFS exporté sans restriction (`*`) ou avec `no_root_squash`** 🔍.
*   **Redis/MongoDB/Elasticsearch/Memcached exposés sans authentification** 🔍 — cible classique de
    scan de masse sur Internet, tout aussi pertinent en interne si segmentation réseau faible.
*   **VNC sans mot de passe ou authentification faible** 🔍.
*   **rlogin/rsh (protocoles "r-commands" hérités)** 🔍 — équivalent Telnet côté Unix historique.
*   **DNS — transfert de zone (AXFR) autorisé à quiconque** ⚔️ (nécessite une requête active pour
    confirmer, mais non destructive).
*   **Communauté SNMP par défaut ("public"/"private") acceptée** ⚔️ — déjà explicitement écarté du
    scan actif automatique (décision du 07/08/2026, cf. `network_protocol_check.py`) ; reste
    pertinent comme *finding* saisi manuellement suite à un audit en lab.
*   **Bannières de service verbeuses (version exacte du serveur SSH/FTP/HTTP)** 🔍 — facilite le
    ciblage de CVE connues, détectable par simple lecture de bannière (déjà l'esprit du TCP
    passif existant).

### 3.6 CVE historiques majeures (scénarios de référence pour la future sonde BAS/Red Team)

Ces CVE emblématiques sont couramment utilisées comme scénarios de test en Breach & Attack
Simulation (détection de la variante *patchée* 🔍 possible sans exploiter ; la démonstration
d'exploitation reste ⚔️, réservée au lab) :

*   **EternalBlue / MS17-010 (CVE-2017-0144)** — SMBv1 Windows, propagateur de WannaCry/NotPetya.
*   **BlueKeep (CVE-2019-0708)** — RDP pré-authentification, exécution de code à distance.
*   **Heartbleed (CVE-2014-0160)** — fuite mémoire OpenSSL via l'extension TLS heartbeat.
*   **Shellshock (CVE-2014-6271)** — exécution de commande via variables d'environnement Bash.
*   **Log4Shell (CVE-2021-44228)** — désérialisation/JNDI dans Log4j, exécution de code à distance.
*   **ProxyShell / ProxyLogon (Microsoft Exchange, 2021)** — chaîne d'exploitation OWA/ECP.
*   **PrintNightmare (CVE-2021-34527)** — déjà listé en §3.4 (contexte AD).
*   **Zerologon (CVE-2020-1472)** — déjà listé en §3.4 (contexte AD).
*   **Apache Struts (CVE-2017-5638)** — déjà listé en §1.
*   **Samba (CVE-2017-7494)** — déjà listé en §1.

### 3.7 Durcissement poste/serveur — pistes pour l'agent (Windows + Linux)

> **13/08/2026** : la quasi-totalité de ce backlog est désormais implémentée côté agent
> (`agent/src/collect/{linux,windows}.rs`, cf. `docs/AGENTS.md` § Checks collectés) — statut ✅/⚠️
> marqué sur chaque ligne. Items encore ouverts : antivirus tiers (seul Windows Defender est
> détectable en lecture seule sans dépendance supplémentaire), clés SSH sans passphrase (détection
> fiable nécessite de tester chaque clé, périmètre pas encore tranché), services/tâches planifiées
> superflus (liste "légitime" très dépendante du contexte de chaque poste, pas encore de règle
> objective posée).

En complément du durcissement déjà couvert par le scan centralisé existant (SMBv1, RDP/NLA,
NTLM, WDigest, LLMNR, pare-feu, algos SSH faibles) — tout 🔍, cohérent avec un agent posé
localement, aucune de ces vérifications ne nécessite d'action offensive :

*   ✅ **Chiffrement de disque absent** (BitLocker désactivé sous Windows, LUKS absent sous Linux) —
    risque majeur spécifique aux postes mobiles (perte/vol), sans objet sur des serveurs en salle
    machine. (`bitlocker`/`disk_encryption`, déjà là avant le 13/08/2026)
*   ⚠️ **Antivirus/EDR absent, désactivé ou définitions obsolètes** — partiel : `defender_realtime`
    (13/08/2026) détecte Windows Defender désactivé, mais ne sait pas identifier un antivirus tiers
    (WithSecure et consorts n'exposent pas cette clé de registre) ni des définitions obsolètes.
*   ✅ **Verrouillage d'écran absent ou délai excessif**. (`screen_lock`, déjà là)
*   ✅ **Comptes locaux administrateurs superflus** (`privileged_accounts`, déjà là) **/ compte
    "Administrateur"/"root" non renommé et actif** — `admin_account_renamed` (13/08/2026, Windows
    uniquement ; côté Linux, `root` ne se "renomme" pas au même sens, seul `sudo_nopasswd`
    couvre l'angle élévation).
*   ✅ **Journalisation PowerShell désactivée** (Script Block Logging — déjà là — **+ Transcription**,
    `powershell_transcription`, 13/08/2026) — angle mort fréquent en détection/réponse à incident
    côté Windows.
*   ✅ **UAC désactivé** (Windows, `uac_enabled`, 13/08/2026) **/ sudo sans mot de passe ou trop
    permissif** (Linux, `sudo_nopasswd`, 13/08/2026).
*   ✅ **Ports USB non restreints** (exfiltration/implantation physique) — politique de groupe
    absente. (`usb_policy`, déjà là)
*   ❌ **Services/tâches planifiées superflus actifs** (surface d'attaque inutilement large) — pas
    encore de règle objective "superflu" posée, resterait à définir avant d'implémenter (liste de
    référence par rôle de machine ?).
*   ✅ **Correctifs OS/applicatifs en retard** — déjà au cœur du produit (patch check), rappelé ici
    comme le fondement de tout le reste.
*   ✅ **Permissions de fichiers/dossiers trop larges** (`chmod 777`, ACL "Tout le monde" en écriture
    sur des chemins sensibles) — `world_writable_files` (13/08/2026, Linux ; périmètre borné à
    `/etc /usr/local /opt`, pas tout le système de fichiers). Windows (ACL NTFS "Everyone") non
    couvert — mécanisme de détection différent (icacls/Get-Acl), pas encore fait.
*   ✅ **Historique bash/PowerShell contenant des secrets en clair** — `shell_history_secrets`
    (13/08/2026, Linux uniquement pour l'instant ; `Get-History` côté Windows non couvert, laissé
    de côté faute de cas d'usage confirmé — PowerShell ne persiste l'historique entre sessions que
    si `PSReadLine` le configure ainsi).
*   ⚠️ **Clés SSH sans passphrase stockées sur le poste** (non fait — détection fiable nécessite de
    tester chaque clé trouvée, périmètre "quel(s) utilisateur(s) ?" pas tranché) **, ou
    `authorized_keys` trop permissif** — `ssh_authorized_keys_perms` (13/08/2026, root uniquement).
*   ✅ **Partages réseau accessibles en écriture par "Tout le monde"/`Everyone`** —
    `network_shares_everyone` (13/08/2026, Windows/SMB ; Linux/Samba non couvert, périmètre
    initialement pensé pour le parc Windows majoritaire du client).
