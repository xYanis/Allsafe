// Solutions + commandes pour chaque check de durcissement (12/08/2026, demande utilisateur —
// "quand je clique sur un cas j'ai des solutions et les commandes pour le faire"). Même principe
// que services/remediation.py côté CVE : Allsafe **propose**, ne modifie jamais rien lui-même —
// l'analyste copie/colle et exécute manuellement après relecture (cf. CLAUDE.md § non-intervention,
// "Générer une recommandation / script" est explicitement listé comme action autorisée).
//
// Clés = mêmes `id` que produits par asset_scanner.py::_check() et agent/src/collect/{linux,windows}.rs
// (cf. docs/AGENTS.md). Certains id sont partagés entre OS (ex. password_max_age) mais le mécanisme
// de remédiation est entièrement différent — deux entrées distinctes, jamais fusionnées.
//
// Chemins de registre Windows repris EXACTEMENT de agent/src/collect/windows.rs (mêmes clés que
// celles lues) — toute divergence romprait la cohérence "ce qu'on corrige = ce qu'on vérifie".
// `New-Item -Force` précède `Set-ItemProperty` quand la clé peut être absente (cas "unknown" déjà
// observés en conditions réelles sur DEPLOYAPP) : `-Force` sur un chemin déjà existant ne fait rien,
// sûr à rejouer.
//
// `category` (13/08/2026) : regroupement affiché côté ComplianceChecklist.jsx — calculé ici plutôt
// que threadé dans le payload Rust/Python (Check n'a pas de champ category côté agent/backend) :
// purement une métadonnée d'affichage, comme le reste de ce fichier, pas une donnée de collecte.

export const REMEDIATION = {
  windows: {
    password_min_length: {
      category: "Mots de passe",
      solution: "Imposer une longueur minimale de mot de passe (12 caractères recommandés) via la stratégie de sécurité locale, ou par GPO si le poste est joint au domaine.",
      commands: ["net accounts /minpwlen:12"],
      note: "Sur un poste joint au domaine, la stratégie de mot de passe du domaine prévaut sur la stratégie locale — passer par une GPO (Ordinateur > Stratégies > Paramètres Windows > Paramètres de sécurité > Stratégies de compte > Stratégie de mot de passe) plutôt que `net accounts` en local.",
    },
    password_max_age: {
      category: "Mots de passe",
      solution: "Imposer un renouvellement du mot de passe tous les 90 jours maximum.",
      commands: ["net accounts /maxpwage:90"],
      note: "Même remarque que ci-dessus si le poste est joint au domaine — GPO plutôt que stratégie locale.",
    },
    rdp_nla: {
      category: "Réseau",
      solution: "Activer l'authentification au niveau réseau (NLA) pour RDP — l'authentification a lieu avant l'ouverture de session complète, réduit la surface d'attaque pré-authentification.",
      commands: [
        'New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Force | Out-Null',
        'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name UserAuthentication -Value 1 -Type DWord',
      ],
    },
    smb1: {
      category: "SMB",
      solution: "Désactiver le protocole SMBv1, obsolète et vulnérable (EternalBlue/WannaCry). Aucun système moderne n'en a besoin sauf compatibilité avec du matériel très ancien.",
      commands: ["Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"],
      warning: "Vérifier qu'aucun équipement legacy (NAS ancien, imprimante réseau ancienne) ne dépend encore de SMBv1 avant de désactiver.",
    },
    smb_signing_server: {
      category: "SMB",
      solution: "Exiger la signature SMB côté serveur — empêche le relais SMB (NTLM relay) sur les connexions entrantes.",
      commands: ['Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name RequireSecuritySignature -Value 1 -Type DWord'],
    },
    smb_signing_client: {
      category: "SMB",
      solution: "Exiger la signature SMB côté client — empêche le relais SMB sur les connexions sortantes.",
      commands: ['Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" -Name RequireSecuritySignature -Value 1 -Type DWord'],
    },
    smb_restrict_anonymous: {
      category: "SMB",
      solution: "Restreindre les sessions anonymes — empêche l'énumération de comptes/partages sans authentification.",
      commands: ['Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name RestrictAnonymous -Value 1 -Type DWord'],
    },
    smb_guest_auth: {
      category: "SMB",
      solution: "Bloquer les connexions invité SMB non sécurisées.",
      commands: [
        'New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" -Force | Out-Null',
        'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" -Name AllowInsecureGuestAuth -Value 0 -Type DWord',
      ],
    },
    smb_encryption: {
      category: "SMB",
      solution: "Activer le chiffrement SMB pour les partages de ce serveur.",
      commands: ["Set-SmbServerConfiguration -EncryptData $true -Force"],
    },
    llmnr: {
      category: "Réseau",
      solution: "Désactiver LLMNR — protocole de résolution de noms sans authentification, exploitable pour du poisoning (type Responder) et la capture de hashs NTLM.",
      commands: [
        'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" -Force | Out-Null',
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" -Name EnableMulticast -Value 0 -Type DWord',
      ],
      note: "Idéalement via GPO (Ordinateur > Modèles d'administration > Réseau > Client DNS > \"Désactiver la résolution de noms de multidiffusion\") pour s'appliquer à tout le parc en une fois.",
    },
    wdigest: {
      category: "Authentification",
      solution: "Désactiver WDigest — sinon les mots de passe restent en clair en mémoire (récupérables via un dump LSASS, type Mimikatz).",
      commands: [
        'New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" -Force | Out-Null',
        'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" -Name UseLogonCredential -Value 0 -Type DWord',
      ],
    },
    ntlm_level: {
      category: "Authentification",
      solution: "Passer le niveau NTLM à 5 (NTLMv2 uniquement, refuse LM et NTLMv1 — tous deux crackables/relayables).",
      commands: ['Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name LmCompatibilityLevel -Value 5 -Type DWord'],
      warning: "Peut casser la compatibilité avec de très vieux systèmes/applications qui n'acceptent que LM/NTLMv1 — tester avant un déploiement large.",
    },
    firewall: {
      category: "Réseau",
      solution: "Réactiver le pare-feu Windows sur le profil concerné.",
      commands: ["Set-NetFirewallProfile -All -Enabled True"],
      note: "Vérifier ensuite qu'aucune règle métier nécessaire n'a été perdue pendant la période où le pare-feu était désactivé.",
    },
    exposed_ports: {
      category: "Réseau",
      solution: "Identifier le service qui écoute sur le port signalé, puis le désactiver s'il n'est pas nécessaire, ou le restreindre par pare-feu si besoin réel.",
      commands: [
        "Get-NetTCPConnection -LocalPort <PORT> | Select-Object OwningProcess",
        "Get-Process -Id <PID>",
        "# Puis, selon le service identifié :",
        "Stop-Service -Name <NomDuService> -Force",
        "Set-Service -Name <NomDuService> -StartupType Disabled",
      ],
    },
    bitlocker: {
      category: "Chiffrement",
      solution: "Activer BitLocker sur le volume système — protège les données au repos en cas de vol/perte de la machine.",
      commands: [
        "Install-WindowsFeature BitLocker -IncludeManagementTools   # si la fonctionnalité n'est pas installée (Server)",
        "Enable-BitLocker -MountPoint \"C:\" -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector",
      ],
      warning: "Nécessite un redémarrage et génère une clé de récupération à sauvegarder impérativement (Azure AD/AD, ou un coffre dédié) avant de continuer.",
    },
    privileged_accounts: {
      category: "Comptes",
      solution: "Revoir la liste des comptes membres du groupe Administrateurs locaux — retirer ceux qui n'ont pas de besoin justifié de droits admin.",
      commands: ["net localgroup administrators <compte> /delete"],
    },
    screen_lock: {
      category: "Système",
      solution: "Imposer un verrouillage automatique après 15 minutes d'inactivité (900s) au maximum.",
      commands: [
        'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop" -Force | Out-Null',
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop" -Name InactivityTimeoutSecs -Value 900 -Type DWord',
      ],
    },
    usb_policy: {
      category: "Système",
      solution: "Désactiver le démarrage automatique du pilote de stockage de masse USB — bloque l'utilisation de clés/disques USB comme support de stockage.",
      commands: ['Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name Start -Value 4 -Type DWord'],
      warning: "Bloque TOUT stockage de masse USB (clés, disques externes) — vérifier qu'aucun usage métier légitime n'en dépend avant d'appliquer à l'échelle du parc.",
    },
    powershell_logging: {
      category: "Journalisation",
      solution: "Activer la journalisation des blocs de script PowerShell — donne une visibilité forensique de première ligne en cas d'exécution malveillante (living-off-the-land).",
      commands: [
        'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Force | Out-Null',
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord',
      ],
    },
    // Backlog complété (13/08/2026, docs/vulnerabilites_securite.md §3.7).
    uac_enabled: {
      category: "Authentification",
      solution: "Réactiver le contrôle de compte utilisateur (UAC) — sans lui, une élévation de privilèges peut se faire silencieusement, sans invite de confirmation.",
      commands: ['Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name EnableLUA -Value 1 -Type DWord'],
      warning: "Nécessite un redémarrage pour prendre effet.",
    },
    powershell_transcription: {
      category: "Journalisation",
      solution: "Activer la transcription PowerShell — capture le texte intégral de chaque session (entrées et sorties), complément à ScriptBlockLogging ci-dessus.",
      commands: [
        'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription" -Force | Out-Null',
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription" -Name EnableTranscripting -Value 1 -Type DWord',
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription" -Name OutputDirectory -Value "C:\\PSTranscripts" -Type String',
      ],
      note: "OutputDirectory optionnel — sans lui, les transcriptions vont dans le dossier personnel de chaque utilisateur (moins pratique à centraliser).",
    },
    defender_realtime: {
      category: "Système",
      solution: "Réactiver la protection temps réel de Windows Defender — vérifier d'abord qu'aucun antivirus tiers n'a été volontairement mis à sa place avant de réactiver.",
      commands: ["Set-MpPreference -DisableRealtimeMonitoring $false"],
      warning: "Ne réactiver que si aucun autre EDR/antivirus n'est en charge de la protection sur ce poste — deux antivirus temps réel actifs simultanément posent souvent problème.",
    },
    admin_account_renamed: {
      category: "Comptes",
      solution: "Renommer le compte administrateur intégré — réduit la surface d'attaque brute-force RDP/SMB, qui cible en priorité le nom par défaut.",
      commands: ['Rename-LocalUser -Name "Administrateur" -NewName "<nouveau-nom>"   # ou "Administrator" selon la langue d\'installation'],
      note: "Le nouveau nom ne doit pas être trivial à deviner (éviter \"admin\", \"root\"...) — combiné idéalement à la désactivation du compte au profit d'un compte nominal avec élévation.",
    },
    network_shares_everyone: {
      category: "Réseau",
      solution: "Retirer l'accès \"Tout le monde\" du partage et le remplacer par des groupes/comptes nommés avec le niveau d'accès strictement nécessaire.",
      commands: [
        "Get-SmbShareAccess -Name <partage>   # lister les autorisations actuelles",
        'Revoke-SmbShareAccess -Name <partage> -AccountName "Everyone" -Force',
        'Grant-SmbShareAccess -Name <partage> -AccountName "<groupe-ou-compte>" -AccessRight Read -Force',
      ],
      warning: "Vérifier qui utilise réellement ce partage avant de révoquer — un accès Everyone parfois délibéré (partage public interne) devient un vrai incident si retiré sans prévenir.",
    },
  },

  linux: {
    password_max_age: {
      category: "Mots de passe",
      solution: "Imposer un renouvellement du mot de passe tous les 90 jours maximum.",
      commands: ["sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs"],
      note: "Ne s'applique qu'aux nouveaux mots de passe/comptes — pour forcer un renouvellement immédiat d'un compte existant : `sudo chage -M 90 <utilisateur>`.",
    },
    password_min_length: {
      category: "Mots de passe",
      solution: "Imposer une longueur minimale de mot de passe (12 caractères recommandés).",
      commands: ["sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs"],
      note: "PASS_MIN_LEN est souvent ignoré par les distributions récentes (délégué à PAM) — pour une application réelle, installer et configurer pam_pwquality : `sudo apt install libpam-pwquality` puis `minlen = 12` dans `/etc/security/pwquality.conf`.",
    },
    ssh_root_login: {
      category: "SSH",
      solution: "Interdire la connexion SSH directe en root — passer par un compte nominal + sudo.",
      commands: [
        "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
        "sudo systemctl restart sshd",
      ],
    },
    ssh_password_auth: {
      category: "SSH",
      solution: "Désactiver l'authentification SSH par mot de passe au profit des clés uniquement.",
      commands: [
        "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
        "sudo systemctl restart sshd",
      ],
      warning: "Vérifier qu'une connexion par clé SSH fonctionne AVANT d'appliquer, sous peine de se retrouver bloqué dehors sans accès console.",
    },
    ssh_weak_algos: {
      category: "SSH",
      solution: "Retirer les algorithmes SSH faibles (échange de clé/chiffrement/MAC) de la configuration, ne garder que des algorithmes modernes.",
      commands: [
        "echo 'KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512' | sudo tee -a /etc/ssh/sshd_config",
        "echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com' | sudo tee -a /etc/ssh/sshd_config",
        "echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com' | sudo tee -a /etc/ssh/sshd_config",
        "sudo systemctl restart sshd",
      ],
    },
    exposed_ports: {
      category: "Réseau",
      solution: "Identifier le service qui écoute sur le port signalé, puis le désactiver s'il n'est pas nécessaire, ou le restreindre par pare-feu si besoin réel.",
      commands: [
        "sudo ss -tulnp | grep :<PORT>",
        "sudo systemctl stop <nom-du-service>",
        "sudo systemctl disable <nom-du-service>",
      ],
    },
    disk_encryption: {
      category: "Chiffrement",
      solution: "Chiffrer le volume avec LUKS — impossible à chaud sur une partition déjà en place sans migration des données, c'est un chantier à planifier, pas une commande unique.",
      commands: [
        "# Sur un NOUVEAU volume/disque uniquement (opération destructrice sur les données existantes) :",
        "sudo cryptsetup luksFormat /dev/sdX",
        "sudo cryptsetup open /dev/sdX volume_chiffre",
      ],
      warning: "Chiffrer un volume déjà en production nécessite de migrer les données vers un nouveau volume LUKS (sauvegarde complète, bascule, validation) — à planifier comme un vrai chantier, jamais en exécution directe sur un système en production.",
    },
    privileged_accounts: {
      category: "Comptes",
      solution: "Revoir la liste des comptes membres du groupe sudo/wheel — retirer ceux qui n'ont pas de besoin justifié de droits élevés.",
      commands: [
        "sudo deluser <utilisateur> sudo      # Debian/Ubuntu",
        "sudo gpasswd -d <utilisateur> wheel  # RHEL/Fedora",
      ],
    },
    screen_lock: {
      category: "Système",
      solution: "Activer le verrouillage automatique d'écran (GNOME) après 5 minutes d'inactivité.",
      commands: [
        "gsettings set org.gnome.desktop.screensaver lock-enabled true",
        "gsettings set org.gnome.desktop.session idle-delay 300",
      ],
      note: "Commandes GNOME uniquement (même limite que la détection) — sur un autre environnement de bureau, l'équivalent dépend du DE utilisé.",
    },
    usb_policy: {
      category: "Système",
      solution: "Bloquer le stockage de masse USB via une règle udev.",
      commands: [
        'echo \'ACTION=="add", SUBSYSTEM=="usb", ATTR{bDeviceClass}=="08", ATTR{authorized}="0"\' | sudo tee /etc/udev/rules.d/99-usb-storage-block.rules',
        "sudo udevadm control --reload-rules",
      ],
      warning: "Bloque TOUT stockage de masse USB — vérifier qu'aucun usage métier légitime n'en dépend avant d'appliquer à l'échelle du parc.",
    },
    // Backlog complété (13/08/2026, docs/vulnerabilites_securite.md §3.7).
    sudo_nopasswd: {
      category: "Comptes",
      solution: "Retirer la directive NOPASSWD — une élévation sudo sans mot de passe permet à quiconque compromet la session du compte concerné d'obtenir root immédiatement.",
      commands: ["sudo visudo -f /etc/sudoers.d/<fichier-concerné>   # éditer directement, jamais sed sur sudoers"],
      warning: "Ne jamais éditer /etc/sudoers ou ses fragments avec sed/écriture directe — une erreur de syntaxe peut bloquer TOUT accès sudo sur la machine. Toujours passer par visudo (valide la syntaxe avant d'enregistrer).",
    },
    ssh_authorized_keys_perms: {
      category: "SSH",
      solution: "Corriger les permissions du fichier authorized_keys — trop permissif, d'autres comptes locaux pourraient y ajouter leur propre clé et obtenir un accès SSH root.",
      commands: ["sudo chmod 600 /root/.ssh/authorized_keys"],
    },
    world_writable_files: {
      category: "Système",
      solution: "Retirer le droit d'écriture pour tous sur les fichiers signalés — vérifier d'abord pourquoi ce droit a été posé (parfois volontaire, ex. logs partagés) avant de le retirer.",
      commands: [
        "find /etc /usr/local /opt -xdev -type f -perm -0002 2>/dev/null   # lister tous les fichiers concernés",
        "sudo chmod o-w <fichier>",
      ],
    },
    shell_history_secrets: {
      category: "Journalisation",
      solution: "Retirer les secrets de l'historique et faire tourner les identifiants exposés — un secret qui a transité en clair dans une commande shell doit être considéré compromis, pas seulement effacé.",
      commands: [
        "history -c && > ~/.bash_history   # efface l'historique de la session courante",
        "# Puis, indispensable : révoquer/régénérer chaque secret identifié — l'effacement seul ne suffit pas",
      ],
      warning: "Effacer l'historique ne suffit jamais seul — si un secret y a transité en clair, il doit être considéré compromis et changé, pas juste caché.",
    },
  },

  // Durcissement switches Cisco IOS/IOS-XE (13/08/2026, services/switch_hardening.py) — mêmes
  // id que produits côté backend. Parc réseau confirmé majoritairement Cisco : commandes IOS
  // spécifiques, pas une abstraction multi-vendor.
  network: {
    telnet_disabled: {
      category: "SSH",
      solution: "Restreindre les lignes VTY au SSH uniquement — Telnet transmet identifiants et commandes en clair sur le réseau.",
      commands: [
        "line vty 0 4",
        " transport input ssh",
        "exit",
      ],
      warning: "Vérifier qu'une session SSH fonctionne AVANT de retirer Telnet — une erreur de configuration SSH sans Telnet en secours peut couper tout accès distant à l'équipement.",
    },
    console_vty_timeout: {
      category: "SSH",
      solution: "Configurer un délai d'inactivité sur les lignes VTY — une session laissée ouverte sans coupure reste exploitable indéfiniment par quiconque accède au poste resté connecté.",
      commands: [
        "line vty 0 4",
        " exec-timeout 10 0",
        "exit",
      ],
    },
    snmp_default_community: {
      category: "Authentification",
      solution: "Retirer les communautés SNMP par défaut (public/private) et les remplacer par une communauté forte, restreinte par ACL.",
      commands: [
        "no snmp-server community public",
        "no snmp-server community private",
        "access-list 99 permit <IP-du-serveur-de-supervision>",
        "snmp-server community <communauté-forte> RO 99",
      ],
      warning: "Coordonner ce changement avec l'outil de supervision (PRTG/Meraki...) qui interroge cet équipement — mettre à jour sa configuration avec la nouvelle communauté au même moment, sinon la supervision de cet équipement s'interrompt.",
    },
    password_encryption: {
      category: "Mots de passe",
      solution: "Activer le chiffrement des mots de passe dans la configuration — sans ça, les mots de passe de type 0 apparaissent en clair dans un `show running-config`.",
      commands: ["service password-encryption"],
      note: "Chiffrement réversible (type 7, faible) — protège seulement contre la lecture directe d'un show running-config exporté, pas contre une attaque dédiée. Préférer des secrets de type 8/9 (algorithme scrypt) où disponible.",
    },
    aaa_authentication: {
      category: "Authentification",
      solution: "Activer AAA pour centraliser l'authentification (RADIUS/TACACS+) plutôt qu'un compte local partagé.",
      commands: [
        "aaa new-model",
        "aaa authentication login default group tacacs+ local",
        "tacacs-server host <IP-serveur-TACACS>",
        "tacacs-server key <clé-partagée>",
      ],
      warning: "Toujours garder \"local\" en repli dans la méthode d'authentification (comme ci-dessus) et tester une session AVANT de fermer la session en cours — une erreur de configuration AAA sans repli peut verrouiller tout accès à l'équipement, y compris console.",
    },
    banner_motd: {
      category: "Système",
      solution: "Configurer une bannière légale affichée à la connexion — rappelle le cadre d'usage autorisé, utile en cas de poursuite pour accès non autorisé.",
      commands: [
        "banner motd ^C",
        "Accès réservé au personnel autorisé. Toute connexion est journalisée.",
        "^C",
      ],
    },
    syslog_configured: {
      category: "Journalisation",
      solution: "Envoyer les journaux vers un serveur syslog centralisé — sans ça, l'historique des événements est perdu au redémarrage (buffer local uniquement).",
      commands: [
        "logging host <IP-serveur-syslog>",
        "logging trap informational",
      ],
    },
    ntp_configured: {
      category: "Système",
      solution: "Synchroniser l'horloge sur un serveur NTP — sans horodatage fiable, les journaux (y compris syslog ci-dessus) sont difficilement exploitables en cas d'incident.",
      commands: ["ntp server <IP-ou-nom-serveur-NTP>"],
    },
  },

  // Durcissement ESXi (13/08/2026, services/vsphere_hardening.py) — mêmes id que produits
  // côté backend. Commandes esxcli/vim-cmd à exécuter depuis une session SSH ou la console
  // DCUI de l'hôte, jamais lancées par Allsafe (cf. CLAUDE.md § non-intervention).
  esxi: {
    lockdown_mode: {
      category: "Système",
      solution: "Activer le mode verrouillage (Lockdown Mode) — restreint les actions directes sur l'hôte (DCUI/vSphere Client local) au strict compte root ou aux utilisateurs listés en exception, force le passage par vCenter pour tout le reste.",
      commands: ["vim-cmd hostsvc/lockdown_mode_enter"],
      warning: "Vérifier l'accès vCenter AVANT d'activer — le mode strict désactive aussi l'accès DCUI local, un vCenter injoignable peut alors couper toute administration de l'hôte.",
      note: "Se configure aussi depuis vSphere Client : Hôte > Configurer > Système > Profil de sécurité > Mode verrouillage.",
    },
    ssh_service: {
      category: "SSH",
      solution: "Désactiver le service SSH (TSM-SSH) — laissé actif en permanence, il élargit la surface d'attaque de l'hôte sans bénéfice si l'administration passe par vCenter.",
      commands: ["vim-cmd hostsvc/stopservice TSM-SSH"],
      note: "Pour l'empêcher de redémarrer au reboot, régler sa politique de démarrage sur \"Manuel\" (vSphere Client : Profil de sécurité > Services > SSH > Modifier la politique de démarrage) — une simple commande esxcli ne suffit pas pour ça.",
    },
    ntp_configured: {
      category: "Système",
      solution: "Synchroniser l'horloge sur un serveur NTP — sans horodatage fiable, les journaux (y compris syslog ci-dessous) sont difficilement exploitables en cas d'incident.",
      commands: [
        "esxcli system ntp set --server=<IP-ou-nom-serveur-NTP>",
        "esxcli system ntp set --enabled=true",
      ],
    },
    syslog_configured: {
      category: "Journalisation",
      solution: "Envoyer les journaux vers un serveur syslog centralisé — sans ça, l'historique des événements est perdu au redémarrage (buffer local uniquement).",
      commands: [
        "esxcli system syslog config set --loghost='udp://<IP-serveur-syslog>:514'",
        "esxcli system syslog reload",
      ],
    },
    account_lockout: {
      category: "Comptes",
      solution: "Activer le verrouillage de compte après un nombre défini d'échecs de connexion — sans ça, un compte local ESXi est exposé à une attaque par force brute sans limite de tentatives.",
      commands: ["esxcli system settings advanced set -o /Security/AccountLockFailures -i 5"],
    },
  },
}

// `os` peut être une valeur détaillée ("Windows Server 2019", "Debian GNU/Linux 12"...) — on ne
// garde que la famille (même logique que collect::os_name() côté agent Rust, cf. docs/AGENTS.md).
// `assetType` (13/08/2026, durcissement switches) prime sur la détection par `os` : un actif
// réseau n'a pas de champ `os` fiable en famille Windows/Linux (modèle Meraki/PRTG, version IOS...).
// ESXi (13/08/2026, durcissement vSphere) : `asset_type="server"` comme un serveur classique
// (décision volontaire, cf. docs/ARCHITECTURE.md § Intégration vSphere) — se distingue donc
// par `os` ("VMware ESXi", posé par services/vsphere_matcher.py), pas par assetType.
export function remediationFor(os, checkId, assetType) {
  const family = assetType === 'network'
    ? 'network'
    : /vmware esxi/i.test(os || '')
      ? 'esxi'
      : (/windows/i.test(os || '') ? 'windows' : 'linux')
  return REMEDIATION[family]?.[checkId] || null
}

// Catégorie d'un check (13/08/2026, regroupement ComplianceChecklist.jsx) — "Autres" en repli
// pour un id qui n'aurait pas (encore) d'entrée ici, jamais une erreur d'affichage.
export function categoryFor(os, checkId, assetType) {
  return remediationFor(os, checkId, assetType)?.category || 'Autres'
}
