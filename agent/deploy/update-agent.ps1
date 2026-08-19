<#
  Met à jour allsafe-agent depuis le serveur Allsafe puis pousse un check-in — prévu
  pour une tâche planifiée déployée par GPO (Group Policy Preferences > Scheduled
  Tasks) sur les postes déjà enrôlés. Remplace l'usage direct de `schtasks ... checkin`
  documenté dans agent/README.md § Installation. Jamais lancé par Allsafe lui-même
  (respect du principe de non-intervention, cf. CLAUDE.md §1) : c'est le poste qui vient
  chercher sa mise à jour, Allsafe ne se connecte/n'exécute jamais rien dessus.

  N'enrôle un poste tout seul QUE si -EnrollToken est fourni (typiquement un jeton
  réutilisable "parc", cf. docs/AGENTS.md § Enrôlement à l'échelle, embarqué dans cette
  même tâche planifiée GPO) — sans lui, un poste non enrôlé reste signalé dans le log.

  **17/08/2026 — aussi la commande recommandée pour un premier poste isolé** (au lieu du
  `msiexec` + `allsafe-agent enroll` manuels documentés dans agent/README.md § Installation) :
  ce script télécharge le .msi, l'installe et enrôle en une seule commande, avec des erreurs
  visibles à l'écran plutôt que le silence de `msiexec /qn` (incident réel, poste aos12 —
  échec d'install sans élévation resté invisible jusqu'à relancer avec `/l*v` à la main).

  Usage : update-agent.ps1 -Server http://hôte-allsafe:3000 -EnrollToken <jeton>
#>
param(
    [string]$Server = "http://192.168.105.84:3000",
    [string]$EnrollToken = ""
)

$ErrorActionPreference = "Stop"
$exe        = "C:\Program Files\Allsafe Agent\allsafe-agent.exe"
$configFile = "$env:ProgramData\allsafe-agent\agent.json"
$stateDir   = "$env:ProgramData\allsafe-agent"
$logFile    = "$stateDir\update.log"

# Élévation (17/08/2026) — sans ce contrôle, `msiexec`/`Uninstall-Package`/`Restart-Service`
# échouent en silence sous un jeton non-admin (être membre du groupe Administrateurs ne
# suffit pas : il faut une session PowerShell lancée "en tant qu'administrateur", UAC).
# Vérifié et arrêté ICI, avant toute action, plutôt que de laisser echouer plus loin un
# `Start-Process msiexec ... -Wait` dont le code de sortie n'était pas contrôlé.
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) {
    Write-Error "Ce script doit tourner dans un PowerShell lancé « en tant qu'administrateur » (élévation UAC) — être membre du groupe Administrateurs ne suffit pas. Ferme cette fenêtre et rouvre PowerShell via clic droit > Exécuter en tant qu'administrateur."
    exit 1
}

New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
# Miroir console (17/08/2026) : avant, tout partait uniquement dans update.log — en usage
# manuel/interactif (premier poste), un échec silencieux dans le fichier est aussi invisible
# qu'un `msiexec /qn` sans log. Write-Host garde le comportement GPO/planifié inchangé (le
# fichier reste la trace faisant foi) tout en rendant l'exécution manuelle diagnosticable.
function Log($msg) {
    "$(Get-Date -Format o)  $msg" | Out-File -FilePath $logFile -Append -Encoding utf8
    Write-Host $msg
}

try {
    $versionInfo = Invoke-RestMethod "$Server/api/agents/latest/version" -TimeoutSec 15
    $latestVersion = $versionInfo.version
} catch {
    Log "Échec de récupération de la version côté serveur ($Server) : $_"
    exit 1
}

$installedVersion = $null
if (Test-Path $exe) {
    $installedVersion = ((& $exe --version) -split ' ')[-1]
}

if ($installedVersion -ne $latestVersion) {
    Log "Mise à jour : $(if ($installedVersion) { $installedVersion } else { 'aucune' }) -> $latestVersion"
    $tmp = "$env:TEMP\allsafe-agent-latest.msi"
    try {
        Invoke-WebRequest "$Server/api/agents/latest/windows" -OutFile $tmp -TimeoutSec 120
    } catch {
        Log "Échec du téléchargement du .msi : $_"
        exit 1
    }

    # Vérification d'intégrité (18/08/2026, cf. audit/AUDIT_SECURITE.md #13/#25 — même
    # correctif que agent/src/install.rs::apply_update) : sans elle, ce script exécutait tout
    # .msi reçu du serveur avec des droits admin déjà confirmés (élévation vérifiée plus haut)
    # — un MITM réseau ou un backend compromis suffisait à en faire un vecteur RCE sur
    # l'ensemble du parc via cette même tâche planifiée GPO.
    if (-not $versionInfo.sha256_windows) {
        Log "Le serveur ne publie pas l'empreinte SHA-256 attendue — installation refusée par sécurité (backend obsolète ou compromis)."
        Remove-Item $tmp -ErrorAction SilentlyContinue
        exit 1
    }
    $actualHash = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash
    if ($actualHash.ToLower() -ne $versionInfo.sha256_windows.ToLower()) {
        Log "Empreinte du .msi invalide (attendu $($versionInfo.sha256_windows), obtenu $actualHash) — installation refusée, le paquet a peut-être été altéré en transit."
        Remove-Item $tmp -ErrorAction SilentlyContinue
        exit 1
    }

    # Uninstall-Package (pas `msiexec /x` pointé sur ce fichier) : chaque build wixl
    # génère un ProductCode aléatoire (Product Id="*" dans wix/main.wxs, pas de
    # <MajorUpgrade>) — /x sur le nouveau .msi ne retrouverait pas l'ancien produit
    # installé. Constaté en conditions réelles le 13/08/2026 sur DEPLOYAPP.
    #
    # Pas de Stop-Service/Start-Service manuel ici (13/08/2026) : `wix/main.wxs::
    # ServiceControl` (Stop="both", Remove="uninstall", Start="install") est exécuté par
    # msiexec lui-même au bon moment de sa propre séquence (arrêt+suppression du service
    # AVANT la suppression des fichiers pendant l'uninstall, démarrage APRÈS la copie
    # pendant l'install) — plus fiable qu'un arrêt manuel décorrélé de cette séquence.
    $installed = Get-Package -Name "Allsafe Agent" -ProviderName msi -ErrorAction SilentlyContinue
    if ($installed) {
        $installed | Uninstall-Package -Force | Out-Null
    }
    $msiProcess = Start-Process msiexec.exe -ArgumentList "/i `"$tmp`" /qn /l*v `"$stateDir\install.log`"" -Wait -PassThru
    Remove-Item $tmp -ErrorAction SilentlyContinue
    # Code de sortie contrôlé (17/08/2026) — avant, un échec silencieux de msiexec (droits,
    # msi corrompu...) laissait le script continuer comme si l'install avait réussi, jusqu'à
    # l'échec du `& $exe enroll` plus bas sans lien évident avec la vraie cause.
    if ($msiProcess.ExitCode -ne 0) {
        Log "Échec de l'installation (code $($msiProcess.ExitCode)) — détail dans $stateDir\install.log"
        exit 1
    }
    Log "Installation terminée."
} else {
    Log "Déjà à jour ($installedVersion)."
}

if (-not (Test-Path $configFile)) {
    if ($EnrollToken) {
        Log "Agent non enrôlé — enrôlement avec le jeton fourni…"
        try {
            & $exe enroll --token $EnrollToken --server $Server 2>&1 | Tee-Object -FilePath $logFile -Append
            Log "Enrôlement réussi."
            Restart-Service AllsafeAgent -ErrorAction SilentlyContinue
        } catch {
            Log "Échec de l'enrôlement — jeton invalide/expiré/déjà à son quota d'usages ? $_"
        }
    } else {
        Log "Agent non enrôlé (pas de $configFile) — générez un jeton dans Allsafe > Sécurité > Agents (ou passez -EnrollToken pour un enrôlement automatique)."
    }
}

$service = Get-Service -Name AllsafeAgent -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Log "Service AllsafeAgent actif — check-in géré par la boucle persistante, pas ce script."
} elseif (Test-Path $configFile) {
    & $exe checkin
    Log "Check-in envoyé."
}
