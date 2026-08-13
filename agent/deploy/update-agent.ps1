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

  Usage : update-agent.ps1 [-Server http://hôte-allsafe:3000] [-EnrollToken <jeton>]
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

New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
function Log($msg) { "$(Get-Date -Format o)  $msg" | Out-File -FilePath $logFile -Append -Encoding utf8 }

try {
    $latestVersion = (Invoke-RestMethod "$Server/api/agents/latest/version" -TimeoutSec 15).version
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
    Start-Process msiexec.exe -ArgumentList "/i `"$tmp`" /qn /l*v `"$stateDir\install.log`"" -Wait
    Remove-Item $tmp -ErrorAction SilentlyContinue
    Log "Installation terminée."
} else {
    Log "Déjà à jour ($installedVersion)."
}

if (-not (Test-Path $configFile)) {
    if ($EnrollToken) {
        Log "Agent non enrôlé — enrôlement avec le jeton fourni…"
        try {
            & $exe enroll --token $EnrollToken --server $Server *>> $logFile
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
