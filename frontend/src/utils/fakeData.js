// Mode Présentation ("Anonyme") — jeu de données 100% fictif + anonymisation
// des données réelles à l'affichage. Rien ici n'est envoyé au backend ni
// stocké en base : c'est un habillage d'affichage côté navigateur uniquement,
// pour pouvoir démontrer l'application sans divulguer d'infos du parc réel.

function hashStr(str) {
  let h = 2166136261
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return h >>> 0
}

export function isFakeId(id) {
  return typeof id === 'string' && id.startsWith('demo-')
}

const FAKE_DOMAIN = 'demo.local'

const FAKE_ASSET_NAMES = [
  'SRV-WEB-01', 'SRV-WEB-02', 'SRV-SQL-01', 'SRV-SQL-02', 'SRV-AD-01', 'SRV-AD-02',
  'SRV-FILE-01', 'SRV-FILE-02', 'SRV-BACKUP-01', 'SRV-MAIL-01', 'SRV-APP-01', 'SRV-APP-02',
  'SRV-DNS-01', 'SRV-VPN-01', 'SRV-PRINT-01', 'SRV-CITRIX-01', 'SRV-ERP-01', 'SRV-GLPI-01',
  'WKS-DIR-01', 'WKS-COMPTA-01', 'WKS-RH-01', 'WKS-DEV-01', 'WKS-SUPPORT-01', 'WKS-ACCUEIL-01',
]

// Pool distinct de celui des actifs 100% fictifs (FAKE_ASSET_NAMES est déjà
// entièrement consommé, un par actif de FAKE_ASSETS) — évite qu'un actif réel
// anonymisé porte, par coïncidence de hash, le même nom qu'un actif de
// démonstration déjà affiché dans la même liste.
const ANON_REAL_NAMES = [
  'SRV-PROD-A1', 'SRV-PROD-B2', 'SRV-PROD-C3', 'SRV-PROD-D4', 'SRV-PROD-E5',
  'SRV-PROD-F6', 'SRV-PROD-G7', 'SRV-PROD-H8', 'SRV-PROD-I9', 'SRV-PROD-J10',
  'WKS-PROD-K1', 'WKS-PROD-L2', 'WKS-PROD-M3', 'WKS-PROD-N4', 'WKS-PROD-O5',
]

export const FAKE_VALIDATORS = ['A. Lambert', 'C. Moreau', 'S. Girard', 'M. Petit', 'J. Roche', 'É. Faure']

const OS_POOL = [
  { os: 'Windows Server', os_version: '2019', type: 'server' },
  { os: 'Windows Server', os_version: '2022', type: 'server' },
  { os: 'Windows Server', os_version: '2016', type: 'server' },
  { os: 'Ubuntu', os_version: '22.04 LTS', type: 'server' },
  { os: 'Debian', os_version: '12 (bookworm)', type: 'server' },
  { os: 'Debian', os_version: '11 (bullseye)', type: 'server' },
  { os: 'Windows 11', os_version: 'Pro 23H2', type: 'workstation' },
  { os: 'Windows 10', os_version: 'Pro 22H2', type: 'workstation' },
]

const APP_POOL = [
  ['7-Zip', '23.01'], ['Google Chrome', '124.0.6367'], ['Mozilla Firefox', '124.0.1'],
  ['Adobe Acrobat Reader DC', '24.001'], ['Java 8 Update', '411'], ['.NET Framework', '4.8.1'],
  ['OpenSSH', '9.6p1'], ['nginx', '1.24.0'], ['PostgreSQL Client', '15.6'], ['VLC media player', '3.0.20'],
  ['Notepad++', '8.6.4'], ['Git', '2.44.0'], ['Python', '3.11.8'], ['Docker Engine', '25.0.3'],
  ['WinRAR', '6.24'], ['PuTTY', '0.80'], ['Zoom', '5.17.5'], ['Microsoft Edge', '123.0'], ['Wireshark', '4.2.4'],
]

function pickApps(seedIdx) {
  const count = 6 + (seedIdx % 8)
  const out = []
  for (let i = 0; i < count; i++) {
    const [name, version] = APP_POOL[(seedIdx * 3 + i * 7) % APP_POOL.length]
    if (!out.some(a => a.name === name)) out.push({ name, version })
  }
  return out
}

function fakeMac(i) {
  const parts = [0x00, 0x1a, 0x2b, (i * 13) % 256, (i * 29) % 256, (i * 47) % 256]
  return parts.map(p => p.toString(16).padStart(2, '0').toUpperCase()).join(':')
}

const FAKE_IPS = FAKE_ASSET_NAMES.map((_, i) => `10.99.${20 + Math.floor(i / 20)}.${10 + i}`)

// Checks de durcissement fictifs — mêmes id/label que ceux réellement produits par
// backend/services/asset_scanner.py (_build_compliance_windows/_linux), pour que la page
// Durcissement affiche une checklist crédible en mode Présentation plutôt qu'une case vide
// (jusqu'ici `last_scan_result: null` sur les FAKE_ASSETS, donc `checks: []` partout).
const WIN_COMPLIANCE_CHECKS = [
  { id: 'password_min_length', label: 'Longueur minimale du mot de passe', ok: '14 caractères', warn: '6 caractères' },
  { id: 'password_max_age', label: 'Âge maximal du mot de passe', ok: '60 jours', warn: "N'expire jamais" },
  { id: 'rdp_nla', label: 'Authentification niveau réseau (RDP/NLA)', ok: 'Activée', warn: 'Désactivée' },
  { id: 'smb1', label: 'SMBv1 activé', ok: 'Désactivé', warn: 'Activé' },
  { id: 'smb_signing_server', label: 'Signature SMB requise (serveur)', ok: 'Requise', warn: 'Non requise — expose au relais SMB entrant' },
  { id: 'smb_signing_client', label: 'Signature SMB requise (client)', ok: 'Requise', warn: 'Non requise — expose au relais SMB sortant' },
  { id: 'smb_restrict_anonymous', label: 'Sessions anonymes restreintes', ok: 'Restreintes', warn: 'Non restreintes — énumération sans authentification possible' },
  { id: 'smb_guest_auth', label: 'Connexions invité non sécurisées', ok: 'Bloquées', warn: 'Autorisées' },
  { id: 'smb_encryption', label: 'Chiffrement SMB', ok: 'Activé', warn: 'Désactivé' },
  { id: 'llmnr', label: 'LLMNR désactivé', ok: 'Désactivé', warn: 'Activé — expose au poisoning LLMNR/NBT-NS (type Responder)' },
  { id: 'wdigest', label: 'WDigest désactivé', ok: 'Désactivé', warn: 'Activé — mots de passe en clair exposés en mémoire (dump LSASS)' },
  { id: 'ntlm_level', label: 'Niveau NTLM (LmCompatibilityLevel)', ok: 'Niveau 5 (NTLMv2 uniquement)', warn: 'Niveau 1 — NTLMv1 accepté, crackable/relayable' },
  { id: 'firewall', label: 'Pare-feu Windows (profil standard)', ok: 'Activé', warn: 'Désactivé' },
]

const LINUX_COMPLIANCE_CHECKS = [
  { id: 'password_max_age', label: 'Âge maximal du mot de passe', ok: '90 jours (PASS_MAX_DAYS)', warn: '99999 jours (PASS_MAX_DAYS)' },
  { id: 'password_min_length', label: 'Longueur minimale du mot de passe', ok: '12 caractères (PASS_MIN_LEN)', warn: '5 caractères (PASS_MIN_LEN)' },
  { id: 'ssh_root_login', label: 'Connexion SSH root directe', ok: 'PermitRootLogin=no', warn: 'PermitRootLogin=yes' },
  { id: 'ssh_password_auth', label: 'Authentification SSH par mot de passe', ok: 'PasswordAuthentication=no', warn: 'PasswordAuthentication=yes' },
  { id: 'ssh_weak_algos', label: 'Algorithmes SSH faibles', ok: 'Aucun algo faible (échange de clé/chiffrement/MAC) accepté', warn: 'Encore acceptés : aes128-cbc' },
]

const EXPOSED_PORTS_CHECK = { id: 'exposed_ports', label: 'Services exposés à risque', ok: 'Aucun service historiquement non sécurisé détecté sur les ports en écoute', warn: 'VNC (souvent sans chiffrement) (port 5900)' }

function buildFakeCompliance(seedIdx, isWin) {
  const pool = [...(isWin ? WIN_COMPLIANCE_CHECKS : LINUX_COMPLIANCE_CHECKS), EXPOSED_PORTS_CHECK]
  return pool.map((c, i) => {
    const warn = (seedIdx + i * 3) % 5 === 0
    return { id: c.id, label: c.label, status: warn ? 'warn' : 'ok', detail: warn ? c.warn : c.ok }
  })
}

function buildFakeOsEol(seedIdx, osInfo) {
  const warn = seedIdx % 6 === 0
  return {
    id: 'os_eol', label: "Fin de support de l'OS", status: warn ? 'warn' : 'ok',
    detail: warn ? `${osInfo.os} ${osInfo.os_version} — support étendu terminé` : `${osInfo.os} ${osInfo.os_version} — support actif`,
  }
}

export const FAKE_ASSETS = FAKE_ASSET_NAMES.map((name, i) => {
  const osInfo = OS_POOL[i % OS_POOL.length]
  const isWin = osInfo.os.startsWith('Windows')
  const apps = pickApps(i)
  return {
    id: `demo-asset-${i + 1}`,
    name,
    hostname: `${name.toLowerCase()}.${FAKE_DOMAIN}`,
    ip_address: FAKE_IPS[i],
    os: osInfo.os,
    os_version: osInfo.os_version,
    asset_type: osInfo.type,
    tags: {},
    cpe_list: [],
    status: 'active',
    last_scan: new Date(Date.now() - ((i * 37) % 20 + 1) * 86400000).toISOString(),
    source: i % 3 === 0 ? 'active_directory' : i % 3 === 1 ? 'ssh' : 'manual',
    package_count: apps.length,
    installed_packages: apps,
    hardware: {
      cpu: isWin ? 'Intel Xeon Silver 4210' : 'AMD EPYC 7302P',
      arch: '64 bits (x64)',
      cores: [4, 8, 16][i % 3],
      ram_gb: [8, 16, 32, 64][i % 4],
      disks: [{ name: 'C:', total_gb: 200 }, ...(i % 2 === 0 ? [{ name: 'D:', total_gb: 500 }] : [])],
      mac: fakeMac(i),
      open_ports: isWin ? [3389, 445, 5985] : [22, 80, 443],
    },
    last_scan_result: { compliance: { checks: buildFakeCompliance(i, isWin) } },
    os_eol_check: buildFakeOsEol(i, osInfo),
    scan_username: null,
    has_scan_password: false,
    vuln_count: 0, // complété plus bas une fois FAKE_VULNERABILITIES construit
  }
})

function findFakeAsset(id) {
  return FAKE_ASSETS.find(a => a.id === id)
}

// ─────────────────────────────────────────────────────────────────────────
// Agents fictifs (module Inventaire > Agents) — un sous-ensemble des actifs
// fictifs seulement (tout le parc n'a pas forcément un agent posé, cf. CLAUDE.md), pas
// un par FAKE_ASSETS. `daysAgoIso` est défini plus bas dans ce fichier (function
// déclarée, donc hoistée — utilisable ici avant sa définition textuelle).
// ─────────────────────────────────────────────────────────────────────────
const FAKE_AGENT_ASSET_INDEXES = [0, 2, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21]

export const FAKE_AGENTS = FAKE_AGENT_ASSET_INDEXES.map((assetIdx, i) => {
  const asset = FAKE_ASSETS[assetIdx]
  const os = asset.os.startsWith('Windows') ? 'windows' : 'linux'
  // Modulo volontairement différent de FAKE_VALIDATORS.length (6) — sinon les agents révoqués
  // tombent toujours sur le même validateur (même reste), au lieu de varier.
  const revoked = i % 5 === 4
  const enrolledDaysAgo = 5 + i * 3
  const lastSeenMinutesAgo = [4, 18, 55, 240][i % 4]
  return {
    id: `demo-agent-${i + 1}`,
    asset_id: asset.id,
    asset_name: asset.name,
    hostname: asset.name,
    os,
    asset_os: asset.os,
    asset_os_version: asset.os_version,
    status: revoked ? 'revoked' : 'enrolled',
    enrolled_at: daysAgoIso(enrolledDaysAgo),
    last_seen_at: revoked ? daysAgoIso(30) : new Date(Date.now() - lastSeenMinutesAgo * 60000).toISOString(),
    agent_version: os === 'windows' ? '0.1.21' : '0.1.10',
    outdated: i % 7 === 0,
    pending_scan_requested_at: null,
    ping_requested_at: null,
    last_pong_at: !revoked && i % 3 === 0 ? new Date(Date.now() - 90_000).toISOString() : null,
    last_pong_ms: !revoked && i % 3 === 0 ? 80 + i * 6 : null,
    last_gap_started_at: null,
    last_gap_failed_attempts: null,
    revoked_at: revoked ? daysAgoIso(2 + i) : null,
    revoked_by: revoked ? FAKE_VALIDATORS[i % FAKE_VALIDATORS.length] : null,
    token_status: 'exhausted',
    enrollment_token_created_at: daysAgoIso(enrolledDaysAgo + 1),
    // Même info, deux noms de champ selon l'endpoint réel (list_agents vs /agents/history,
    // cf. routers/agents.py) — les deux couverts pour que les 3 pages du module l'affichent.
    enrollment_token_created_by: FAKE_VALIDATORS[i % FAKE_VALIDATORS.length],
    enrolled_by: FAKE_VALIDATORS[i % FAKE_VALIDATORS.length],
  }
})

// Frise "Historique des contacts" (AgentHistory.jsx) pour un agent fictif — construite à la
// volée plutôt que stockée, pas d'appel API (l'agent n'existe pas en base). Une coupure sur
// 2 pour la variété visuelle, jamais sur le check-in le plus récent (redondant avec
// last_seen_at déjà affiché en haut de page).
export function buildFakeAgentCheckins(agent) {
  if (!agent) return { items: [], total: 0 }
  const count = 5
  const items = Array.from({ length: count }, (_, k) => {
    const hoursAgo = k * 1 + (agent.status === 'revoked' ? 30 * 24 : 0)
    const hasGap = k === 3
    return {
      id: `demo-checkin-${agent.id}-${k}`,
      checked_in_at: new Date(Date.now() - hoursAgo * 3600_000).toISOString(),
      on_demand: k === 0 && agent.status !== 'revoked',
      package_count: 6 + ((k + hashStr(agent.id)) % 8),
      agent_version: agent.agent_version,
      gap_started_at: hasGap ? new Date(Date.now() - (hoursAgo + 2) * 3600_000).toISOString() : null,
      gap_failed_attempts: hasGap ? 3 : null,
    }
  })
  // Entrée de ping (17/08/2026, cf. AgentHistory.jsx::CheckinEntry `is_ping`) — présente
  // seulement si l'agent a un dernier ping enregistré (FAKE_AGENTS::last_pong_at), pour ne
  // pas afficher un évènement sans le StatTile "Dernier ping" qui va avec.
  if (agent.last_pong_at) {
    items.unshift({
      id: `demo-checkin-${agent.id}-ping`,
      is_ping: true,
      checked_in_at: agent.last_pong_at,
      pong_ms: agent.last_pong_ms,
    })
  }
  return { items, total: items.length }
}

// ─────────────────────────────────────────────────────────────────────────
// Notes de version fictives (Param​ètres > Notes de version + sa page miroir Agents >
// Notes de version) — contenu générique, jamais lié à une vraie décision produit (le
// changelog réel reste alimenté en session, cf. models.py::ReleaseNote docstring) : juste
// de quoi ne pas présenter une page vide en démo sur une base fraîchement installée.
// ─────────────────────────────────────────────────────────────────────────
export const FAKE_RELEASE_NOTES = {
  allsafe: [
    { id: 'demo-note-a1', version: '1.4.0', category: 'feature', title: 'Filtres du tableau de bord CyberVuln', description: "Filtrage par actif et par sévérité directement depuis le tableau de bord (donnée de démonstration)." },
    { id: 'demo-note-a2', version: '1.4.0', category: 'fix', title: "Correction d'un export CSV tronqué", description: "Les rapports hebdomadaires de plus de 500 lignes n'étaient plus complets à l'export (donnée de démonstration)." },
    { id: 'demo-note-a3', version: '1.3.0', category: 'feature', title: 'Surveillance Identités', description: "Croisement des identités surveillées avec les fuites de données collectées (donnée de démonstration)." },
    { id: 'demo-note-a4', version: '1.3.0', category: 'feature', title: 'Module Audits', description: "Un seul modèle pour les 5 types d'audit : architecture, configuration, code, pentest, Red Team (donnée de démonstration)." },
    { id: 'demo-note-a5', version: '1.2.0', category: 'fix', title: "Correction d'un doublon de notification NIS 2", description: "Le rappel d'échéance à 24h pouvait s'afficher deux fois sur certains incidents (donnée de démonstration)." },
    { id: 'demo-note-a6', version: '1.2.0', category: 'feature', title: 'Gestion de crise', description: "Journal de décisions et de communications séparé du registre d'incidents (donnée de démonstration)." },
  ].map((n, i) => ({ ...n, scope: 'allsafe', created_at: daysAgoIso(3 + i * 9) })),
  agent: [
    { id: 'demo-note-g1', version: '0.1.10', category: 'feature', title: 'Ping à la demande', description: "Un administrateur peut vérifier qu'un poste répond sans attendre le prochain check-in (donnée de démonstration)." },
    { id: 'demo-note-g2', version: '0.1.9', category: 'fix', title: 'Correction d’un plantage au démarrage sur Windows Server 2016', description: "Le service ne redémarrait pas correctement après une mise à jour (donnée de démonstration)." },
    { id: 'demo-note-g3', version: '0.1.8', category: 'feature', title: 'Scan à la demande', description: "Déclenchement d'un scan complet sans attendre le cycle horaire (donnée de démonstration)." },
    { id: 'demo-note-g4', version: '0.1.7', category: 'feature', title: 'Détection des coupures réseau', description: "L'agent signale la durée d'une coupure lors de sa reconnexion (donnée de démonstration)." },
  ].map((n, i) => ({ ...n, scope: 'agent', created_at: daysAgoIso(5 + i * 12) })),
}

// ─────────────────────────────────────────────────────────────────────────
// CVE fictives — IDs et contenus 100% inventés, jamais de vraie CVE réutilisée
// ─────────────────────────────────────────────────────────────────────────
const FAKE_CVE_POOL = [
  { cve_id: 'CVE-2026-71001', severity: 'CRITICAL', cvss_score: 9.8, epss_score: 0.62, description: "Exécution de code à distance sans authentification via un service exposé (donnée de démonstration)." },
  { cve_id: 'CVE-2026-71002', severity: 'CRITICAL', cvss_score: 9.1, epss_score: 0.44, description: "Contournement d'authentification permettant une élévation de privilèges (donnée de démonstration)." },
  { cve_id: 'CVE-2026-71003', severity: 'CRITICAL', cvss_score: 9.6, epss_score: 0.58, description: "Désérialisation non sécurisée menant à une exécution de code arbitraire (donnée de démonstration)." },
  { cve_id: 'CVE-2026-71004', severity: 'HIGH', cvss_score: 8.1, epss_score: 0.21, description: "Injection de commandes OS via un paramètre non filtré (donnée de démonstration)." },
  { cve_id: 'CVE-2026-71005', severity: 'HIGH', cvss_score: 7.8, epss_score: 0.18, description: "Dépassement de tampon dans un service réseau (donnée de démonstration)." },
  { cve_id: 'CVE-2026-71006', severity: 'HIGH', cvss_score: 7.5, epss_score: 0.15, description: "Traversée de répertoires permettant la lecture de fichiers sensibles (donnée de démonstration)." },
  { cve_id: 'CVE-2026-71007', severity: 'HIGH', cvss_score: 8.4, epss_score: 0.27, description: "Élévation de privilèges locale via un service mal configuré (donnée de démonstration)." },
  { cve_id: 'CVE-2026-71008', severity: 'HIGH', cvss_score: 7.2, epss_score: 0.12, description: "Injection SQL dans un composant applicatif (donnée de démonstration)." },
  { cve_id: 'CVE-2026-71009', severity: 'MEDIUM', cvss_score: 6.5, epss_score: 0.08, description: "Divulgation d'informations sensibles via un message d'erreur (donnée de démonstration)." },
  { cve_id: 'CVE-2026-71010', severity: 'MEDIUM', cvss_score: 5.9, epss_score: 0.06, description: "Déni de service via une requête malformée (donnée de démonstration)." },
  { cve_id: 'CVE-2026-71011', severity: 'MEDIUM', cvss_score: 6.1, epss_score: 0.05, description: "Injection XSS réfléchie dans une interface d'administration (donnée de démonstration)." },
  { cve_id: 'CVE-2026-71012', severity: 'MEDIUM', cvss_score: 5.4, epss_score: 0.04, description: "Contrôle d'accès insuffisant sur une ressource interne (donnée de démonstration)." },
  { cve_id: 'CVE-2026-71013', severity: 'LOW', cvss_score: 3.7, epss_score: 0.02, description: "Fuite d'information mineure sans impact direct (donnée de démonstration)." },
  { cve_id: 'CVE-2026-71014', severity: 'LOW', cvss_score: 2.8, epss_score: 0.01, description: "Faiblesse de configuration par défaut sans exploitation connue (donnée de démonstration)." },
].map((c, i) => ({ ...c, published: new Date(Date.now() - (5 + i * 6) * 86400000).toISOString() }))

// Catalogue CVE fictif (page CVEs.jsx) — même pool que ci-dessus, enrichi des champs
// propres à cette page (maturité d'exploit, source). Pas de lien avec un actif : c'est
// le catalogue NVD dans son ensemble, pas les vulnérabilités détectées sur le parc.
export const FAKE_CVE_CATALOG = FAKE_CVE_POOL.map((c, i) => ({
  ...c,
  id: c.cve_id,
  source: 'nvd',
  kev: i === 0 || i === 3,
  kev_ransomware: i === 0,
  msf_module: i === 0 || i === 4,
  msf_best_rank: (i === 0 || i === 4) ? 'excellent' : null,
}))

const STATUS_CYCLE = ['patched', 'patched', 'patched', 'open', 'open', 'awaiting_fix', 'false_positive']

function daysAgoIso(n) { return new Date(Date.now() - n * 86400000).toISOString() }
function hoursAgoIso(n) { return new Date(Date.now() - n * 3600000).toISOString() }

function buildFakeVulnerabilities() {
  const list = []
  let counter = 0
  FAKE_ASSETS.forEach((asset, ai) => {
    const count = 2 + (ai % 5)
    for (let j = 0; j < count; j++) {
      const cve = FAKE_CVE_POOL[(ai * 5 + j * 3) % FAKE_CVE_POOL.length]
      const status = STATUS_CYCLE[(ai + j) % STATUS_CYCLE.length]
      const detected_at = daysAgoIso(10 + ((ai + j) % 30))
      const vuln = {
        id: `demo-vuln-${ai + 1}-${j + 1}`,
        status,
        cve,
        asset: { id: asset.id, name: asset.name },
        detected_at,
        patched_at: status === 'patched' ? daysAgoIso((ai + j) % 8) : null,
        awaiting_fix_at: status === 'awaiting_fix' ? daysAgoIso((ai + j) % 5) : null,
        false_positive_at: status === 'false_positive' ? daysAgoIso((ai + j) % 5) : null,
        validated_by: (status === 'patched' || status === 'false_positive') ? FAKE_VALIDATORS[(ai + j) % FAKE_VALIDATORS.length] : null,
        notes: status === 'awaiting_fix' ? "Aucun correctif publié par l'éditeur à ce jour (donnée de démonstration)."
          : status === 'false_positive' ? 'Composant non présent après vérification (donnée de démonstration).' : null,
        patch_detected: status === 'patched',
      }
      list.push(vuln)
      counter++
    }
  })
  return list
}

export const FAKE_VULNERABILITIES = buildFakeVulnerabilities()

// Complète vuln_count (toutes sévérités confondues) sur chaque actif fictif
FAKE_ASSETS.forEach(a => {
  a.vuln_count = FAKE_VULNERABILITIES.filter(v => v.asset.id === a.id).length
  // `open_vuln_count` (11/08/2026) : même distinction que côté backend (routers/assets.py)
  // — uniquement status="open", pour que la colonne "Vulnérabilités ouvertes" d'Assets.jsx
  // reste cohérente en mode Présentation.
  a.open_vuln_count = FAKE_VULNERABILITIES.filter(v => v.asset.id === a.id && v.status === 'open').length
})

// ─────────────────────────────────────────────────────────────────────────
// Incidents fictifs (module Incidents) — variété volontaire des jalons NIS 2 pour montrer
// les 3 états du compte à rebours (`nis2Countdown.js::milestoneStatus`) : urgent (incident 1,
// échéance alerte précoce dans <4h), dépassé (incident 2, rapport final jamais envoyé) et
// dans les temps (incident 5, tout juste déclaré). Actifs référencés = ceux de FAKE_ASSETS,
// pour rester cohérent avec le reste de la démo.
// ─────────────────────────────────────────────────────────────────────────
export const FAKE_INCIDENTS = [
  {
    id: 'demo-incident-1',
    title: 'Chiffrement de fichiers détecté sur SRV-FILE-01 (donnée de démonstration)',
    description: "Plusieurs partages réseau du serveur de fichiers présentent des extensions renommées et une note de rançon. Isolation réseau en cours (donnée de démonstration).",
    category: 'ransomware', category_label: 'Ransomware',
    severity: 'critical', severity_label: 'Critique',
    status: 'in_progress', status_label: 'En cours',
    detected_at: hoursAgoIso(21), aware_at: hoursAgoIso(20), aware_at_locked: true,
    reported_by: FAKE_VALIDATORS[0],
    created_at: hoursAgoIso(20), updated_at: hoursAgoIso(2),
    requires_notification: true,
    notification_qualified_by: FAKE_VALIDATORS[0], notification_qualified_at: hoursAgoIso(19),
    notification_justification: "Chiffrement massif de fichiers sur un serveur de partage, service impacté (donnée de démonstration).",
    early_warning_due_at: hoursAgoIso(-4), early_warning_sent_at: null, early_warning_sent_by: null,
    incident_notification_due_at: hoursAgoIso(-52), incident_notification_sent_at: null, incident_notification_sent_by: null,
    final_report_due_at: hoursAgoIso(-700), final_report_sent_at: null, final_report_sent_by: null,
    affected_asset_ids: [FAKE_ASSETS[6].id], affected_asset_names: [FAKE_ASSETS[6].name],
    completed_response_steps: [
      { index: 0, by: FAKE_VALIDATORS[1], at: hoursAgoIso(18) },
      { index: 1, by: FAKE_VALIDATORS[1], at: hoursAgoIso(15) },
    ],
    crisis_id: 'demo-crisis-1', crisis_title: 'Ransomware SRV-FILE-01 (donnée de démonstration)',
  },
  {
    id: 'demo-incident-2',
    title: 'Exfiltration de données constatée sur SRV-SQL-01 (donnée de démonstration)',
    description: "Volumétrie de sortie anormale vers une IP externe inconnue, confirmée par les journaux de la base (donnée de démonstration).",
    category: 'data_breach', category_label: 'Fuite de données',
    severity: 'major', severity_label: 'Majeur',
    status: 'resolved', status_label: 'Résolu',
    detected_at: daysAgoIso(41), aware_at: daysAgoIso(40), aware_at_locked: true,
    reported_by: FAKE_VALIDATORS[2],
    created_at: daysAgoIso(40), updated_at: daysAgoIso(9),
    requires_notification: true,
    notification_qualified_by: FAKE_VALIDATORS[2], notification_qualified_at: daysAgoIso(40),
    notification_justification: "Données à caractère personnel de clients concernées (donnée de démonstration).",
    early_warning_due_at: daysAgoIso(39), early_warning_sent_at: daysAgoIso(39), early_warning_sent_by: FAKE_VALIDATORS[2],
    incident_notification_due_at: daysAgoIso(37), incident_notification_sent_at: daysAgoIso(37), incident_notification_sent_by: FAKE_VALIDATORS[0],
    // Rapport final en retard, jamais envoyé (donnée de démonstration) — illustre pourquoi le
    // compte à rebours reste affiché même sur un incident déjà "Résolu" côté traitement technique.
    final_report_due_at: daysAgoIso(10), final_report_sent_at: null, final_report_sent_by: null,
    affected_asset_ids: [FAKE_ASSETS[2].id], affected_asset_names: [FAKE_ASSETS[2].name],
    completed_response_steps: [
      { index: 0, by: FAKE_VALIDATORS[2], at: daysAgoIso(39) },
      { index: 1, by: FAKE_VALIDATORS[0], at: daysAgoIso(38) },
      { index: 2, by: FAKE_VALIDATORS[0], at: daysAgoIso(35) },
    ],
    crisis_id: null, crisis_title: null,
  },
  {
    id: 'demo-incident-3',
    title: "Campagne d'hameçonnage ciblant le service comptabilité (donnée de démonstration)",
    description: "Plusieurs employés ont signalé un email imitant un fournisseur habituel, demandant une modification de coordonnées bancaires (donnée de démonstration).",
    category: 'phishing', category_label: 'Hameçonnage',
    severity: 'minor', severity_label: 'Mineur',
    status: 'closed', status_label: 'Clôturé',
    detected_at: daysAgoIso(16), aware_at: daysAgoIso(16), aware_at_locked: true,
    reported_by: FAKE_VALIDATORS[3],
    created_at: daysAgoIso(16), updated_at: daysAgoIso(14),
    requires_notification: false,
    notification_qualified_by: null, notification_qualified_at: null, notification_justification: null,
    early_warning_due_at: null, early_warning_sent_at: null, early_warning_sent_by: null,
    incident_notification_due_at: null, incident_notification_sent_at: null, incident_notification_sent_by: null,
    final_report_due_at: null, final_report_sent_at: null, final_report_sent_by: null,
    affected_asset_ids: [FAKE_ASSETS[19].id], affected_asset_names: [FAKE_ASSETS[19].name],
    completed_response_steps: [
      { index: 0, by: FAKE_VALIDATORS[3], at: daysAgoIso(15) },
      { index: 1, by: FAKE_VALIDATORS[3], at: daysAgoIso(15) },
    ],
    crisis_id: null, crisis_title: null,
  },
  {
    id: 'demo-incident-4',
    title: 'Sauvegarde exposée sans authentification sur SRV-BACKUP-01 (donnée de démonstration)',
    description: "Un partage de sauvegarde nouvellement créé était accessible sans identifiants depuis le réseau interne (donnée de démonstration).",
    category: 'misconfiguration', category_label: 'Erreur de configuration',
    severity: 'minor', severity_label: 'Mineur',
    status: 'contained', status_label: 'Contenu',
    detected_at: daysAgoIso(4), aware_at: daysAgoIso(4), aware_at_locked: true,
    reported_by: FAKE_VALIDATORS[1],
    created_at: daysAgoIso(4), updated_at: daysAgoIso(3),
    requires_notification: false,
    notification_qualified_by: null, notification_qualified_at: null, notification_justification: null,
    early_warning_due_at: null, early_warning_sent_at: null, early_warning_sent_by: null,
    incident_notification_due_at: null, incident_notification_sent_at: null, incident_notification_sent_by: null,
    final_report_due_at: null, final_report_sent_at: null, final_report_sent_by: null,
    affected_asset_ids: [FAKE_ASSETS[8].id], affected_asset_names: [FAKE_ASSETS[8].name],
    completed_response_steps: [{ index: 0, by: FAKE_VALIDATORS[1], at: daysAgoIso(3) }],
    crisis_id: null, crisis_title: null,
  },
  {
    id: 'demo-incident-5',
    title: 'Connexion administrateur hors plage horaire sur SRV-AD-01 (donnée de démonstration)',
    description: "Authentification réussie sur un compte à privilèges à 3h du matin, depuis un poste jamais vu auparavant (donnée de démonstration).",
    category: 'intrusion', category_label: 'Intrusion',
    severity: 'major', severity_label: 'Majeur',
    status: 'declared', status_label: 'Déclaré',
    detected_at: hoursAgoIso(2), aware_at: hoursAgoIso(2), aware_at_locked: true,
    reported_by: FAKE_VALIDATORS[0],
    created_at: hoursAgoIso(2), updated_at: hoursAgoIso(1),
    requires_notification: true,
    notification_qualified_by: FAKE_VALIDATORS[0], notification_qualified_at: hoursAgoIso(1),
    notification_justification: "Compte à privilèges compromis, portée encore en cours d'évaluation (donnée de démonstration).",
    early_warning_due_at: hoursAgoIso(-22), early_warning_sent_at: null, early_warning_sent_by: null,
    incident_notification_due_at: hoursAgoIso(-70), incident_notification_sent_at: null, incident_notification_sent_by: null,
    final_report_due_at: hoursAgoIso(-718), final_report_sent_at: null, final_report_sent_by: null,
    affected_asset_ids: [FAKE_ASSETS[4].id], affected_asset_names: [FAKE_ASSETS[4].name],
    completed_response_steps: [],
    crisis_id: null, crisis_title: null,
  },
].map(inc => ({ ...inc, aware_at_locked: true, security_event_id: null, vulnerability_id: null, watch_item_id: null, audit_finding_id: null, agent_security_event_id: null }))

// ─────────────────────────────────────────────────────────────────────────
// Crises fictives (module Incidents > Gestion de crise) — une seule crise active, rattachée
// à demo-incident-1 (même logique de cohérence croisée que les autres modules fictifs).
// ─────────────────────────────────────────────────────────────────────────
export const FAKE_CRISES = [
  {
    id: 'demo-crisis-1',
    title: 'Ransomware SRV-FILE-01 (donnée de démonstration)',
    description: "Cellule de crise activée suite au chiffrement constaté sur le serveur de fichiers — isolation réseau en cours, RSSI et direction mobilisés (donnée de démonstration).",
    status: 'active',
    activated_at: hoursAgoIso(19), activated_by: FAKE_VALIDATORS[0],
    stood_down_at: null, stood_down_by: null, stand_down_justification: null,
    crisis_roles: [
      { role: 'RSSI', analyst_name: FAKE_VALIDATORS[0] },
      { role: 'Direction générale', analyst_name: FAKE_VALIDATORS[2] },
      { role: 'Communication / RP', analyst_name: FAKE_VALIDATORS[3] },
    ],
    completed_crisis_steps: [{ index: 0, by: FAKE_VALIDATORS[0], at: hoursAgoIso(18) }],
    created_at: hoursAgoIso(19),
    linked_incidents: [{ id: 'demo-incident-1', title: 'Chiffrement de fichiers détecté sur SRV-FILE-01 (donnée de démonstration)', status: 'in_progress' }],
  },
]

// Chronologie (IncidentDetailModal.jsx/CrisisDetailModal.jsx::IncidentTimeline) d'un incident
// ou d'une crise fictif — reconstruite depuis ses propres champs plutôt que codée en dur par
// entrée, pour rester cohérente si les données ci-dessus changent.
export function buildFakeIncidentTimeline(incident) {
  let id = 0
  const entries = [{ id: `demo-tl-${incident.id}-${id++}`, event_type: 'created', occurred_at: incident.created_at, author: incident.reported_by }]
  if (incident.requires_notification) {
    entries.push({ id: `demo-tl-${incident.id}-${id++}`, event_type: 'notification_qualified', occurred_at: incident.notification_qualified_at, author: incident.notification_qualified_by, notes: incident.notification_justification })
    for (const m of ['early_warning', 'incident_notification', 'final_report']) {
      if (incident[`${m}_sent_at`]) {
        entries.push({ id: `demo-tl-${incident.id}-${id++}`, event_type: 'milestone_sent', occurred_at: incident[`${m}_sent_at`], author: incident[`${m}_sent_by`], meta: { milestone: m } })
      }
    }
  }
  return entries.sort((a, b) => new Date(b.occurred_at) - new Date(a.occurred_at))
}

const MILESTONE_LABELS_FR = { early_warning: 'Alerte précoce (24h)', incident_notification: 'Notification (72h)', final_report: 'Rapport final (1 mois)' }

// Rapport par incident (RapportIncidents.jsx) pour un incident fictif — reconstruit côté
// client, mêmes ingrédients que services/incident_report.py (pas d'appel API, l'incident
// n'existe pas en base).
export function buildFakeIncidentReport(incident) {
  const lines = [
    `# ${incident.title}`, '',
    `**Catégorie** : ${incident.category_label} — **Sévérité** : ${incident.severity_label} — **Statut** : ${incident.status_label}`, '',
    `Déclaré par ${incident.reported_by} le ${new Date(incident.created_at).toLocaleString('fr-FR')}.`, '',
    '## Description', incident.description || 'Non renseignée.', '',
  ]
  if (incident.affected_asset_names?.length) {
    lines.push('## Actifs concernés', incident.affected_asset_names.join(', '), '')
  }
  lines.push('## Notification NIS 2')
  if (!incident.requires_notification) {
    lines.push('Non qualifié — aucune échéance légale suivie pour cet incident.', '')
  } else {
    lines.push(incident.notification_justification || '', '')
    for (const m of ['early_warning', 'incident_notification', 'final_report']) {
      const sentAt = incident[`${m}_sent_at`]
      const dueAt = incident[`${m}_due_at`]
      lines.push(`- **${MILESTONE_LABELS_FR[m]}** : ${sentAt ? `envoyé le ${new Date(sentAt).toLocaleString('fr-FR')}` : dueAt ? `échéance ${new Date(dueAt).toLocaleString('fr-FR')}` : 'sans échéance'}`)
    }
    lines.push('')
  }
  return lines.join('\n')
}

export function buildFakeCrisisTimeline(crisis) {
  let id = 0
  const entries = [{ id: `demo-tl-${crisis.id}-${id++}`, event_type: 'activated', occurred_at: crisis.activated_at, author: crisis.activated_by }]
  for (const r of crisis.crisis_roles || []) {
    entries.push({ id: `demo-tl-${crisis.id}-${id++}`, event_type: 'role_assigned', occurred_at: crisis.activated_at, author: crisis.activated_by, new_value: `${r.role} — ${r.analyst_name}` })
  }
  for (const li of crisis.linked_incidents || []) {
    entries.push({ id: `demo-tl-${crisis.id}-${id++}`, event_type: 'incident_linked', occurred_at: crisis.activated_at, author: crisis.activated_by, new_value: li.title })
  }
  return entries.sort((a, b) => new Date(b.occurred_at) - new Date(a.occurred_at))
}

// ─────────────────────────────────────────────────────────────────────────
// Audits fictifs (module Sécurité > Audits) — tous déjà autorisés (scope/RoE/mandataire
// posés) pour ne pas avoir à simuler le flux d'autorisation lui-même : l'essentiel du module
// à montrer en démo, c'est la table de findings et le retest, pas le cadrage. 3 statuts
// différents (en_cours/termine flaggé/termine propre) pour varier l'affichage.
// ─────────────────────────────────────────────────────────────────────────
export const FAKE_AUDITS = [
  {
    id: 'demo-audit-1', title: 'Pentest externe — portail client (donnée de démonstration)',
    type: 'pentest', methodology: 'boite_grise', referential: 'OWASP Testing Guide',
    status: 'termine',
    scope: "Application web publique (portail client) et API associée (donnée de démonstration).",
    rules_of_engagement: "Tests en heures ouvrées, pas de déni de service, comptes de test dédiés uniquement (donnée de démonstration).",
    authorized_by: FAKE_VALIDATORS[0], authorized_at: daysAgoIso(20),
    conducted_by: FAKE_VALIDATORS[1], started_at: daysAgoIso(19), ended_at: daysAgoIso(12),
    executive_summary: "3 findings critiques/élevés remontés, dont une injection SQL sur le formulaire de contact. Correctifs déployés, contre-vérification partielle (donnée de démonstration).",
    created_at: daysAgoIso(21),
    asset_ids: [FAKE_ASSETS[0].id, FAKE_ASSETS[1].id], asset_names: [FAKE_ASSETS[0].name, FAKE_ASSETS[1].name],
  },
  {
    id: 'demo-audit-2', title: 'Audit de configuration — Active Directory (donnée de démonstration)',
    type: 'configuration', methodology: 'boite_blanche', referential: 'CIS Benchmarks',
    status: 'en_cours',
    scope: "Contrôleur de domaine principal et stratégies de groupe associées (donnée de démonstration).",
    rules_of_engagement: "Lecture seule, aucune modification en environnement de production (donnée de démonstration).",
    authorized_by: FAKE_VALIDATORS[2], authorized_at: daysAgoIso(5),
    conducted_by: FAKE_VALIDATORS[2], started_at: daysAgoIso(4), ended_at: null,
    executive_summary: null,
    created_at: daysAgoIso(6),
    asset_ids: [FAKE_ASSETS[4].id], asset_names: [FAKE_ASSETS[4].name],
  },
  {
    id: 'demo-audit-3', title: 'Red Team — scénario ingénierie sociale (donnée de démonstration)',
    type: 'redteam', methodology: 'boite_noire', referential: 'PTES',
    status: 'termine',
    scope: "Personnel du siège, sans notification préalable des équipes ciblées (donnée de démonstration).",
    rules_of_engagement: "Pas de collecte de données personnelles au-delà du strict nécessaire à la démonstration, débriefing obligatoire en fin de mission (donnée de démonstration).",
    authorized_by: FAKE_VALIDATORS[3], authorized_at: daysAgoIso(46),
    conducted_by: FAKE_VALIDATORS[3], started_at: daysAgoIso(45), ended_at: daysAgoIso(30),
    executive_summary: "Deux scénarios ont abouti (hameçonnage ciblé, élévation de privilèges via un partage réseau). Correctifs déployés et intégralement contre-vérifiés (donnée de démonstration).",
    created_at: daysAgoIso(47),
    asset_ids: [], asset_names: [],
  },
]

export const FAKE_AUDIT_FINDINGS = {
  'demo-audit-1': [
    {
      id: 'demo-finding-1-1', audit_id: 'demo-audit-1', title: 'Injection SQL sur le formulaire de contact',
      description: "Le paramètre `email` du formulaire de contact n'est pas échappé avant insertion en base (donnée de démonstration).",
      severity: 'CRITICAL', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvss_score: 9.8,
      cwe_id: 'CWE-89', owasp_ref: 'A03:2021',
      affected_asset_id: FAKE_ASSETS[0].id, affected_asset_name: FAKE_ASSETS[0].name, affected_component: 'POST /contact',
      cve_id: null,
      proof_of_concept: "`email=test@test.com' OR '1'='1` renvoie l'ensemble des enregistrements (donnée de démonstration).",
      impact: "Extraction complète de la base clients possible sans authentification (donnée de démonstration).",
      recommendation: "Passer par des requêtes préparées / un ORM, valider strictement le format de l'entrée (donnée de démonstration).",
      status: 'corrige', mitre_techniques: [],
      discovered_at: daysAgoIso(18), retested_at: daysAgoIso(11), retest_result: 'corrige', retested_by: FAKE_VALIDATORS[0],
      created_at: daysAgoIso(18),
    },
    {
      id: 'demo-finding-1-2', audit_id: 'demo-audit-1', title: 'Absence de limitation des tentatives de connexion',
      description: "Aucun verrouillage ni ralentissement après une série d'échecs d'authentification (donnée de démonstration).",
      severity: 'HIGH', cvss_vector: null, cvss_score: 7.5,
      cwe_id: 'CWE-307', owasp_ref: 'A07:2021',
      affected_asset_id: FAKE_ASSETS[0].id, affected_asset_name: FAKE_ASSETS[0].name, affected_component: 'POST /login',
      cve_id: null,
      proof_of_concept: "10 000 tentatives envoyées en 5 minutes sans blocage (donnée de démonstration).",
      impact: "Attaque par force brute réaliste sur les comptes clients (donnée de démonstration).",
      recommendation: "Verrouillage progressif + CAPTCHA après un seuil d'échecs (donnée de démonstration).",
      // Corrigé mais jamais recontrôlé — alimente volontairement le badge "⚠ non retesté"
      // (Audits.jsx/AuditDetail.jsx), scénario réaliste d'audit "termine" incomplet.
      status: 'corrige', mitre_techniques: [],
      discovered_at: daysAgoIso(18), retested_at: null, retest_result: null, retested_by: null,
      created_at: daysAgoIso(18),
    },
    {
      id: 'demo-finding-1-3', audit_id: 'demo-audit-1', title: 'En-têtes de sécurité HTTP manquants',
      description: "Content-Security-Policy et X-Frame-Options absents sur l'ensemble du site (donnée de démonstration).",
      severity: 'MEDIUM', cvss_vector: null, cvss_score: 5.4,
      cwe_id: 'CWE-693', owasp_ref: 'A05:2021',
      affected_asset_id: FAKE_ASSETS[0].id, affected_asset_name: FAKE_ASSETS[0].name, affected_component: null,
      cve_id: null,
      proof_of_concept: null,
      impact: "Surface d'exposition accrue au clickjacking et à l'injection de contenu (donnée de démonstration).",
      recommendation: "Ajouter les en-têtes recommandés OWASP Secure Headers (donnée de démonstration).",
      status: 'risque_accepte', mitre_techniques: [],
      discovered_at: daysAgoIso(17), retested_at: null, retest_result: null, retested_by: null,
      created_at: daysAgoIso(17),
    },
    {
      id: 'demo-finding-1-4', audit_id: 'demo-audit-1', title: 'Version du serveur web divulguée',
      description: "L'en-tête `Server` expose la version exacte du serveur web (donnée de démonstration).",
      severity: 'LOW', cvss_vector: null, cvss_score: 2.7,
      cwe_id: 'CWE-200', owasp_ref: null,
      affected_asset_id: FAKE_ASSETS[1].id, affected_asset_name: FAKE_ASSETS[1].name, affected_component: null,
      cve_id: null, proof_of_concept: null,
      impact: "Facilite le ciblage de vulnérabilités connues pour cette version (donnée de démonstration).",
      recommendation: "Masquer l'en-tête `Server` (donnée de démonstration).",
      status: 'faux_positif', mitre_techniques: [],
      discovered_at: daysAgoIso(17), retested_at: null, retest_result: null, retested_by: null,
      created_at: daysAgoIso(17),
    },
  ],
  'demo-audit-2': [
    {
      id: 'demo-finding-2-1', audit_id: 'demo-audit-2', title: "Comptes de service avec mot de passe n'expirant jamais",
      description: "Plusieurs comptes de service ont l'attribut « le mot de passe n'expire jamais » activé (donnée de démonstration).",
      severity: 'HIGH', cvss_vector: null, cvss_score: 6.8,
      cwe_id: 'CWE-262', owasp_ref: null,
      affected_asset_id: FAKE_ASSETS[4].id, affected_asset_name: FAKE_ASSETS[4].name, affected_component: null,
      cve_id: null, proof_of_concept: null,
      impact: "Une fuite de ces identifiants resterait exploitable indéfiniment (donnée de démonstration).",
      recommendation: "Basculer vers des Group Managed Service Accounts (gMSA) (donnée de démonstration).",
      status: 'ouvert', mitre_techniques: [],
      discovered_at: daysAgoIso(3), retested_at: null, retest_result: null, retested_by: null,
      created_at: daysAgoIso(3),
    },
    {
      id: 'demo-finding-2-2', audit_id: 'demo-audit-2', title: 'Journalisation des évènements de sécurité insuffisante',
      description: "L'audit des accès aux objets sensibles de l'annuaire n'est pas activé (donnée de démonstration).",
      severity: 'MEDIUM', cvss_vector: null, cvss_score: 5.3,
      cwe_id: 'CWE-778', owasp_ref: null,
      affected_asset_id: FAKE_ASSETS[4].id, affected_asset_name: FAKE_ASSETS[4].name, affected_component: null,
      cve_id: null, proof_of_concept: null,
      impact: "Une compromission de l'annuaire serait difficile à reconstituer a posteriori (donnée de démonstration).",
      recommendation: "Activer l'audit avancé (Advanced Audit Policy) sur les objets critiques (donnée de démonstration).",
      status: 'remediation_planifiee', mitre_techniques: [],
      discovered_at: daysAgoIso(2), retested_at: null, retest_result: null, retested_by: null,
      created_at: daysAgoIso(2),
    },
  ],
  'demo-audit-3': [
    {
      id: 'demo-finding-3-1', audit_id: 'demo-audit-3', title: 'Hameçonnage ciblé réussi sur 2 employés sur 10 testés',
      description: "Un email imitant le service informatique a conduit 2 employés à saisir leurs identifiants sur un portail cloné (donnée de démonstration).",
      severity: 'HIGH', cvss_vector: null, cvss_score: 7.1,
      cwe_id: null, owasp_ref: null,
      affected_asset_id: null, affected_asset_name: null, affected_component: null,
      cve_id: null,
      proof_of_concept: "Portail de connexion cloné, journal des soumissions (donnée de démonstration).",
      impact: "Compromission initiale de comptes utilisateurs standards (donnée de démonstration).",
      recommendation: "Campagne de sensibilisation ciblée + MFA généralisé (donnée de démonstration).",
      status: 'corrige', mitre_techniques: ['T1566.001'],
      discovered_at: daysAgoIso(40), retested_at: daysAgoIso(25), retest_result: 'corrige', retested_by: FAKE_VALIDATORS[3],
      created_at: daysAgoIso(40),
    },
    {
      id: 'demo-finding-3-2', audit_id: 'demo-audit-3', title: 'Élévation de privilèges via un partage réseau mal configuré',
      description: "Un partage réseau accessible en écriture par tous permettait de remplacer un exécutable lancé par une tâche planifiée privilégiée (donnée de démonstration).",
      severity: 'MEDIUM', cvss_vector: null, cvss_score: 6.5,
      cwe_id: 'CWE-732', owasp_ref: null,
      affected_asset_id: null, affected_asset_name: null, affected_component: null,
      cve_id: null,
      proof_of_concept: null,
      impact: "Élévation de privilèges standard → administrateur local (donnée de démonstration).",
      recommendation: "Restreindre les droits d'écriture sur le partage aux seuls comptes de service nécessaires (donnée de démonstration).",
      status: 'corrige', mitre_techniques: ['T1021.002'],
      discovered_at: daysAgoIso(38), retested_at: daysAgoIso(25), retest_result: 'corrige', retested_by: FAKE_VALIDATORS[3],
      created_at: daysAgoIso(38),
    },
  ],
}

// Résumé par sévérité + compteurs (Audits.jsx::flagged, AuditDetail.jsx) — dérivé des findings
// ci-dessus plutôt que codé en dur, pour ne jamais diverger si la liste change.
export function fakeAuditSummary(auditId) {
  const findings = FAKE_AUDIT_FINDINGS[auditId] || []
  const by_severity = {}
  for (const f of findings) by_severity[f.severity] = (by_severity[f.severity] || 0) + 1
  const unretested_closed = findings.filter(f => ['corrige', 'risque_accepte'].includes(f.status) && !f.retested_at).length
  return {
    findings_total: findings.length,
    findings_by_severity: by_severity,
    findings_open: findings.filter(f => f.status === 'ouvert').length,
    findings_unretested_closed: unretested_closed,
  }
}

// Complète chaque FAKE_AUDITS avec son résumé de findings, pour qu'Audits.jsx (liste) affiche
// les mêmes badges de sévérité/le même flag "non retesté" que la page de détail.
FAKE_AUDITS.forEach(a => Object.assign(a, fakeAuditSummary(a.id)))

// ─────────────────────────────────────────────────────────────────────────
// Veille technologique fictive (module CyberVeille > Veille technologique) — registre
// auditable NIS 2, statuts/sévérités variés. `url: null` volontairement (pas de vrai lien
// externe à ouvrir depuis une donnée de démonstration).
// ─────────────────────────────────────────────────────────────────────────
export const FAKE_WATCH_ITEMS = [
  {
    id: 'demo-watch-1', source: 'cert-fr-avis', source_label: 'CERT-FR Avis',
    title: 'Vulnérabilité critique dans un pare-feu périmétrique largement déployé (donnée de démonstration)',
    url: null, summary: "Une exécution de code à distance sans authentification affecte plusieurs versions du firmware. Un correctif est disponible (donnée de démonstration).",
    published_at: daysAgoIso(2), received_at: daysAgoIso(2),
    severity: 'critical', status: 'new', reviewed_by: null, reviewed_at: null, decision: null,
    linked_cve_id: 'CVE-2026-71001', cve_ids_found: ['CVE-2026-71001'],
    themes: ['Cyber', 'Vulnérabilité', 'Réseau'], country: 'FR', asset_ids: [], sla_exceeded: false, delay_hours: null,
  },
  {
    id: 'demo-watch-2', source: 'cert-fr-alerte', source_label: 'CERT-FR Alerte',
    title: "Campagne d'exploitation active visant un CMS très répandu (donnée de démonstration)",
    url: null, summary: "Des indices de compromission confirment une exploitation en masse dans la nature. Mise à jour à appliquer en urgence (donnée de démonstration).",
    published_at: daysAgoIso(1), received_at: daysAgoIso(1),
    severity: 'critical', status: 'in_review', reviewed_by: FAKE_VALIDATORS[1], reviewed_at: null, decision: null,
    linked_cve_id: null, cve_ids_found: [],
    themes: ['Cyber', 'Vulnérabilité'], country: 'FR', asset_ids: [], sla_exceeded: true, delay_hours: null,
  },
  {
    id: 'demo-watch-3', source: 'anssi', source_label: 'ANSSI',
    title: 'Nouvelle version du guide de configuration Active Directory (donnée de démonstration)',
    url: null, summary: "Mise à jour des recommandations de durcissement AD, notamment sur la délégation Kerberos (donnée de démonstration).",
    published_at: daysAgoIso(6), received_at: daysAgoIso(6),
    severity: 'informational', status: 'treated', reviewed_by: FAKE_VALIDATORS[2], reviewed_at: daysAgoIso(5),
    decision: "Recommandations comparées à notre configuration actuelle — aucun écart majeur identifié (donnée de démonstration).",
    linked_cve_id: null, cve_ids_found: [],
    themes: ['Admin', 'Réglementation'], country: 'FR', asset_ids: [FAKE_ASSETS[4].id], sla_exceeded: false, delay_hours: 26,
  },
  {
    id: 'demo-watch-4', source: 'sekoia', source_label: 'Sekoia TDR',
    title: 'Nouveau mode opératoire ransomware ciblant les hyperviseurs VMware ESXi (donnée de démonstration)',
    url: null, summary: "Chiffrement direct des datastores après compromission d'un compte vCenter. Indicateurs de compromission publiés (donnée de démonstration).",
    published_at: daysAgoIso(4), received_at: daysAgoIso(4),
    severity: 'important', status: 'new', reviewed_by: null, reviewed_at: null, decision: null,
    linked_cve_id: null, cve_ids_found: [],
    themes: ['Ransomware', 'Cyber'], country: 'FR', asset_ids: [], sla_exceeded: false, delay_hours: null,
  },
  {
    id: 'demo-watch-5', source: 'cert-fr-avis', source_label: 'CERT-FR Avis',
    title: 'Multiples vulnérabilités dans une suite bureautique largement utilisée (donnée de démonstration)',
    url: null, summary: "Plusieurs failles de gravité modérée corrigées dans la dernière mise à jour cumulative (donnée de démonstration).",
    published_at: daysAgoIso(9), received_at: daysAgoIso(9),
    severity: 'important', status: 'treated', reviewed_by: FAKE_VALIDATORS[0], reviewed_at: daysAgoIso(8),
    decision: "Déploiement de la mise à jour planifié via WSUS sur le prochain cycle de maintenance (donnée de démonstration).",
    linked_cve_id: null, cve_ids_found: ['CVE-2026-71009', 'CVE-2026-71010'],
    themes: ['Software', 'Vulnérabilité'], country: 'FR', asset_ids: [], sla_exceeded: false, delay_hours: 22,
  },
]

// ─────────────────────────────────────────────────────────────────────────
// Fuites de données fictives (module CyberVeille > Fuite de données) — purement
// informatif, mêmes sources dédiées que la page réelle (ZATAZ/fuitesinfos/Ransomware.live/
// DataBreaches.net/HIBP). `url: null` (pas de vrai lien externe).
// ─────────────────────────────────────────────────────────────────────────
export const FAKE_LEAK_ITEMS = [
  {
    id: 'demo-leak-1', source: 'ransomware-live', source_label: 'Ransomware.live',
    title: 'Société Exemple SARL — LockDemo (Industrie manufacturière) (donnée de démonstration)',
    url: null, summary: "Revendication de vol de données par un groupe de ransomware, publication partielle sur le site de fuite (donnée de démonstration).",
    published_at: daysAgoIso(3), received_at: daysAgoIso(3),
    severity: 'critical', status: 'new', country: 'FR', themes: [], cve_ids_found: [], asset_ids: [],
  },
  {
    id: 'demo-leak-2', source: 'zataz', source_label: 'ZATAZ',
    title: 'Base de données clients exposée sans authentification (donnée de démonstration)',
    url: null, summary: "Un serveur mal configuré exposait plusieurs milliers d'enregistrements clients (donnée de démonstration).",
    published_at: daysAgoIso(7), received_at: daysAgoIso(7),
    severity: 'important', status: 'new', country: 'FR', themes: [], cve_ids_found: [], asset_ids: [],
  },
  {
    id: 'demo-leak-3', source: 'hibp', source_label: 'Have I Been Pwned',
    title: 'Fuite historique intégrant des adresses du domaine surveillé (donnée de démonstration)',
    url: null, summary: "Nouvel ajout à une base de fuites déjà connue, quelques correspondances avec le domaine surveillé (donnée de démonstration).",
    published_at: daysAgoIso(12), received_at: daysAgoIso(12),
    severity: 'informational', status: 'new', country: 'FR', themes: [], cve_ids_found: [], asset_ids: [],
  },
]

// ─────────────────────────────────────────────────────────────────────────
// Anonymisation des données réelles (affichage uniquement — id réel conservé)
// ─────────────────────────────────────────────────────────────────────────
function fakeIpForReal(id) {
  const h = hashStr('ip:' + String(id))
  // Décalage non-signé (>>>) : `h` (déjà >>> 0, donc 0..2^32-1) traité comme
  // signé par `>>` deviendrait négatif pour h >= 2^31, produisant un octet
  // d'IP négatif (ex: "10.99.227.-201") — bug constaté sur les connexions.
  return `10.99.${100 + (h % 50)}.${10 + ((h >>> 8) % 240)}`
}

export function anonymizeAsset(asset) {
  if (!asset || isFakeId(asset.id)) return asset
  const idx = hashStr(String(asset.id)) % ANON_REAL_NAMES.length
  const fakeName = ANON_REAL_NAMES[idx]
  const fakeIp = fakeIpForReal(asset.id)
  return {
    ...asset,
    name: fakeName,
    hostname: asset.hostname ? `${fakeName.toLowerCase()}.${FAKE_DOMAIN}` : asset.hostname,
    ip_address: asset.ip_address ? fakeIp : asset.ip_address,
    // IP remontée par l'agent (services/asset_scanner.py::detected_ip), distincte de
    // ip_address (scan réseau SSH/WinRM) — même donnée réelle, oubliée ici jusqu'ici
    // (AgentHistory.jsx/Inventaire.jsx l'affichaient encore en clair en mode Présentation).
    hardware: asset.hardware ? { ...asset.hardware, ip: asset.hardware.ip ? fakeIp : asset.hardware.ip } : asset.hardware,
  }
}

// Agent posé sur un poste (module Inventaire > Agents) — identité distincte de l'Asset
// (hostname auto-déclaré à l'enrôlement, pas forcément identique à Asset.hostname), donc pas
// couvert par anonymizeAsset. Seed sur asset_id quand connu (même actif → même nom fictif que
// partout ailleurs) ; à défaut (agent orphelin, ou entrée d'historique sans id, cf.
// AgentsGlobalHistory.jsx) on retombe sur l'id de l'agent puis sur son hostname.
export function anonymizeAgent(agent) {
  if (!agent || isFakeId(agent.id)) return agent
  const seed = agent.asset_id || agent.id || agent.hostname
  const fakeName = ANON_REAL_NAMES[hashStr(String(seed)) % ANON_REAL_NAMES.length]
  return {
    ...agent,
    hostname: agent.hostname ? fakeName : agent.hostname,
    asset_name: agent.asset_name ? fakeName : agent.asset_name,
    enrolled_by: agent.enrolled_by ? anonymizeValidator(agent.enrolled_by) : agent.enrolled_by,
    revoked_by: agent.revoked_by ? anonymizeValidator(agent.revoked_by) : agent.revoked_by,
    deleted_by: agent.deleted_by ? anonymizeValidator(agent.deleted_by) : agent.deleted_by,
    enrollment_token_created_by: agent.enrollment_token_created_by ? anonymizeValidator(agent.enrollment_token_created_by) : agent.enrollment_token_created_by,
  }
}

export function anonymizeValidator(name) {
  if (!name || name === 'Auto (patch check)') return name
  const idx = hashStr('validator:' + name) % FAKE_VALIDATORS.length
  return FAKE_VALIDATORS[idx]
}

// Registre « Rôles » (organigramme, Administration > Rôles) — noms complets, distincts de
// FAKE_VALIDATORS (initiales abrégées, pensées pour un dropdown compact) : un organigramme
// affiche un nom complet crédible. `position` (RSSI, DPO...) n'est jamais modifiée, elle n'est
// pas sensible — seuls le nom et l'email d'une personne réelle le sont.
const FAKE_ROLE_HOLDER_NAMES = [
  'Camille Bertrand', 'Julien Faucher', 'Sophie Marchand', 'Nicolas Delattre',
  'Amandine Rousseau', 'Thomas Guillet', 'Léa Fontaine', 'Antoine Perrot',
]

function slugifyName(name) {
  return name.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^a-z]+/g, '.')
}

export function anonymizeRoleHolder(role) {
  if (!role) return role
  const idx = hashStr('role-holder:' + String(role.id || role.name)) % FAKE_ROLE_HOLDER_NAMES.length
  const fakeName = FAKE_ROLE_HOLDER_NAMES[idx]
  return { ...role, name: fakeName, email: role.email ? `${slugifyName(fakeName)}@${FAKE_DOMAIN}` : role.email }
}

export function anonymizeVuln(vuln) {
  if (!vuln || isFakeId(vuln.id)) return vuln
  return {
    ...vuln,
    asset: vuln.asset ? anonymizeAsset(vuln.asset) : vuln.asset,
    validated_by: vuln.validated_by ? anonymizeValidator(vuln.validated_by) : vuln.validated_by,
  }
}

export function anonymizeConnection(log) {
  if (!log) return log
  const h = hashStr('conn:' + String(log.id))
  return { ...log, ip: `10.99.${200 + (h % 40)}.${10 + ((h >>> 8) % 240)}` }
}

// Journal de connexion PAR UTILISATEUR (12/08/2026) — email nominatif en plus de l'IP,
// donc anonymisé lui aussi (même pool que anonymizeRoleHolder, cohérent avec le reste de
// l'app : une même personne réelle garde le même nom fictif partout).
export function anonymizeUserConnection(log) {
  if (!log) return log
  const h = hashStr('user-conn:' + String(log.id))
  const fakeName = FAKE_ROLE_HOLDER_NAMES[hashStr('login-email:' + (log.email || log.id)) % FAKE_ROLE_HOLDER_NAMES.length]
  return {
    ...log,
    email: log.email ? `${slugifyName(fakeName)}@${FAKE_DOMAIN}` : log.email,
    ip: log.ip ? `10.99.${200 + (h % 40)}.${10 + ((h >>> 8) % 240)}` : log.ip,
  }
}

// Remplace, dans un texte libre (résumé exécutif, CSV...), toute occurrence
// des noms/hostnames/IP/analystes réels par leur équivalent fictif — pour que
// les exports/rapports générés ne divulguent rien même en mode Présentation.
export function redactText(text, realAssets, realValidatorNames) {
  if (!text || typeof text !== 'string') return text
  let out = text
  for (const a of realAssets || []) {
    if (!a || isFakeId(a.id)) continue
    const fake = anonymizeAsset(a)
    if (a.name) out = out.split(a.name).join(fake.name)
    if (a.hostname && a.hostname !== a.name) out = out.split(a.hostname).join(fake.hostname)
    if (a.ip_address) out = out.split(a.ip_address).join(fake.ip_address)
  }
  for (const name of realValidatorNames || []) {
    if (!name) continue
    out = out.split(name).join(anonymizeValidator(name))
  }
  return out
}

// Anonymisation des ENTITÉS RÉELLES d'Incidents/Crises/Audits/Veille (21/08/2026, retour
// utilisateur — "il manque beaucoup de fake data un peu partout") : jusqu'ici ces 4 pages ne
// faisaient qu'ajouter les FAKE_* aux vraies lignes SANS les transformer (`[...data.items,
// ...FAKE_X]`), contrairement à Assets.jsx/Agents.jsx/Vulnerabilities.jsx qui appellent bien
// anonymizeAsset/anonymizeAgent/anonymizeVuln sur les vraies lignes avant de les afficher — une
// ligne réelle restait donc intégralement en clair (titre, description, noms d'actifs, analystes)
// en mode Présentation. Même principe que anonymizeVuln (id fictif → inchangé), texte libre
// passé par redactText (a besoin de la liste des vrais actifs pour savoir quoi remplacer dedans),
// noms d'analystes par anonymizeValidator (déterministe, pas besoin de connaître le nom réel à
// l'avance).
export function anonymizeIncident(inc, realAssets) {
  if (!inc || isFakeId(inc.id)) return inc
  const redact = t => redactText(t, realAssets)
  return {
    ...inc,
    title: redact(inc.title),
    description: redact(inc.description),
    notification_justification: inc.notification_justification ? redact(inc.notification_justification) : inc.notification_justification,
    crisis_title: inc.crisis_title ? redact(inc.crisis_title) : inc.crisis_title,
    reported_by: inc.reported_by ? anonymizeValidator(inc.reported_by) : inc.reported_by,
    notification_qualified_by: inc.notification_qualified_by ? anonymizeValidator(inc.notification_qualified_by) : inc.notification_qualified_by,
    early_warning_sent_by: inc.early_warning_sent_by ? anonymizeValidator(inc.early_warning_sent_by) : inc.early_warning_sent_by,
    incident_notification_sent_by: inc.incident_notification_sent_by ? anonymizeValidator(inc.incident_notification_sent_by) : inc.incident_notification_sent_by,
    final_report_sent_by: inc.final_report_sent_by ? anonymizeValidator(inc.final_report_sent_by) : inc.final_report_sent_by,
    affected_asset_names: (inc.affected_asset_names || []).map(n => redact(n)),
    completed_response_steps: (inc.completed_response_steps || []).map(s => ({ ...s, by: s.by ? anonymizeValidator(s.by) : s.by })),
  }
}

export function anonymizeCrisis(crisis, realAssets) {
  if (!crisis || isFakeId(crisis.id)) return crisis
  const redact = t => redactText(t, realAssets)
  return {
    ...crisis,
    title: redact(crisis.title),
    description: redact(crisis.description),
    stand_down_justification: crisis.stand_down_justification ? redact(crisis.stand_down_justification) : crisis.stand_down_justification,
    activated_by: crisis.activated_by ? anonymizeValidator(crisis.activated_by) : crisis.activated_by,
    stood_down_by: crisis.stood_down_by ? anonymizeValidator(crisis.stood_down_by) : crisis.stood_down_by,
    crisis_roles: (crisis.crisis_roles || []).map(r => ({ ...r, analyst_name: r.analyst_name ? anonymizeValidator(r.analyst_name) : r.analyst_name })),
    completed_crisis_steps: (crisis.completed_crisis_steps || []).map(s => ({ ...s, by: s.by ? anonymizeValidator(s.by) : s.by })),
    linked_incidents: (crisis.linked_incidents || []).map(li => ({ ...li, title: redact(li.title) })),
  }
}

export function anonymizeAudit(audit, realAssets) {
  if (!audit || isFakeId(audit.id)) return audit
  const redact = t => redactText(t, realAssets)
  return {
    ...audit,
    title: redact(audit.title),
    scope: audit.scope ? redact(audit.scope) : audit.scope,
    rules_of_engagement: audit.rules_of_engagement ? redact(audit.rules_of_engagement) : audit.rules_of_engagement,
    executive_summary: audit.executive_summary ? redact(audit.executive_summary) : audit.executive_summary,
    authorized_by: audit.authorized_by ? anonymizeValidator(audit.authorized_by) : audit.authorized_by,
    conducted_by: audit.conducted_by ? anonymizeValidator(audit.conducted_by) : audit.conducted_by,
    asset_names: (audit.asset_names || []).map(n => redact(n)),
  }
}

// Un finding d'audit réel n'a pas d'id fictif propre (il hérite du statut Présentation de son
// audit parent, cf. AuditDetail.jsx) — pas de garde `isFakeId` ici, l'appelant décide déjà quand
// l'appliquer (uniquement sur les findings d'un audit réel, jamais sur FAKE_AUDIT_FINDINGS).
export function anonymizeAuditFinding(finding, realAssets) {
  if (!finding) return finding
  const redact = t => redactText(t, realAssets)
  return {
    ...finding,
    title: redact(finding.title),
    description: finding.description ? redact(finding.description) : finding.description,
    proof_of_concept: finding.proof_of_concept ? redact(finding.proof_of_concept) : finding.proof_of_concept,
    impact: finding.impact ? redact(finding.impact) : finding.impact,
    recommendation: finding.recommendation ? redact(finding.recommendation) : finding.recommendation,
    affected_asset_name: finding.affected_asset_name ? redact(finding.affected_asset_name) : finding.affected_asset_name,
    retested_by: finding.retested_by ? anonymizeValidator(finding.retested_by) : finding.retested_by,
  }
}

// Module Gouvernance (21/08/2026, retour utilisateur — cette page n'avait jusqu'ici AUCUNE
// couverture Présentation) : `type.name` (PSSI, Charte...) reste en clair — ce sont des
// catégories de gouvernance, pas des données d'entreprise nominatives. Seuls le nom de fichier
// réel, l'auteur et la note libre d'un document UPLOADÉ sont masqués — le contenu du fichier
// lui-même (texte libre arbitraire, impossible à passer par redactText de façon fiable) est
// bloqué à la source dans DocumentPreviewModal.jsx plutôt que "anonymisé".
export function anonymizeDocument(doc) {
  if (!doc) return doc
  return {
    ...doc,
    filename: 'document' + (doc.filename?.match(/\.[a-zA-Z0-9]+$/)?.[0] || '.pdf'),
    uploaded_by: doc.uploaded_by ? anonymizeValidator(doc.uploaded_by) : doc.uploaded_by,
    notes: doc.notes ? 'Note masquée en mode Présentation.' : doc.notes,
  }
}

export function anonymizeWatchItem(item, realAssets) {
  if (!item || isFakeId(item.id)) return item
  const redact = t => redactText(t, realAssets)
  return {
    ...item,
    title: redact(item.title),
    summary: item.summary ? redact(item.summary) : item.summary,
    decision: item.decision ? redact(item.decision) : item.decision,
    reviewed_by: item.reviewed_by ? anonymizeValidator(item.reviewed_by) : item.reviewed_by,
  }
}

// ─────────────────────────────────────────────────────────────────────────
// KPI — recalcul local (mode Présentation) à partir des listes déjà fusionnées
// réel+fictif, sur le même modèle que backend/services/stats.py
// ─────────────────────────────────────────────────────────────────────────
function round1(n) { return Math.round(n * 10) / 10 }

export function computeDashboardStats(openVulns, patchedVulns, awaitingVulns, totalAssets) {
  const all = [...openVulns, ...patchedVulns, ...awaitingVulns]
  const total = all.length
  const patchedCount = patchedVulns.filter(v => v.status === 'patched').length
  const awaitingCount = awaitingVulns.length
  const exposedAssets = new Set(openVulns.map(v => v.asset?.id).filter(Boolean)).size
  const severity_rates = {}
  for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
    const totalSev = all.filter(v => v.cve?.severity === sev).length
    const patchedSev = all.filter(v => v.cve?.severity === sev && v.status === 'patched').length
    severity_rates[sev.toLowerCase()] = { total: totalSev, patched: patchedSev, rate: totalSev ? round1(patchedSev / totalSev * 100) : 0 }
  }
  return {
    total_assets: totalAssets,
    exposed_assets: exposedAssets,
    patch_rate_percent: total ? round1(patchedCount / total * 100) : 0,
    awaiting_fix_rate_percent: total ? round1(awaitingCount / total * 100) : 0,
    severity_rates,
  }
}

const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

export function sortVulnList(list, sort) {
  return [...list].sort((a, b) => {
    let va, vb
    if (sort.by === 'severity') { va = SEV_ORDER[a.cve?.severity] ?? 0; vb = SEV_ORDER[b.cve?.severity] ?? 0 }
    else if (sort.by === 'score') { va = a.cve?.cvss_score ?? 0; vb = b.cve?.cvss_score ?? 0 }
    else { va = a.cve?.published ? new Date(a.cve.published).getTime() : 0; vb = b.cve?.published ? new Date(b.cve.published).getTime() : 0 }
    return sort.dir === 'desc' ? vb - va : va - vb
  })
}

// ─────────────────────────────────────────────────────────────────────────
// Simulation des actions interactives sur les vulnérabilités de démonstration
// (id `demo-vuln-*`) — jamais d'appel réseau, tout est calculé localement.
// ─────────────────────────────────────────────────────────────────────────
export function fakePatchCheckResult(vuln) {
  const h = hashStr('patch:' + vuln.id)
  const detected = (h % 100) < 55
  const kbs = [`KB50${(h % 90000 + 10000)}`, `KB50${(hashStr('b' + vuln.id) % 90000 + 10000)}`]
  return {
    patch_detected: detected,
    note: detected ? 'Correctif détecté (simulation — mode Présentation)' : 'Aucun correctif détecté (simulation — mode Présentation)',
    kb_checked: kbs,
    kb_installed: detected ? kbs.slice(0, 1) : [],
  }
}

export function fakeAnalysis(vuln) {
  const cve = vuln.cve || {}
  const cvss = cve.cvss_score || 5
  const priority = cvss >= 9 ? 'immédiate' : cvss >= 7 ? 'haute' : cvss >= 4 ? 'normale' : 'faible'
  const urgency = {
    immédiate: 'Corriger dans les 24-48 heures.', haute: 'Corriger dans les 7 jours.',
    normale: 'Corriger dans le mois.', faible: 'Corriger à la prochaine fenêtre de maintenance.',
  }[priority]
  return {
    priority,
    cvss_score: cvss,
    urgency,
    summary: `Vulnérabilité ${cve.severity || ''} (CVSS ${cvss.toFixed(1)}) — analyse simulée en mode Présentation, aucune donnée réelle utilisée.`,
    description_fr: 'Vulnérabilité de démonstration',
    affected_product: 'Composant de démonstration',
    exploitation_probability: `EPSS ${((cve.epss_score ?? 0.2) * 100).toFixed(1)}% (simulation)`,
    criticite_asset: 'standard (simulation)',
    contexte_technique: {
      acces: 'Exploitable à distance via le réseau (donnée simulée)',
      conditions: 'Aucun compte requis (donnée simulée)',
      impact: 'Confidentialité et intégrité potentiellement compromises (donnée simulée)',
      score_context: cvss >= 9 ? 'Score critique élevé' : cvss >= 7 ? 'Score élevé' : 'Score modéré',
    },
    links: { nvd: `https://nvd.nist.gov/vuln/detail/${cve.cve_id}` },
    recommendation: {
      steps: [
        'Identifier le correctif éditeur correspondant (simulation)',
        'Planifier une fenêtre de maintenance (simulation)',
        'Appliquer et vérifier le correctif (simulation)',
      ],
      estimated_effort: cvss >= 9 ? 'Urgent — 1-2h max' : '30-60 min',
      reboot_required: cvss >= 7,
    },
  }
}

export function fakeRecommendation(vuln) {
  const asset = findFakeAsset(vuln.asset?.id)
  const isWin = (asset?.os || '').toLowerCase().includes('windows')
  const cve = vuln.cve || {}
  const steps = isWin ? [
    'Identifier le KB associé sur catalog.update.microsoft.com (simulation)',
    'Ouvrir Windows Update et appliquer le correctif correspondant (simulation)',
    "Vérifier l'installation dans l'historique des mises à jour (simulation)",
    'Redémarrer si nécessaire, hors heures de production (simulation)',
  ] : [
    'sudo apt-get update && sudo apt-get upgrade <paquet> (simulation)',
    'Vérifier la version installée après mise à jour (simulation)',
    'Redémarrer le service concerné si nécessaire (simulation)',
  ]
  return {
    steps,
    kb_or_package: isWin ? 'Voir catalog.update.microsoft.com (simulation)' : 'paquet-demo (simulation)',
    verification_cmd: isWin ? 'Get-HotFix | Sort-Object InstalledOn -Desc | Select -First 5' : 'dpkg -l | grep paquet-demo',
    reboot_required: isWin,
    estimated_effort: (cve.cvss_score || 0) >= 9 ? 'Urgent — 1-2h max' : '30-60 min',
    source: 'demo',
  }
}

export function fakeScript(vuln) {
  const asset = findFakeAsset(vuln.asset?.id)
  const isWin = (asset?.os || '').toLowerCase().includes('windows')
  const cve = vuln.cve || {}
  const script_type = isWin ? 'powershell' : 'bash'
  const script = isWin
    ? `# SIMULATION — mode Présentation, aucune action réelle\n# CVE : ${cve.cve_id}  |  CVSS : ${cve.cvss_score}\nWrite-Host "Ceci est un script de démonstration, non exécutable en conditions réelles."`
    : `#!/bin/bash\n# SIMULATION — mode Présentation, aucune action réelle\n# CVE : ${cve.cve_id}  |  CVSS : ${cve.cvss_score}\necho "Ceci est un script de démonstration, non exécutable en conditions réelles."`
  return { script, script_type }
}

export function fakeScanResult(asset) {
  return {
    reachable: true,
    packages: asset.installed_packages,
    hardware: asset.hardware,
    package_count: asset.package_count,
    last_scan: asset.last_scan,
    declared: { hostname: asset.hostname, ip_address: asset.ip_address, os: asset.os, os_version: asset.os_version },
    detected: { hostname: asset.hostname, ip_address: asset.ip_address, os: asset.os, os_version: asset.os_version },
    hostname_match: true, ip_match: true, os_match: true, os_version_match: true,
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Surveillance Identités — les identités surveillées (nom d'entreprise réel,
// domaines réels) sont le cas le plus sensible du mode Présentation : leur
// simple présence à l'écran divulgue l'identité du client. Les items de fuite
// associés viennent en plus d'articles publics en texte libre (impossible à
// anonymiser par substitution de champ comme un hostname) — on redirige donc
// les occurrences du nom/domaine réel dans le titre/résumé vers leur
// équivalent fictif (même technique que redactText), et on complète avec des
// fuites 100% fictives pour que la démo reste parlante même quand
// l'entreprise réelle n'a (heureusement) aucune fuite recensée.
// ─────────────────────────────────────────────────────────────────────────

const FAKE_COMPANY_NAMES = [
  'Norvenia Group', 'Kaltrix Industries', 'Solvane Corp', 'Meridian Dynamics',
  'Arkwell Holdings', 'Blythorn SA', 'Halden Systems', 'Verakko Group',
]
const FAKE_COMPANY_DOMAINS = [
  'norvenia.io', 'kaltrix.com', 'solvane.fr', 'meridian-dynamics.com',
  'arkwell.io', 'blythorn.fr', 'halden-systems.com', 'verakko.io',
]
// Identités "email" (28/07/2026, services/leak_lookup.py § XposedOrNot) —
// domaines cohérents avec FAKE_COMPANY_DOMAINS pour rester crédible en démo.
const FAKE_EMAILS = [
  'contact@norvenia.io', 'admin@kaltrix.com', 'contact@solvane.fr', 'it@meridian-dynamics.com',
]
// Plages documentaires (RFC 5737, TEST-NET) — jamais routées sur Internet,
// donc sûres à afficher tel quel sans risquer de pointer vers une vraie IP.
const FAKE_PUBLIC_IPS = ['203.0.113.10', '203.0.113.42', '198.51.100.7', '198.51.100.23']
const FAKE_PUBLIC_IP_RANGES = ['203.0.113.0/24', '198.51.100.0/24']

export function anonymizeIdentity(identity) {
  if (!identity || isFakeId(identity.id)) return identity
  const pools = { domain: FAKE_COMPANY_DOMAINS, ip: FAKE_PUBLIC_IPS, ip_range: FAKE_PUBLIC_IP_RANGES, email: FAKE_EMAILS }
  const pool = pools[identity.kind] || FAKE_COMPANY_NAMES
  const idx = hashStr('identity:' + String(identity.id)) % pool.length
  return { ...identity, value: pool[idx] }
}

export const FAKE_IDENTITIES = [
  { id: 'demo-identity-1', value: 'Norvenia Group', kind: 'name', enabled: true, created_at: daysAgoIso(120) },
  { id: 'demo-identity-2', value: 'norvenia.io', kind: 'domain', enabled: true, created_at: daysAgoIso(120) },
]

export const FAKE_IDENTITY_MATCHES = [
  {
    id: 'demo-identity-match-1', source: 'ransomware-live', source_label: 'Ransomware.live',
    title: 'Norvenia Group — LockBit (Extorsion)', url: '#',
    summary: "Le groupe LockBit revendique le vol de données internes de Norvenia Group, menaçant de publier les fichiers si une rançon n'est pas versée.",
    received_at: daysAgoIso(6), country: 'FR', matched_identities: ['Norvenia Group'],
  },
  {
    id: 'demo-identity-match-2', source: 'databreaches-net', source_label: 'DataBreaches.net',
    title: 'Fuite de données chez un sous-traitant de Norvenia Group', url: '#',
    summary: "Un prestataire tiers de Norvenia Group signale l'exposition accidentelle d'une base de données contenant des identifiants professionnels.",
    received_at: daysAgoIso(23), country: 'FR', matched_identities: ['norvenia.io'],
  },
]

// `realIdentities` : liste réelle (non anonymisée) reçue de l'API, nécessaire
// pour retrouver quelle identité réelle correspond à chaque valeur détectée
// dans `matched_identities` et donc quel remplacement fictif appliquer.
export function anonymizeIdentityMatch(item, realIdentities) {
  if (!item || isFakeId(item.id)) return item
  let title = item.title
  let summary = item.summary
  const matched = (item.matched_identities || []).map(value => {
    const real = (realIdentities || []).find(i => i.value === value)
    const fake = real ? anonymizeIdentity(real).value : value
    if (value) {
      if (title) title = title.split(value).join(fake)
      if (summary) summary = summary.split(value).join(fake)
    }
    return fake
  })
  return { ...item, title, summary, matched_identities: matched }
}

// IP/plage IP surveillée réelle (`identity_value`) à remplacer — l'IP
// blocklistée elle-même (`ip`) est une donnée publique (IP attaquante
// tierce), pas besoin de l'anonymiser.
export function anonymizeIpMatch(match, realIdentities) {
  const real = (realIdentities || []).find(i => i.value === match.identity_value)
  return { ...match, identity_value: real ? anonymizeIdentity(real).value : match.identity_value }
}

export const FAKE_IP_MATCHES = [
  {
    identity_value: '203.0.113.0/24', identity_kind: 'ip_range',
    source_label: 'IPsum (FireHOL)', ip: '203.0.113.42', detail: 'score 6',
  },
  {
    identity_value: '198.51.100.7', identity_kind: 'ip',
    source_label: 'Blocklist.de', ip: '198.51.100.7', detail: null,
  },
]

// Identité email/domaine réelle (`identity_value`) à remplacer — même logique
// que anonymizeIpMatch, mais sans équivalent "IP tierce publique" à préserver
// ici (`url`, quand présent, pointe vers du code GitHub public sans rapport
// avec l'entreprise réelle, pas besoin d'y toucher).
export function anonymizeOsintMatch(match, realIdentities) {
  const real = (realIdentities || []).find(i => i.value === match.identity_value)
  return { ...match, identity_value: real ? anonymizeIdentity(real).value : match.identity_value }
}

export const FAKE_OSINT_MATCHES = [
  {
    identity_value: 'contact@norvenia.io', identity_kind: 'email',
    source_label: 'XposedOrNot', detail: '3 fuite(s) connue(s) : Collection-1, Dropbox, LinkedIn', url: null,
  },
  {
    identity_value: 'norvenia.io', identity_kind: 'domain',
    source_label: 'GitHub (code public)',
    detail: '2 résultat(s) associant ce domaine à un identifiant potentiel',
    url: '#',
  },
]
