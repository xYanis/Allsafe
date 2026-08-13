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
    last_scan_result: null,
    scan_username: null,
    has_scan_password: false,
    vuln_count: 0, // complété plus bas une fois FAKE_VULNERABILITIES construit
  }
})

function findFakeAsset(id) {
  return FAKE_ASSETS.find(a => a.id === id)
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

const STATUS_CYCLE = ['patched', 'patched', 'patched', 'open', 'open', 'awaiting_fix', 'false_positive']

function daysAgoIso(n) { return new Date(Date.now() - n * 86400000).toISOString() }

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
  return {
    ...asset,
    name: fakeName,
    hostname: asset.hostname ? `${fakeName.toLowerCase()}.${FAKE_DOMAIN}` : asset.hostname,
    ip_address: asset.ip_address ? fakeIpForReal(asset.id) : asset.ip_address,
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
