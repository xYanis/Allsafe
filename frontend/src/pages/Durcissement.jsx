import { Fragment, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { assets as fetchAssets, runWebHardeningCheck, scanPolicies } from '../api/client.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { FAKE_ASSETS, anonymizeAsset, isFakeId } from '../utils/fakeData.js'
import { assetCategory, categoryStyle } from '../utils/assetCategory.js'
import PageLoader from '../components/PageLoader.jsx'
import PageHero from '../components/PageHero.jsx'
import OsLogo from '../components/OsLogo.jsx'
import CategoryIcon from '../components/CategoryIcon.jsx'
import ComplianceChecklist, { complianceSummary } from '../components/ComplianceChecklist.jsx'
import { MODULES } from '../constants/modules.js'
import { tintedCard } from '../utils/cardStyle.js'

// Durcissement (12/08/2026, ex-section "Durcissement / conformité" de la modale de scan
// d'Assets.jsx, demande utilisateur — "sortir la modal pour en faire un module à part") : vue
// dédiée sur tout le parc, plus adaptée pour repérer les non-conformités que noyée dans une
// modale par-actif. Aucun nouvel endpoint : `GET /assets` porte déjà `last_scan_result` (serveurs/
// postes, compte de service ou agent) et `network_compliance` (équipements réseau Meraki/PRTG) en
// entier pour chaque actif — la page recalcule juste le résumé côté client.
//
// 13/08/2026 : la modale de détail (DetailModal) a été retirée — demande utilisateur, pas
// pratique pour lire une liste de checks (hauteur/largeur contraintes). Remplacée par un
// dépliage inline de la ligne, même esprit que les sections repliables de
// ComplianceChecklist.jsx — une seule ligne dépliée à la fois.
const MODULE_HOVER = `${MODULES.inventaire.color}0a`
const CARD = tintedCard(MODULES.inventaire.color)

function checksFor(asset) {
  // web_compliance (17/08/2026, asset_type="website") : même principe que network_compliance
  // ci-dessous — ni OS ni scan SSH/WinRM, checks passifs propres (en-têtes HTTP, TLS).
  const base = asset.asset_type === 'network'
    ? asset.network_compliance?.checks || []
    : asset.asset_type === 'website'
    ? asset.web_compliance?.checks || []
    : asset.last_scan_result?.compliance?.checks || []
  // os_eol_check (17/08/2026) : calculé serveur-side à la volée (routers/assets.py::_asset_dict,
  // jamais stocké) depuis os/os_version déjà connus — préfixé plutôt qu'ajouté à la fin, c'est
  // le check le plus actionnable quand il est présent (warn = OS en fin de support).
  return asset.os_eol_check ? [asset.os_eol_check, ...base] : base
}

function SummaryBadges({ summary }) {
  if (summary.total === 0) {
    return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Aucun check collecté</span>
  }
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {summary.ok > 0 && (
        <span className="text-xs px-1.5 py-0.5 rounded font-medium" style={{ background: 'rgba(63,185,80,0.1)', color: '#3fb950' }}>
          ✓ {summary.ok}
        </span>
      )}
      {summary.warn > 0 && (
        <span className="text-xs px-1.5 py-0.5 rounded font-medium" style={{ background: 'rgba(251,143,68,0.1)', color: '#fb8f44' }}>
          ⚠ {summary.warn}
        </span>
      )}
      {summary.unknown > 0 && (
        <span className="text-xs px-1.5 py-0.5 rounded font-medium" style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)' }}>
          — {summary.unknown}
        </span>
      )}
    </div>
  )
}

const filterSelectStyle = { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }
const activeFilterStyle = { background: `${MODULES.inventaire.color}1f`, color: MODULES.inventaire.color, border: `1px solid ${MODULES.inventaire.color}59` }

// Tri des colonnes (13/08/2026, demande utilisateur) — même convention visuelle que
// Vulnerabilities.jsx (flèche ↑/↓ sur l'en-tête actif), en client-side ici (tout le parc est
// déjà chargé en une fois par cette page, contrairement à Vulnerabilities.jsx qui pagine
// côté serveur — pas besoin d'aller-retour réseau pour trier une liste déjà en mémoire).
function SortHeader({ label, col, sort, onSort }) {
  const active = sort.by === col
  const arrow = active ? (sort.dir === 'desc' ? ' ↓' : ' ↑') : ''
  return (
    <th
      onClick={() => onSort(col)}
      className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide cursor-pointer select-none"
      style={{ color: active ? MODULES.inventaire.color : 'var(--text-muted)' }}
    >
      {label}{arrow}
    </th>
  )
}

// Valeur comparable par colonne triable — seulement "summary"/"last_scan" (13/08/2026, retour
// utilisateur : OS/Catégorie ont trop peu de valeurs distinctes pour qu'un tri croissant/
// décroissant serve à quelque chose, ce qu'il fallait là c'est choisir QUELLES valeurs afficher
// — remplacé par des menus déroulants, cf. osOptions/categoryOptions plus bas). "summary" trie
// par nombre d'avertissements d'abord (le signal le plus actionnable), puis indéterminés — pas
// par nombre total de checks, qui ne dit rien de l'état de conformité. "last_scan" : jamais
// scanné traité comme le plus ancien possible (0), reste groupé en premier en tri croissant et
// en dernier en tri décroissant.
function sortValue(col, asset, summary) {
  switch (col) {
    case 'summary': return summary.warn * 1000 + summary.unknown
    case 'last_scan': return asset.last_scan ? new Date(asset.last_scan).getTime() : 0
    default: return ''
  }
}

// Cache module (pas du state React) qui survit au démontage/remontage du composant —
// cette page est entièrement redémontée à chaque navigation (pas de keep-alive de route),
// donc y revenir relançait le fetch et l'écran de chargement plein écran à CHAQUE fois.
// Permet de réafficher instantanément les dernières données connues au remontage pendant
// qu'un rafraîchissement silencieux les met à jour en fond. Réponse BRUTE de fetchAssets()
// (avant tri/filtrage local), pas les listes déjà filtrées par l'utilisateur — cette page
// est celle qui porte le payload par actif le plus lourd de l'app (last_scan_result.compliance/
// network_compliance en entier), le cache stocke donc la réponse complète telle que reçue.
let durcissementPageCache = null

export default function Durcissement() {
  const { isAnonymous } = usePresentation()
  const [assetList, setAssetList] = useState(() => {
    if (durcissementPageCache == null) return []
    return isAnonymous ? [...durcissementPageCache.map(anonymizeAsset), ...FAKE_ASSETS] : durcissementPageCache
  })
  const [loading, setLoading] = useState(() => durcissementPageCache == null)
  const [search, setSearch] = useState('')
  const [warnOnly, setWarnOnly] = useState(false)
  // "Actifs configurés uniquement" (13/08/2026, demande utilisateur ; critère corrigé 17/08/2026)
  // : ne garde que les actifs avec un compte de service ou un agent — exclut les actifs réseau
  // importés (Meraki/PRTG), les sites web (checks passifs, aucun credential) et les hôtes ESXi
  // (`collection_method="vsphere_api"`, pas de durcissement dans cette passe, cf.
  // docs/ARCHITECTURE.md § Intégration vSphere). 1er jet (`checks.length === 0`, proxy indirect)
  // cassé par l'ajout d'`os_eol_check` (17/08/2026, calculé même sans scan réel dès qu'un OS est
  // déclaré) — remplacé par un critère direct sur `collection_method`, qui ne dépend d'aucun
  // autre check et ne se recassera pas si un nouveau check "toujours présent" est ajouté plus tard.
  const [configuredOnly, setConfiguredOnly] = useState(false)
  // Filtres OS/Catégorie (13/08/2026) : menus déroulants plutôt qu'un tri — peu de valeurs
  // distinctes possibles (poignée d'OS, poignée de catégories), choisir LAQUELLE afficher est
  // plus utile qu'un ordre croissant/décroissant dessus. '' = toutes.
  const [osFilter, setOsFilter] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')
  const [expandedId, setExpandedId] = useState(null)
  // { by: null, dir } = ordre par défaut de GET /assets (alphabétique par nom), jusqu'au
  // premier clic sur un en-tête triable.
  const [sort, setSort] = useState({ by: null, dir: 'desc' })
  const [searchParams, setSearchParams] = useSearchParams()
  // Bouton "Lancer le scan web" (17/08/2026) — seul déclencheur de POST /assets/web-hardening/run
  // exposé côté UI (l'endpoint existait déjà sans bouton, comme network-protocol-check/
  // switch-hardening juste à côté dans routers/assets.py, mais un actif "Site web" nouvellement
  // créé n'a sinon aucun moyen de se faire scanner sans curl direct).
  const [scanningWeb, setScanningWeb] = useState(false)
  const [webScanMsg, setWebScanMsg] = useState('')
  // Signal de fraîcheur des actifs agent (17/08/2026) — un actif collecté par l'agent Rust
  // pousse ses données lui-même (checkin), Allsafe ne peut pas le forcer à se reconnecter sur
  // planning comme un actif service_account (cf. services/scan_policy.py). Seuil dérivé
  // directement de la fréquence de la politique de scan du même groupe de criticité : une seule
  // source de vérité pour "quelle fraîcheur est attendue", pas un réglage séparé à maintenir.
  const [policyFrequencyByCriticite, setPolicyFrequencyByCriticite] = useState({})

  useEffect(() => {
    scanPolicies().then(r => {
      const map = {}
      for (const p of r.data.items) map[p.criticite] = p.frequency
      setPolicyFrequencyByCriticite(map)
    }).catch(() => {})
  }, [])

  function agentStaleness(asset) {
    if (asset.collection_method !== 'agent' || !asset.last_scan) return null
    const criticite = asset.tags?.criticite || 'moyenne'
    const frequency = policyFrequencyByCriticite[criticite]
    if (!frequency) return null
    const maxAgeDays = frequency === 'daily' ? 1 : 7
    const ageDays = (Date.now() - new Date(asset.last_scan).getTime()) / 86400000
    if (ageDays <= maxAgeDays) return null
    return `Dernier checkin il y a ${Math.floor(ageDays)} jour(s) — attendu : ${frequency === 'daily' ? 'quotidien' : 'hebdomadaire'}`
  }

  function reload() {
    return fetchAssets()
      .then(r => {
        const raw = r.data || []
        durcissementPageCache = raw   // alimente le cache module pour le prochain remontage
        let list = raw
        if (isAnonymous) list = [...list.map(anonymizeAsset), ...FAKE_ASSETS]
        setAssetList(list)
      })
  }

  useEffect(() => { reload().finally(() => setLoading(false)) }, [isAnonymous])

  async function handleWebScan() {
    setScanningWeb(true)
    setWebScanMsg('')
    try {
      const { data } = await runWebHardeningCheck()
      await reload()
      setWebScanMsg(data.checked > 0
        ? `${data.checked} site(s) vérifié(s), ${data.warnings} avec avertissement(s)`
        : "Aucun actif \"Site web\" à vérifier")
    } catch {
      setWebScanMsg('Erreur lors du scan web')
    } finally {
      setScanningWeb(false)
      setTimeout(() => setWebScanMsg(''), 6000)
    }
  }

  // Deep-link depuis Assets.jsx ("Voir le durcissement/conformité de cet actif →",
  // ?asset=<id>) — même esprit que le bandeau de rattrapage CVE du Dashboard. Déplie la ligne
  // visée au lieu d'ouvrir une modale (13/08/2026).
  useEffect(() => {
    const assetId = searchParams.get('asset')
    if (!assetId || assetList.length === 0) return
    const target = assetList.find(a => a.id === assetId)
    if (target) {
      setExpandedId(target.id)
      searchParams.delete('asset')
      setSearchParams(searchParams, { replace: true })
      // Sans ça, la ligne se dépliait bien mais restait hors écran dans un tableau non paginé
      // (potentiellement des dizaines d'actifs) — perçu à tort comme "revenu sur la page de
      // base sans rien garder de sélectionné" (18/08/2026, retour utilisateur). Un frame
      // d'attente : la ligne doit être montée avant de pouvoir la cibler par id.
      requestAnimationFrame(() => {
        document.getElementById(`durcissement-row-${target.id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
      })
    }
  }, [assetList, searchParams, setSearchParams])

  const rows = useMemo(() => {
    return assetList.map(a => ({ asset: a, checks: checksFor(a), summary: complianceSummary(checksFor(a)) }))
  }, [assetList])

  // Options des menus déroulants OS/Catégorie — dérivées des actifs réellement présents plutôt
  // qu'une liste codée en dur (cf. principe "penser scalable", CLAUDE.md) : s'adapte
  // automatiquement à ce que le parc contient vraiment.
  const osOptions = useMemo(
    () => [...new Set(rows.map(r => r.asset.os).filter(Boolean))].sort((a, b) => a.localeCompare(b)),
    [rows],
  )
  const categoryOptions = useMemo(
    () => [...new Set(rows.map(r => assetCategory(r.asset)))].sort((a, b) => a.localeCompare(b)),
    [rows],
  )

  const sorted = useMemo(() => {
    if (!sort.by) return rows
    const dir = sort.dir === 'desc' ? -1 : 1
    return [...rows].sort((a, b) => {
      const va = sortValue(sort.by, a.asset, a.summary)
      const vb = sortValue(sort.by, b.asset, b.summary)
      if (va < vb) return -1 * dir
      if (va > vb) return 1 * dir
      return 0
    })
  }, [rows, sort])

  const filtered = sorted.filter(({ asset, summary }) => {
    if (search.trim() && !asset.name.toLowerCase().includes(search.trim().toLowerCase())) return false
    if (warnOnly && summary.warn === 0) return false
    if (configuredOnly) {
      if (asset.asset_type === 'network' || asset.asset_type === 'website') return false
      if (asset.collection_method !== 'service_account' && asset.collection_method !== 'agent') return false
    }
    if (osFilter && asset.os !== osFilter) return false
    if (categoryFilter && assetCategory(asset) !== categoryFilter) return false
    return true
  })

  function handleSort(col) {
    setSort(s => s.by === col ? { by: col, dir: s.dir === 'desc' ? 'asc' : 'desc' } : { by: col, dir: 'desc' })
  }

  if (loading) return <PageLoader />

  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M6 13.5V3.75m0 9.75a1.5 1.5 0 010 3m0-3a1.5 1.5 0 000 3m0 3.75V16.5m12-12V3.75m0 9.75a1.5 1.5 0 010 3m0-3a1.5 1.5 0 000 3m0 3.75V16.5m-6-9V3.75m0 3.75a1.5 1.5 0 010 3m0-3a1.5 1.5 0 000 3m0 9.75V10.5"
        title="Durcissement"
        color="#39c5cf"
        subtitle="Conformité CIS-like du parc — compte de service ou agent, lecture seule."
      />

      <div className="flex flex-wrap items-center gap-2">
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Rechercher un actif…"
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={filterSelectStyle} />
        <select value={osFilter} onChange={e => setOsFilter(e.target.value)}
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={osFilter ? activeFilterStyle : filterSelectStyle}>
          <option value="">Tous les OS</option>
          {osOptions.map(os => <option key={os} value={os}>{os}</option>)}
        </select>
        <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)}
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={categoryFilter ? activeFilterStyle : filterSelectStyle}>
          <option value="">Toutes les catégories</option>
          {categoryOptions.map(cat => <option key={cat} value={cat}>{cat}</option>)}
        </select>
        <button onClick={() => setWarnOnly(w => !w)}
          className="text-xs px-2.5 py-1.5 rounded-lg font-medium"
          style={warnOnly
            ? { background: 'rgba(251,143,68,0.12)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.35)' }
            : filterSelectStyle}>
          ⚠ Avec avertissements uniquement
        </button>
        <button onClick={() => setConfiguredOnly(c => !c)}
          className="text-xs px-2.5 py-1.5 rounded-lg font-medium"
          style={configuredOnly ? activeFilterStyle : filterSelectStyle}>
          Actifs configurés uniquement
        </button>
        <button onClick={handleWebScan} disabled={scanningWeb}
          title="Checks passifs (en-têtes HTTP, protocole TLS) sur tous les actifs Site web"
          className="text-xs px-2.5 py-1.5 rounded-lg font-medium disabled:opacity-60"
          style={filterSelectStyle}>
          {scanningWeb ? 'Scan en cours…' : 'Lancer le scan web'}
        </button>
        {webScanMsg && <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{webScanMsg}</span>}
      </div>

      <div style={CARD} className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Nom</th>
                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>OS</th>
                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Catégorie</th>
                <SortHeader label="Résumé" col="summary" sort={sort} onSort={handleSort} />
                <SortHeader label="Dernier scan" col="last_scan" sort={sort} onSort={handleSort} />
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>Aucun actif ne correspond à ces filtres</td></tr>
              )}
              {filtered.map(({ asset, checks, summary }) => {
                const isOpen = expandedId === asset.id
                return (
                  <Fragment key={asset.id}>
                    <tr
                      id={`durcissement-row-${asset.id}`}
                      onClick={() => setExpandedId(isOpen ? null : asset.id)}
                      className="cursor-pointer"
                      style={{ borderBottom: isOpen ? 'none' : '1px solid var(--border-subtle)', background: isOpen ? MODULE_HOVER : 'transparent' }}
                      onMouseEnter={e => { if (!isOpen) e.currentTarget.style.background = MODULE_HOVER }}
                      onMouseLeave={e => { if (!isOpen) e.currentTarget.style.background = 'transparent' }}
                    >
                      <td className="px-4 py-3 font-semibold" style={{ color: 'var(--text-primary)' }}>
                        <span className="inline-block mr-1.5 transition-transform" style={{ transform: isOpen ? 'rotate(90deg)' : 'none', color: 'var(--text-muted)' }}>›</span>
                        {asset.name}
                      </td>
                      <td className="px-4 py-3">
                        <OsLogo os={asset.os} size={18} />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-center" title={assetCategory(asset)}>
                          <CategoryIcon category={assetCategory(asset)} style={{ color: categoryStyle(assetCategory(asset)).color }} />
                        </div>
                      </td>
                      <td className="px-4 py-3"><SummaryBadges summary={summary} /></td>
                      <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                        <div className="flex items-center gap-1.5">
                          <span>{asset.last_scan ? new Date(asset.last_scan).toLocaleDateString('fr-FR') : '—'}</span>
                          {agentStaleness(asset) && (
                            <span title={agentStaleness(asset)} style={{ color: '#d29922' }}>
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                              </svg>
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                    {isOpen && (
                      <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td colSpan={5} className="px-4 pb-4 pt-1" style={{ background: 'var(--bg-secondary)' }}>
                          <ComplianceChecklist checks={checks} os={asset.os} assetType={asset.asset_type} maxHeight="420px" />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
