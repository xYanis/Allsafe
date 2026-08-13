import { Fragment, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { assets as fetchAssets } from '../api/client.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { FAKE_ASSETS, anonymizeAsset, isFakeId } from '../utils/fakeData.js'
import { assetCategory, categoryStyle } from '../utils/assetCategory.js'
import PageLoader from '../components/PageLoader.jsx'
import OsLogo from '../components/OsLogo.jsx'
import ComplianceChecklist, { complianceSummary } from '../components/ComplianceChecklist.jsx'
import { MODULES } from '../constants/modules.js'

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
const CARD = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px' }

function checksFor(asset) {
  return asset.asset_type === 'network'
    ? asset.network_compliance?.checks || []
    : asset.last_scan_result?.compliance?.checks || []
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

export default function Durcissement() {
  const [assetList, setAssetList] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [warnOnly, setWarnOnly] = useState(false)
  // "Actifs configurés uniquement" (13/08/2026, demande utilisateur) : masque les actifs sans
  // aucun check collecté — typiquement des actifs réseau importés (Meraki/PRTG) sans
  // scan_username renseigné (jamais de durcissement Cisco possible dessus) ou un hôte ESXi
  // (collection_method="vsphere_api", pas de durcissement dans cette passe, cf. docs/ARCHITECTURE.md
  // § Intégration vSphere) — réduit le bruit plutôt que d'afficher une ligne qui ne dira jamais
  // rien d'utile.
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
  const { isAnonymous } = usePresentation()
  const [searchParams, setSearchParams] = useSearchParams()

  useEffect(() => {
    fetchAssets()
      .then(r => {
        let list = r.data || []
        if (isAnonymous) list = [...list.map(anonymizeAsset), ...FAKE_ASSETS]
        setAssetList(list)
      })
      .finally(() => setLoading(false))
  }, [isAnonymous])

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

  const filtered = sorted.filter(({ asset, summary, checks }) => {
    if (search.trim() && !asset.name.toLowerCase().includes(search.trim().toLowerCase())) return false
    if (warnOnly && summary.warn === 0) return false
    if (configuredOnly && checks.length === 0) return false
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
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Durcissement{' '}
            <span className="font-normal text-lg" style={{ color: 'var(--text-muted)' }}>({filtered.length} / {rows.length})</span>
          </h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Conformité CIS-like du parc — compte de service ou agent, lecture seule.
          </p>
        </div>
      </div>

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
                      onClick={() => setExpandedId(isOpen ? null : asset.id)}
                      className="cursor-pointer"
                      style={{ borderBottom: isOpen ? 'none' : '1px solid var(--border-subtle)' }}
                      onMouseEnter={e => e.currentTarget.style.background = MODULE_HOVER}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <td className="px-4 py-3 font-semibold" style={{ color: 'var(--text-primary)' }}>
                        <span className="inline-block mr-1.5 transition-transform" style={{ transform: isOpen ? 'rotate(90deg)' : 'none', color: 'var(--text-muted)' }}>›</span>
                        {asset.name}
                      </td>
                      <td className="px-4 py-3">
                        <OsLogo os={asset.os} size={18} />
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs px-2 py-0.5 rounded-md font-medium whitespace-nowrap" style={categoryStyle(assetCategory(asset))}>
                          {assetCategory(asset)}
                        </span>
                      </td>
                      <td className="px-4 py-3"><SummaryBadges summary={summary} /></td>
                      <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                        {asset.last_scan ? new Date(asset.last_scan).toLocaleDateString('fr-FR') : '—'}
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
