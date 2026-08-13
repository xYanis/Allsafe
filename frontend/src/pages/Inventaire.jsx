import { useEffect, useState } from 'react'
import { assets as fetchAssets, scanAsset, getAssetPackages, exportInventoryPdf } from '../api/client.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { FAKE_ASSETS, anonymizeAsset, isFakeId } from '../utils/fakeData.js'
import { merakiModelLabel, assetCategory } from '../utils/assetCategory.js'
import SeverityBadge from '../components/SeverityBadge.jsx'
import NetworkStatusBadge, { NETWORK_STATUS_LABELS } from '../components/NetworkStatusBadge.jsx'
import PageLoader from '../components/PageLoader.jsx'
import OsLogo from '../components/OsLogo.jsx'
import { CRITICITE_LABELS } from '../constants/criticite.js'
import { MODULES } from '../constants/modules.js'

// Survol de ligne teinté Inventaire (11/08/2026, tour visuel) — pas de CTA principal coloré sur
// cette page (les deux boutons d'en-tête, "Scanner tout"/"Exporter en PDF", restent neutres),
// seule la table gagne le rappel de couleur du module.
const MODULE_HOVER = `${MODULES.inventaire.color}0a`

const CARD = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px' }

function formatDisks(disks) {
  if (!disks || disks.length === 0) return '—'
  return disks.map(d => `${d.name} ${d.total_gb ?? '?'} Go`).join(', ')
}

function PackagesModal({ asset, data, onClose, onRescan, rescanning }) {
  const [search, setSearch] = useState('')
  const packages = data?.packages || []
  const hardware = data?.hardware || {}
  const filtered = search.trim()
    ? packages.filter(p => (p.name || '').toLowerCase().includes(search.toLowerCase()))
    : packages

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-2xl w-full max-h-[85vh] rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>{asset.name}</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {data?.last_scan ? `Dernier scan : ${new Date(data.last_scan).toLocaleString('fr-FR')}` : 'Aucun scan effectué'}
            </p>
          </div>
          <div className="flex items-center gap-1.5 flex-shrink-0">
            {onRescan && (
              <button onClick={onRescan} disabled={rescanning}
                className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg font-medium disabled:opacity-60"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                title="Relance une connexion SSH/WinRM en lecture seule pour rafraîchir ces données"
              >
                <svg className={`w-3.5 h-3.5 ${rescanning ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                {rescanning ? 'Scan…' : 'Relancer un scan'}
              </button>
            )}
            <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>
        </div>

        <div className="p-6 space-y-4 overflow-y-auto">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>Specs matérielles</p>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="px-3 py-2 rounded-lg" style={{ background: 'var(--bg-secondary)' }}>
                <span style={{ color: 'var(--text-muted)' }}>CPU : </span>
                <span style={{ color: 'var(--text-secondary)' }}>{hardware.cpu || '—'}{hardware.cores ? ` (${hardware.cores} cœurs)` : ''}</span>
              </div>
              <div className="px-3 py-2 rounded-lg" style={{ background: 'var(--bg-secondary)' }}>
                <span style={{ color: 'var(--text-muted)' }}>RAM : </span>
                <span style={{ color: 'var(--text-secondary)' }}>{hardware.ram_gb ? `${hardware.ram_gb} Go` : '—'}</span>
              </div>
              <div className="px-3 py-2 rounded-lg col-span-2" style={{ background: 'var(--bg-secondary)' }}>
                <span style={{ color: 'var(--text-muted)' }}>Architecture : </span>
                <span style={{ color: 'var(--text-secondary)' }}>{hardware.arch || '—'}</span>
              </div>
              <div className="px-3 py-2 rounded-lg col-span-2" style={{ background: 'var(--bg-secondary)' }}>
                <span style={{ color: 'var(--text-muted)' }}>Disques : </span>
                <span style={{ color: 'var(--text-secondary)' }}>{formatDisks(hardware.disks)}</span>
              </div>
              <div className="px-3 py-2 rounded-lg col-span-2" style={{ background: 'var(--bg-secondary)' }}>
                <span style={{ color: 'var(--text-muted)' }}>IP : </span>
                <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{hardware.ip || '—'}</span>
              </div>
              <div className="px-3 py-2 rounded-lg col-span-2" style={{ background: 'var(--bg-secondary)' }}>
                <span style={{ color: 'var(--text-muted)' }}>Adresse MAC : </span>
                <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{hardware.mac || '—'}</span>
              </div>
              <div className="px-3 py-2 rounded-lg col-span-2" style={{ background: 'var(--bg-secondary)' }}>
                <span style={{ color: 'var(--text-muted)' }}>Ports ouverts : </span>
                <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>
                  {hardware.open_ports?.length > 0 ? hardware.open_ports.join(', ') : '—'}
                </span>
              </div>
            </div>
          </div>

          {packages.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
                  Applications installées ({packages.length})
                </p>
                <input
                  value={search} onChange={e => setSearch(e.target.value)}
                  placeholder="Rechercher…"
                  className="text-xs px-2.5 py-1 rounded-lg"
                  style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', outline: 'none', width: 160 }}
                />
              </div>
              <div className="max-h-64 overflow-y-auto rounded-lg" style={{ border: '1px solid var(--border)' }}>
                <table className="w-full text-xs">
                  <thead>
                    <tr style={{ background: 'var(--bg-secondary)' }}>
                      <th className="text-left px-3 py-1.5 font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Nom</th>
                      <th className="text-left px-3 py-1.5 font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Version</th>
                      <th className="text-left px-3 py-1.5 font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>MAJ disponible</th>
                      <th className="text-right px-3 py-1.5 font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Vulnérabilités</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.length === 0 && (
                      <tr><td colSpan={4} className="px-3 py-4 text-center" style={{ color: 'var(--text-muted)' }}>Aucun résultat</td></tr>
                    )}
                    {filtered.map((p, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td className="px-3 py-1.5" style={{ color: 'var(--text-secondary)' }}>{p.name}</td>
                        {/* Même code couleur qu'Assets.jsx (07/08/2026) : gris = pas de MAJ connue,
                            rouge = version installée obsolète, vert = version candidate (cible). */}
                        <td className="px-3 py-1.5 font-mono" style={{ color: p.available_version ? '#f85149' : 'var(--text-muted)' }}>
                          {p.version || '—'}
                        </td>
                        <td className="px-3 py-1.5 font-mono" style={{ color: p.available_version ? '#3fb950' : 'var(--text-muted)' }}
                            title={p.available_version ? 'Version candidate détectée dans le cache apt local du serveur (lecture seule, jamais "apt update" depuis Allsafe)' : undefined}
                        >
                          {p.available_version || '—'}
                        </td>
                        <td className="px-3 py-1.5 text-right">
                          {p.vuln_count > 0 ? (
                            <span title={p.cve_ids?.join(', ')} className="inline-flex items-center gap-1 cursor-help">
                              <SeverityBadge value={p.severity} />
                              <span style={{ color: 'var(--text-muted)' }}>×{p.vuln_count}</span>
                            </span>
                          ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="text-xs mt-2" style={{ color: 'var(--text-faint, var(--text-muted))' }}>
                Vulnérabilités déjà connues et non résolues pour cet actif (pas une vérification "dernière version publiée").
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function Inventaire() {
  const { isAnonymous } = usePresentation()
  const [assetList, setAssetList] = useState([])
  const [loading, setLoading] = useState(true)
  const [scanLoading, setScanLoading] = useState({})
  const [viewModal, setViewModal] = useState(null)
  const [pdfLoading, setPdfLoading] = useState(false)
  const [pdfError, setPdfError] = useState('')
  const [bulkScan, setBulkScan] = useState(null) // null | { total, done, errors }

  // Mêmes filtres que la page Actifs (frontend/src/pages/Assets.jsx) — même parc,
  // deux vues (sécurité vs patrimoine, cf. CLAUDE.md), même logique de filtrage.
  const [filterOs, setFilterOs] = useState('')
  const [filterCriticite, setFilterCriticite] = useState('')
  const [filterCategory, setFilterCategory] = useState('')
  const [filterNetworkStatus, setFilterNetworkStatus] = useState('')
  const [searchName, setSearchName] = useState('')
  const [configFilter, setConfigFilter] = useState('all') // 'all' | 'configured' | 'unconfigured'

  useEffect(() => {
    fetchAssets().then(a => {
      const list = a.data || []
      setAssetList(isAnonymous ? [...list.map(anonymizeAsset), ...FAKE_ASSETS] : list)
    }).finally(() => setLoading(false))
  }, [isAnonymous])

  const osOptions = [...new Set(assetList.map(a => a.os).filter(Boolean))].sort()
  const categoryOptions = [...new Set(assetList.map(assetCategory).filter(Boolean))].sort()
  const isConfigured = a => a.asset_type !== 'network' && a.package_count > 0
  const filteredAssets = assetList.filter(a => {
    if (filterOs && a.os !== filterOs) return false
    if (filterCriticite && (a.tags?.criticite || 'moyenne') !== filterCriticite) return false
    if (filterCategory && assetCategory(a) !== filterCategory) return false
    if (filterNetworkStatus && a.network_status?.status !== filterNetworkStatus) return false
    if (searchName && !a.name?.toLowerCase().includes(searchName.trim().toLowerCase())) return false
    if (configFilter === 'configured' && !isConfigured(a)) return false
    if (configFilter === 'unconfigured' && isConfigured(a)) return false
    return true
  })

  async function handleScan(asset) {
    if (isFakeId(asset.id)) {
      setViewModal({ asset, data: { packages: asset.installed_packages, hardware: asset.hardware, last_scan: asset.last_scan } })
      return
    }
    setScanLoading(l => ({ ...l, [asset.id]: true }))
    try {
      const { data } = await scanAsset(asset.id)
      if (data.reachable) {
        // Le scan peut corriger le nom/hostname déclarés (cf. routers/assets.py,
        // détail visible côté Actifs) — répercute au moins le nom ici aussi.
        const renamed = data.name_corrected
          ? { name: data.name_corrected.to, hostname: data.name_corrected.to }
          : {}
        setAssetList(prev => prev.map(a => a.id === asset.id
          ? {
              ...a, hardware: data.hardware, package_count: data.package_count, last_scan: new Date().toISOString(),
              // Bug réel corrigé (11/08/2026) : le badge "MAJ dispo" gardait sa valeur
              // périmée du chargement de page après un rescan — même correctif
              // qu'Assets.jsx, cf. son commentaire.
              available_updates_count: (data.packages || []).filter(p => p.available_version).length,
              ...renamed,
            }
          : a
        ))
        setViewModal({ asset: { ...asset, ...renamed }, data: { packages: data.packages, hardware: data.hardware, last_scan: new Date().toISOString() } })
      } else {
        setViewModal({ asset, data: { packages: [], hardware: {}, error: data.error } })
      }
    } catch (e) {
      setViewModal({ asset, data: { packages: [], hardware: {}, error: e?.response?.data?.detail || 'Erreur lors du scan.' } })
    } finally {
      setScanLoading(l => ({ ...l, [asset.id]: false }))
    }
  }

  // Comme sur la page Actifs : privilégier le résultat déjà en base (rapide) plutôt
  // que de relancer systématiquement une connexion SSH/WinRM au clic sur "Scanner" —
  // un scan live reste possible via "Relancer un scan" dans la modale.
  function handleRowScanClick(asset) {
    if (asset.last_scan) {
      handleView(asset)
    } else if (!scanLoading[asset.id]) {
      handleScan(asset)
    }
  }

  async function handleView(asset) {
    if (isFakeId(asset.id)) {
      setViewModal({ asset, data: { packages: asset.installed_packages, hardware: asset.hardware, last_scan: asset.last_scan } })
      return
    }
    try {
      const { data } = await getAssetPackages(asset.id)
      setViewModal({ asset, data })
    } catch {
      setViewModal({ asset, data: { packages: [], hardware: {}, error: 'Erreur lors du chargement.' } })
    }
  }

  // Action groupée (03/08/2026) : scanne les actifs réels un par un (jamais les fictifs du mode
  // Présentation) plutôt que de forcer l'utilisateur à cliquer "Scanner" ligne par ligne sur les
  // 72 actifs du parc. Toujours lecture seule (SSH/WinRM, cf. handleScan) — même connexion que le
  // scan unitaire, juste répétée avec une concurrence limitée pour ne pas saturer le réseau/AD
  // d'un coup. Les échecs individuels (actif injoignable) ne bloquent pas les suivants.
  async function handleScanAll() {
    const targets = assetList.filter(a => !isFakeId(a.id) && !scanLoading[a.id])
    if (targets.length === 0 || bulkScan) return
    setBulkScan({ total: targets.length, done: 0, errors: 0 })

    const CONCURRENCY = 3
    let idx = 0
    async function worker() {
      while (idx < targets.length) {
        const asset = targets[idx++]
        setScanLoading(l => ({ ...l, [asset.id]: true }))
        let failed = false
        try {
          const { data } = await scanAsset(asset.id)
          if (data.reachable) {
            const renamed = data.name_corrected
              ? { name: data.name_corrected.to, hostname: data.name_corrected.to }
              : {}
            setAssetList(prev => prev.map(a => a.id === asset.id
              ? {
                  ...a, hardware: data.hardware, package_count: data.package_count, last_scan: new Date().toISOString(),
                  available_updates_count: (data.packages || []).filter(p => p.available_version).length,
                  ...renamed,
                }
              : a
            ))
          } else {
            failed = true
          }
        } catch {
          failed = true
        } finally {
          setScanLoading(l => ({ ...l, [asset.id]: false }))
          setBulkScan(b => b && ({ ...b, done: b.done + 1, errors: b.errors + (failed ? 1 : 0) }))
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, targets.length) }, worker))
    setTimeout(() => setBulkScan(b => (b?.done === b?.total ? null : b)), 5000)
  }

  // Généré côté backend depuis les vraies données (cf. services/inventory_export.py) —
  // pas de version anonymisée possible pour un PDF, donc bloqué en mode Présentation
  // plutôt que de risquer d'exposer noms d'actifs/IP réels à l'écran pendant une démo.
  function handleExportPdf() {
    if (isAnonymous) {
      setPdfError('Export indisponible en mode Présentation (données réelles non anonymisées).')
      return
    }
    setPdfLoading(true)
    setPdfError('')
    exportInventoryPdf()
      .then(r => {
        const blob = new Blob([r.data], { type: 'application/pdf' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `cbr-inventaire-${new Date().toISOString().slice(0, 10)}.pdf`
        a.click()
        URL.revokeObjectURL(url)
      })
      .catch(() => setPdfError('Erreur lors de l\'export PDF.'))
      .finally(() => setPdfLoading(false))
  }

  if (loading) return <PageLoader />

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Inventaire Complet <span className="font-normal text-lg" style={{ color: 'var(--text-muted)' }}>
              ({filteredAssets.length}{filteredAssets.length !== assetList.length ? ` / ${assetList.length}` : ''})
            </span>
          </h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>Specs matérielles et applications installées — lecture seule, jamais d'écriture sur les serveurs</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap flex-shrink-0">
          <input
            value={searchName}
            onChange={e => setSearchName(e.target.value)}
            placeholder="Rechercher un actif…"
            className="text-sm"
            style={{
              background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8,
              color: 'var(--text-primary)', padding: '6px 12px', outline: 'none', width: 160,
            }}
          />
          <select
            value={filterOs}
            onChange={e => setFilterOs(e.target.value)}
            style={{
              background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8,
              color: 'var(--text-secondary)', padding: '6px 12px', fontSize: 13, outline: 'none', cursor: 'pointer',
            }}
          >
            <option value="">Tous les OS</option>
            {osOptions.map(os => {
              const category = merakiModelLabel(os)
              return <option key={os} value={os}>{category ? `${category} (${os})` : os}</option>
            })}
          </select>
          <select
            value={filterCriticite}
            onChange={e => setFilterCriticite(e.target.value)}
            style={{
              background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8,
              color: 'var(--text-secondary)', padding: '6px 12px', fontSize: 13, outline: 'none', cursor: 'pointer',
            }}
          >
            <option value="">Toutes criticités</option>
            {Object.entries(CRITICITE_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
          <select
            value={filterCategory}
            onChange={e => setFilterCategory(e.target.value)}
            style={{
              background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8,
              color: 'var(--text-secondary)', padding: '6px 12px', fontSize: 13, outline: 'none', cursor: 'pointer',
            }}
          >
            <option value="">Toutes catégories</option>
            {categoryOptions.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          <select
            value={filterNetworkStatus}
            onChange={e => setFilterNetworkStatus(e.target.value)}
            style={{
              background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8,
              color: 'var(--text-secondary)', padding: '6px 12px', fontSize: 13, outline: 'none', cursor: 'pointer',
            }}
          >
            <option value="">Tout statut réseau</option>
            {Object.entries(NETWORK_STATUS_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
          <select
            value={configFilter}
            onChange={e => setConfigFilter(e.target.value)}
            style={{
              background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8,
              color: 'var(--text-secondary)', padding: '6px 12px', fontSize: 13, outline: 'none', cursor: 'pointer',
            }}
          >
            <option value="all">Configurés et non configurés</option>
            <option value="configured">Configurés uniquement</option>
            <option value="unconfigured">Non configurés uniquement</option>
          </select>
          <button onClick={handleScanAll} disabled={!!bulkScan}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg transition-colors disabled:opacity-60"
            style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
            title="Scanne tous les actifs un par un — lecture seule (SSH/WinRM), jamais d'écriture sur les serveurs"
          >
            <svg className={`w-3.5 h-3.5 ${bulkScan ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            {bulkScan ? `Scan… ${bulkScan.done}/${bulkScan.total}` : 'Scanner tout'}
          </button>
          <button onClick={handleExportPdf} disabled={pdfLoading}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg transition-colors disabled:opacity-50"
            style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
            title="Export PDF de tous les actifs — nom, CPU, architecture, cœurs, RAM, disques et applications installées"
          >
            {pdfLoading ? (
              <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
            ) : (
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H8a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
            )}
            {pdfLoading ? 'Génération…' : 'Exporter en PDF'}
          </button>
        </div>
      </div>
      {bulkScan && bulkScan.errors > 0 && (
        <div className="text-xs px-3 py-2 rounded-lg" style={{ background: 'rgba(251,143,68,0.1)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.2)' }}>
          {bulkScan.errors} actif{bulkScan.errors > 1 ? 's' : ''} injoignable{bulkScan.errors > 1 ? 's' : ''} pour l'instant — les autres continuent.
        </div>
      )}
      {pdfError && (
        <div className="text-xs px-3 py-2 rounded-lg" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {pdfError}
        </div>
      )}

      <div style={CARD} className="overflow-hidden">
        <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
              {['Nom', 'Réseau', 'CPU', 'Arch.', 'Cœurs', 'RAM', 'Disques', 'Apps', 'Dernier scan', 'Actions'].map(h => (
                <th key={h}
                  className={`px-4 py-3 text-xs font-semibold uppercase tracking-wide ${h === 'Réseau' ? 'text-center' : 'text-left'}`}
                  style={{ color: 'var(--text-muted)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {assetList.length === 0 && (
              <tr><td colSpan={10} className="px-4 py-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>Aucun actif importé</td></tr>
            )}
            {assetList.length > 0 && filteredAssets.length === 0 && (
              <tr><td colSpan={10} className="px-4 py-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>Aucun actif ne correspond à ces filtres</td></tr>
            )}
            {filteredAssets.map(a => {
              const hw = a.hardware || {}
              return (
                <tr key={a.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}
                  onMouseEnter={e => e.currentTarget.style.background = MODULE_HOVER}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td className="px-4 py-3 font-semibold" style={{ color: 'var(--text-primary)' }}>
                    <span className="inline-flex items-center gap-1.5">
                      <OsLogo os={a.os} title={a.os} />
                      {a.name}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-center">
                      <NetworkStatusBadge networkStatus={a.network_status} compact />
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>{hw.cpu || '—'}</td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>{hw.arch || '—'}</td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>{hw.cores ?? '—'}</td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>{hw.ram_gb ? `${hw.ram_gb} Go` : '—'}</td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>{formatDisks(hw.disks)}</td>
                  <td className="px-4 py-3 text-xs">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {a.package_count > 0 ? (
                        <button onClick={() => handleView(a)}
                          className="px-2 py-0.5 rounded-md font-medium"
                          style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.2)' }}
                        >{a.package_count} app{a.package_count !== 1 ? 's' : ''}</button>
                      ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                      {/* MAJ dispo indépendamment d'une CVE connue (10/08/2026), même champ que
                          Assets.jsx — Linux uniquement (apt list --upgradable côté serveur). */}
                      {a.available_updates_count > 0 && (
                        <button onClick={() => handleView(a)}
                          className="px-2 py-0.5 rounded-md font-medium"
                          style={{ background: 'rgba(210,153,34,0.1)', color: '#d29922', border: '1px solid rgba(210,153,34,0.25)' }}
                          title={`${a.available_updates_count} paquet${a.available_updates_count !== 1 ? 's' : ''} avec une version plus récente dans le cache apt local du serveur — indépendamment de toute CVE connue`}
                        >{a.available_updates_count} MAJ dispo</button>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                    {a.last_scan ? new Date(a.last_scan).toLocaleDateString('fr-FR') : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <button onClick={() => handleRowScanClick(a)}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-lg transition-colors"
                      style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                      title={a.last_scan ? "Voir le dernier scan (bouton “Relancer un scan” dans la fenêtre pour rescanner)" : "Scanner"}
                    >
                      {scanLoading[a.id] ? (
                        <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
                      ) : (
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-4.35-4.35M17 10.5a6.5 6.5 0 11-13 0 6.5 6.5 0 0113 0z" /></svg>
                      )}
                      {scanLoading[a.id] ? 'Scan…' : 'Scanner'}
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        </div>
      </div>

      {viewModal && (
        <PackagesModal asset={viewModal.asset} data={viewModal.data} onClose={() => setViewModal(null)}
          onRescan={isFakeId(viewModal.asset.id) ? undefined : () => handleScan(viewModal.asset)}
          rescanning={!!scanLoading[viewModal.asset.id]}
        />
      )}
    </div>
  )
}
