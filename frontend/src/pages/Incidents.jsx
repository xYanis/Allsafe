import { useEffect, useState, useCallback } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { incidents as fetchIncidents, createIncident, updateIncident, assets as fetchAssets, prefillIncident, exportIncidents } from '../api/client.js'
import PageLoader from '../components/PageLoader.jsx'
import IncidentSeverityBadge from '../components/IncidentSeverityBadge.jsx'
import IncidentNIS2Badges from '../components/IncidentNIS2Badges.jsx'
import IncidentFormModal, { INCIDENT_CATEGORIES, INCIDENT_SEVERITIES, INCIDENT_STATUSES } from '../components/IncidentFormModal.jsx'
import IncidentDetailModal from '../components/IncidentDetailModal.jsx'
import { MODULES } from '../constants/modules.js'
import PageHero from '../components/PageHero.jsx'
import { tintedCard } from '../utils/cardStyle.js'

const MODULE_COLOR = MODULES.incidents.color

const STATUS_STYLES = {
  declared:    { background: 'rgba(139,148,158,0.12)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' },
  in_progress: { background: 'rgba(88,166,255,0.12)',  color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' },
  contained:   { background: 'rgba(251,143,68,0.12)',  color: '#fb8f44', border: '1px solid rgba(251,143,68,0.3)' },
  resolved:    { background: 'rgba(63,185,80,0.12)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)'  },
  closed:      { background: 'rgba(163,113,247,0.12)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.3)' },
}

function StatusBadge({ value }) {
  const s = STATUS_STYLES[value] || STATUS_STYLES.declared
  const label = INCIDENT_STATUSES.find(s2 => s2.value === value)?.label || value
  return <span style={{ ...s, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, display: 'inline-block' }}>{label}</span>
}

const filterSelectStyle = { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }
const activeFilterSelectStyle = { background: `${MODULE_COLOR}1f`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }
const PER_PAGE = 25

// Cache module (pas du state React) qui survit au démontage/remontage du composant —
// cette page est entièrement redémontée à chaque navigation (pas de keep-alive de route),
// donc y revenir relançait le fetch et l'écran de chargement plein écran à CHAQUE fois.
// Permet de réafficher instantanément les dernières données connues au remontage pendant
// qu'un rafraîchissement silencieux les met à jour en fond. Seule la liste non filtrée
// (celle qui déclenche le PageLoader plein écran) est mise en cache.
let incidentsListCache = null
let incidentsAssetsCache = null

export default function Incidents() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [data, setData] = useState(() => incidentsListCache ?? { items: [], total: 0 })
  const [loading, setLoading] = useState(() => incidentsListCache == null)
  const [assetList, setAssetList] = useState(() => incidentsAssetsCache ?? [])

  const [statusFilter, setStatusFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')
  const [notifOnly, setNotifOnly] = useState(false)
  const [overdueOnly, setOverdueOnly] = useState(false)
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)

  const [createModal, setCreateModal] = useState(null)   // null | payload (éventuellement préempli)
  const [detailIncident, setDetailIncident] = useState(null)
  const [editIncident, setEditIncident] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchAssets().then(r => {
      const sorted = [...(r.data || [])].sort((a, b) => a.name.localeCompare(b.name))
      setAssetList(sorted)
      incidentsAssetsCache = sorted
    }).catch(() => {})
  }, [])

  const noFilterActive = !statusFilter && !severityFilter && !categoryFilter && !notifOnly && !overdueOnly && !search

  const load = useCallback(() => {
    setLoading(true)
    fetchIncidents({
      status: statusFilter || undefined,
      severity: severityFilter || undefined,
      category: categoryFilter || undefined,
      requires_notification: notifOnly ? true : undefined,
      overdue_only: overdueOnly || undefined,
      q: search || undefined,
      page,
      per_page: PER_PAGE,
    })
      .then(r => {
        setData(r.data)
        setError('')
        if (noFilterActive) incidentsListCache = r.data
      })
      .catch(() => {
        setData({ items: [], total: 0 })
        setError('Impossible de charger les incidents — le serveur a peut-être renvoyé une erreur.')
      })
      .finally(() => setLoading(false))
  }, [statusFilter, severityFilter, categoryFilter, notifOnly, overdueOnly, search, page, noFilterActive])

  useEffect(() => { load() }, [load])

  // Arrivée depuis un autre module (Sécurité/Vulnérabilités/Veille) via
  // DeclareIncidentButton : /incidents?from=<source_type>&id=<source_id>.
  // Préremplit la modale de création sans jamais créer d'incident tout seul.
  useEffect(() => {
    const from = searchParams.get('from')
    const id = searchParams.get('id')
    if (from && id) {
      prefillIncident(from, id).then(r => setCreateModal(r.data)).catch(() => setCreateModal({}))
      setSearchParams({}, { replace: true })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function updateLocalIncident(fresh) {
    setData(d => ({ ...d, items: d.items.map(i => i.id === fresh.id ? fresh : i) }))
    setDetailIncident(fresh)
  }

  async function handleCreate(payload) {
    const { data: created } = await createIncident(payload)
    setCreateModal(null)
    // Ouvre directement le détail (donc la Roadmap) au lieu de retomber sur la
    // liste — l'analyste vient de décrire l'incident, la suite logique est
    // d'y voir tout de suite les bonnes pratiques et qui contacter.
    setDetailIncident(created)
    load()
  }

  async function handleEdit(payload) {
    const { data: fresh } = await updateIncident(editIncident.id, payload)
    setEditIncident(null)
    updateLocalIncident(fresh)
    load()
  }

  async function handleExport() {
    const { data: blob } = await exportIncidents()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `cybervuln-incidents-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const totalPages = Math.ceil(data.total / PER_PAGE)

  if (loading && data.items.length === 0 && noFilterActive) {
    return <PageLoader />
  }

  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M15.362 5.214A8.252 8.252 0 0112 21 8.25 8.25 0 016.038 7.048 8.287 8.287 0 009 9.6a8.983 8.983 0 013.361-6.867 8.21 8.21 0 003 2.48z M12 18a3.75 3.75 0 00.495-7.468 5.99 5.99 0 00-1.925 3.547 5.975 5.975 0 01-2.133-1.001A3.75 3.75 0 0012 18z"
        title="Incidents" color={MODULE_COLOR}
        subtitle="Registre auditable — suivi des délais légaux de notification NIS 2"
      >
        <div className="flex items-center gap-2">
          <button onClick={handleExport}
            className="px-3 py-2 text-sm font-medium rounded-lg"
            style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
            Exporter CSV
          </button>
          <button onClick={() => setCreateModal({})}
            className="px-4 py-2 text-sm font-medium rounded-lg"
            style={{ background: MODULE_COLOR, color: MODULES.incidents.dark }}>
            + Déclarer un incident
          </button>
        </div>
      </PageHero>

      <div className="flex flex-wrap items-center gap-2">
        <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1) }}
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={statusFilter ? activeFilterSelectStyle : filterSelectStyle}>
          <option value="">Tous statuts</option>
          {INCIDENT_STATUSES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
        <select value={severityFilter} onChange={e => { setSeverityFilter(e.target.value); setPage(1) }}
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={severityFilter ? activeFilterSelectStyle : filterSelectStyle}>
          <option value="">Toutes sévérités</option>
          {INCIDENT_SEVERITIES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
        <select value={categoryFilter} onChange={e => { setCategoryFilter(e.target.value); setPage(1) }}
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={categoryFilter ? activeFilterSelectStyle : filterSelectStyle}>
          <option value="">Toutes catégories</option>
          {INCIDENT_CATEGORIES.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
        </select>
        <button onClick={() => { setNotifOnly(v => !v); setPage(1) }}
          className="text-xs px-2.5 py-1.5 rounded-lg font-medium"
          style={notifOnly
            ? { background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}66` }
            : filterSelectStyle}>
          À notifier NIS 2
        </button>
        <button onClick={() => { setOverdueOnly(v => !v); setPage(1) }}
          className="text-xs px-2.5 py-1.5 rounded-lg font-medium"
          style={overdueOnly
            ? { background: 'rgba(248,81,73,0.15)', color: '#f85149', border: '1px solid rgba(248,81,73,0.4)' }
            : filterSelectStyle}>
          Échéance dépassée
        </button>
        <input value={search} onChange={e => { setSearch(e.target.value); setPage(1) }} placeholder="Rechercher…"
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={filterSelectStyle} />
      </div>

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      <div className="rounded-2xl overflow-hidden" style={tintedCard(MODULE_COLOR)}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Titre', 'Catégorie', 'Sévérité', 'Statut', 'Prise de connaissance', 'Actifs', 'NIS 2'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={7} className="px-4 py-12 text-center"><PageLoader size="sm" /></td></tr>
              )}
              {!loading && data.items.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-16 text-center" style={{ color: 'var(--text-muted)' }}>
                    <p className="text-sm font-medium mb-1">Aucun incident</p>
                    <p className="text-xs">Cliquez sur "Déclarer un incident" pour commencer le registre</p>
                  </td>
                </tr>
              )}
              {!loading && data.items.map(inc => (
                <tr key={inc.id} onClick={() => setDetailIncident(inc)} className="cursor-pointer"
                  style={{ borderBottom: '1px solid var(--border-subtle)' }}
                  onMouseEnter={e => e.currentTarget.style.background = `${MODULE_COLOR}0a`}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td className="px-4 py-3 font-medium" style={{ color: 'var(--text-primary)', maxWidth: 260 }}>
                    {inc.title}
                    {inc.crisis_title && (
                      <button onClick={e => { e.stopPropagation(); navigate('/crises') }}
                        className="ml-2 text-xs px-1.5 py-0.5 rounded font-medium"
                        style={{ background: 'rgba(248,81,73,0.12)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}
                        title={`Rattaché à la crise « ${inc.crisis_title} »`}>
                        🚨 crise
                      </button>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>{inc.category_label}</td>
                  <td className="px-4 py-3 whitespace-nowrap"><IncidentSeverityBadge value={inc.severity} /></td>
                  <td className="px-4 py-3 whitespace-nowrap"><StatusBadge value={inc.status} /></td>
                  <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                    {inc.aware_at ? new Date(inc.aware_at).toLocaleDateString('fr-FR') : '—'}
                  </td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {inc.affected_asset_names?.length
                      ? `${inc.affected_asset_names.slice(0, 2).join(', ')}${inc.affected_asset_names.length > 2 ? ` +${inc.affected_asset_names.length - 2}` : ''}`
                      : '—'}
                  </td>
                  <td className="px-4 py-3"><IncidentNIS2Badges incident={inc} compact /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="px-5 py-3.5 flex items-center justify-between" style={{ borderTop: '1px solid var(--border)' }}>
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{data.total} résultats</span>
            <div className="flex items-center gap-2">
              <button onClick={() => setPage(p => p - 1)} disabled={page === 1}
                className="text-xs px-2.5 py-1.5 rounded-lg font-medium disabled:opacity-40"
                style={filterSelectStyle}>← Préc.</button>
              <span className="text-xs px-2" style={{ color: 'var(--text-muted)' }}>Page {page} / {totalPages}</span>
              <button onClick={() => setPage(p => p + 1)} disabled={page === totalPages}
                className="text-xs px-2.5 py-1.5 rounded-lg font-medium disabled:opacity-40"
                style={filterSelectStyle}>Suiv. →</button>
            </div>
          </div>
        )}
      </div>

      {createModal && (
        <IncidentFormModal initial={createModal} assetList={assetList} onSave={handleCreate} onClose={() => setCreateModal(null)} />
      )}
      {detailIncident && !editIncident && (
        <IncidentDetailModal
          incident={detailIncident}
          onClose={() => setDetailIncident(null)}
          onEdit={() => setEditIncident(detailIncident)}
          onUpdated={updateLocalIncident}
          onDeleted={() => { setDetailIncident(null); load() }}
        />
      )}
      {editIncident && (
        <IncidentFormModal initial={editIncident} assetList={assetList} onSave={handleEdit} onClose={() => setEditIncident(null)} />
      )}
    </div>
  )
}
