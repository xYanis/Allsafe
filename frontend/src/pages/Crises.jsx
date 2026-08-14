import { useEffect, useState, useCallback } from 'react'
import { crises as fetchCrises, createCrisis } from '../api/client.js'
import PageLoader from '../components/PageLoader.jsx'
import CrisisFormModal from '../components/CrisisFormModal.jsx'
import CrisisDetailModal from '../components/CrisisDetailModal.jsx'
import { MODULES } from '../constants/modules.js'
import PageHero from '../components/PageHero.jsx'

const MODULE_COLOR = MODULES.incidents.color
const filterSelectStyle = { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }

function StatusPill({ active }) {
  return active
    ? <span className="text-xs px-2 py-0.5 rounded-lg font-medium" style={{ background: 'rgba(248,81,73,0.15)', color: '#f85149', border: '1px solid rgba(248,81,73,0.4)' }}>Active</span>
    : <span className="text-xs px-2 py-0.5 rounded-lg font-medium" style={{ background: 'rgba(139,148,158,0.12)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' }}>Désactivée</span>
}

// Liste des crises — escalade d'un ou plusieurs incidents (cellule de crise, journal de
// décisions/communications). Même charpente que pages/Incidents.jsx (filtres, tableau,
// modale de création/détail), sans pagination serveur : le volume attendu est faible
// (une crise est un évènement rare, contrairement aux incidents).
export default function Crises() {
  const [data, setData] = useState({ items: [], total: 0 })
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState('')
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [detailCrisis, setDetailCrisis] = useState(null)
  const [error, setError] = useState('')

  const load = useCallback(() => {
    setLoading(true)
    fetchCrises({ status: statusFilter || undefined, q: search || undefined })
      .then(r => { setData(r.data); setError('') })
      .catch(() => {
        setData({ items: [], total: 0 })
        setError('Impossible de charger les crises — le serveur a peut-être renvoyé une erreur.')
      })
      .finally(() => setLoading(false))
  }, [statusFilter, search])

  useEffect(() => { load() }, [load])

  function updateLocal(fresh) {
    setData(d => ({ ...d, items: d.items.map(c => c.id === fresh.id ? fresh : c) }))
    setDetailCrisis(fresh)
  }

  async function handleCreate(payload) {
    const { data: created } = await createCrisis(payload)
    setCreateModal(false)
    setDetailCrisis(created)
    load()
  }

  if (loading && data.items.length === 0 && !statusFilter && !search) {
    return <PageLoader />
  }

  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M12 9v3.75m9.303 3.376c.866 1.5-.217 3.374-1.948 3.374H4.645c-1.73 0-2.813-1.874-1.948-3.374L10.697 3.376c.866-1.5 3.032-1.5 3.898 0l7.303 12.75zM12 15.75h.007v.008H12v-.008z"
        title="Gestion de crise" color={MODULE_COLOR}
        subtitle="Escalade en crise — cellule de crise, décisions et communications tracées"
      >
        <button onClick={() => setCreateModal(true)}
          className="px-4 py-2 text-sm font-medium rounded-lg"
          style={{ background: MODULE_COLOR, color: MODULES.incidents.dark }}>
          + Activer une crise
        </button>
      </PageHero>

      <div className="flex flex-wrap items-center gap-2">
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={filterSelectStyle}>
          <option value="">Tous statuts</option>
          <option value="active">Active</option>
          <option value="stood_down">Désactivée</option>
        </select>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Rechercher…"
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={filterSelectStyle} />
      </div>

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      <div className="rounded-2xl overflow-hidden" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Titre', 'Statut', 'Activée par', 'Incidents liés', 'Cellule de crise'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={5} className="px-4 py-12 text-center"><PageLoader size="sm" /></td></tr>
              )}
              {!loading && data.items.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-16 text-center" style={{ color: 'var(--text-muted)' }}>
                    <p className="text-sm font-medium mb-1">Aucune crise</p>
                    <p className="text-xs">Cliquez sur "Activer une crise" en cas d'escalade nécessitant une cellule de crise dédiée</p>
                  </td>
                </tr>
              )}
              {!loading && data.items.map(c => (
                <tr key={c.id} onClick={() => setDetailCrisis(c)} className="cursor-pointer"
                  style={{ borderBottom: '1px solid var(--border-subtle)' }}
                  onMouseEnter={e => e.currentTarget.style.background = `${MODULE_COLOR}0a`}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td className="px-4 py-3 font-medium" style={{ color: 'var(--text-primary)', maxWidth: 260 }}>{c.title}</td>
                  <td className="px-4 py-3 whitespace-nowrap"><StatusPill active={c.status === 'active'} /></td>
                  <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>
                    {c.activated_by} · {c.activated_at ? new Date(c.activated_at).toLocaleDateString('fr-FR') : '—'}
                  </td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {c.linked_incidents?.length
                      ? `${c.linked_incidents.slice(0, 2).map(li => li.title).join(', ')}${c.linked_incidents.length > 2 ? ` +${c.linked_incidents.length - 2}` : ''}`
                      : '—'}
                  </td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {c.crisis_roles?.length ? `${c.crisis_roles.length} rôle${c.crisis_roles.length > 1 ? 's' : ''}` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {createModal && (
        <CrisisFormModal onSave={handleCreate} onClose={() => setCreateModal(false)} />
      )}
      {detailCrisis && (
        <CrisisDetailModal
          crisis={detailCrisis}
          onClose={() => setDetailCrisis(null)}
          onUpdated={updateLocal}
          onDeleted={() => { setDetailCrisis(null); load() }}
        />
      )}
    </div>
  )
}
