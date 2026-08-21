import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { audits as fetchAudits, createAudit, assets as fetchAssets } from '../api/client.js'
import PageLoader from '../components/PageLoader.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import AuditFormModal, { AUDIT_TYPES, AUDIT_STATUSES } from '../components/AuditFormModal.jsx'
import { MODULES } from '../constants/modules.js'
import PageHero from '../components/PageHero.jsx'
import { tintedCard } from '../utils/cardStyle.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { FAKE_AUDITS, anonymizeAudit, anonymizeAsset } from '../utils/fakeData.js'

const MODULE_COLOR = MODULES.securite.color

const STATUS_STYLES = {
  cadrage:  { background: 'rgba(139,148,158,0.12)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' },
  autorise: { background: 'rgba(88,166,255,0.12)',  color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' },
  en_cours: { background: 'rgba(251,143,68,0.12)',  color: '#fb8f44', border: '1px solid rgba(251,143,68,0.3)' },
  termine:  { background: 'rgba(63,185,80,0.12)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)'  },
  archive:  { background: 'rgba(163,113,247,0.12)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.3)' },
}

function StatusBadge({ value }) {
  const s = STATUS_STYLES[value] || STATUS_STYLES.cadrage
  const label = AUDIT_STATUSES.find(x => x.value === value)?.label || value
  return <span style={{ ...s, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, display: 'inline-block' }}>{label}</span>
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const filterSelectStyle = { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }
const activeFilterSelectStyle = { background: `${MODULE_COLOR}1f`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }
const PER_PAGE = 25

// Cache module (pas du state React) qui survit au démontage/remontage du composant —
// cette page est entièrement redémontée à chaque navigation (pas de keep-alive de route),
// donc y revenir relançait le fetch et l'écran de chargement plein écran à CHAQUE fois.
// Ne couvre que la première page sans filtre (le seul cas qui affiche le PageLoader plein
// écran) — un résultat déjà filtré/paginé par l'utilisateur n'est jamais mis en cache.
let auditsListCache = null

export default function Audits() {
  const navigate = useNavigate()
  const [data, setData] = useState(() => auditsListCache ?? { items: [], total: 0 })
  const [loading, setLoading] = useState(() => auditsListCache == null)
  const [assetList, setAssetList] = useState([])
  const [statusFilter, setStatusFilter] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [createModal, setCreateModal] = useState(false)
  const [error, setError] = useState('')
  const { isAnonymous } = usePresentation()

  useEffect(() => {
    fetchAssets().then(r => setAssetList([...(r.data || [])].sort((a, b) => a.name.localeCompare(b.name)))).catch(() => {})
  }, [])

  const load = useCallback(() => {
    setLoading(true)
    fetchAudits({ status: statusFilter || undefined, type: typeFilter || undefined, q: search || undefined, page, per_page: PER_PAGE })
      .then(r => {
        setData(r.data)
        setError('')
        if (!statusFilter && !typeFilter && !search && page === 1) auditsListCache = r.data
      })
      .catch(() => {
        setData({ items: [], total: 0 })
        setError('Impossible de charger les audits — le serveur a peut-être renvoyé une erreur.')
      })
      .finally(() => setLoading(false))
  }, [statusFilter, typeFilter, search, page])

  useEffect(() => { load() }, [load])

  async function handleCreate(payload) {
    const { data: created } = await createAudit(payload)
    setCreateModal(false)
    navigate(`/audits/${created.id}`)
  }

  const totalPages = Math.ceil(data.total / PER_PAGE)
  const noFilterActive = !statusFilter && !typeFilter && !search
  // Vraies lignes anonymisées (21/08/2026, retour utilisateur) avant l'ajout des fake data —
  // restaient jusqu'ici en clair (titre/scope/périmètre/mandataire), seules des lignes
  // FAKE_AUDITS s'y ajoutaient.
  const anonymizedItems = isAnonymous ? data.items.map(a => anonymizeAudit(a, assetList)) : data.items
  const displayItems = isAnonymous && noFilterActive && page === 1 ? [...anonymizedItems, ...FAKE_AUDITS] : anonymizedItems
  const displayAssetList = isAnonymous ? assetList.map(anonymizeAsset) : assetList

  if (loading && data.items.length === 0 && !statusFilter && !typeFilter && !search) {
    return <PageLoader />
  }

  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
        title="Audits" color={MODULE_COLOR}
        subtitle="Cadrage, autorisation, findings et contre-vérification — Allsafe héberge et trace l'audit, ne l'exécute jamais."
      >
        <button onClick={() => setCreateModal(true)}
          className="px-4 py-2 text-sm font-medium rounded-lg"
          style={{ background: MODULE_COLOR, color: MODULES.securite.dark }}>
          + Nouvel audit
        </button>
      </PageHero>

      <div className="flex flex-wrap items-center gap-2">
        <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1) }}
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={statusFilter ? activeFilterSelectStyle : filterSelectStyle}>
          <option value="">Tous statuts</option>
          {AUDIT_STATUSES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
        <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(1) }}
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={typeFilter ? activeFilterSelectStyle : filterSelectStyle}>
          <option value="">Tous types</option>
          {AUDIT_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
        </select>
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
                {['Titre', 'Type', 'Statut', 'Période', 'Conduit par', 'Findings'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={6} className="px-4 py-12 text-center"><PageLoader size="sm" /></td></tr>
              )}
              {!loading && displayItems.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-16 text-center" style={{ color: 'var(--text-muted)' }}>
                    <p className="text-sm font-medium mb-1">Aucun audit</p>
                    <p className="text-xs">Cliquez sur "Nouvel audit" pour démarrer un cadrage</p>
                  </td>
                </tr>
              )}
              {!loading && displayItems.map(a => {
                const flagged = a.status === 'termine' && a.findings_unretested_closed > 0
                return (
                  <tr key={a.id} onClick={() => navigate(`/audits/${a.id}`)} className="cursor-pointer"
                    style={{ borderBottom: '1px solid var(--border-subtle)' }}
                    onMouseEnter={e => e.currentTarget.style.background = `${MODULE_COLOR}0a`}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <td className="px-4 py-3 font-medium" style={{ color: 'var(--text-primary)', maxWidth: 280 }}>
                      {a.title}
                      {flagged && (
                        <span className="ml-2 text-xs px-1.5 py-0.5 rounded font-medium"
                          style={{ background: 'rgba(210,153,34,0.12)', color: '#d29922', border: '1px solid rgba(210,153,34,0.3)' }}
                          title={`${a.findings_unretested_closed} finding(s) clos jamais retesté(s)`}>
                          ⚠ non retesté
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>
                      {AUDIT_TYPES.find(t => t.value === a.type)?.label || a.type}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap"><StatusBadge value={a.status} /></td>
                    <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                      {a.started_at ? new Date(a.started_at).toLocaleDateString('fr-FR') : '—'}
                      {a.ended_at ? ` → ${new Date(a.ended_at).toLocaleDateString('fr-FR')}` : ''}
                    </td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{a.conducted_by || '—'}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1 flex-wrap">
                        {a.findings_total === 0 && <span className="text-xs" style={{ color: 'var(--text-muted)' }}>—</span>}
                        {SEVERITY_ORDER.filter(s => a.findings_by_severity?.[s]).map(s => (
                          <span key={s} className="inline-flex items-center gap-1">
                            <SeverityBadge value={s} /><span className="text-xs" style={{ color: 'var(--text-muted)' }}>×{a.findings_by_severity[s]}</span>
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                )
              })}
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
        <AuditFormModal assetList={displayAssetList} onClose={() => setCreateModal(false)} onSaved={handleCreate} />
      )}
    </div>
  )
}
