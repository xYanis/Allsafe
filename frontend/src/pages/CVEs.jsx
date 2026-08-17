import { useEffect, useState, useCallback, useRef } from 'react'
import { cves as fetchCves, syncNvd, syncTaskStatus } from '../api/client.js'
import PageHero from '../components/PageHero.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import ExploitBadge from '../components/ExploitBadge.jsx'
import PageLoader from '../components/PageLoader.jsx'
import { MODULES } from '../constants/modules.js'

const REFRESH_OPTIONS = [7, 15]
// Survol de ligne teinté CyberVuln (11/08/2026, tour visuel) — cf. même remarque que
// Vulnerabilities.jsx : uniquement le survol, pas les boutons d'action (rouge = déjà
// "sévérité" sur cette page).
const MODULE_HOVER = `${MODULES.cybervuln.color}0a`

function RefreshDropdown({ onSelect, status }) {
  const [open, setOpen] = useState(false)
  const [menuStyle, setMenuStyle] = useState({})
  const btnRef = useRef(null)
  const menuRef = useRef(null)

  useEffect(() => {
    if (!open) return
    const handler = e => {
      if (
        btnRef.current && !btnRef.current.contains(e.target) &&
        menuRef.current && !menuRef.current.contains(e.target)
      ) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  function toggle() {
    if (status === 'loading') return
    if (!open && btnRef.current) {
      const r = btnRef.current.getBoundingClientRect()
      setMenuStyle({ position: 'fixed', top: r.bottom + 4, right: window.innerWidth - r.right, zIndex: 9999 })
    }
    setOpen(o => !o)
  }

  const labels = { idle: null, loading: 'Actualisation…', done: 'Terminé ✓', error: 'Erreur ✕' }
  const styles = {
    idle:    { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' },
    loading: { background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.25)' },
    done:    { background: 'rgba(63,185,80,0.1)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.25)' },
    error:   { background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.25)' },
  }

  return (
    <>
      <button ref={btnRef} onClick={toggle} disabled={status === 'loading'}
        className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg transition-colors flex-shrink-0 disabled:opacity-70"
        style={styles[status]}
      >
        {status === 'loading' ? (
          <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
        ) : (
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
        )}
        {labels[status] ?? 'Actualiser'}
      </button>
      {open && (
        <div ref={menuRef} style={{
          ...menuStyle, minWidth: 170, background: 'var(--bg-secondary)', border: '1px solid var(--border)',
          borderRadius: 10, boxShadow: '0 8px 24px rgba(0,0,0,0.6)', overflow: 'hidden',
        }}>
          <p className="px-3 py-2 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)', borderBottom: '1px solid var(--border)' }}>
            Synchroniser NVD
          </p>
          {REFRESH_OPTIONS.map(days => (
            <button key={days} onClick={() => { onSelect(days); setOpen(false) }}
              className="w-full text-left text-xs px-3 py-2.5 transition-colors"
              style={{ color: 'var(--text-secondary)' }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(88,166,255,0.1)'; e.currentTarget.style.color = '#58a6ff' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text-secondary)' }}
            >
              {days} derniers jours
            </button>
          ))}
        </div>
      )}
    </>
  )
}

const CARD = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px' }
const INPUT_STYLE = {
  background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8,
  color: 'var(--text-secondary)', padding: '6px 12px', fontSize: 13, outline: 'none',
}
const SELECT_STYLE = { ...INPUT_STYLE, cursor: 'pointer' }
// Style "filtre actif" (17/08/2026, demande explicite — étendre à tous les menus déroulants
// de l'app le comportement déjà posé sur Durcissement.jsx/Assets.jsx/Inventaire.jsx) — même
// formule, couleur du module de cette page (CyberVuln).
const ACTIVE_SELECT_STYLE = { background: `${MODULES.cybervuln.color}1f`, color: MODULES.cybervuln.color, border: `1px solid ${MODULES.cybervuln.color}59`, cursor: 'pointer' }

// Toutes les CVE (pas seulement celles qui touchent le parc) des N derniers jours.
// 30j testé en réel : ~6 min de sync (l'API NVD elle-même est le facteur limitant,
// pas notre code) — trop lourd pour un bouton "Actualiser" cliqué à la demande.
// 15j : ~3500 CVE, plus raisonnable.
const DAYS_WINDOW = 15

const REFRESH_STYLES = {
  idle:    { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' },
  loading: { background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.25)' },
  done:    { background: 'rgba(63,185,80,0.1)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.25)' },
  error:   { background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.25)' },
}

export default function CVEs() {
  const [data, setData] = useState({ items: [], total: 0 })
  const [page, setPage] = useState(1)
  const [filters, setFilters] = useState({ severity: '', search: '', min_cvss: '', kev: false, msf_module: false })
  const [loading, setLoading] = useState(false)
  const [syncStatus, setSyncStatus] = useState('idle')
  const [syncMsg, setSyncMsg] = useState('')
  const pollRef = useRef(null)
  const perPage = 50

  const load = useCallback(() => {
    setLoading(true)
    const params = { page, per_page: perPage, matched_only: false, days: DAYS_WINDOW }
    if (filters.severity) params.severity = filters.severity
    if (filters.search)   params.search   = filters.search
    if (filters.min_cvss) params.min_cvss = filters.min_cvss
    if (filters.kev) params.kev = true
    if (filters.msf_module) params.msf_module = true
    fetchCves(params).then(r => setData(r.data)).finally(() => setLoading(false))
  }, [page, filters])

  useEffect(() => { load() }, [load])
  useEffect(() => () => clearInterval(pollRef.current), [])

  function setFilter(k, v) { setFilters(f => ({ ...f, [k]: v })); setPage(1) }

  function finishSync(status, msg) {
    clearInterval(pollRef.current)
    setSyncStatus(status)
    setSyncMsg(msg)
    setTimeout(() => setSyncStatus('idle'), 6000)
  }

  async function handleRefresh(days) {
    if (syncStatus === 'loading') return
    setSyncStatus('loading')
    setSyncMsg(`Synchronisation NVD (${days} derniers jours)… peut prendre 1-3 min`)
    try {
      const { data: started } = await syncNvd(days)
      pollRef.current = setInterval(async () => {
        try {
          const { data: status } = await syncTaskStatus(started.task_id)
          if (status.status === 'SUCCESS') {
            const r = status.result || {}
            setPage(1)
            load()
            finishSync('done', `Terminé — ${r.created ?? 0} créées, ${r.updated ?? 0} mises à jour`)
          } else if (status.status === 'FAILURE') {
            finishSync('error', 'Erreur lors de la synchronisation NVD')
          }
        } catch {
          finishSync('error', 'Erreur lors du suivi de la synchronisation')
        }
      }, 3000)
    } catch {
      finishSync('error', 'Erreur lors du déclenchement de la synchronisation')
    }
  }

  const totalPages = Math.ceil(data.total / perPage)

  const cvssColor = score => score >= 9 ? '#f85149' : score >= 7 ? '#fb8f44' : score >= 4 ? '#58a6ff' : '#8b949e'

  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
        title="CVE" color="#f85149"
        subtitle={`Toutes les CVE publiées dans les ${DAYS_WINDOW} derniers jours (pas seulement celles touchant le parc)`}
      >
        <RefreshDropdown status={syncStatus} onSelect={handleRefresh} />
      </PageHero>

      {syncMsg && syncStatus !== 'idle' && (
        <div className="text-sm px-4 py-3 rounded-xl" style={REFRESH_STYLES[syncStatus]}>{syncMsg}</div>
      )}

      {/* Filtres */}
      <div style={CARD} className="px-5 py-3.5 flex flex-wrap gap-3 items-center">
        <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Filtres</span>
        <input
          type="text"
          placeholder="Rechercher CVE ID ou description…"
          value={filters.search}
          onChange={e => setFilter('search', e.target.value)}
          style={{ ...INPUT_STYLE, width: 280 }}
        />
        <select value={filters.severity} onChange={e => setFilter('severity', e.target.value)} style={{ ...(filters.severity ? ACTIVE_SELECT_STYLE : SELECT_STYLE), width: 160 }}>
          <option value="">Toutes sévérités</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <input
          type="number"
          placeholder="CVSS min"
          min="0" max="10" step="0.1"
          value={filters.min_cvss}
          onChange={e => setFilter('min_cvss', e.target.value)}
          style={{ ...INPUT_STYLE, width: 100 }}
        />
        {/* KEV/maturité d'exploit (17/08/2026) — toggles booléens, pas un <select> :
            filtre binaire, pas un ensemble de valeurs dérivées du parc (cf. osOptions). */}
        <button
          onClick={() => setFilter('kev', !filters.kev)}
          className="text-xs px-3 py-1.5 rounded-lg font-medium transition-colors"
          style={filters.kev
            ? { background: 'rgba(248,81,73,0.12)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }
            : { background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
        >⚠ KEV uniquement</button>
        <button
          onClick={() => setFilter('msf_module', !filters.msf_module)}
          className="text-xs px-3 py-1.5 rounded-lg font-medium transition-colors"
          style={filters.msf_module
            ? { background: 'rgba(163,113,247,0.12)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.3)' }
            : { background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
        >Metasploit uniquement</button>
      </div>

      {/* Tableau */}
      <div style={CARD} className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                {['CVE ID', 'Publiée', 'Description', 'CVSS', 'EPSS', 'Sévérité', 'Source'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="stagger-rows">
              {loading && (
                <tr><td colSpan={7} className="px-4 py-12 text-center"><PageLoader size="sm" /></td></tr>
              )}
              {!loading && data.items.length === 0 && (
                <tr><td colSpan={7} className="px-4 py-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>Aucun résultat</td></tr>
              )}
              {!loading && data.items.map(c => (
                <tr key={c.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}
                  onMouseEnter={e => e.currentTarget.style.background = MODULE_HOVER}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td className="px-4 py-3 font-mono text-xs font-semibold" style={{ color: '#58a6ff' }}>
                    <a href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`} target="_blank" rel="noopener noreferrer" className="hover:underline">{c.cve_id}</a>
                  </td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>{c.published ? new Date(c.published).toLocaleDateString('fr-FR') : '—'}</td>
                  <td className="px-4 py-3 max-w-xs truncate text-xs" style={{ color: 'var(--text-muted)' }} title={c.description}>{c.description || '—'}</td>
                  <td className="px-4 py-3 font-bold" style={{ color: cvssColor(c.cvss_score) }}>{c.cvss_score ?? '—'}</td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>{c.epss_score != null ? (c.epss_score * 100).toFixed(1) + '%' : '—'}</td>
                  <td className="px-4 py-3">
                    <div style={{ display: 'inline-grid', justifyItems: 'start', gap: 4, position: 'relative' }}>
                      <SeverityBadge value={c.severity} />
                      <ExploitBadge kev={c.kev} kevRansomware={c.kev_ransomware} msfModule={c.msf_module} msfRank={c.msf_best_rank} spread />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs px-2 py-0.5 rounded-md uppercase font-medium" style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
                      {c.source || '—'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="px-5 py-3.5 flex items-center justify-between" style={{ borderTop: '1px solid var(--border)' }}>
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{data.total} résultats</span>
            <div className="flex items-center gap-2">
              {[
                { label: '← Préc.', disabled: page === 1, action: () => setPage(p => p - 1) },
                { label: `Page ${page} / ${totalPages}`, disabled: true, action: null },
                { label: 'Suiv. →', disabled: page === totalPages, action: () => setPage(p => p + 1) },
              ].map(({ label, disabled, action }) => (
                <button key={label} disabled={disabled} onClick={action}
                  className="text-xs px-3 py-1.5 rounded-lg transition-colors disabled:opacity-40"
                  style={{ background: action ? 'var(--bg-secondary)' : 'transparent', color: 'var(--text-muted)', border: action ? '1px solid var(--border)' : 'none' }}
                >{label}</button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
