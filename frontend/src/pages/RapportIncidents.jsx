import { useEffect, useState } from 'react'
import { incidents as fetchIncidents, exportIncidents, getIncidentReport } from '../api/client.js'
import IncidentSeverityBadge from '../components/IncidentSeverityBadge.jsx'
import IncidentNIS2Badges from '../components/IncidentNIS2Badges.jsx'
import { renderMd, exportPdf } from '../components/ReportMarkdown.jsx'
import { MODULES } from '../constants/modules.js'
import PageHero from '../components/PageHero.jsx'
import { tintedCard } from '../utils/cardStyle.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { SYNTHETIC_INCIDENTS, isSyntheticId, buildSyntheticIncidentReport } from '../utils/syntheticData.js'

const MODULE_COLOR = MODULES.incidents.color
const HERO_COLOR = MODULES.rapports.color
const CARD = tintedCard(HERO_COLOR)

const STATUS_STYLES = {
  declared:    { background: 'rgba(139,148,158,0.12)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' },
  in_progress: { background: 'rgba(88,166,255,0.12)',  color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' },
  contained:   { background: 'rgba(251,143,68,0.12)',  color: '#fb8f44', border: '1px solid rgba(251,143,68,0.3)' },
  resolved:    { background: 'rgba(63,185,80,0.12)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)'  },
  closed:      { background: 'rgba(163,113,247,0.12)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.3)' },
}
const STATUS_LABELS = {
  declared: 'Déclaré', in_progress: 'En cours', contained: 'Contenu', resolved: 'Résolu', closed: 'Clôturé',
}
function StatusBadge({ value }) {
  const s = STATUS_STYLES[value] || STATUS_STYLES.declared
  return <span style={{ ...s, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, display: 'inline-block' }}>{STATUS_LABELS[value] || value}</span>
}

// Un incident étant rare et jamais multiple la même semaine (contrairement aux
// CVE/veille/identités), son rapport se génère à l'unité et à la demande —
// pas de figeage hebdomadaire ici : les champs qui le composent (jalons envoyés,
// justifications) sont déjà écrits une seule fois et ne changent plus ensuite
// (cf. services/incident_report.py, garde-fous nis2_deadlines.py). L'export CSV
// du registre complet, lui, reste inchangé — il n'a rien à voir avec ce rapport.
export default function RapportIncidents() {
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [exportLoading, setExportLoading] = useState(false)

  const [openId, setOpenId] = useState(null)
  const [openSummary, setOpenSummary] = useState('')
  const [reportLoading, setReportLoading] = useState(false)
  const { isAnonymous } = usePresentation()

  useEffect(() => {
    setLoading(true)
    fetchIncidents({ per_page: 200 })
      .then(r => setItems(r.data.items || []))
      .catch(() => setError('Erreur lors du chargement des incidents.'))
      .finally(() => setLoading(false))
  }, [])

  const displayItems = isAnonymous ? [...items, ...SYNTHETIC_INCIDENTS] : items

  function handleExportCsv() {
    setExportLoading(true)
    setError('')
    exportIncidents()
      .then(({ data: blob }) => {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `cybervuln-incidents-${new Date().toISOString().slice(0, 10)}.csv`
        a.click()
        URL.revokeObjectURL(url)
      })
      .catch(() => setError("Erreur lors de l'export CSV."))
      .finally(() => setExportLoading(false))
  }

  function handleOpenReport(id) {
    if (openId === id) { setOpenId(null); return }
    // Incident de démonstration : rapport reconstruit côté client, pas d'appel API.
    if (isSyntheticId(id)) {
      const inc = SYNTHETIC_INCIDENTS.find(i => i.id === id)
      setOpenId(id)
      setOpenSummary(inc ? buildSyntheticIncidentReport(inc) : '')
      return
    }
    setReportLoading(true)
    setError('')
    getIncidentReport(id)
      .then(r => { setOpenId(id); setOpenSummary(r.data.summary || '') })
      .catch(() => setError("Erreur lors de la génération du rapport."))
      .finally(() => setReportLoading(false))
  }

  const openIncident = displayItems.find(i => i.id === openId)

  return (
    <div className="p-6 space-y-6">
      <PageHero
        icon="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
        title="Rapport Incidents" color={HERO_COLOR}
        subtitle="Un rapport par incident, généré à la demande — suivi des délais légaux de notification NIS 2"
      >
        <button onClick={handleExportCsv} disabled={exportLoading}
          className="px-4 py-2 text-sm font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
          onMouseEnter={e => { if (!exportLoading) e.currentTarget.style.background = 'var(--border)' }}
          onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-secondary)' }}
        >
          {exportLoading && (
            <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
          )}
          {exportLoading ? 'Export…' : 'Exporter CSV (registre complet)'}
        </button>
      </PageHero>

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      <div style={CARD} className="overflow-hidden">
        <div className="px-6 py-4" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>Registre des incidents</h2>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Consultez le rapport détaillé d'un incident — qualification NIS 2, contenu des jalons envoyés, pièces jointes du rapport final, chronologie complète.
          </p>
        </div>

        {loading ? (
          <p className="px-6 py-8 text-sm text-center" style={{ color: 'var(--text-muted)' }}>Chargement…</p>
        ) : displayItems.length === 0 ? (
          <p className="px-6 py-8 text-sm text-center" style={{ color: 'var(--text-muted)' }}>Aucun incident déclaré pour l'instant.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                  {['Titre', 'Catégorie', 'Sévérité', 'Statut', 'NIS 2', 'Déclaré le', 'Actions'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displayItems.map(inc => {
                  const isOpen = openId === inc.id
                  return (
                    <tr key={inc.id} className="transition-colors"
                      style={{ borderBottom: '1px solid var(--border-subtle)', background: isOpen ? `${MODULE_COLOR}0f` : 'transparent' }}
                      onMouseEnter={e => { if (!isOpen) e.currentTarget.style.background = `${MODULE_COLOR}0a` }}
                      onMouseLeave={e => { if (!isOpen) e.currentTarget.style.background = 'transparent' }}
                    >
                      <td className="px-4 py-3 font-medium" style={{ color: 'var(--text-primary)' }}>{inc.title}</td>
                      <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{inc.category_label}</td>
                      <td className="px-4 py-3 whitespace-nowrap"><IncidentSeverityBadge value={inc.severity} /></td>
                      <td className="px-4 py-3 whitespace-nowrap"><StatusBadge value={inc.status} /></td>
                      <td className="px-4 py-3"><IncidentNIS2Badges incident={inc} compact /></td>
                      <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                        {inc.created_at ? new Date(inc.created_at).toLocaleDateString('fr-FR') : '—'}
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => handleOpenReport(inc.id)} disabled={reportLoading}
                          className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium disabled:opacity-50"
                          style={{ background: `${MODULE_COLOR}1a`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}40` }}
                        >{isOpen ? 'Fermer' : '👁 Consulter le rapport'}</button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {openIncident && (
        <div style={CARD} className="overflow-hidden">
          <div className="px-6 py-4 flex items-center justify-between flex-wrap gap-2" style={{ borderBottom: '1px solid var(--border)' }}>
            <div>
              <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>Rapport — {openIncident.title}</h2>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                Généré à la demande, à partir de l'état actuel de l'incident — pas un instantané figé.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => {
                  const ok = exportPdf(openSummary)
                  setError(ok ? '' : 'Export PDF bloqué par le navigateur — autorisez les fenêtres pop-up pour ce site, puis réessayez.')
                }}
                className="px-3 py-1.5 text-xs font-medium rounded-lg transition-colors"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
              >Exporter PDF</button>
              <button onClick={() => setOpenId(null)}
                className="px-3 py-1.5 text-xs rounded-lg transition-colors"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
              >Fermer</button>
            </div>
          </div>
          <div className="p-6 space-y-0.5">
            {renderMd(openSummary)}
          </div>
        </div>
      )}
    </div>
  )
}
