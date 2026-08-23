import { useState, useEffect } from 'react'
import { weeklyReports, weeklyReport, generateWeekly, weeklyReportCsv } from '../api/client.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { redactText, isSyntheticId } from '../utils/syntheticData.js'
import { renderMd, exportPdf } from './ReportMarkdown.jsx'

const CARD = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px' }

// Archives hebdomadaires figées, partagées par les pages de rapport (Rapport
// exécutif CVE, Rapport Veille, et Surveillance à venir).
//
// Extrait de Reports.jsx le 22/07/2026 **avant** d'écrire le 2e rapport : la
// liste, la consultation, la génération et les exports sont identiques d'un
// rapport à l'autre, seules changent la portée (`kind`), les colonnes de
// comptage et les données sous-jacentes. Dupliquer ce bloc aurait reproduit le
// sort de la modale de patch check (cf. STATUS.md).
//
// `kind`          : cve | veille | surveillance
// `countColumns`  : colonnes de comptage propres au type — [{key, label, color}],
//                   `key` étant une section de `activity` (patched, received…)
// `assetIds`      : portée par actif (rapport CVE uniquement) ; ailleurs, laisser vide
// `assetScoped`   : affiche la colonne "Portée" et décline la génération par actif
export default function WeeklyArchives({
  kind,
  countColumns,
  description,
  assetIds = [],
  assetScoped = false,
  redactAssets = [],
}) {
  const { isAnonymous } = usePresentation()
  const { names: ANALYSTS } = useAnalysts()
  const [archives, setArchives] = useState([])
  const [openReport, setOpenReport] = useState(null)
  const [genLoading, setGenLoading] = useState(false)
  const [error, setError] = useState('')

  const realAssetIds = assetIds.filter(id => !isSyntheticId(id))
  const scopeKey = realAssetIds.join(',')

  useEffect(() => {
    loadArchives()
    setOpenReport(null)
  }, [scopeKey, kind])

  function loadArchives() {
    weeklyReports(kind, scopeKey || undefined)
      .then(r => { setArchives(r.data.items || []); setError('') })
      // Bug réel corrigé (11/08/2026) : un échec réseau était avalé silencieusement,
      // indiscernable de "aucun rapport archivé pour l'instant" — problématique pour
      // des archives qui servent de preuve opposable à un auditeur NIS 2.
      .catch(() => setError('Impossible de charger les archives hebdomadaires — le serveur a peut-être renvoyé une erreur.'))
  }

  // Génère le rapport de la dernière semaine complète pour la portée courante.
  // Le backend ne réécrit pas un rapport déjà figé (sauf semaine encore en cours
  // au moment de sa génération, qu'il rafraîchit) — d'où le message quand rien
  // n'a changé.
  function handleGenerate() {
    if (assetScoped && assetIds.length > 0 && realAssetIds.length === 0) {
      setError("Génération indisponible pour une sélection composée uniquement d'actifs de démonstration.")
      return
    }
    setGenLoading(true)
    setError('')
    const scopes = assetScoped && realAssetIds.length ? realAssetIds : [undefined]
    Promise.all(scopes.map(assetId => generateWeekly({
      kind, generated_by: 'Manuel', ...(assetId ? { asset_id: assetId } : {}),
    })))
      .then(responses => {
        loadArchives()
        setOpenReport(responses[0].data.report)
        if (responses.every(r => !r.data.created)) {
          setError(`Le rapport ${responses[0].data.report.label} était déjà archivé — affiché tel qu'il a été figé.`)
        }
      })
      .catch(() => setError('Erreur lors de la génération du rapport hebdomadaire.'))
      .finally(() => setGenLoading(false))
  }

  function handleOpenArchive(id) {
    weeklyReport(id).then(r => setOpenReport(r.data)).catch(() => setError("Erreur lors de l'ouverture du rapport."))
  }

  function handleArchiveCsv(report) {
    weeklyReportCsv(report.id)
      .then(async r => {
        let blob = new Blob([r.data], { type: 'text/csv;charset=utf-8;' })
        if (isAnonymous) {
          const text = await blob.text()
          blob = new Blob([redactText(text, redactAssets, ANALYSTS)], { type: 'text/csv;charset=utf-8;' })
        }
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `cybervuln-rapport-${kind}-${report.asset_label ? report.asset_label + '-' : ''}${report.label.replace('/', '-')}.csv`
        a.click()
        URL.revokeObjectURL(url)
      })
      .catch(() => setError("Erreur lors de l'export CSV du rapport."))
  }

  const summaryText = openReport
    ? (isAnonymous ? redactText(openReport.summary || '', redactAssets, ANALYSTS) : (openReport.summary || ''))
    : ''

  return (
    <>
      {error && (
        <div className="text-sm px-4 py-3 rounded-xl mb-4"
          style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

    <div style={CARD} className="overflow-hidden">
      <div className="px-6 py-4 flex items-center justify-between flex-wrap gap-3" style={{ borderBottom: '1px solid var(--border)' }}>
        <div>
          <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>Archives hebdomadaires</h2>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {description}
          </p>
        </div>
        <button onClick={handleGenerate} disabled={genLoading}
          className="px-3 py-2 text-xs font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          style={{ background: 'rgba(163,113,247,0.1)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.3)' }}
        >
          {genLoading && (
            <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
          )}
          {genLoading ? 'Génération…' : '📅 Générer la semaine écoulée'}
        </button>
      </div>

      {archives.length === 0 ? (
        <p className="px-6 py-8 text-sm text-center" style={{ color: 'var(--text-muted)' }}>
          {realAssetIds.length > 0 ? 'Aucun rapport archivé pour cette sélection' : 'Aucun rapport archivé pour l\'instant'} — le premier sera généré lundi, ou dès maintenant avec le bouton ci-dessus.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                {['Semaine', ...(assetScoped ? ['Portée'] : []), 'Période', ...countColumns.map(c => c.label), 'Généré le', 'Actions'].map(h => (
                  <th key={h} className="text-left px-4 py-2.5 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {archives.map(r => {
                const isOpen = openReport?.id === r.id
                return (
                  <tr key={r.id} className="transition-colors"
                    style={{ borderBottom: '1px solid var(--border-subtle)', background: isOpen ? 'rgba(163,113,247,0.06)' : 'transparent' }}
                    onMouseEnter={e => { if (!isOpen) e.currentTarget.style.background = 'rgba(163,113,247,0.04)' }}
                    onMouseLeave={e => { if (!isOpen) e.currentTarget.style.background = 'transparent' }}
                  >
                    <td className="px-4 py-3 font-semibold" style={{ color: '#a371f7' }}>
                      {r.label}
                      {/* Semaine encore en cours au moment de la génération : chiffres
                          partiels, régénérés automatiquement une fois la semaine close. */}
                      {!r.complete && (
                        <span className="ml-2 text-xs font-normal px-1.5 py-0.5 rounded whitespace-nowrap"
                          style={{ background: 'rgba(210,153,34,0.15)', color: '#d29922', border: '1px dashed rgba(210,153,34,0.5)' }}
                          title="Semaine encore en cours au moment de la génération — chiffres partiels, le rapport sera régénéré une fois la semaine terminée">
                          en cours
                        </span>
                      )}
                    </td>
                    {assetScoped && (
                      <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>
                        {r.asset_label
                          ? <span className="px-2 py-0.5 rounded" style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff' }}>{r.asset_label}</span>
                          : <span style={{ color: 'var(--text-muted)' }}>Parc entier</span>}
                      </td>
                    )}
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                      {r.period_start ? new Date(r.period_start).toLocaleDateString('fr-FR') : '—'}
                      {' → '}
                      {r.period_end ? new Date(new Date(r.period_end).getTime() - 86400000).toLocaleDateString('fr-FR') : '—'}
                    </td>
                    {countColumns.map(c => (
                      <td key={c.key} className="px-4 py-3 font-semibold" style={{ color: c.color }}>{r.counts?.[c.key] ?? 0}</td>
                    ))}
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                      {r.generated_at ? new Date(r.generated_at).toLocaleDateString('fr-FR') : '—'}
                      {r.generated_by ? <span className="block opacity-70">{r.generated_by}</span> : null}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1.5">
                        <button onClick={() => handleOpenArchive(r.id)}
                          className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                          style={{ background: 'rgba(163,113,247,0.1)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.25)' }}
                        >👁 Consulter</button>
                        <button onClick={() => handleArchiveCsv(r)}
                          className="text-xs px-2.5 py-1.5 rounded-lg transition-colors"
                          style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                        >CSV</button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>

    {/* Rapport hebdomadaire figé sélectionné */}
    {openReport && (
      <div style={CARD} className="overflow-hidden">
        <div className="px-6 py-4 flex items-center justify-between flex-wrap gap-2" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>
              Rapport {openReport.label}{assetScoped ? ` — ${openReport.asset_label || 'parc entier'}` : ''}
            </h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Instantané figé — généré le {openReport.generated_at ? new Date(openReport.generated_at).toLocaleString('fr-FR') : '—'}
              {openReport.generated_by ? ` par ${openReport.generated_by}` : ''}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => {
                const ok = exportPdf(summaryText)
                setError(ok ? '' : 'Export PDF bloqué par le navigateur — autorisez les fenêtres pop-up pour ce site, puis réessayez.')
              }}
              className="px-3 py-1.5 text-xs font-medium rounded-lg transition-colors"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
            >Exporter PDF</button>
            <button onClick={() => setOpenReport(null)}
              className="px-3 py-1.5 text-xs rounded-lg transition-colors"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Fermer</button>
          </div>
        </div>
        <div className="p-6 space-y-0.5">
          {renderMd(summaryText)}
        </div>
      </div>
    )}

  </>
  )
}
