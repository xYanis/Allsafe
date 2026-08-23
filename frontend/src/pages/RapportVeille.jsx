import { useState, useEffect } from 'react'
import { exportWatch, assets as fetchAssets } from '../api/client.js'
import WeeklyArchives from '../components/WeeklyArchives.jsx'
import PageHero from '../components/PageHero.jsx'
import { MODULES } from '../constants/modules.js'
import { tintedCard } from '../utils/cardStyle.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { redactText } from '../utils/syntheticData.js'

const CARD = tintedCard(MODULES.rapports.color)

const THEMES = [
  'Admin', 'APT', 'Cyber', 'Données', 'Hardware', 'IA',
  'Ransomware', 'Réglementation', 'Réseau', 'Software', 'Vulnérabilité',
]

function ThemeChip({ label, active, onClick }) {
  return (
    <button
      onClick={onClick}
      className="text-xs px-2.5 py-1 rounded-lg font-medium transition-colors"
      style={active
        ? { background: 'rgba(88,166,255,0.15)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' }
        : { background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }
      }
    >
      {label}
    </button>
  )
}

// Export CSV auditeur — déplacé depuis Veille technologique (Watch.jsx) vers le
// module Rapports pour centraliser tous les exports au même endroit.
export default function RapportVeille() {
  const [selThemes, setSelThemes] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const { isAnonymous } = usePresentation()
  const { names: ANALYSTS } = useAnalysts()
  // Ne sert qu'à l'anonymisation du CSV exporté (redactText a besoin de savoir quels
  // hostnames/noms réels chercher/remplacer, cf. Reports.jsx qui suit le même principe) — pas
  // de sélecteur d'actifs sur cette page, contrairement à Reports.jsx/RapportIncidents.jsx.
  const [realAssetList, setRealAssetList] = useState([])
  useEffect(() => { fetchAssets().then(r => setRealAssetList(r.data || [])).catch(() => {}) }, [])

  function toggleTheme(val) {
    setSelThemes(s => s.includes(val) ? s.filter(x => x !== val) : [...s, val])
  }

  async function handleExport() {
    setLoading(true)
    setError('')
    try {
      const params = {}
      if (selThemes.length) params.themes = selThemes.join(',')
      const r = await exportWatch(params)
      let blob = new Blob([r.data], { type: 'text/csv;charset=utf-8;' })
      // Export anonymisé en mode Présentation (21/08/2026, retour utilisateur — ce bouton
      // téléchargeait jusqu'ici le vrai registre en clair, seul Reports.jsx/RapportIncidents.jsx
      // avaient ce garde-fou).
      if (isAnonymous) {
        const text = await blob.text()
        blob = new Blob([redactText(text, realAssetList, ANALYSTS)], { type: 'text/csv;charset=utf-8;' })
      }
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href = url
      a.download = `cybervuln-veille-${new Date().toISOString().slice(0, 10)}.csv`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      setError('Erreur lors de l\'export CSV.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 space-y-6">
      <PageHero
        icon="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
        title="Rapport Veille" color={MODULES.rapports.color}
        subtitle="Rapports hebdomadaires et export CSV du registre — traçabilité auditable NIS 2"
      />

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      <div style={CARD} className="p-6">
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
            style={{ background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.2)' }}>
            <svg className="w-5 h-5" style={{ color: '#58a6ff' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <div className="flex-1">
            <h2 className="font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Export CSV — registre de veille</h2>
            <p className="text-sm mb-4 leading-relaxed" style={{ color: 'var(--text-muted)' }}>
              Liste complète des items de veille (source, sévérité, thèmes, statut, analyste, décision) —
              document destiné à prouver le traitement à un auditeur NIS 2. Filtrable par thème.
            </p>
            <div className="flex flex-wrap gap-1.5 mb-4">
              {THEMES.map(t => (
                <ThemeChip key={t} label={t} active={selThemes.includes(t)} onClick={() => toggleTheme(t)} />
              ))}
            </div>
            <button onClick={handleExport} disabled={loading}
              className="px-4 py-2 text-sm font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
              onMouseEnter={e => { if (!loading) e.currentTarget.style.background = 'var(--border)' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-secondary)' }}
            >
              {loading && (
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                </svg>
              )}
              {loading ? 'Export…' : 'Exporter CSV'}
            </button>
          </div>
        </div>
      </div>

      {/* Rapports hebdomadaires figés — même composant que le Rapport exécutif
          CVE, seules changent la portée (`kind`) et les colonnes de comptage.
          Pas de portée par actif ici : le registre de veille n'est pas rattaché
          au parc (cf. ASSET_SCOPED_KINDS, backend/services/weekly_report.py). */}
      <WeeklyArchives
        kind="veille"
        countColumns={[
          { key: 'received',         label: 'Collectés',        color: '#58a6ff' },
          { key: 'treated',          label: 'Traités',          color: '#3fb950' },
          { key: 'critical_pending', label: 'Critiques ouverts', color: '#f85149' },
        ]}
        description="Un rapport figé par semaine (S30/2026), généré automatiquement chaque lundi à 7h sur la semaine écoulée : volume collecté, éléments traités, respect du SLA 48 h sur les critiques et décisions consignées. Les chiffres d'une semaine archivée ne changent plus — c'est ce qui en fait une preuve opposable à un auditeur."
      />
    </div>
  )
}
