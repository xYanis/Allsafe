import { useState, useEffect } from 'react'
import { exportCsv, assets as fetchAssets } from '../api/client.js'
import AssetDropdown from '../components/AssetDropdown.jsx'
import PageHero from '../components/PageHero.jsx'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { FAKE_ASSETS, anonymizeAsset, redactText, isFakeId } from '../utils/fakeData.js'
import WeeklyArchives from '../components/WeeklyArchives.jsx'
import { MODULES } from '../constants/modules.js'
import { tintedCard } from '../utils/cardStyle.js'

const CARD = tintedCard(MODULES.rapports.color)

export default function Reports() {
  const { isAnonymous } = usePresentation()
  const { names: ANALYSTS } = useAnalysts()
  // `realAssetList` : toujours les vraies données (nécessaire pour savoir quoi
  // chercher/remplacer dans redactText et pour interroger le backend, qui
  // ignore les actifs de démonstration). `displayAssetList` : ce qui est
  // montré à l'écran (filtre, libellés) — anonymisé + complété par les actifs
  // fictifs en mode Présentation, comme sur Dashboard/Actifs/Inventaire.
  const [realAssetList, setRealAssetList] = useState([])
  const [selectedAssetIds, setSelectedAssetIds] = useState([])
  const [csvLoading, setCsvLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchAssets().then(r => setRealAssetList([...(r.data || [])].sort((a, b) => a.name.localeCompare(b.name)))).catch(() => {})
  }, [])

  const displayAssetList = isAnonymous
    ? [...realAssetList.map(anonymizeAsset), ...FAKE_ASSETS].sort((a, b) => a.name.localeCompare(b.name))
    : realAssetList

  // Le backend ne connaît rien des actifs de démonstration — seuls les ids
  // réels lui sont transmis pour le résumé/l'export.
  function realSelectedIds() {
    return selectedAssetIds.filter(id => !isFakeId(id))
  }
  // Sélection composée uniquement d'actifs fictifs : pas de vraies données à
  // résumer, on l'indique plutôt que d'appeler le backend sur tout le parc
  // (ce qui donnerait un résumé qui ne correspond pas à la sélection affichée).
  function onlyFakeAssetsSelected() {
    return selectedAssetIds.length > 0 && realSelectedIds().length === 0
  }

  function assetParam() {
    const ids = realSelectedIds()
    return ids.length ? ids.join(',') : undefined
  }

  function handleExportCsv() {
    if (onlyFakeAssetsSelected()) {
      setError('Export indisponible pour une sélection composée uniquement d\'actifs de démonstration.')
      return
    }
    setCsvLoading(true)
    setError('')
    exportCsv({ asset_id: assetParam() })
      .then(async r => {
        let blob = new Blob([r.data], { type: 'text/csv;charset=utf-8;' })
        if (isAnonymous) {
          const text = await blob.text()
          blob = new Blob([redactText(text, realAssetList, ANALYSTS)], { type: 'text/csv;charset=utf-8;' })
        }
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `cybervuln-vulnerabilites-${new Date().toISOString().slice(0, 10)}.csv`
        a.click()
        URL.revokeObjectURL(url)
      })
      .catch(() => setError('Erreur lors de l\'export CSV.'))
      .finally(() => setCsvLoading(false))
  }

  const assetLabel = selectedAssetIds.length === 0
    ? 'tous les actifs'
    : selectedAssetIds.length === 1
      ? (displayAssetList.find(a => a.id === selectedAssetIds[0])?.name ?? '1 actif')
      : `${selectedAssetIds.length} actifs sélectionnés`

  return (
    <div className="p-6 space-y-6">
      <PageHero
        icon="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
        title="Rapport exécutif CVE" color="#a371f7"
        subtitle="Résumé exécutif, export CSV et journaux d'accès"
      />

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl flex items-center gap-2"
          style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          {error}
        </div>
      )}

      {/* Filtres — communs au résumé exécutif et à l'export CSV */}
      <div style={{ ...CARD, padding: '12px 20px', display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center' }}>
        <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Filtres</span>
        <AssetDropdown assetList={displayAssetList} selected={selectedAssetIds} onChange={setSelectedAssetIds} />
      </div>

      {/* Export CSV */}
      <div style={CARD} className="p-6">
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
            style={{ background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.2)' }}>
            <svg className="w-5 h-5" style={{ color: '#58a6ff' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <div className="flex-1">
            <h2 className="font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Export CSV — backlog courant</h2>
            <p className="text-sm mb-4 leading-relaxed" style={{ color: 'var(--text-muted)' }}>
              Liste complète des vulnérabilités non corrigées sur {assetLabel} (ouvertes, en attente de
              correctif, faux positifs) — document de travail détaillé, en complément du résumé exécutif.
              Ne tient pas compte de la période sélectionnée ci-dessus.
            </p>
            <button onClick={handleExportCsv} disabled={csvLoading}
              className="px-4 py-2 text-sm font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
              onMouseEnter={e => { if (!csvLoading) e.currentTarget.style.background = 'var(--border)' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-secondary)' }}
            >
              {csvLoading && (
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                </svg>
              )}
              {csvLoading ? 'Export…' : 'Exporter CSV'}
            </button>
          </div>
        </div>
      </div>

      <WeeklyArchives
        kind="cve"
        assetIds={selectedAssetIds}
        assetScoped
        redactAssets={realAssetList}
        countColumns={[
          { key: 'patched',        label: 'Corrigées',     color: '#3fb950' },
          { key: 'awaiting_fix',   label: 'En attente',    color: '#d29922' },
          { key: 'false_positive', label: 'Faux positifs', color: '#a371f7' },
        ]}
        description="Un rapport figé par semaine (S30/2026), généré automatiquement chaque lundi à 7h sur la semaine écoulée — pour le parc entier et pour chaque actif. Sélectionnez un actif dans les filtres ci-dessus pour n'afficher que les siens. Les chiffres d'une semaine archivée ne changent plus."
      />

    </div>
  )
}
