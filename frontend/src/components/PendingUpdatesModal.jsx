import { useEffect, useState } from 'react'
import { getAssetPendingUpdates } from '../api/client.js'
import SeverityBadge from './SeverityBadge.jsx'
import StatusBadge from './StatusBadge.jsx'

// Détail des mises à jour en attente d'un actif, ouvert au clic sur une pastille
// de PendingUpdatesBadge.jsx (07/08/2026, demande explicite : les pastilles
// n'affichaient qu'un compte, pas la liste des CVE derrière). Même schéma de
// modale que ScanResultModal (Assets.jsx) — fetch à l'ouverture, pas de prop
// pré-chargée : le compte affiché dans la colonne vient d'un agrégat SQL
// (routers/assets.py::list_assets), pas de la liste elle-même.
export default function PendingUpdatesModal({ asset, onClose }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    getAssetPendingUpdates(asset.id)
      .then(r => { if (!cancelled) setData(r.data) })
      .catch(() => { if (!cancelled) setError('Erreur lors du chargement du détail.') })
    return () => { cancelled = true }
  }, [asset.id])

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-lg w-full max-h-[85vh] rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>Mises à jour en attente — {asset.name}</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Vulnérabilités encore ouvertes, système et applicatif</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        <div className="p-6 space-y-5 overflow-y-auto">
          {error && <p className="text-sm" style={{ color: '#f85149' }}>{error}</p>}
          {!error && !data && <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Chargement…</p>}
          {data && (
            <>
              <UpdateSection title="🖥 Système" items={data.system} />
              <UpdateSection title="📦 Application" items={data.application} />
              {data.system.length === 0 && data.application.length === 0 && (
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucune mise à jour en attente sur cet actif.</p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function UpdateSection({ title, items }) {
  if (items.length === 0) return null
  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>
        {title} ({items.length})
      </p>
      <div className="space-y-1.5">
        {items.map(v => (
          <div key={v.vuln_id} className="flex items-center gap-2 text-xs px-3 py-2 rounded-lg" style={{ background: 'var(--bg-secondary)' }}>
            <div className="flex-1 min-w-0">
              {/* `packages` : uniquement le groupe "application" (cf.
                  routers/assets.py::asset_pending_updates) — le nom du logiciel
                  installé concerné, sans quoi le CVE seul ne dit pas quoi mettre
                  à jour. Vide possible même côté application (candidats produit
                  et paquets installés peuvent diverger légèrement, cf.
                  cpe_matcher.py) : repli sur le CVE seul plutôt que rien afficher. */}
              {v.packages?.length > 0 && (
                <p className="font-medium truncate" style={{ color: 'var(--text-primary)' }} title={v.packages.join(', ')}>
                  {v.packages.join(', ')}
                </p>
              )}
              <p className="font-mono truncate" style={{ color: v.packages?.length > 0 ? 'var(--text-muted)' : 'var(--text-primary)' }}>{v.cve_id}</p>
            </div>
            <SeverityBadge value={v.severity} />
            <StatusBadge value={v.status} />
          </div>
        ))}
      </div>
    </div>
  )
}
