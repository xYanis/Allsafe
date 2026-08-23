import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { agentsHistory } from '../api/client.js'
import PageLoader from '../components/PageLoader.jsx'
import PageHero from '../components/PageHero.jsx'
import OsLogo from '../components/OsLogo.jsx'
import { StatusBadge, formatDateTime } from '../components/AgentBadges.jsx'
import { MODULES } from '../constants/modules.js'
import { tintedCard } from '../utils/cardStyle.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { anonymizeAgent, SYNTHETIC_AGENTS } from '../utils/syntheticData.js'

// Historique global des agents (19/08/2026, demande explicite) — vue de parc COMPLÉMENTAIRE
// à la page de détail par agent (AgentHistory.jsx) : on ne rejoue pas ici la frise de
// check-ins d'un poste, on donne l'état de TOUS les agents ayant existé, y compris révoqués
// et supprimés. But premier : voir d'un coup d'œil ce qui a été révoqué/retiré du parc.
// Données : GET /agents/history (agents vivants ∪ AgentDeletionLog, cf. routers/agents.py).
const MODULE_COLOR = MODULES.inventaire.color
const CARD = tintedCard(MODULE_COLOR)

// Badge d'état unifié — StatusBadge (AgentBadges) ne connaît qu'enrôlé/révoqué ; "supprimé"
// (agent hard-delete, présent seulement via AgentDeletionLog) a son propre rendu gris neutre.
function StateBadge({ item }) {
  if (item.deleted) {
    return <span style={{ background: 'rgba(139,148,158,0.15)', color: '#8b949e', borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, display: 'inline-block' }}>Supprimé</span>
  }
  return <StatusBadge value={item.status} />
}

function StatTile({ label, value, color }) {
  return (
    <div className="rounded-xl p-3" style={CARD}>
      <p className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{label}</p>
      <p className="text-xl font-semibold mt-1" style={{ color: color || 'var(--text-primary)' }}>{value}</p>
    </div>
  )
}

export default function AgentsGlobalHistory() {
  const [history, setHistory] = useState(null)
  const [error, setError] = useState('')
  // Filtre (but premier de la page) : se concentrer sur ce qui a quitté le parc actif.
  const [inactiveOnly, setInactiveOnly] = useState(false)
  const { isAnonymous } = usePresentation()

  useEffect(() => {
    agentsHistory()
      .then(r => { setHistory(r.data); setError('') })
      .catch(() => setError('Impossible de charger l\'historique des agents — le serveur a peut-être renvoyé une erreur.'))
  }, [])

  if (error) {
    return (
      <div className="p-6 space-y-3">
        <Link to="/agents" className="text-xs inline-block" style={{ color: MODULE_COLOR }}>← Retour aux agents</Link>
        <p className="text-sm" style={{ color: '#f85149' }}>{error}</p>
      </div>
    )
  }
  if (!history) return <PageLoader />

  const items = history.items || []
  const revokedCount = items.filter(i => !i.deleted && i.status === 'revoked').length
  // Compteurs des tuiles ("Total"/"Actifs"/"Révoqués"/"Supprimés") gardés sur les seules
  // données réelles (history.total/live_count/deleted_count, ci-dessous) — les agents fictifs
  // ne s'ajoutent qu'au tableau, jamais aux stats globales du parc.
  const combined = isAnonymous ? [...items, ...SYNTHETIC_AGENTS.map(a => ({ ...a, deleted: false }))] : items
  // "Inactif" = a quitté le parc actif : révoqué (encore en base) ou supprimé (journal).
  const filtered = inactiveOnly ? combined.filter(i => i.deleted || i.status === 'revoked') : combined
  const shown = isAnonymous ? filtered.map(anonymizeAgent) : filtered

  return (
    <div className="p-6 space-y-5">
      <Link to="/agents" className="text-xs inline-block" style={{ color: MODULE_COLOR }}>← Retour aux agents</Link>

      <PageHero
        icon="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25"
        title="Historique des agents"
        color={MODULE_COLOR}
        subtitle="Vue de parc complémentaire — tous les agents ayant existé, y compris révoqués et supprimés. Le suivi détaillé d'un poste (check-ins) reste sur sa page d'agent."
      />

      <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))' }}>
        <StatTile label="Total (depuis le début)" value={history.total} />
        <StatTile label="Actifs" value={history.live_count - revokedCount} color="#3fb950" />
        <StatTile label="Révoqués" value={revokedCount} color={revokedCount > 0 ? '#f85149' : undefined} />
        <StatTile label="Supprimés" value={history.deleted_count} color={history.deleted_count > 0 ? '#8b949e' : undefined} />
      </div>

      <div style={CARD} className="p-6">
        <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
          <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
            {shown.length} agent{shown.length !== 1 ? 's' : ''}{inactiveOnly ? ' révoqué(s)/supprimé(s)' : ''}
          </h2>
          <label className="text-xs flex items-center gap-2 cursor-pointer" style={{ color: 'var(--text-secondary)' }}>
            <input type="checkbox" checked={inactiveOnly} onChange={e => setInactiveOnly(e.target.checked)} />
            Révoqués et supprimés uniquement
          </label>
        </div>

        {shown.length === 0 ? (
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
            {inactiveOnly ? 'Aucun agent révoqué ni supprimé.' : 'Aucun agent enregistré.'}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                  {['Hôte', 'Enrôlé le', 'Enrôlé par', 'État', 'Sortie du parc'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-xs font-semibold uppercase tracking-wide whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {shown.map((it, idx) => {
                  const exit = it.deleted
                    ? (it.deleted_at ? `Supprimé le ${formatDateTime(it.deleted_at)}${it.deleted_by ? ` par ${it.deleted_by}` : ''}` : 'Supprimé')
                    : it.status === 'revoked'
                    ? (it.revoked_at ? `Révoqué le ${formatDateTime(it.revoked_at)}${it.revoked_by ? ` par ${it.revoked_by}` : ''}` : 'Révoqué')
                    : null
                  return (
                    <tr key={idx} style={{ borderBottom: '1px solid var(--border-subtle)', opacity: it.deleted ? 0.75 : 1 }}>
                      <td className="px-4 py-2.5">
                        <span className="inline-flex items-center gap-1.5">
                          <OsLogo os={it.os} size={14} />
                          <span style={{ color: 'var(--text-primary)' }}>{it.hostname}</span>
                        </span>
                        {it.asset_name && <span className="block text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{it.asset_name}</span>}
                      </td>
                      <td className="px-4 py-2.5 text-xs whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>{it.enrolled_at ? formatDateTime(it.enrolled_at) : '—'}</td>
                      <td className="px-4 py-2.5 text-xs" style={{ color: 'var(--text-secondary)' }}>{it.enrolled_by || '—'}</td>
                      <td className="px-4 py-2.5"><StateBadge item={it} /></td>
                      <td className="px-4 py-2.5 text-xs" style={{ color: exit ? 'var(--text-secondary)' : 'var(--text-faint)' }}>{exit || '—'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
