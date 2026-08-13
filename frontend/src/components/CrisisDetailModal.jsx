import { useEffect, useState } from 'react'
import IncidentTimeline from './IncidentTimeline.jsx'
import CrisisActionModal from './CrisisActionModal.jsx'
import CrisisRoadmap from './CrisisRoadmap.jsx'
import Stepper from './Stepper.jsx'
import ConfirmModal from './ConfirmModal.jsx'
import MarkdownNote from './MarkdownNote.jsx'
import {
  crisisTimeline, standDownCrisis, assignCrisisRole, removeCrisisRole,
  linkCrisisIncident, unlinkCrisisIncident, addCrisisDecision, addCrisisCommunication,
  deleteCrisis, incidents as fetchIncidents,
} from '../api/client.js'
import { MODULES } from '../constants/modules.js'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { useAuth } from '../contexts/AuthContext.jsx'

const MODULE_COLOR = MODULES.incidents.color

const CRISIS_EVENT_LABELS = {
  activated: 'Crise activée',
  stood_down: 'Crise désactivée',
  role_assigned: 'Rôle assigné',
  role_removed: 'Rôle retiré',
  incident_linked: 'Incident rattaché',
  incident_unlinked: 'Incident détaché',
  decision: 'Décision',
  communication: 'Communication',
}

function fmtShort(iso) {
  if (!iso) return null
  const d = new Date(iso)
  return d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit' }) + ' ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
}

// Frise du haut (31/07/2026) — même principe qu'IncidentDetailModal.jsx::incidentSteps, vue
// d'ensemble complémentaire au journal détaillé plus bas. "Désactivée" reste 'pending' tant
// que la crise est active — c'est une étape terminale, pas "en cours" au sens du stepper.
function crisisSteps(crisis) {
  const roleCount = (crisis.crisis_roles || []).length
  const linkedCount = (crisis.linked_incidents || []).length
  return [
    { key: 'activated', label: 'Activée', state: 'done', sublabel: fmtShort(crisis.activated_at) },
    { key: 'team', label: 'Cellule constituée', state: roleCount > 0 ? 'done' : 'pending', sublabel: roleCount > 0 ? `${roleCount} rôle${roleCount > 1 ? 's' : ''}` : null },
    { key: 'linked', label: 'Incident(s) rattaché(s)', state: linkedCount > 0 ? 'done' : 'pending', sublabel: linkedCount > 0 ? `${linkedCount}` : null },
    { key: 'stood_down', label: 'Désactivée', state: crisis.status === 'stood_down' ? 'done' : 'pending', sublabel: crisis.status === 'stood_down' ? fmtShort(crisis.stood_down_at) : null },
  ]
}

function StatusPill({ active }) {
  return active
    ? <span className="text-xs px-2 py-0.5 rounded-lg font-medium" style={{ background: 'rgba(248,81,73,0.15)', color: '#f85149', border: '1px solid rgba(248,81,73,0.4)' }}>Active</span>
    : <span className="text-xs px-2 py-0.5 rounded-lg font-medium" style={{ background: 'rgba(139,148,158,0.12)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' }}>Désactivée</span>
}

// Détail d'une crise : cellule de crise (rôles), incidents liés, journal de décisions et
// communications. Même charpente que IncidentDetailModal.jsx (sections empilées,
// `actionModal` pour les sous-actions) — CrisisActionModal.jsx couvre les 4 actions
// sensibles (désactivation, décision, communication, rôle).
export default function CrisisDetailModal({ crisis, onClose, onUpdated, onDeleted }) {
  const { names: ANALYSTS } = useAnalysts()
  // Suppression réservée admin côté serveur (03/08/2026, audit sécurité) — masqué ici
  // pour ne pas laisser un compte analyst se heurter à un 403 après confirmation.
  const { user } = useAuth()
  const canDelete = user?.role === 'admin'
  const [entries, setEntries] = useState([])
  const [loadingTimeline, setLoadingTimeline] = useState(true)
  const [actionModal, setActionModal] = useState(null) // null | 'stand-down' | 'decision' | 'communication' | 'role'
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [incidentOptions, setIncidentOptions] = useState([])
  const [linkIncidentId, setLinkIncidentId] = useState('')
  const [linkBy, setLinkBy] = useState('')
  const [error, setError] = useState('')

  const active = crisis.status === 'active'

  function loadTimeline() {
    setLoadingTimeline(true)
    crisisTimeline(crisis.id).then(r => setEntries(r.data.entries)).catch(() => setEntries([])).finally(() => setLoadingTimeline(false))
  }
  useEffect(() => { loadTimeline() }, [crisis.id])

  useEffect(() => {
    fetchIncidents({ per_page: 200 }).then(r => setIncidentOptions(r.data.items || [])).catch(() => {})
  }, [])

  async function refresh(fresh) {
    onUpdated(fresh)
    loadTimeline()
  }

  async function handleStandDown({ justification, analyst }) {
    const { data } = await standDownCrisis(crisis.id, analyst, justification)
    setActionModal(null)
    refresh(data)
  }
  async function handleDecision({ content, author }) {
    await addCrisisDecision(crisis.id, author, content)
    setActionModal(null)
    loadTimeline()
  }
  async function handleCommunication({ content, audience, author }) {
    await addCrisisCommunication(crisis.id, author, content, audience)
    setActionModal(null)
    loadTimeline()
  }
  async function handleRole({ role, analyst_name, by }) {
    const { data } = await assignCrisisRole(crisis.id, role, analyst_name, by)
    setActionModal(null)
    refresh(data)
  }
  async function handleRemoveRole(role) {
    if (!ANALYSTS.length) return
    const by = window.prompt(`Retirer le rôle « ${role} » — par qui ? (${ANALYSTS.join(', ')})`)
    if (!by) return
    const { data } = await removeCrisisRole(crisis.id, role, by)
    refresh(data)
  }

  async function handleLinkIncident() {
    if (!linkIncidentId || !linkBy) return
    setError('')
    try {
      const { data } = await linkCrisisIncident(crisis.id, linkIncidentId, linkBy)
      setLinkIncidentId('')
      refresh(data)
    } catch (e) {
      setError(e?.response?.data?.detail || 'Impossible de rattacher cet incident.')
    }
  }
  async function handleUnlinkIncident(incidentId) {
    if (!ANALYSTS.length) return
    const by = window.prompt(`Détacher cet incident — par qui ? (${ANALYSTS.join(', ')})`)
    if (!by) return
    const { data } = await unlinkCrisisIncident(crisis.id, incidentId, by)
    refresh(data)
  }

  async function confirmDelete() {
    await deleteCrisis(crisis.id)
    onDeleted()
  }

  const linkableIncidents = incidentOptions.filter(i => !crisis.linked_incidents?.some(li => li.id === i.id))

  return (
    <>
      <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={onClose}>
        <div className="max-w-2xl w-full rounded-2xl flex flex-col max-h-[90vh] animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
          <div className="px-6 py-4 flex items-start justify-between flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>{crisis.title}</h2>
                <StatusPill active={active} />
              </div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Activée par {crisis.activated_by} le {new Date(crisis.activated_at).toLocaleString('fr-FR')}
                {!active && crisis.stood_down_at && ` · Désactivée par ${crisis.stood_down_by} le ${new Date(crisis.stood_down_at).toLocaleString('fr-FR')}`}
              </p>
            </div>
            <button onClick={onClose} className="p-1.5 rounded-lg flex-shrink-0" style={{ color: 'var(--text-muted)' }}>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>

          <div className="p-6 space-y-4 overflow-y-auto">
            <Stepper steps={crisisSteps(crisis)} color={MODULE_COLOR} />

            {crisis.description && <MarkdownNote text={crisis.description} />}
            {!active && crisis.stand_down_justification && (
              <div className="rounded-xl p-3" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                <p className="text-xs font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--text-muted)' }}>Justification de désactivation</p>
                <MarkdownNote text={crisis.stand_down_justification} className="text-xs" />
              </div>
            )}

            <div className="rounded-xl p-4" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Cellule de crise</p>
                {active && (
                  <button onClick={() => setActionModal('role')} className="text-xs px-2.5 py-1 rounded-lg font-medium"
                    style={{ background: `${MODULE_COLOR}1f`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}4d` }}>
                    + Assigner un rôle
                  </button>
                )}
              </div>
              {(crisis.crisis_roles || []).length === 0 ? (
                <p className="text-xs" style={{ color: 'var(--text-faint)' }}>Aucun rôle assigné.</p>
              ) : (
                <div className="space-y-1.5">
                  {crisis.crisis_roles.map(r => (
                    <div key={r.role} className="flex items-center justify-between text-xs">
                      <span style={{ color: 'var(--text-secondary)' }}><strong style={{ color: 'var(--text-primary)' }}>{r.role}</strong> — {r.analyst_name}</span>
                      {active && (
                        <button onClick={() => handleRemoveRole(r.role)} style={{ color: 'var(--text-faint)' }} title="Retirer">✕</button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-xl p-4" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
              <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>Incidents liés</p>
              {(crisis.linked_incidents || []).length === 0 ? (
                <p className="text-xs mb-2" style={{ color: 'var(--text-faint)' }}>Aucun incident rattaché.</p>
              ) : (
                <div className="space-y-1.5 mb-2">
                  {crisis.linked_incidents.map(li => (
                    <div key={li.id} className="flex items-center justify-between text-xs">
                      <span style={{ color: 'var(--text-secondary)' }}>{li.title}</span>
                      {active && (
                        <button onClick={() => handleUnlinkIncident(li.id)} style={{ color: 'var(--text-faint)' }} title="Détacher">✕</button>
                      )}
                    </div>
                  ))}
                </div>
              )}
              {active && (
                <div className="flex items-center gap-1.5 flex-wrap">
                  <select value={linkIncidentId} onChange={e => setLinkIncidentId(e.target.value)}
                    className="text-xs px-2 py-1.5 rounded-lg outline-none flex-1 min-w-[140px]"
                    style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                    <option value="">Rattacher un incident…</option>
                    {linkableIncidents.map(i => <option key={i.id} value={i.id}>{i.title}</option>)}
                  </select>
                  <select value={linkBy} onChange={e => setLinkBy(e.target.value)}
                    className="text-xs px-2 py-1.5 rounded-lg outline-none"
                    style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                    <option value="">Par…</option>
                    {ANALYSTS.map(name => <option key={name} value={name}>{name}</option>)}
                  </select>
                  <button onClick={handleLinkIncident} disabled={!linkIncidentId || !linkBy}
                    className="text-xs px-2.5 py-1.5 rounded-lg font-medium disabled:opacity-50"
                    style={{ background: `${MODULE_COLOR}1f`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}4d` }}>
                    Rattacher
                  </button>
                </div>
              )}
              {error && <p className="text-xs mt-1.5" style={{ color: '#f85149' }}>{error}</p>}
            </div>

            <div className="rounded-xl p-4" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
              <p className="text-xs font-semibold uppercase tracking-wide mb-3" style={{ color: 'var(--text-muted)' }}>Roadmap</p>
              <CrisisRoadmap crisis={crisis} onUpdated={onUpdated} />
            </div>

            <div>
              <div className="flex items-center justify-between mb-2 flex-wrap gap-1.5">
                <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Journal</p>
                {active && (
                  <div className="flex gap-1.5">
                    <button onClick={() => setActionModal('decision')} className="text-xs px-2 py-1 rounded-lg font-medium"
                      style={{ background: 'var(--bg-card)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>+ Décision</button>
                    <button onClick={() => setActionModal('communication')} className="text-xs px-2 py-1 rounded-lg font-medium"
                      style={{ background: 'var(--bg-card)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>+ Communication</button>
                  </div>
                )}
              </div>
              <IncidentTimeline entries={entries} loading={loadingTimeline} labels={CRISIS_EVENT_LABELS} />
            </div>
          </div>

          <div className={`px-6 py-3 flex ${canDelete ? 'justify-between' : 'justify-end'} flex-shrink-0`} style={{ borderTop: '1px solid var(--border)' }}>
            {canDelete && (
              <button onClick={() => setShowDeleteConfirm(true)}
                className="text-xs px-3 py-2 rounded-lg font-medium"
                style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}>
                Supprimer
              </button>
            )}
            {active && (
              <button onClick={() => setActionModal('stand-down')} className="text-xs px-3 py-2 rounded-lg font-medium"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                Désactiver la crise
              </button>
            )}
          </div>
        </div>
      </div>

      {actionModal && (
        <CrisisActionModal
          kind={actionModal}
          subtitle={crisis.title}
          onConfirm={
            actionModal === 'stand-down' ? handleStandDown
            : actionModal === 'decision' ? handleDecision
            : actionModal === 'communication' ? handleCommunication
            : handleRole
          }
          onClose={() => setActionModal(null)}
        />
      )}
      {showDeleteConfirm && (
        <ConfirmModal
          title="Supprimer cette crise ?"
          message={<>Supprimer définitivement « <strong>{crisis.title}</strong> » ? Sa chronologie sera aussi effacée. Les incidents rattachés ne sont pas supprimés. Cette action est irréversible.</>}
          confirmLabel="Supprimer"
          onConfirm={confirmDelete}
          onClose={() => setShowDeleteConfirm(false)}
        />
      )}
    </>
  )
}
