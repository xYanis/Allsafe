import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import IncidentSeverityBadge from './IncidentSeverityBadge.jsx'
import IncidentTimeline from './IncidentTimeline.jsx'
import IncidentRoadmap from './IncidentRoadmap.jsx'
import Stepper from './Stepper.jsx'
import AnnotationModal from './AnnotationModal.jsx'
import ConfirmModal from './ConfirmModal.jsx'
import MilestoneDetailModal from './MilestoneDetailModal.jsx'
import EscalateToCrisisModal from './EscalateToCrisisModal.jsx'
import MarkdownNote from './MarkdownNote.jsx'
import { INCIDENT_STATUSES } from './IncidentFormModal.jsx'
import {
  incidentTimeline, qualifyIncidentNotification, unqualifyIncidentNotification,
  markIncidentMilestoneSent, addIncidentNote, deleteIncident,
  incidentAttachments, uploadIncidentAttachment, deleteIncidentAttachment, incidentAttachmentDownloadUrl,
} from '../api/client.js'
import { milestoneStatus, MILESTONE_LABELS } from '../utils/nis2Countdown.js'
import { MODULES } from '../constants/modules.js'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { useAuth } from '../contexts/AuthContext.jsx'

const MILESTONES = ['early_warning', 'incident_notification', 'final_report']
const MODULE_COLOR = MODULES.incidents.color
const MAX_ATTACHMENT_SIZE = 5 * 1024 * 1024

function fmtShort(iso) {
  if (!iso) return null
  const d = new Date(iso)
  return d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit' }) + ' ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
}

// Frise du haut (31/07/2026) — vue d'ensemble, pas un remplacement du bloc "Notification NIS 2"
// ni du journal détaillé plus bas : un coup d'œil sur où en est l'incident. Un seul jalon NIS 2
// non envoyé est marqué 'current'/'overdue' à la fois (le premier), les suivants restent 'pending'
// même si leur propre échéance est déjà dépassée — l'attention doit porter sur le plus urgent.
function incidentSteps(incident) {
  const now = new Date()
  const steps = [
    { key: 'declared', label: 'Déclaré', state: 'done', sublabel: fmtShort(incident.created_at) },
  ]

  if (incident.requires_notification) {
    steps.push({ key: 'qualified', label: 'Qualifié NIS 2', state: 'done', sublabel: fmtShort(incident.notification_qualified_at) })
    let activeAssigned = false
    for (const m of MILESTONES) {
      const sentAt = incident[`${m}_sent_at`]
      const dueAt = incident[`${m}_due_at`]
      let state, sublabel
      if (sentAt) {
        state = 'done'
        sublabel = fmtShort(sentAt)
      } else if (!activeAssigned) {
        activeAssigned = true
        const overdue = dueAt && new Date(dueAt) < now
        state = overdue ? 'overdue' : 'current'
        sublabel = dueAt ? `avant le ${fmtShort(dueAt)}` : null
      } else {
        state = 'pending'
        sublabel = null
      }
      steps.push({ key: m, label: MILESTONE_LABELS[m], state, sublabel })
    }
  } else {
    steps.push({ key: 'qualified', label: 'Qualification NIS 2', state: 'skipped', sublabel: 'Non requise' })
  }

  steps.push({
    key: 'closed', label: 'Clôturé',
    state: incident.status === 'closed' ? 'done' : 'pending',
    sublabel: incident.status === 'closed' ? fmtShort(incident.updated_at) : null,
  })
  return steps
}

// Pièces jointes PDF du rapport final — 5 Mo max chacune (cf. backend/services/
// incident_attachments.py pour la validation faisant foi ; la vérif ici n'est qu'un
// confort UX, pas une garantie de sécurité).
function AttachmentsSection({ incidentId }) {
  const { names: ANALYSTS } = useAnalysts()
  const [attachments, setAttachments] = useState([])
  const [uploadedBy, setUploadedBy] = useState('')
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')

  function load() {
    incidentAttachments(incidentId).then(r => setAttachments(r.data.items)).catch(() => {})
  }
  useEffect(() => { load() }, [incidentId])

  async function handleFileChange(e) {
    const file = e.target.files[0]
    e.target.value = ''
    if (!file) return
    setError('')
    if (file.size > MAX_ATTACHMENT_SIZE) {
      setError('Fichier trop volumineux — 5 Mo maximum.')
      return
    }
    if (!uploadedBy) {
      setError('Sélectionnez qui ajoute ce fichier avant de le téléverser.')
      return
    }
    setUploading(true)
    try {
      await uploadIncidentAttachment(incidentId, file, uploadedBy)
      load()
    } catch (err) {
      setError(err?.response?.data?.detail || "Échec de l'envoi.")
    } finally {
      setUploading(false)
    }
  }

  async function handleDelete(attachmentId) {
    await deleteIncidentAttachment(incidentId, attachmentId)
    load()
  }

  return (
    <div className="mt-2 pl-3 space-y-1.5" style={{ borderLeft: '2px solid var(--border)' }}>
      {attachments.map(a => (
        <div key={a.id} className="flex items-center justify-between text-xs gap-2">
          <a href={incidentAttachmentDownloadUrl(incidentId, a.id)} target="_blank" rel="noopener noreferrer"
            className="hover:underline truncate" style={{ color: MODULE_COLOR }}>
            📎 {a.filename} <span style={{ color: 'var(--text-faint)' }}>({(a.size_bytes / 1024).toFixed(0)} Ko)</span>
          </a>
          <button onClick={() => handleDelete(a.id)} className="flex-shrink-0" style={{ color: 'var(--text-faint)' }} title="Retirer">✕</button>
        </div>
      ))}
      <div className="flex items-center gap-2 flex-wrap">
        <select value={uploadedBy} onChange={e => setUploadedBy(e.target.value)}
          className="text-xs px-2 py-1 rounded outline-none" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
          <option value="">Ajouté par…</option>
          {ANALYSTS.map(name => <option key={name} value={name}>{name}</option>)}
        </select>
        <label className="text-xs px-2.5 py-1 rounded-lg font-medium cursor-pointer"
          style={{ background: 'var(--bg-card)', color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}4d` }}>
          {uploading ? 'Envoi…' : '+ Joindre un PDF'}
          <input type="file" accept=".pdf,application/pdf" onChange={handleFileChange} disabled={uploading} className="hidden" />
        </label>
      </div>
      {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
    </div>
  )
}

// Détail d'un incident : infos, qualification/échéances NIS 2, chronologie.
// Les 4 actions sensibles (qualifier/déqualifier/marquer un jalon envoyé/note
// libre) réutilisent AnnotationModal telle quelle — justification + validateur
// obligatoires, exactement le pattern déjà en place pour les vulnérabilités.
export default function IncidentDetailModal({ incident, onClose, onEdit, onUpdated, onDeleted }) {
  const navigate = useNavigate()
  // Suppression réservée admin côté serveur (03/08/2026, audit sécurité) — masqué ici
  // pour ne pas laisser un compte analyst se heurter à un 403 après confirmation.
  const { user } = useAuth()
  const canDelete = user?.role === 'admin'
  const [entries, setEntries] = useState([])
  const [loadingTimeline, setLoadingTimeline] = useState(true)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [actionModal, setActionModal] = useState(null) // null | 'qualify' | 'unqualify' | 'note' | <milestone>
  const [viewMilestone, setViewMilestone] = useState(null)

  function loadTimeline() {
    setLoadingTimeline(true)
    incidentTimeline(incident.id)
      .then(r => setEntries(r.data.entries))
      .catch(() => setEntries([]))
      .finally(() => setLoadingTimeline(false))
  }
  useEffect(() => { loadTimeline() }, [incident.id])

  async function handleQualify(note, validator) {
    const { data } = await qualifyIncidentNotification(incident.id, validator, note)
    setActionModal(null)
    onUpdated(data)
    loadTimeline()
  }
  async function handleUnqualify(note, validator) {
    const { data } = await unqualifyIncidentNotification(incident.id, validator, note)
    setActionModal(null)
    onUpdated(data)
    loadTimeline()
  }
  async function handleMilestoneSent(note, validator) {
    const { data } = await markIncidentMilestoneSent(incident.id, actionModal, validator, note)
    setActionModal(null)
    onUpdated(data)
    loadTimeline()
  }
  async function handleNote(note, validator) {
    await addIncidentNote(incident.id, validator, note)
    setActionModal(null)
    loadTimeline()
  }
  function handleEscalated(freshIncident) {
    setActionModal(null)
    onUpdated(freshIncident)
  }

  async function confirmDelete() {
    await deleteIncident(incident.id)
    onDeleted()
  }

  const statusLabel = INCIDENT_STATUSES.find(s => s.value === incident.status)?.label || incident.status

  return (
    <>
      <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={onClose}>
        <div className="max-w-2xl w-full rounded-2xl flex flex-col max-h-[90vh] animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
          <div className="px-6 py-4 flex items-start justify-between flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>{incident.title}</h2>
                <IncidentSeverityBadge value={incident.severity} />
              </div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                {incident.category_label} · {statusLabel} · Déclaré par {incident.reported_by}
              </p>
              {incident.crisis_title ? (
                <button onClick={() => navigate('/crises')}
                  className="mt-1.5 text-xs px-1.5 py-0.5 rounded font-medium"
                  style={{ background: 'rgba(248,81,73,0.12)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}>
                  🚨 Rattaché à la crise « {incident.crisis_title} »
                </button>
              ) : (
                <button onClick={() => setActionModal('escalate')}
                  className="mt-1.5 text-xs px-1.5 py-0.5 rounded font-medium"
                  style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
                  🚨 Escalader en crise
                </button>
              )}
            </div>
            <button onClick={onClose} className="p-1.5 rounded-lg flex-shrink-0" style={{ color: 'var(--text-muted)' }}>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>

          <div className="p-6 space-y-4 overflow-y-auto">
            <Stepper steps={incidentSteps(incident)} color={MODULE_COLOR} />

            {incident.description && <MarkdownNote text={incident.description} />}

            {incident.affected_asset_names?.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {incident.affected_asset_names.map(n => (
                  <span key={n} className="text-xs px-2 py-0.5 rounded" style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>{n}</span>
                ))}
              </div>
            )}

            <div className="rounded-xl p-4" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Notification NIS 2</p>
                {!incident.requires_notification ? (
                  <button onClick={() => setActionModal('qualify')} className="text-xs px-2.5 py-1 rounded-lg font-medium"
                    style={{ background: `${MODULE_COLOR}1f`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}4d` }}>
                    Qualifier à notifier
                  </button>
                ) : (
                  <button onClick={() => setActionModal('unqualify')} className="text-xs px-2.5 py-1 rounded-lg font-medium"
                    style={{ background: 'var(--bg-card)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
                    Déqualifier
                  </button>
                )}
              </div>

              {incident.requires_notification ? (
                <div className="space-y-2">
                  {incident.notification_justification && <MarkdownNote text={incident.notification_justification} className="text-xs" />}
                  {MILESTONES.map(m => {
                    const sentAt = incident[`${m}_sent_at`]
                    const dueAt = incident[`${m}_due_at`]
                    const s = milestoneStatus(m, dueAt, sentAt)
                    return (
                      <div key={m}>
                        <div className="flex items-center justify-between text-xs gap-2">
                          <span style={{ color: 'var(--text-secondary)' }}>{MILESTONE_LABELS[m]}</span>
                          {sentAt ? (
                            <span className="flex items-center gap-2">
                              <span style={{ color: '#3fb950' }}>Envoyé le {new Date(sentAt).toLocaleString('fr-FR')}</span>
                              <button onClick={() => setViewMilestone(m)} className="px-2 py-0.5 rounded font-medium flex-shrink-0"
                                style={{ background: 'var(--bg-card)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
                                Consulter
                              </button>
                            </span>
                          ) : (
                            <span className="flex items-center gap-2">
                              <span style={{ color: s.color }}>{s.label}{dueAt ? ` (${new Date(dueAt).toLocaleString('fr-FR')})` : ''}</span>
                              <button onClick={() => setActionModal(m)} className="px-2 py-0.5 rounded font-medium flex-shrink-0"
                                style={{ background: 'var(--bg-card)', color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}4d` }}>
                                Marquer envoyé
                              </button>
                            </span>
                          )}
                        </div>
                        {m === 'final_report' && sentAt && <AttachmentsSection incidentId={incident.id} />}
                      </div>
                    )
                  })}
                </div>
              ) : (
                <p className="text-xs" style={{ color: 'var(--text-faint)' }}>Non qualifié — aucune échéance légale suivie pour cet incident.</p>
              )}
            </div>

            <div className="rounded-xl p-4" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
              <p className="text-xs font-semibold uppercase tracking-wide mb-3" style={{ color: 'var(--text-muted)' }}>Roadmap</p>
              <IncidentRoadmap incident={incident} onUpdated={onUpdated} />
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Historique</p>
                <button onClick={() => setActionModal('note')} className="text-xs" style={{ color: 'var(--text-muted)' }}>+ Ajouter une note</button>
              </div>
              <IncidentTimeline entries={entries} loading={loadingTimeline} />
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
            <button onClick={onEdit} className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
              Modifier
            </button>
          </div>
        </div>
      </div>

      {actionModal === 'qualify' && (
        <AnnotationModal
          title="Qualifier à notifier (NIS 2)" color={MODULE_COLOR}
          subtitle={incident.title}
          helpText="Justifiez pourquoi cet incident relève de l'obligation de notification NIS 2 (Art. 23). Les échéances (24h/72h/1 mois) seront calculées depuis la prise de connaissance."
          placeholder="Ex : fuite de données personnelles confirmée, impact sur la continuité de service…"
          confirmLabel="Qualifier"
          onConfirm={handleQualify}
          onClose={() => setActionModal(null)}
        />
      )}
      {actionModal === 'unqualify' && (
        <AnnotationModal
          title="Déqualifier" color="#8b949e"
          subtitle={incident.title}
          helpText="Justifiez pourquoi cet incident ne relève finalement pas de l'obligation de notification NIS 2."
          placeholder="Ex : erreur de qualification, portée réévaluée…"
          confirmLabel="Déqualifier"
          onConfirm={handleUnqualify}
          onClose={() => setActionModal(null)}
        />
      )}
      {MILESTONES.includes(actionModal) && (
        <AnnotationModal
          title={`Marquer « ${MILESTONE_LABELS[actionModal]} » comme envoyé`} color={MODULE_COLOR}
          subtitle={incident.title}
          helpText="Confirme que cette notification a réellement été envoyée hors application (ex. au CERT-FR/ANSSI). Ce jalon ne pourra plus être modifié ensuite."
          placeholder="Référence, canal d'envoi… (optionnel)"
          confirmLabel="Marquer envoyé"
          noteRequired={false}
          onConfirm={handleMilestoneSent}
          onClose={() => setActionModal(null)}
        />
      )}
      {actionModal === 'note' && (
        <AnnotationModal
          title="Ajouter une note" color="#8b949e"
          subtitle={incident.title}
          helpText="Note libre ajoutée à la chronologie de l'incident."
          placeholder="…"
          confirmLabel="Ajouter"
          onConfirm={handleNote}
          onClose={() => setActionModal(null)}
        />
      )}
      {actionModal === 'escalate' && (
        <EscalateToCrisisModal
          incident={incident}
          onEscalated={handleEscalated}
          onClose={() => setActionModal(null)}
        />
      )}
      {showDeleteConfirm && (
        <ConfirmModal
          title="Supprimer cet incident ?"
          message={<>Supprimer définitivement « <strong>{incident.title}</strong> » ? Sa chronologie sera aussi effacée. Cette action est irréversible.</>}
          confirmLabel="Supprimer"
          onConfirm={confirmDelete}
          onClose={() => setShowDeleteConfirm(false)}
        />
      )}
      {viewMilestone && (() => {
        const sentEntry = entries.find(e => e.event_type === 'milestone_sent' && e.meta?.milestone === viewMilestone)
        return (
          <MilestoneDetailModal
            title={MILESTONE_LABELS[viewMilestone]}
            subtitle={incident.title}
            date={sentEntry?.occurred_at}
            author={sentEntry?.author}
            text={sentEntry?.notes}
            onClose={() => setViewMilestone(null)}
          />
        )
      })()}
    </>
  )
}
