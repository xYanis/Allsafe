import { useEffect, useState } from 'react'
import { NATIVE_CONTACTS, RESPONSE_STEPS, contactsForCategory } from '../constants/incidentPlaybooks.js'
import { notificationContacts, createNotificationContact, updateIncident, organizationRoles } from '../api/client.js'
import AddContactModal from './AddContactModal.jsx'
import { MODULES } from '../constants/modules.js'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { anonymizeRoleHolder } from '../utils/fakeData.js'

const MODULE_COLOR = MODULES.incidents.color
const SCOPE_STYLES = {
  interne: { background: 'rgba(88,166,255,0.12)', color: '#58a6ff' },
  externe: { background: 'rgba(251,143,68,0.12)', color: '#fb8f44' },
}
// Exporté : réutilisé tel quel par CrisisRoadmap.jsx.
export function ScopeTag({ scope }) {
  return (
    <span className="text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded flex-shrink-0"
      style={SCOPE_STYLES[scope]}>
      {scope === 'interne' ? 'Interne' : 'Externe'}
    </span>
  )
}

// Exporté : réutilisé tel quel par CrisisRoadmap.jsx (déjà générique — name/role/email/
// phone/website_url, sans rien de spécifique aux incidents).
export function ContactRow({ contact }) {
  return (
    <div className="rounded-lg px-3 py-2.5" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{contact.name}</p>
          {contact.role && <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{contact.role}</p>}
        </div>
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2 text-xs">
        {contact.email && (
          <a href={`mailto:${contact.email}`} className="hover:underline" style={{ color: MODULE_COLOR }}>✉ {contact.email}</a>
        )}
        {contact.phone && <span style={{ color: 'var(--text-secondary)' }}>☎ {contact.phone}</span>}
        {contact.portal_url && (
          <a href={contact.portal_url} target="_blank" rel="noopener noreferrer" className="hover:underline" style={{ color: MODULE_COLOR }}>Portail de déclaration ↗</a>
        )}
        {contact.website_url && (
          <a href={contact.website_url} target="_blank" rel="noopener noreferrer" className="hover:underline" style={{ color: 'var(--text-muted)' }}>Site ↗</a>
        )}
      </div>
    </div>
  )
}

// Roadmap contextuelle à un incident : checklist de traitement chronologique (par catégorie)
// et annuaire des organismes/contacts à prévenir. Purement une aide pour l'analyste — l'app
// n'envoie jamais rien elle-même (cf. services/nis2_deadlines.py, même garde-fou).
function stepsMap(steps) {
  const m = new Map()
  ;(steps || []).forEach(s => m.set(s.index, { by: s.by, at: s.at }))
  return m
}

export default function IncidentRoadmap({ incident, onUpdated }) {
  const { names: ANALYSTS } = useAnalysts()
  const { isAnonymous } = usePresentation()
  // Initialisé depuis l'incident (persisté en base, cf. completed_response_steps) —
  // pas un état purement local : la progression ne doit pas se perdre en refermant
  // la fiche. Resynchronisé si on change d'incident (changement de `incident.id`).
  const [checkedResponse, setCheckedResponse] = useState(() => stepsMap(incident.completed_response_steps))
  const [personalData, setPersonalData] = useState(false)
  const [customContacts, setCustomContacts] = useState([])
  const [roles, setRoles] = useState([])
  const [showAddContact, setShowAddContact] = useState(false)
  // Qui coche — obligatoire avant de cocher une étape.
  const [actor, setActor] = useState('')
  const [actorError, setActorError] = useState(false)

  useEffect(() => {
    setCheckedResponse(stepsMap(incident.completed_response_steps))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incident.id])

  function loadContacts() {
    notificationContacts().then(r => setCustomContacts(r.data.items)).catch(() => {})
  }
  useEffect(() => { loadContacts() }, [])
  useEffect(() => {
    organizationRoles().then(r => setRoles(r.data.items || [])).catch(() => {})
  }, [])

  async function toggleResponseStep(i) {
    const next = new Map(checkedResponse)
    if (next.has(i)) {
      next.delete(i)
    } else {
      if (!actor) { setActorError(true); return }
      next.set(i, { by: actor, at: new Date().toISOString() })
    }
    setActorError(false)
    setCheckedResponse(next)
    try {
      const payload = [...next.entries()].map(([index, v]) => ({ index, by: v.by, at: v.at }))
      const { data: fresh } = await updateIncident(incident.id, { completed_response_steps: payload })
      onUpdated?.(fresh)
    } catch {
      setCheckedResponse(checkedResponse) // échec réseau : revient à l'état précédent
    }
  }

  async function handleAddContact(payload) {
    await createNotificationContact(payload)
    setShowAddContact(false)
    loadContacts()
  }

  const responseSteps = RESPONSE_STEPS[incident.category] || RESPONSE_STEPS.other
  const contacts = contactsForCategory(incident.category, personalData, customContacts)
  const nativeIds = new Set(NATIVE_CONTACTS.map(c => c.id))
  // Registre « Rôles » (organigramme, Administration) — postes internes (RSSI, DPO...), en
  // complément des organismes externes ci-dessus. Contient des noms réels, anonymisé en mode
  // Présentation (cf. CrisisRoadmap.jsx, même logique).
  const roleContacts = roles.map(r => {
    const mapped = { id: `role-${r.id}`, name: r.name, role: r.position, email: r.email }
    return isAnonymous ? anonymizeRoleHolder(mapped) : mapped
  })

  return (
    <div className="space-y-4">
      <div>
        <div className="flex items-center justify-between mb-2 gap-3 flex-wrap">
          <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Plan d'action</p>
          <div className="flex items-center gap-1.5">
            <label className="text-xs" style={{ color: 'var(--text-faint)' }}>Réalisé par</label>
            <select value={actor} onChange={e => { setActor(e.target.value); setActorError(false) }}
              className="text-xs px-2 py-1 rounded outline-none"
              style={{ background: 'var(--bg-card)', border: `1px solid ${actorError ? '#f85149' : 'var(--border)'}`, color: 'var(--text-secondary)' }}>
              <option value="">Sélectionner…</option>
              {ANALYSTS.map(name => <option key={name} value={name}>{name}</option>)}
            </select>
          </div>
        </div>
        <p className="text-xs mb-2.5" style={{ color: 'var(--text-faint)' }}>
          Ce qu'il reste à mener pour traiter cet incident, dans l'ordre — simple aide-mémoire,
          cocher ici n'envoie ni n'atteste rien (cf. qualification et jalons NIS 2 ci-dessous).
        </p>
        {actorError && (
          <p className="text-xs mb-2" style={{ color: '#f85149' }}>Sélectionnez qui réalise l'action avant de cocher une étape.</p>
        )}
        <div className="space-y-1.5">
          {responseSteps.map((s, i) => {
            const done = checkedResponse.get(i)
            return (
              <label key={i} className="flex items-start gap-2.5 text-sm cursor-pointer" style={{ color: done ? 'var(--text-faint)' : 'var(--text-secondary)' }}>
                <input type="checkbox" checked={Boolean(done)} onChange={() => toggleResponseStep(i)}
                  className="mt-0.5 w-3.5 h-3.5 flex-shrink-0" style={{ accentColor: MODULE_COLOR }} />
                <span className="flex items-start gap-2 flex-1">
                  <span className="text-xs font-semibold flex-shrink-0" style={{ color: 'var(--text-faint)', minWidth: '1.1rem' }}>{i + 1}.</span>
                  <span className="flex-1">
                    <span style={{ textDecoration: done ? 'line-through' : 'none' }}>{s.text}</span>
                    {done && (
                      <span className="block text-[11px] mt-0.5 not-italic" style={{ color: 'var(--text-faint)' }}>
                        ✓ {done.by}{done.at ? ` — ${new Date(done.at).toLocaleDateString('fr-FR')}` : ''}
                      </span>
                    )}
                  </span>
                  <ScopeTag scope={s.scope} />
                </span>
              </label>
            )
          })}
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Qui contacter</p>
          <button onClick={() => setShowAddContact(true)} className="text-xs" style={{ color: MODULE_COLOR }}>+ Ajouter un contact</button>
        </div>

        <label className="flex items-center gap-2 text-xs mb-2.5 cursor-pointer" style={{ color: 'var(--text-secondary)' }}>
          <input type="checkbox" checked={personalData} onChange={e => setPersonalData(e.target.checked)}
            className="w-3.5 h-3.5" style={{ accentColor: MODULE_COLOR }} />
          Des données personnelles sont concernées
        </label>

        <div className="space-y-2">
          {contacts.map(c => <ContactRow key={c.id} contact={c} />)}
          {contacts.length === 0 && (
            <p className="text-xs" style={{ color: 'var(--text-faint)' }}>Aucun contact pour cette catégorie — ajoutez-en un ci-dessus.</p>
          )}
        </div>

        {contacts.some(c => nativeIds.has(c.id)) && (
          <p className="text-xs mt-2.5" style={{ color: 'var(--text-faint)' }}>
            Coordonnées des organismes officiels vérifiées le 29/07/2026 — à confirmer/compléter selon votre contexte.
          </p>
        )}

        {roleContacts.length > 0 && (
          <div className="mt-4">
            <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>Postes internes à contacter</p>
            <div className="space-y-2">
              {roleContacts.map(c => <ContactRow key={c.id} contact={c} />)}
            </div>
          </div>
        )}
      </div>

      {showAddContact && (
        <AddContactModal onConfirm={handleAddContact} onClose={() => setShowAddContact(false)} />
      )}
    </div>
  )
}
