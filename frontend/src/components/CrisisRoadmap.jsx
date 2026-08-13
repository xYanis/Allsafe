import { useEffect, useState } from 'react'
import { CRISIS_STEPS } from '../constants/crisisPlaybook.js'
import { crisisContacts, createCrisisContact, updateCrisis, organizationRoles } from '../api/client.js'
import { ContactRow, ScopeTag } from './IncidentRoadmap.jsx'
import AddCrisisContactModal from './AddCrisisContactModal.jsx'
import { MODULES } from '../constants/modules.js'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { anonymizeRoleHolder } from '../utils/fakeData.js'

const MODULE_COLOR = MODULES.incidents.color

// Roadmap d'une crise : plan d'action générique (pas de branchement par catégorie,
// contrairement à IncidentRoadmap.jsx — une crise n'en a pas) et annuaire des intervenants
// de mobilisation interne à prévenir. Même principe et mêmes garde-fous que côté incident :
// simple aide-mémoire pour l'analyste, l'app n'envoie jamais rien elle-même.
function stepsMap(steps) {
  const m = new Map()
  ;(steps || []).forEach(s => m.set(s.index, { by: s.by, at: s.at }))
  return m
}

export default function CrisisRoadmap({ crisis, onUpdated }) {
  const { names: ANALYSTS } = useAnalysts()
  const { isAnonymous } = usePresentation()
  const [checked, setChecked] = useState(() => stepsMap(crisis.completed_crisis_steps))
  const [customContacts, setCustomContacts] = useState([])
  const [roles, setRoles] = useState([])
  const [showAddContact, setShowAddContact] = useState(false)
  const [actor, setActor] = useState('')
  const [actorError, setActorError] = useState(false)

  useEffect(() => {
    setChecked(stepsMap(crisis.completed_crisis_steps))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [crisis.id])

  function loadContacts() {
    crisisContacts().then(r => setCustomContacts(r.data.items)).catch(() => {})
  }
  useEffect(() => { loadContacts() }, [])
  useEffect(() => {
    organizationRoles().then(r => setRoles(r.data.items || [])).catch(() => {})
  }, [])

  async function toggleStep(i) {
    const next = new Map(checked)
    if (next.has(i)) {
      next.delete(i)
    } else {
      if (!actor) { setActorError(true); return }
      next.set(i, { by: actor, at: new Date().toISOString() })
    }
    setActorError(false)
    setChecked(next)
    try {
      const payload = [...next.entries()].map(([index, v]) => ({ index, by: v.by, at: v.at }))
      const { data: fresh } = await updateCrisis(crisis.id, { completed_crisis_steps: payload })
      onUpdated?.(fresh)
    } catch {
      setChecked(checked) // échec réseau : revient à l'état précédent
    }
  }

  async function handleAddContact(payload) {
    await createCrisisContact(payload)
    setShowAddContact(false)
    loadContacts()
  }

  // Registre « Rôles » (organigramme, Administration) — poste réel -> personne réelle -> email,
  // mappé à la forme attendue par ContactRow (name/role/email). Anonymisé en mode Présentation :
  // ce registre contient des noms réels, contrairement aux intervenants ad-hoc (CrisisContact)
  // qui restent volontairement du texte libre saisi par l'utilisateur (pas de garantie qu'il
  // s'agisse d'une personne nominative réelle, donc non anonymisés — même logique que les
  // contacts d'incident déjà en place).
  const roleContacts = roles.map(r => {
    const mapped = { id: `role-${r.id}`, name: r.name, role: r.position, email: r.email }
    return isAnonymous ? anonymizeRoleHolder(mapped) : mapped
  })
  const contacts = [...roleContacts, ...customContacts]

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
          Ce qu'il reste à mener pour piloter cette crise, dans l'ordre — simple aide-mémoire,
          cocher ici n'envoie ni n'atteste rien (cf. journal ci-dessous).
        </p>
        {actorError && (
          <p className="text-xs mb-2" style={{ color: '#f85149' }}>Sélectionnez qui réalise l'action avant de cocher une étape.</p>
        )}
        <div className="space-y-1.5">
          {CRISIS_STEPS.map((s, i) => {
            const done = checked.get(i)
            return (
              <label key={i} className="flex items-start gap-2.5 text-sm cursor-pointer" style={{ color: done ? 'var(--text-faint)' : 'var(--text-secondary)' }}>
                <input type="checkbox" checked={Boolean(done)} onChange={() => toggleStep(i)}
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
          <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Intervenants à prévenir</p>
          <button onClick={() => setShowAddContact(true)} className="text-xs" style={{ color: MODULE_COLOR }}>+ Ajouter un intervenant</button>
        </div>
        <div className="space-y-2">
          {contacts.map(c => <ContactRow key={c.id} contact={c} />)}
        </div>
      </div>

      {showAddContact && (
        <AddCrisisContactModal onConfirm={handleAddContact} onClose={() => setShowAddContact(false)} />
      )}
    </div>
  )
}
