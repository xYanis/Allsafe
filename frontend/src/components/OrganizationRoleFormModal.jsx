import { useEffect, useState } from 'react'
import { services as fetchServices, organizationRoles as fetchOrganizationRoles } from '../api/client.js'
import { MODULES } from '../constants/modules.js'
import ServiceIcon from './ServiceIcon.jsx'

const MODULE_COLOR = MODULES.parametres.color

// Postes suggérés (datalist, pas une liste fermée) — même principe que le champ Rôle de la
// cellule de crise (CrisisActionModal.jsx::SUGGESTED_ROLES) : une organisation peut avoir des
// postes non prévus d'avance, donc texte libre avec suggestions plutôt qu'un select bloquant.
const SUGGESTED_POSITIONS = ['DG', 'DAF', 'DRH', 'DSI', 'RSSI', 'REI', 'DPO', 'Communication / RP', 'Juridique', 'RH', 'Assureur cyber']

// Création/édition d'une entrée du registre « Rôles » (organigramme) — poste -> personne -> email,
// utilisé par la Gestion de crise et les Incidents pour savoir à qui se référer selon le poste.
// Le Service (RH, DSI, Juridique, Direction... Administration > onglet Services) est optionnel,
// juste sous le poste — regroupe visuellement les rôles par couleur dans la grille de cartes.
export default function OrganizationRoleFormModal({ initial, onConfirm, onClose }) {
  const [position, setPosition] = useState(initial?.position || '')
  const [serviceId, setServiceId] = useState(initial?.service_id || '')
  const [reportsToId, setReportsToId] = useState(initial?.reports_to_id || '')
  const [name, setName] = useState(initial?.name || '')
  const [email, setEmail] = useState(initial?.email || '')
  const [svcList, setSvcList] = useState([])
  const [roleList, setRoleList] = useState([])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchServices().then(r => setSvcList(r.data.items || [])).catch(() => {})
    fetchOrganizationRoles().then(r => setRoleList(r.data.items || [])).catch(() => {})
  }, [])

  const isEdit = Boolean(initial?.id)
  // Un poste ne peut pas se désigner lui-même comme supérieur — les autres cas de boucle
  // (A -> B -> A) sont bloqués côté API (_validate_reports_to), pas reproductibles ici sans
  // recharger toute la chaîne à chaque frappe.
  const managerOptions = roleList.filter(r => r.id !== initial?.id)
  // Postes déjà tapés dans le registre, en plus des suggestions codées en dur — sans ça, un
  // poste inédit saisi une première fois n'était jamais repropose ensuite (uniquement les 11
  // valeurs fixes de SUGGESTED_POSITIONS). Alimente seulement le <datalist> (pas de pastilles
  // visibles, ça prenait trop de place) : Poste reste du texte libre, jamais une liste fermée.
  const knownPositions = Array.from(new Set([...SUGGESTED_POSITIONS, ...roleList.map(r => r.position).filter(Boolean)]))

  async function confirm() {
    if (!position.trim() || !name.trim() || saving) return
    setSaving(true)
    setError('')
    try {
      const payload = { position: position.trim(), name: name.trim(), email: email.trim() || null }
      if (serviceId) payload.service_id = serviceId
      else if (isEdit) payload.clear_service = true
      if (reportsToId) payload.reports_to_id = reportsToId
      else if (isEdit) payload.clear_reports_to = true
      await onConfirm(payload)
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'enregistrer ce rôle.")
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: MODULE_COLOR }}>{isEdit ? 'Modifier le rôle' : 'Ajouter un rôle'}</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-3">
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Poste</label>
            <input autoFocus list="organization-role-positions" value={position} onChange={e => setPosition(e.target.value)}
              placeholder="Ex : RSSI"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
            <datalist id="organization-role-positions">
              {knownPositions.map(p => <option key={p} value={p} />)}
            </datalist>
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Service (optionnel)</label>
            {/* Pastilles colorées (couleur + icône propres à chaque service, cf. Administration >
                Services) plutôt qu'un <select> natif au texte plat — on choisit visuellement le
                même repère couleur que partout ailleurs (cartes Rôles, onglet Services). */}
            <div className="flex flex-wrap gap-1.5">
              <button type="button" onClick={() => setServiceId('')}
                className="text-xs px-2.5 py-1.5 rounded-full font-medium transition-transform"
                style={{
                  background: serviceId === '' ? 'var(--bg-card)' : 'var(--bg-secondary)',
                  color: serviceId === '' ? 'var(--text-primary)' : 'var(--text-muted)',
                  border: `1px solid ${serviceId === '' ? 'var(--text-faint)' : 'var(--border)'}`,
                  transform: serviceId === '' ? 'scale(1.04)' : 'scale(1)',
                }}>Aucun</button>
              {svcList.map(s => (
                <button key={s.id} type="button" onClick={() => setServiceId(s.id)}
                  className="flex items-center gap-1.5 text-xs pl-2 pr-2.5 py-1.5 rounded-full font-medium transition-transform"
                  style={{
                    background: `${s.color}${serviceId === s.id ? '33' : '1a'}`,
                    color: s.color,
                    border: `1px solid ${s.color}${serviceId === s.id ? '99' : '4d'}`,
                    transform: serviceId === s.id ? 'scale(1.04)' : 'scale(1)',
                  }}>
                  <ServiceIcon icon={s.icon} size={13} />
                  {s.name}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Rapporte à (optionnel)</label>
            <select value={reportsToId} onChange={e => setReportsToId(e.target.value)}
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>
              <option value="">Personne (sommet de la hiérarchie)</option>
              {managerOptions.map(r => <option key={r.id} value={r.id}>{r.position} — {r.name}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Nom</label>
            <input value={name} onChange={e => setName(e.target.value)}
              placeholder="Ex : Michel Lacroix"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Email (optionnel)</label>
            <input value={email} onChange={e => setEmail(e.target.value)}
              placeholder="michel.lacroix@exemple.fr"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button onClick={confirm} disabled={!position.trim() || !name.trim() || saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }}
            >{saving ? 'Enregistrement…' : (isEdit ? 'Enregistrer' : 'Ajouter')}</button>
          </div>
        </div>
      </div>
    </div>
  )
}
