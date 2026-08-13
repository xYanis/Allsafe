import { useState } from 'react'
import { MODULES } from '../constants/modules.js'

const MODULE_COLOR = MODULES.incidents.color

// Modale d'ajout d'un intervenant personnalisé pour la roadmap de crise (Direction dédiée,
// PR agency, avocat spécialisé...) — en complément des rôles-type codés en dur
// (constants/crisisPlaybook.js::NATIVE_CRISIS_CONTACTS). Calquée sur AddContactModal.jsx
// (incidents) mais sans sélecteur de catégories : une crise n'en a pas.
export default function AddCrisisContactModal({ onConfirm, onClose }) {
  const [name, setName] = useState('')
  const [role, setRole] = useState('')
  const [email, setEmail] = useState('')
  const [phone, setPhone] = useState('')
  const [website, setWebsite] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function confirm() {
    if (!name.trim() || saving) return
    setSaving(true)
    setError('')
    try {
      await onConfirm({
        name: name.trim(),
        role: role.trim() || null,
        email: email.trim() || null,
        phone: phone.trim() || null,
        website_url: website.trim() || null,
      })
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'ajouter cet intervenant.")
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: MODULE_COLOR }}>Ajouter un intervenant</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-3">
          <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
            Direction dédiée, agence de communication, avocat spécialisé... Apparaîtra dans les
            intervenants à prévenir de toute crise.
          </p>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Nom</label>
            <input autoFocus value={name} onChange={e => setName(e.target.value)}
              placeholder="Ex : Agence de communication de crise"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Rôle / quand le contacter</label>
            <input value={role} onChange={e => setRole(e.target.value)}
              placeholder="Ex : Communication externe en cas de crise médiatique"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Email</label>
              <input value={email} onChange={e => setEmail(e.target.value)} placeholder="contact@exemple.fr"
                className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
            </div>
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Téléphone</label>
              <input value={phone} onChange={e => setPhone(e.target.value)} placeholder="01 23 45 67 89"
                className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
            </div>
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Site web</label>
            <input value={website} onChange={e => setWebsite(e.target.value)} placeholder="https://exemple.fr"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button onClick={confirm} disabled={!name.trim() || saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }}
            >{saving ? 'Ajout…' : 'Ajouter'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}
