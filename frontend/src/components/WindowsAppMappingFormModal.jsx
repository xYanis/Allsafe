import { useState } from 'react'
import { MODULES } from '../constants/modules.js'

const MODULE_COLOR = MODULES.parametres.color

// Création/édition d'une correspondance nom d'application Windows -> produit CPE
// (cf. backend/models.py::WindowsAppMapping) — alimente le badge vulnérabilité sur les
// applications installées côté Windows, là où les paquets Linux se dérivent par
// convention de nommage (Debian/RPM).
export default function WindowsAppMappingFormModal({ initial, onConfirm, onClose }) {
  const [pattern, setPattern] = useState(initial?.pattern || '')
  const [cpeProduct, setCpeProduct] = useState(initial?.cpe_product || '')
  const [cpeVendor, setCpeVendor] = useState(initial?.cpe_vendor || '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const isEdit = Boolean(initial?.id)

  async function confirm() {
    if (!pattern.trim() || !cpeProduct.trim() || saving) return
    setSaving(true)
    setError('')
    try {
      await onConfirm({
        pattern: pattern.trim(),
        cpe_product: cpeProduct.trim(),
        cpe_vendor: cpeVendor.trim() || null,
      })
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'enregistrer cette correspondance.")
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: MODULE_COLOR }}>{isEdit ? 'Modifier la correspondance' : 'Ajouter une correspondance'}</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-3">
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Motif (sous-chaîne du nom affiché)</label>
            <input autoFocus value={pattern} onChange={e => setPattern(e.target.value)}
              placeholder="Ex : putty"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
            <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
              Recherché sans tenir compte de la casse dans le nom d'application installée (ex : « PuTTY release 0.81 (64-bit) »). Survit aux changements de version.
            </p>
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Produit CPE</label>
            <input value={cpeProduct} onChange={e => setCpeProduct(e.target.value)}
              placeholder="Ex : putty"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Vendeur CPE (optionnel, informatif)</label>
            <input value={cpeVendor} onChange={e => setCpeVendor(e.target.value)}
              placeholder="Ex : simon_tatham"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button onClick={confirm} disabled={!pattern.trim() || !cpeProduct.trim() || saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }}
            >{saving ? 'Enregistrement…' : (isEdit ? 'Enregistrer' : 'Ajouter')}</button>
          </div>
        </div>
      </div>
    </div>
  )
}
