import { useState } from 'react'
import { MODULES } from '../constants/modules.js'
import { SERVICE_COLOR_PALETTE } from '../constants/serviceColors.js'

const MODULE_COLOR = MODULES.documentation.color

// Palette fixe d'emojis pour les thèmes de notes — cohérent avec le reste de l'app
// (emojis dans les badges/boutons, cf. CLAUDE.md § Style), pas une palette d'icônes
// SVG à clés comme ServiceIcon.jsx : overkill pour un registre personnel ouvert.
const THEME_EMOJI_PALETTE = ['📁', '🛡️', '🌐', '💻', '🧠', '📚', '🔐', '⚙️', '📊', '🧪', '☁️', '🐧']

// Création/édition d'un thème de notes (Cybersécurité, Réseau, Système, IA... en seed,
// registre ouvert) — cf. Notes.jsx.
export default function NoteThemeFormModal({ initial, onConfirm, onClose }) {
  const [name, setName] = useState(initial?.name || '')
  const [color, setColor] = useState(initial?.color || SERVICE_COLOR_PALETTE[0])
  const [icon, setIcon] = useState(initial?.icon || THEME_EMOJI_PALETTE[0])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const isEdit = Boolean(initial?.id)

  async function confirm() {
    if (!name.trim() || saving) return
    setSaving(true)
    setError('')
    try {
      await onConfirm({ name: name.trim(), color, icon })
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'enregistrer ce thème.")
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: MODULE_COLOR }}>{isEdit ? 'Modifier le thème' : 'Ajouter un thème'}</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-3">
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Nom</label>
            <input autoFocus value={name} onChange={e => setName(e.target.value)}
              placeholder="Ex : Cryptographie"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Couleur</label>
            <div className="flex flex-wrap gap-2">
              {SERVICE_COLOR_PALETTE.map(c => (
                <button key={c} type="button" onClick={() => setColor(c)}
                  className="w-8 h-8 rounded-full flex-shrink-0 transition-transform"
                  style={{ background: c, transform: color === c ? 'scale(1.15)' : 'scale(1)', border: color === c ? '2px solid var(--text-primary)' : '2px solid transparent' }}
                  aria-label={c} />
              ))}
            </div>
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Icône</label>
            <div className="flex flex-wrap gap-2">
              {THEME_EMOJI_PALETTE.map(e => (
                <button key={e} type="button" onClick={() => setIcon(e)}
                  className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 text-base transition-transform"
                  style={{
                    background: icon === e ? `${color}26` : 'var(--bg-secondary)',
                    border: icon === e ? `1px solid ${color}59` : '1px solid var(--border)',
                    transform: icon === e ? 'scale(1.1)' : 'scale(1)',
                  }}
                  aria-label={e}>
                  {e}
                </button>
              ))}
            </div>
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
            >{saving ? 'Enregistrement…' : (isEdit ? 'Enregistrer' : 'Ajouter')}</button>
          </div>
        </div>
      </div>
    </div>
  )
}
