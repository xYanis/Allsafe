import { useState } from 'react'
import { COUNTRIES } from '../utils/countries.js'
import { hexToRgba } from '../utils/color.js'

// Modale d'ajout d'une source RSS/Atom personnalisée — partagée entre Fuite
// de données et Veille technologique. `category` ("leak" | "general") est
// fixé par l'appelant (pas un choix utilisateur dans le formulaire) : il
// détermine où la source apparaîtra ensuite, cf. GET /watch/leak-sources.
export default function AddSourceModal({ category, accent = '#a371f7', onConfirm, onClose }) {
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [feedType, setFeedType] = useState('rss')
  const [country, setCountry] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function confirm() {
    if (!name.trim() || !url.trim() || saving) return
    setSaving(true)
    setError('')
    try {
      await onConfirm({ name: name.trim(), url: url.trim(), feed_type: feedType, category, country: country || undefined })
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'ajouter cette source.")
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: accent }}>Ajouter une source</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-3">
          <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
            Un flux RSS ou Atom. Il sera collecté avec les autres sources à chaque synchronisation.
          </p>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Nom</label>
            <input
              autoFocus value={name} onChange={e => setName(e.target.value)}
              placeholder="Ex : Mon flux de veille"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
            />
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>URL du flux RSS/Atom</label>
            <input
              value={url} onChange={e => setUrl(e.target.value)}
              placeholder="https://exemple.com/feed.xml"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
            />
          </div>
          <div className="flex gap-3">
            <div className="flex-1">
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Format</label>
              <select
                value={feedType} onChange={e => setFeedType(e.target.value)}
                className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
              >
                <option value="rss">RSS</option>
                <option value="atom">Atom</option>
              </select>
            </div>
            <div className="flex-1">
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Pays par défaut</label>
              <select
                value={country} onChange={e => setCountry(e.target.value)}
                className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
              >
                <option value="">— Aucun —</option>
                {COUNTRIES.map(c => <option key={c.code} value={c.code}>{c.label}</option>)}
              </select>
            </div>
          </div>
          {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button onClick={confirm} disabled={!name.trim() || !url.trim() || saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: hexToRgba(accent, 0.15), color: accent, border: `1px solid ${hexToRgba(accent, 0.35)}` }}
            >{saving ? 'Ajout…' : 'Ajouter'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}
