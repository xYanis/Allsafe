import { useState } from 'react'

const EYE_OPEN = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
const EYE_OFF = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>

// Champ mot de passe avec bascule afficher/masquer — même charpente visuelle que
// les autres inputs de l'app (AnalystFormModal.jsx, etc.), factorisé dès la 2e
// utilisation (Login, changement de mot de passe forcé, création de compte).
export default function PasswordInput({ value, onChange, minLength, autoFocus, placeholder, id }) {
  const [visible, setVisible] = useState(false)

  return (
    <div className="relative">
      <input
        id={id}
        autoFocus={autoFocus}
        required
        type={visible ? 'text' : 'password'}
        minLength={minLength}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        className="w-full text-sm rounded-lg pl-3 pr-10 py-2 outline-none"
        style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
      />
      <button type="button" onClick={() => setVisible(v => !v)}
        title={visible ? 'Masquer le mot de passe' : 'Afficher le mot de passe'}
        className="absolute right-0 top-0 h-full px-2.5 flex items-center"
        style={{ color: 'var(--text-muted)' }}
        tabIndex={-1}
      >
        {visible ? EYE_OFF : EYE_OPEN}
      </button>
    </div>
  )
}
