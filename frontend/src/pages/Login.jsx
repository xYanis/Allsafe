import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext.jsx'
import PasswordInput from '../components/PasswordInput.jsx'
import { CbrLogoTile } from '../components/CbrMark.jsx'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    if (submitting) return
    setSubmitting(true)
    setError('')
    try {
      await login(email.trim(), password)
      navigate('/', { replace: true, state: { justLoggedIn: true } })
    } catch (err) {
      // Message générique voulu côté serveur (pas d'énumération de comptes) —
      // le 429 (verrou anti-bruteforce) mérite son propre message.
      setError(err?.response?.status === 429
        ? 'Trop de tentatives — réessayez dans quelques minutes.'
        : (err?.response?.data?.detail || 'Email ou mot de passe incorrect.'))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="relative min-h-screen flex flex-col items-center justify-center p-6 overflow-hidden" style={{ background: 'var(--bg-app)' }}>
      <div className="hero-grid hero-grid-boot" />
      <div className="home-glow" />

      <div className="relative z-10 flex flex-col items-center text-center mb-6">
        <div className="relative mb-3">
          <span className="brand-ring" aria-hidden="true" />
          <CbrLogoTile size={56} rounded={18} className="brand-pop" />
        </div>
        <h1 className="brand-text-shimmer text-3xl font-bold tracking-tight" style={{
          fontFamily: 'var(--font-mono)', animationDelay: '260ms',
        }}>Allsafe</h1>
      </div>

      {/* Plus de cadre/carte autour des champs — ils reposent directement sur le fond de
          page, chacun ne se distinguant que par son propre fond (déjà présent sur les
          inputs). Séquence volontairement plus lente/espacée qu'ailleurs dans l'app (cf.
          emil-design-eng § fréquence — le login est une occasion rare, une fois par
          session, elle peut se permettre d'être vue plutôt que juste perçue) : logo →
          titre, PUIS une vraie pause avant que les champs n'arrivent un par un, bouton
          en dernier avec un petit rebond — la CTA de l'écran mérite plus de présence
          qu'un simple fondu. */}
      <form onSubmit={handleSubmit} className="relative z-10 w-full max-w-sm space-y-4">
        <div className="login-enter" style={{ animationDelay: '900ms' }}>
          <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Email</label>
          <input autoFocus required type="email" value={email} onChange={e => setEmail(e.target.value)}
            className="w-full text-sm rounded-lg px-3 py-2 outline-none"
            style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
        </div>
        <div className="login-enter" style={{ animationDelay: '1100ms' }}>
          <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Mot de passe</label>
          <PasswordInput value={password} onChange={e => setPassword(e.target.value)} />
        </div>
        {/* `key={error}` : force le remontage à chaque nouvelle tentative ratée pour
            rejouer le tremblement même si le message d'erreur reste identique. */}
        {error && <p key={error} className="login-error text-xs" style={{ color: '#f85149' }}>{error}</p>}
        <button type="submit" disabled={submitting}
          className="login-button-enter w-full text-sm px-3 py-2.5 rounded-lg font-medium disabled:opacity-50 transition-colors"
          style={{ background: 'color-mix(in srgb, var(--brand) 15%, transparent)', color: 'var(--brand)', border: '1px solid color-mix(in srgb, var(--brand) 35%, transparent)', animationDelay: '1350ms' }}
        >{submitting ? 'Connexion…' : 'Se connecter'}</button>
      </form>
    </div>
  )
}
