import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext.jsx'
import PasswordInput from '../components/PasswordInput.jsx'
import { CbrLogoTile } from '../components/CbrMark.jsx'

// Arène de fuite du bouton, en px autour de sa position naturelle. Pas de borne
// haute fixe : la zone interdite au-dessus (les champs + le message d'erreur
// éventuel) est mesurée en direct via fieldsRef, cf. flee() — un chiffre codé en
// dur se serait décalé dès que l'erreur apparaît/disparaît et change la hauteur
// du bloc au-dessus du bouton.
const DODGE_RANGE = { minX: -150, maxX: 150, maxY: 140 }
const DODGE_TRIGGER_DISTANCE = 95
// Nettement plus grand que DODGE_TRIGGER_DISTANCE (hystérésis) : sans cet écart,
// une souris qui s'attarde pile à la frontière ferait fuir/revenir le bouton en
// boucle à chaque micro-mouvement.
const DODGE_RETURN_DISTANCE = 170
const FIELDS_MARGIN = 16

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const canSubmit = email.trim() && password
  const buttonRef = useRef(null)
  const fieldsRef = useRef(null)
  const [dodge, setDodge] = useState({ x: 0, y: 0, rot: 0 })
  const fleeing = !!(dodge.x || dodge.y || dodge.rot)

  // "Runaway login" : tant qu'email ou mot de passe manque, le bouton s'écarte du
  // curseur avant qu'il ne puisse cliquer, avec une petite bascule qui accentue
  // l'effet "sursaut". Dès que les deux sont remplis, il se fige et redescend en
  // place (transition CSS sur le style, cf. plus bas) — pas de piège une fois
  // qu'il y a vraiment quelque chose à soumettre. Respecte prefers-reduced-motion
  // (même convention que .login-enter dans index.css) et ne joue jamais sur le
  // focus clavier, seulement sur la souris.
  useEffect(() => {
    if (canSubmit) {
      setDodge({ x: 0, y: 0, rot: 0 })
      return
    }
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return

    function flee(clientX, clientY) {
      const btn = buttonRef.current
      if (!btn) return
      setDodge(prev => {
        const rect = btn.getBoundingClientRect()
        const centerX = rect.left + rect.width / 2
        const centerY = rect.top + rect.height / 2
        const angle = Math.atan2(centerY - clientY, centerX - clientX) + (Math.random() - 0.5) * 0.9
        const jump = 100 + Math.random() * 80
        const naturalLeft = rect.left - prev.x
        const naturalTop = rect.top - prev.y
        const margin = 12
        let nx = prev.x + Math.cos(angle) * jump
        let ny = prev.y + Math.sin(angle) * jump
        nx = Math.min(Math.max(nx, DODGE_RANGE.minX), DODGE_RANGE.maxX)
        ny = Math.min(ny, DODGE_RANGE.maxY)
        nx = Math.min(Math.max(nx, margin - naturalLeft), window.innerWidth - margin - rect.width - naturalLeft)
        ny = Math.min(ny, window.innerHeight - margin - rect.height - naturalTop)
        // Jamais au-dessus des champs (email/mot de passe/erreur) — bord mesuré en
        // direct, pas une constante, cf. commentaire DODGE_RANGE plus haut.
        const fieldsBottom = fieldsRef.current ? fieldsRef.current.getBoundingClientRect().bottom : naturalTop
        ny = Math.max(ny, fieldsBottom + FIELDS_MARGIN - naturalTop)
        const rot = Math.max(-14, Math.min(14, (nx - prev.x) / 7))
        return { x: nx, y: ny, rot }
      })
    }

    function handleMouseMove(e) {
      const btn = buttonRef.current
      if (!btn) return
      const rect = btn.getBoundingClientRect()
      const dist = Math.hypot(rect.left + rect.width / 2 - e.clientX, rect.top + rect.height / 2 - e.clientY)
      if (dist < DODGE_TRIGGER_DISTANCE) {
        flee(e.clientX, e.clientY)
      } else if (dist > DODGE_RETURN_DISTANCE) {
        // Souris repartie loin : le bouton revient à sa place plutôt que de rester
        // planté où il a atterri au dernier saut.
        setDodge(prev => (prev.x || prev.y || prev.rot) ? { x: 0, y: 0, rot: 0 } : prev)
      }
    }

    window.addEventListener('mousemove', handleMouseMove)
    return () => window.removeEventListener('mousemove', handleMouseMove)
  }, [canSubmit])

  async function handleSubmit(e) {
    e.preventDefault()
    if (submitting || !canSubmit) return
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
          {/* Rotation périodique désormais portée par CbrLogoTile lui-même
              (.cbr-logo-spin, cf. CbrMark.jsx) — plus une classe posée ici. */}
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
      <form onSubmit={handleSubmit} className="relative z-10 w-full max-w-sm flex flex-col">
        {/* fieldsRef délimite la zone interdite au bouton fuyant (cf. flee() plus haut) :
            mesurée en direct plutôt que codée en dur, pour suivre automatiquement
            l'apparition du message d'erreur. `gap` (pas `space-y-4`, sujet au margin
            collapsing) pour garantir un espacement rigoureusement identique entre
            email/mot de passe/erreur. */}
        <div ref={fieldsRef} className="flex flex-col gap-4">
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
        </div>
        {/* Wrapper séparé pour l'animation d'entrée CSS (`login-button-enter`, anime déjà
            `transform` en fill-mode both) : une animation CSS avec fill "both" possède la
            propriété `transform` en continu et écraserait silencieusement le translate de
            fuite s'il était posé sur le même élément que le bouton. `mt-7` volontairement
            plus large que le `gap-4` entre les champs — le bouton respire davantage,
            demande explicite, sans devoir égaler l'espacement des champs entre eux. */}
        <div className="login-button-enter mt-7" style={{ animationDelay: '1350ms' }}>
          <button type="submit" ref={buttonRef} disabled={submitting}
            className="w-full text-sm px-3 py-2.5 rounded-lg font-medium disabled:opacity-50"
            style={{
              background: 'color-mix(in srgb, var(--brand) 15%, transparent)', color: 'var(--brand)',
              border: '1px solid color-mix(in srgb, var(--brand) 35%, transparent)',
              transform: fleeing ? `translate(${dodge.x}px, ${dodge.y}px) rotate(${dodge.rot}deg)` : undefined,
              boxShadow: fleeing ? '0 14px 28px -10px color-mix(in srgb, var(--brand) 55%, transparent)' : 'none',
              transitionProperty: 'transform, box-shadow, background-color',
              // Sursaut = rapide + overshoot ; retour au calme = un peu plus lent et
              // posé, sans rebond, pour bien distinguer les deux mouvements.
              transitionDuration: fleeing ? '340ms' : '280ms',
              transitionTimingFunction: fleeing ? 'cubic-bezier(.34,1.65,.4,1)' : 'cubic-bezier(.22,1,.36,1)',
              position: 'relative',
            }}
          >{submitting ? 'Connexion…' : 'Se connecter'}</button>
        </div>
      </form>
    </div>
  )
}
