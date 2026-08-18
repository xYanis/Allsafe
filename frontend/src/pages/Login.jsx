import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext.jsx'
import { requestPasswordReset } from '../api/client.js'
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
// Effet "j'entre dans l'application" (18/08/2026, demande explicite) : délai entre la
// connexion validée et la navigation réelle, le temps de voir le formulaire repartir et
// le logo/Allsafe regrossir — cf. handleSubmit et phase 'entering'.
const ENTER_MS = 2800

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const canSubmit = email.trim() && password

  // « Mot de passe oublié » (18/08/2026) : pas d'infra SMTP dans ce projet (cf.
  // backend/routers/users.py) — la demande reste visible par un admin (Administration >
  // Utilisateurs) jusqu'à ce qu'il fixe lui-même un mot de passe provisoire, communiqué
  // hors application. `forgot-sent` volontairement distinct de `login` : le message de
  // confirmation reste affiché tant qu'on ne revient pas explicitement en arrière, pas de
  // retour automatique qui le ferait manquer.
  const [view, setView] = useState('login') // 'login' | 'forgot' | 'forgot-sent'
  const [forgotEmail, setForgotEmail] = useState('')
  const [forgotMessage, setForgotMessage] = useState('')
  const [forgotSubmitting, setForgotSubmitting] = useState(false)
  const [forgotError, setForgotError] = useState('')

  const buttonRef = useRef(null)
  const fieldsRef = useRef(null)
  const headerLogoRef = useRef(null)
  const [dodge, setDodge] = useState({ x: 0, y: 0, rot: 0 })
  const fleeing = !!(dodge.x || dodge.y || dodge.rot)
  // Position de départ du logo qui voyage vers le centre (18/08/2026, demande explicite) —
  // mesurée juste avant `setPhase('entering')` dans handleSubmit, cf. index.css::.login-logo-flip.
  const [flipOrigin, setFlipOrigin] = useState(null)

  // Splash d'ouverture (18/08/2026, demande explicite) : 'splash' (logo seul en
  // grand, centré) → 'exiting' (le splash s'efface EN MÊME TEMPS que l'en-tête +
  // le formulaire habituels se montent à leur place normale, cf. index.css §
  // Login.jsx) → 'docked' (splash retiré du DOM). Sauté directement en 'docked'
  // avec prefers-reduced-motion — pas de délai artificiel avant de pouvoir se
  // connecter pour qui a demandé moins de mouvement.
  // 'entering' (18/08/2026, demande explicite) : une fois les identifiants
  // validés, effet inverse — champs/bouton repartent (animations sortantes,
  // exception assumée à la convention "jamais d'animation de sortie" du reste
  // de l'app, cf. index.css § tokens : ce moment précis, unique par session,
  // mérite l'effet "on entre dans l'application") pendant que le même logo +
  // "Allsafe" du splash d'ouverture regrossit et se recentre. `navigate()`
  // n'est déclenché qu'à la fin de ce délai, cf. handleSubmit.
  const [phase, setPhase] = useState(() => (
    window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'docked' : 'splash'
  ))
  const entering = phase === 'entering'

  useEffect(() => {
    if (phase !== 'splash') return
    const t = setTimeout(() => setPhase('exiting'), 2600)
    return () => clearTimeout(t)
  }, [phase])

  useEffect(() => {
    if (phase !== 'exiting') return
    const t = setTimeout(() => setPhase('docked'), 550)
    return () => clearTimeout(t)
  }, [phase])

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

  async function handleForgotSubmit(e) {
    e.preventDefault()
    if (forgotSubmitting) return
    // `noValidate` sur le <form> (18/08/2026, demande explicite) — la bulle de validation
    // native du navigateur ("Veuillez remplir ce champ") ne peut pas être restylée pour
    // suivre le thème sombre de l'app ; ce message custom reprend le même `.login-error`
    // que les erreurs serveur juste en dessous.
    if (!forgotEmail.trim()) {
      setForgotError('Veuillez renseigner ce champ.')
      return
    }
    setForgotSubmitting(true)
    setForgotError('')
    try {
      await requestPasswordReset(forgotEmail.trim(), forgotMessage.trim() || undefined)
      setView('forgot-sent')
    } catch {
      // Le serveur répond toujours 200 (même anti-énumération que /login) — ce filet ne
      // couvre qu'un serveur injoignable, jamais un email inconnu/inactif.
      setForgotError("Impossible d'envoyer la demande — réessayez plus tard.")
    } finally {
      setForgotSubmitting(false)
    }
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (submitting) return
    // `noValidate` sur le <form> (18/08/2026, demande explicite) — la bulle de validation
    // native du navigateur ("Veuillez remplir ce champ") ne peut pas être restylée pour
    // suivre le thème sombre de l'app ; ce message custom reprend le même `.login-error`
    // que les erreurs de connexion (couleur/animation identiques).
    if (!canSubmit) {
      setError('Veuillez renseigner tous les champs.')
      return
    }
    setSubmitting(true)
    setError('')
    try {
      await login(email.trim(), password)
      // Pas de `finally` sur ce chemin : `submitting` doit rester true jusqu'à la
      // navigation, le formulaire est en train de repartir, pas la peine de
      // réactiver le bouton pendant qu'il disparaît.
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        navigate('/', { replace: true, state: { justLoggedIn: true } })
        return
      }
      // Mesuré ICI, juste avant de déclencher la transition — le petit logo d'en-tête
      // est encore à sa position normale à cet instant précis (cf. .login-logo-flip,
      // index.css). `96` = taille du logo de destination (cf. JSX plus bas).
      const rect = headerLogoRef.current?.getBoundingClientRect()
      if (rect) {
        setFlipOrigin({
          dx: rect.left + rect.width / 2 - window.innerWidth / 2,
          dy: rect.top + rect.height / 2 - window.innerHeight / 2,
          scale: rect.width / 96,
        })
      }
      setPhase('entering')
      setTimeout(() => navigate('/', { replace: true, state: { justLoggedIn: true } }), ENTER_MS)
    } catch (err) {
      // Message générique voulu côté serveur (pas d'énumération de comptes) —
      // le 429 (verrou anti-bruteforce) mérite son propre message.
      setError(err?.response?.status === 429
        ? 'Trop de tentatives — réessayez dans quelques minutes.'
        : (err?.response?.data?.detail || 'Email ou mot de passe incorrect.'))
      setSubmitting(false)
    }
  }

  return (
    <div className="relative min-h-screen flex flex-col items-center justify-center p-6 overflow-hidden" style={{ background: 'var(--bg-app)' }}>
      <div className="hero-grid hero-grid-boot" />
      <div className="home-glow" />

      {(phase !== 'docked') && (
        <div
          className={`fixed inset-0 z-20 flex flex-col items-center justify-center gap-4 ${phase === 'exiting' ? 'brand-splash-exit' : ''}`}
          style={{ background: entering ? 'transparent' : 'var(--bg-app)' }}
        >
          {/* Pas de `key` ici (18/08/2026) : sur splash→exiting, ce même bloc reste monté en
              continu, un remontage aurait rejoué le pop/reveal du logo/titre PENDANT que le
              parent joue sa propre sortie (`brand-splash-exit`) — flicker constaté. Sur
              'entering' au contraire, tout ce bloc vient d'apparaître pour la première fois
              (le wrapper au-dessus est conditionné sur `phase !== 'docked'`, faux juste avant) :
              déjà un montage neuf sans avoir besoin d'une key pour le forcer. */}
          {entering && flipOrigin ? (
            <CbrLogoTile size={96} rounded={26} className="login-logo-flip"
              style={{ '--flip-dx': `${flipOrigin.dx}px`, '--flip-dy': `${flipOrigin.dy}px`, '--flip-scale': flipOrigin.scale }} />
          ) : (
            <CbrLogoTile size={96} rounded={26} className="brand-pop" />
          )}
          <h1 className="brand-splash-title text-3xl font-bold tracking-tight" style={{
            fontFamily: 'var(--font-mono)', animationDelay: '650ms',
          }}>Allsafe</h1>
        </div>
      )}

      {phase !== 'splash' && (
      <div className="relative z-10 flex flex-col items-center text-center mb-6" style={{ opacity: entering ? 0 : 1 }}>
        {/* Reste monté (juste invisible) pendant 'entering' — le démonter ferait sauter la
            mise en page du formulaire encore affiché en dessous, toute la page étant centrée
            verticalement (cf. commentaire .login-logo-flip, index.css). `headerLogoRef` :
            position de départ du logo qui voyage vers le centre, mesurée dans handleSubmit
            juste avant que ce bloc ne passe à opacity:0. */}
        <div ref={headerLogoRef} className="relative mb-3">
          <span className="brand-ring" aria-hidden="true" />
          {/* Rotation périodique désormais portée par CbrLogoTile lui-même
              (.cbr-logo-spin, cf. CbrMark.jsx) — plus une classe posée ici. */}
          <CbrLogoTile size={56} rounded={18} className="brand-pop" />
        </div>
        <h1 className="brand-text-shimmer text-3xl font-bold tracking-tight" style={{
          fontFamily: 'var(--font-mono)', animationDelay: '260ms',
        }}>Allsafe</h1>
      </div>
      )}

      {/* Plus de cadre/carte autour des champs — ils reposent directement sur le fond de
          page, chacun ne se distinguant que par son propre fond (déjà présent sur les
          inputs). Séquence volontairement plus lente/espacée qu'ailleurs dans l'app (cf.
          emil-design-eng § fréquence — le login est une occasion rare, une fois par
          session, elle peut se permettre d'être vue plutôt que juste perçue) : logo →
          titre, PUIS une vraie pause avant que les champs n'arrivent un par un, bouton
          en dernier avec un petit rebond — la CTA de l'écran mérite plus de présence
          qu'un simple fondu. Gaté sur `phase` en plus de `view` : les champs ne se
          montent qu'une fois le splash d'ouverture parti, pour rejouer leurs propres
          délais (1100ms/1650ms/2350ms) à partir de ce moment-là. */}
      {phase !== 'splash' && view === 'login' && (
      <form onSubmit={handleSubmit} noValidate className="relative z-10 w-full max-w-sm flex flex-col">
        {/* fieldsRef délimite la zone interdite au bouton fuyant (cf. flee() plus haut) :
            mesurée en direct plutôt que codée en dur, pour suivre automatiquement
            l'apparition du message d'erreur. `gap` (pas `space-y-4`, sujet au margin
            collapsing) pour garantir un espacement rigoureusement identique entre
            email/mot de passe/erreur. */}
        <div ref={fieldsRef} className="flex flex-col gap-4">
          <div className={entering ? 'login-field-left-exit' : 'login-field-left'} style={{ animationDelay: entering ? '500ms' : '1100ms' }}>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--brand)' }}>Email</label>
            <input autoFocus required type="email" value={email} onChange={e => setEmail(e.target.value)}
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          <div className={entering ? 'login-field-right-exit' : 'login-field-right'} style={{ animationDelay: entering ? '250ms' : '1650ms' }}>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--brand)' }}>Mot de passe</label>
            <PasswordInput value={password} onChange={e => setPassword(e.target.value)} iconColor="var(--brand)" />
            <div className="flex justify-end mt-1.5">
              <button type="button" onClick={() => { setForgotEmail(email); setView('forgot') }}
                className="text-xs hover:underline" style={{ color: 'var(--brand)' }}>
                Mot de passe oublié ?
              </button>
            </div>
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
        <div className={`${entering ? 'login-button-exit' : 'login-button-enter'} mt-7`} style={{ animationDelay: entering ? '0ms' : '2350ms' }}>
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
      )}

      {phase !== 'splash' && view === 'forgot' && (
        <form onSubmit={handleForgotSubmit} noValidate className="relative z-10 w-full max-w-sm flex flex-col gap-4">
          <div className="login-enter">
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Email</label>
            <input autoFocus required type="email" value={forgotEmail} onChange={e => setForgotEmail(e.target.value)}
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          <div className="login-enter">
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Message pour l'administrateur (optionnel)</label>
            <textarea rows={2} value={forgotMessage} onChange={e => setForgotMessage(e.target.value)}
              placeholder="Contexte utile (facultatif)"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none resize-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          {forgotError && <p className="login-error text-xs" style={{ color: '#f85149' }}>{forgotError}</p>}
          <button type="submit" disabled={forgotSubmitting || !forgotEmail.trim()}
            className="w-full text-sm px-3 py-2.5 rounded-lg font-medium disabled:opacity-50"
            style={{ background: 'color-mix(in srgb, var(--brand) 15%, transparent)', color: 'var(--brand)', border: '1px solid color-mix(in srgb, var(--brand) 35%, transparent)' }}
          >{forgotSubmitting ? 'Envoi…' : 'Envoyer la demande'}</button>
          <button type="button" onClick={() => setView('login')}
            className="text-xs text-center hover:underline" style={{ color: 'var(--text-muted)' }}>
            ← Retour à la connexion
          </button>
        </form>
      )}

      {phase !== 'splash' && view === 'forgot-sent' && (
        <div className="login-enter relative z-10 w-full max-w-sm text-center space-y-4">
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            Si un compte existe avec cet email, une demande a été transmise à un administrateur —
            il vous communiquera un mot de passe provisoire à utiliser à votre prochaine connexion.
          </p>
          <button type="button" onClick={() => setView('login')}
            className="text-xs hover:underline" style={{ color: 'var(--brand)' }}>
            ← Retour à la connexion
          </button>
        </div>
      )}
    </div>
  )
}
