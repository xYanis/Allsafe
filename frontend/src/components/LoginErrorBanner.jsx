// Bannière d'erreur de connexion (23/08/2026, demande explicite — le message texte seul
// en rouge passait quasi inaperçu). Une config par cause réelle (Login.jsx::handleSubmit/
// handleForgotSubmit) plutôt qu'un style unique : la sévérité et l'icône changent selon que
// l'utilisateur s'est fait limiter, ou que le serveur est injoignable/saturé — cf. couleurs
// déjà posées par ErrorPage.jsx (ambre=throttle, bleu=capacité/info, gris=technique neutre).
// Volontairement PAS de statut 401/validation ici (retiré le 23/08/2026, demande explicite) :
// réservé aux erreurs d'infrastructure, où rien n'est "à corriger" côté utilisateur — 401 et
// le champ requis restent un simple message texte dans Login.jsx.
const CONFIG = {
  429: {
    code: '429', color: '#e3b341', title: 'Trop de tentatives',
    icon: 'M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z',
    pulse: true,
  },
  503: {
    code: '503', color: '#58a6ff', title: 'Capacité atteinte',
    icon: null, stack: true, // rendu à part, cf. StackIcon plus bas — pas un chemin unique
    pulse: false,
  },
  network: {
    code: '—', color: '#8b949e', title: 'Connexion impossible',
    icon: null, slash: true, // rendu à part, cf. SlashIcon plus bas
    pulse: false,
  },
}

const FALLBACK = {
  code: '⚠', color: '#f85149', title: 'Erreur imprévue',
  icon: 'M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z',
  pulse: false,
}

function PathIcon({ d }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" className="w-5 h-5">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d={d} />
    </svg>
  )
}

// 503 (limite de connexions simultanées) : trois créneaux empilés, le dernier estompé —
// « plus de place » plutôt qu'un pictogramme mémorisé au hasard, geometry garantie plutôt
// qu'un chemin SVG complexe recopié de mémoire.
function StackIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" className="w-5 h-5">
      <rect x="4" y="3.5" width="16" height="5" rx="1.4" strokeWidth={1.8} />
      <rect x="4" y="10" width="16" height="5" rx="1.4" strokeWidth={1.8} />
      <rect x="4" y="16.5" width="16" height="4" rx="1.4" strokeWidth={1.8} opacity="0.4" />
    </svg>
  )
}

// Réseau injoignable (pas de réponse HTTP du tout) : cercle barré, universel, aucune
// ambiguïté avec les autres icônes de cette bannière.
function SlashIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" className="w-5 h-5">
      <circle cx="12" cy="12" r="8.25" strokeWidth={1.8} />
      <line x1="6.6" y1="6.6" x2="17.4" y2="17.4" strokeWidth={1.8} strokeLinecap="round" />
    </svg>
  )
}

/**
 * status : 429 | 503 | 'network' | tout autre code HTTP (retombe sur le fallback générique).
 * message : détail déjà formulé en français (celui du serveur ou un fallback client).
 */
export default function LoginErrorBanner({ status, message }) {
  const cfg = CONFIG[status] || FALLBACK

  return (
    <div
      className="login-err-banner"
      style={{
        display: 'flex', alignItems: 'flex-start', gap: 12,
        padding: '12px 14px', borderRadius: 10, textAlign: 'left',
        background: `color-mix(in srgb, ${cfg.color} 8%, var(--bg-secondary))`,
        border: `1px solid color-mix(in srgb, ${cfg.color} 28%, transparent)`,
      }}
    >
      <div
        className={`login-err-icon ${cfg.pulse ? 'login-err-pulse' : ''}`}
        style={{
          '--err-color': cfg.color,
          flexShrink: 0, width: 32, height: 32, borderRadius: 9,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: `color-mix(in srgb, ${cfg.color} 16%, transparent)`,
          color: cfg.color,
        }}
      >
        {cfg.stack ? <StackIcon /> : cfg.slash ? <SlashIcon /> : <PathIcon d={cfg.icon} />}
      </div>
      <div style={{ minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
          <span style={{
            fontSize: 10, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase',
            color: cfg.color, fontFamily: 'var(--font-mono)',
          }}>
            Erreur {cfg.code}
          </span>
        </div>
        <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', margin: 0, lineHeight: 1.35 }}>
          {cfg.title}
        </p>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '2px 0 0', lineHeight: 1.45 }}>
          {message}
        </p>
      </div>
    </div>
  )
}
