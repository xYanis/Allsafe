import { useNavigate } from 'react-router-dom'

const EASE = 'cubic-bezier(0.23, 1, 0.32, 1)'

const KEYFRAMES = `
@keyframes err-code-in {
  from { opacity: 0; transform: scale(0.84) translateY(18px); }
  to   { opacity: 1; transform: scale(1) translateY(0); }
}
@keyframes err-item-in {
  from { opacity: 0; transform: translateY(10px); }
  to   { opacity: 1; transform: translateY(0); }
}
@keyframes err-glow {
  0%, 100% { opacity: 0.78; }
  50%       { opacity: 1; }
}
@keyframes err-bg {
  0%, 100% { opacity: 0.8; }
  50%       { opacity: 1; }
}
@media (prefers-reduced-motion: reduce) {
  .err-animated { animation: none !important; opacity: 1 !important; transform: none !important; }
}
`

const ERROR_CONFIG = {
  403: {
    color: '#e3b341',
    title: 'Accès refusé',
    message: "Vous n'avez pas les droits nécessaires pour accéder à cette page.",
  },
  404: {
    color: '#8b949e',
    title: 'Page introuvable',
    message: "Cette page n'existe pas ou a été déplacée.",
  },
  500: {
    color: '#f85149',
    title: 'Erreur serveur',
    message: "Une erreur inattendue s'est produite. Rechargez la page ou revenez plus tard.",
  },
}

function ErrorBtn({ onClick, href, color, children, variant = 'neutral' }) {
  const isColored = variant === 'colored'
  const base = {
    fontSize: 13, fontWeight: 500, padding: '8px 16px', borderRadius: 8,
    border: '1px solid', cursor: 'pointer', fontFamily: 'inherit',
    transition: 'transform 90ms ease, background 120ms ease',
    display: 'inline-block', textDecoration: 'none', lineHeight: 1.4,
    background: isColored
      ? `color-mix(in srgb, ${color} 12%, transparent)`
      : 'var(--bg-card)',
    color: isColored ? color : 'var(--text-primary)',
    borderColor: isColored
      ? `color-mix(in srgb, ${color} 30%, transparent)`
      : 'var(--border)',
  }
  const handlers = {
    onPointerDown: e => { e.currentTarget.style.transform = 'scale(0.96)' },
    onPointerUp:   e => { e.currentTarget.style.transform = 'scale(1)' },
    onPointerLeave:e => { e.currentTarget.style.transform = 'scale(1)' },
    onMouseEnter:  e => { e.currentTarget.style.transform = 'scale(1.03)' },
    onMouseLeave:  e => { e.currentTarget.style.transform = 'scale(1)' },
  }
  if (href) return <a href={href} style={base} {...handlers}>{children}</a>
  return <button style={base} onClick={onClick} {...handlers}>{children}</button>
}

export default function ErrorPage({ code = 404, message }) {
  const navigate = useNavigate()
  const cfg = ERROR_CONFIG[code] ?? ERROR_CONFIG[404]
  const displayMessage = message ?? cfg.message

  return (
    <>
      <style>{KEYFRAMES}</style>
      <div style={{
        position: 'relative', overflow: 'hidden',
        minHeight: '70vh', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        gap: 32, padding: '48px 32px', textAlign: 'center',
      }}>

        {/* halo radial ambiant */}
        <div className="err-animated" style={{
          position: 'absolute', inset: 0, pointerEvents: 'none',
          background: `radial-gradient(ellipse 55% 45% at 50% 42%,
            color-mix(in srgb, ${cfg.color} 10%, transparent) 0%,
            transparent 68%)`,
          animation: `err-bg 6s ease-in-out infinite`,
        }} />

        {/* code */}
        <div className="err-animated" style={{
          fontSize: 128, fontWeight: 700, lineHeight: 1,
          letterSpacing: '-0.02em', userSelect: 'none',
          color: cfg.color, position: 'relative', zIndex: 1,
          animation: `err-code-in 520ms ${EASE} both,
                      err-glow 5s ease-in-out 560ms infinite`,
        }}>
          {code}
        </div>

        {/* titre */}
        <div style={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <h1 className="err-animated" style={{
            fontSize: 18, fontWeight: 600, color: 'var(--text-primary)', margin: 0,
            animation: `err-item-in 400ms ${EASE} 120ms both`,
          }}>
            {cfg.title}
          </h1>
          <p className="err-animated" style={{
            fontSize: 13, color: 'var(--text-muted)', margin: 0,
            maxWidth: 230, lineHeight: 1.6,
            animation: `err-item-in 400ms ${EASE} 210ms both`,
          }}>
            {displayMessage}
          </p>
        </div>

        {/* boutons */}
        <div className="err-animated" style={{
          display: 'flex', gap: 10, position: 'relative', zIndex: 1,
          animation: `err-item-in 400ms ${EASE} 320ms both`,
        }}>
          <ErrorBtn onClick={() => navigate(-1)} color={cfg.color}>
            ← Retour
          </ErrorBtn>
          <ErrorBtn onClick={() => navigate('/')} color={cfg.color} variant="colored">
            Accueil
          </ErrorBtn>
        </div>
      </div>
    </>
  )
}
