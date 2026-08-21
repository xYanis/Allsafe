import { Component } from 'react'

// Error boundary React (doit être une classe — pas d'équivalent hook) : sans
// elle, une erreur de rendu n'importe où dans l'arbre (import manquant, accès
// à une propriété undefined...) démonte l'app React entière plutôt que le seul
// composant fautif — incident réel le 27/07/2026 (`SeverityBadge` jamais
// importé dans Assets.jsx), corrigé au cas par cas sans rien empêcher de
// pareil la prochaine fois (cf. STATUS.md).
//
// Placée autour de <Outlet/> dans Layout.jsx (pas au sommet de l'app) : la
// sidebar/nav reste utilisable même si la page courante plante, l'utilisateur
// peut naviguer ailleurs plutôt que de recharger l'onglet en entier. Le div
// parent est déjà keyé par `location.pathname` (transition de page) — changer
// de route démonte donc aussi cette boundary et réinitialise `hasError`
// automatiquement, sans logique de reset dédiée.
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
@keyframes err-glow  { 0%,100%{opacity:.78} 50%{opacity:1} }
@keyframes err-bg    { 0%,100%{opacity:.8}  50%{opacity:1} }
`

const BTN_BASE = {
  fontSize: 13, fontWeight: 500, padding: '8px 16px', borderRadius: 8,
  border: '1px solid', cursor: 'pointer', fontFamily: 'inherit',
  transition: 'transform 90ms ease, background 120ms ease',
  textDecoration: 'none', display: 'inline-block', lineHeight: 1.4,
}
const btnHandlers = {
  onPointerDown: e => { e.currentTarget.style.transform = 'scale(0.96)' },
  onPointerUp:   e => { e.currentTarget.style.transform = 'scale(1)' },
  onPointerLeave:e => { e.currentTarget.style.transform = 'scale(1)' },
  onMouseEnter:  e => { e.currentTarget.style.transform = 'scale(1.03)' },
  onMouseLeave:  e => { e.currentTarget.style.transform = 'scale(1)' },
}

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    // Aucun service de suivi d'erreurs externe configuré dans ce projet
    // (cf. CLAUDE.md § anonymisation) — la console reste la seule trace,
    // suffisante pour un outil interne sans télémétrie.
    console.error('Erreur de rendu interceptée par ErrorBoundary :', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <>
          <style>{KEYFRAMES}</style>
          <div style={{
            position: 'relative', overflow: 'hidden', minHeight: '70vh',
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            justifyContent: 'center', gap: 32, padding: '48px 32px', textAlign: 'center',
          }}>

            <div style={{
              position: 'absolute', inset: 0, pointerEvents: 'none',
              background: 'radial-gradient(ellipse 55% 45% at 50% 42%, color-mix(in srgb, #f85149 10%, transparent) 0%, transparent 68%)',
              animation: 'err-bg 6s ease-in-out infinite',
            }} />

            <div style={{
              fontSize: 128, fontWeight: 700, lineHeight: 1,
              letterSpacing: '-0.02em', userSelect: 'none',
              color: '#f85149', position: 'relative', zIndex: 1,
              animation: `err-code-in 520ms ${EASE} both, err-glow 5s ease-in-out 560ms infinite`,
            }}>
              500
            </div>

            <div style={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
              <h2 style={{
                fontSize: 18, fontWeight: 600, color: 'var(--text-primary)', margin: 0,
                animation: `err-item-in 400ms ${EASE} 120ms both`,
              }}>
                Erreur inattendue
              </h2>
              <p style={{
                fontSize: 13, color: 'var(--text-muted)', margin: 0, maxWidth: 230, lineHeight: 1.6,
                animation: `err-item-in 400ms ${EASE} 210ms both`,
              }}>
                La navigation reste utilisable — changez de page ou rechargez.
              </p>
            </div>

            <details style={{
              fontSize: 12, maxWidth: 480, textAlign: 'left', width: '100%',
              color: 'var(--text-muted)', position: 'relative', zIndex: 1,
              animation: `err-item-in 400ms ${EASE} 290ms both`,
            }}>
              <summary style={{ cursor: 'pointer', userSelect: 'none' }}>Détail technique</summary>
              <pre style={{
                marginTop: 8, padding: 12, borderRadius: 8, overflowX: 'auto',
                background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                fontSize: 11, lineHeight: 1.5,
              }}>
                {String(this.state.error?.stack || this.state.error)}
              </pre>
            </details>

            <div style={{
              display: 'flex', gap: 10, position: 'relative', zIndex: 1,
              animation: `err-item-in 400ms ${EASE} 350ms both`,
            }}>
              <a href="/" style={{ ...BTN_BASE, background: 'var(--bg-card)', borderColor: 'var(--border)', color: 'var(--text-primary)' }} {...btnHandlers}>
                Accueil
              </a>
              <button onClick={() => window.location.reload()}
                style={{ ...BTN_BASE, background: 'color-mix(in srgb, #f85149 12%, transparent)', color: '#f85149', borderColor: 'color-mix(in srgb, #f85149 30%, transparent)' }}
                {...btnHandlers}>
                Recharger
              </button>
            </div>
          </div>
        </>
      )
    }
    return this.props.children
  }
}
