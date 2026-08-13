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
        <div className="flex flex-col items-center justify-center text-center p-12 gap-4" style={{ minHeight: '50vh' }}>
          <div className="text-4xl">⚠️</div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Cette page a rencontré une erreur
          </h2>
          <p className="text-sm max-w-md" style={{ color: 'var(--text-secondary)' }}>
            Le reste de l'application reste utilisable — la navigation ci-contre fonctionne toujours.
          </p>
          <details className="text-xs max-w-lg text-left" style={{ color: 'var(--text-muted)' }}>
            <summary className="cursor-pointer select-none">Détail technique</summary>
            <pre className="mt-2 p-2 rounded-lg overflow-x-auto" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
              {String(this.state.error?.stack || this.state.error)}
            </pre>
          </details>
          <a
            href="/"
            className="text-sm font-medium px-4 py-2 rounded-lg transition-colors"
            style={{ background: 'var(--accent-blue)', color: '#fff' }}
          >
            ← Retour à l'accueil
          </a>
        </div>
      )
    }
    return this.props.children
  }
}
