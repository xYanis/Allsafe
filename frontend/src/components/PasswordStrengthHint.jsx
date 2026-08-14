// Indice de force de mot de passe (14/08/2026, demande utilisateur) — même règles
// exactement que backend/services/auth.py::validate_password_strength, dupliquées
// ici en JS pur (pas de logique métier partagée possible entre Python et JS) :
// tenir les deux synchronisées si la politique change. Guide l'utilisateur pendant
// la saisie plutôt que de le laisser découvrir les critères manquants au rejet
// serveur — utilisé par Settings.jsx (changement de mot de passe) et
// ProtectedRoute.jsx::ForcedPasswordChange (même moment de saisie).
const RULES = [
  { key: 'length',  label: 'Au moins 16 caractères', test: p => p.length >= 16 },
  { key: 'upper',   label: 'Une majuscule',           test: p => /[A-Z]/.test(p) },
  { key: 'lower',   label: 'Une minuscule',           test: p => /[a-z]/.test(p) },
  { key: 'digit',   label: 'Un chiffre',              test: p => /\d/.test(p) },
  { key: 'special', label: 'Un caractère spécial',    test: p => /[^A-Za-z0-9]/.test(p) },
]

export function passwordMeetsPolicy(password) {
  return RULES.every(r => r.test(password))
}

export default function PasswordStrengthHint({ password }) {
  const rules = RULES.map(r => ({ ...r, ok: r.test(password) }))
  const metCount = rules.filter(r => r.ok).length
  const pct = (metCount / rules.length) * 100
  const color = metCount === rules.length ? '#3fb950' : metCount >= 3 ? '#d29922' : '#f85149'
  const label = !password ? '' : metCount === rules.length ? 'Robuste' : metCount >= 3 ? 'Correct' : 'Trop faible'

  return (
    <div className="mt-2">
      <div className="flex items-center gap-2 mb-1.5">
        <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-secondary)' }}>
          <div style={{ width: `${pct}%`, height: '100%', background: color, transition: 'width 200ms ease, background 200ms ease' }} />
        </div>
        {label && <span className="text-[11px] font-medium flex-shrink-0" style={{ color }}>{label}</span>}
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1">
        {rules.map(r => (
          <span key={r.key} className="text-[11px] inline-flex items-center gap-1" style={{ color: r.ok ? '#3fb950' : 'var(--text-muted)' }}>
            <svg className="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              {r.ok
                ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M4.5 12.75l6 6 9-13.5" />
                : <circle cx="12" cy="12" r="3" fill="currentColor" stroke="none" />}
            </svg>
            {r.label}
          </span>
        ))}
      </div>
    </div>
  )
}
