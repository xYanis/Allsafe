const CARD = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px' }

export default function Bastion() {
  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Bastion</h1>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>Module à venir</p>
      </div>

      <div style={CARD} className="p-10 flex flex-col items-center gap-3 text-center">
        <svg className="w-8 h-8" fill="none" stroke="var(--text-muted)" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
        </svg>
        <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>En cours de développement</p>
        <p className="text-xs max-w-md" style={{ color: 'var(--text-muted)' }}>
          Ce module accueillera un accès bastion (jump host) vers les serveurs critiques —
          portée à définir. Distinct du reste d'Allsafe : cet outil n'exécute et n'écrit
          jamais rien sur un serveur (cf. CLAUDE.md § Non-intervention) — un bastion de
          connexion directe entrera en tension avec cette règle, à trancher explicitement
          avant l'implémentation.
        </p>
      </div>
    </div>
  )
}
