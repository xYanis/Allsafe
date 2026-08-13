import { useState } from 'react'
import { remediationFor, categoryFor } from '../utils/hardeningRemediation.js'

// Ordre d'affichage des catégories (13/08/2026, regroupement — la liste plate ne passait plus
// bien une fois le catalogue étendu à ~19-23 checks/OS, cf. docs/AGENTS.md § Durcissement
// étendu) — "Autres" toujours en dernier, filet de sécurité pour un id sans entrée de
// remédiation (jamais une catégorie qui casse l'affichage).
const CATEGORY_ORDER = [
  'Mots de passe', 'SSH', 'Réseau', 'SMB', 'Authentification', 'Comptes',
  'Chiffrement', 'Journalisation', 'Système', 'Autres',
]

// Liste des checks de durcissement/conformité d'un actif — extrait de la modale "Résultat du
// scan" d'Assets.jsx (12/08/2026) pour devenir la brique d'affichage partagée de la page
// Durcissement (module Inventaire). `checks` attend la forme produite par
// `services/asset_scanner.py::_check()` / l'agent Rust : `[{id, label, status, detail}]`, status
// "ok"|"warn"|"unknown" — même shape que `network_compliance.checks` (actifs réseau).
//
// Chaque ligne est cliquable (12/08/2026, demande utilisateur — "quand je clique sur un cas
// j'ai des solutions et les commandes pour le faire") : déplie une solution + des commandes
// prêtes à copier, cf. `utils/hardeningRemediation.js`. Jamais exécuté par Allsafe lui-même —
// même principe que services/remediation.py côté CVE, l'analyste copie/colle après relecture
// (cf. CLAUDE.md § non-intervention). Rien à déplier pour un actif réseau (`os` absent/non
// Windows-Linux) : `remediationFor` retombe sur `null`, la ligne reste non cliquable.
function ComplianceRow({ id, label, status, detail, os, assetType }) {
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const icon = status === 'ok' ? '✓' : status === 'warn' ? '⚠' : '—'
  const color = status === 'ok' ? '#3fb950' : status === 'warn' ? '#fb8f44' : 'var(--text-muted)'
  const remediation = remediationFor(os, id, assetType)

  function copyCommands() {
    navigator.clipboard?.writeText(remediation.commands.join('\n')).catch(() => {})
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="rounded-lg overflow-hidden" style={{ background: 'var(--bg-secondary)' }}>
      <div
        className={`flex items-center gap-3 px-3 py-2 text-xs ${remediation ? 'cursor-pointer' : ''}`}
        onClick={() => remediation && setOpen(o => !o)}
      >
        <span className="font-bold flex-shrink-0 w-4 text-center" style={{ color }}>{icon}</span>
        <span className="flex-shrink-0 font-semibold" style={{ color: 'var(--text-secondary)', minWidth: 220 }}>{label}</span>
        <span className="flex-1" style={{ color: 'var(--text-muted)' }}>{detail || '—'}</span>
        {remediation && (
          <span className="flex-shrink-0 transition-transform" style={{ color: 'var(--text-muted)', transform: open ? 'rotate(90deg)' : 'none' }}>
            ›
          </span>
        )}
      </div>

      {open && remediation && (
        <div className="px-3 pb-3 pt-1 space-y-2" style={{ borderTop: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
          <p className="text-xs pt-2" style={{ color: 'var(--text-secondary)' }}>{remediation.solution}</p>
          {remediation.warning && (
            <p className="text-xs px-2.5 py-1.5 rounded-lg" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149' }}>
              ⚠ {remediation.warning}
            </p>
          )}
          <div className="relative">
            <pre className="text-xs font-mono p-3 rounded-lg overflow-x-auto whitespace-pre-wrap leading-relaxed" style={{ background: 'var(--bg-app)', color: '#3fb950', margin: 0 }}>
              {remediation.commands.join('\n')}
            </pre>
            <button
              onClick={copyCommands}
              className="absolute top-2 right-2 text-xs px-2 py-1 rounded-md font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
            >
              {copied ? 'Copié ✓' : 'Copier'}
            </button>
          </div>
          {remediation.note && (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{remediation.note}</p>
          )}
          <p className="text-xs font-medium" style={{ color: 'var(--text-muted)' }}>
            ⚠ Allsafe propose uniquement — à relire, tester et exécuter soi-même. Aucune commande n'est jamais lancée automatiquement.
          </p>
        </div>
      )}
    </div>
  )
}

export function complianceSummary(checks) {
  const list = checks || []
  return {
    ok: list.filter(c => c.status === 'ok').length,
    warn: list.filter(c => c.status === 'warn').length,
    unknown: list.filter(c => c.status !== 'ok' && c.status !== 'warn').length,
    total: list.length,
  }
}

// Section repliable par catégorie — ouverte par défaut seulement si elle contient au moins un
// avertissement (sinon repliée, pour ne pas noyer les catégories qui posent problème dans
// celles qui n'en ont pas — l'utilisateur peut toujours déplier manuellement).
function CategorySection({ category, items, os, assetType }) {
  const hasWarn = items.some(c => c.status === 'warn')
  const [open, setOpen] = useState(hasWarn)
  const warnCount = items.filter(c => c.status === 'warn').length

  return (
    <div className="rounded-lg overflow-hidden" style={{ border: '1px solid var(--border-subtle)' }}>
      <button type="button" onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 text-xs font-semibold"
        style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
        <span className="transition-transform" style={{ transform: open ? 'rotate(90deg)' : 'none' }}>›</span>
        {category}
        <span className="font-normal" style={{ color: 'var(--text-muted)' }}>({items.length})</span>
        {warnCount > 0 && (
          <span className="ml-auto" style={{ color: '#fb8f44' }}>{warnCount} ⚠</span>
        )}
      </button>
      {open && (
        <div className="space-y-1.5 p-1.5">
          {items.map(c => (
            <ComplianceRow key={c.id} id={c.id} label={c.label} status={c.status} detail={c.detail} os={os} assetType={assetType} />
          ))}
        </div>
      )}
    </div>
  )
}

export default function ComplianceChecklist({ checks, os, maxHeight = 'none', assetType }) {
  const list = checks || []
  if (list.length === 0) {
    return <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucun check de durcissement collecté pour cet actif.</p>
  }

  const grouped = new Map()
  for (const c of list) {
    const cat = categoryFor(os, c.id, assetType)
    if (!grouped.has(cat)) grouped.set(cat, [])
    grouped.get(cat).push(c)
  }
  const orderedCategories = CATEGORY_ORDER.filter(cat => grouped.has(cat))

  return (
    <div>
      <div className="space-y-2 overflow-y-auto pr-1" style={{ maxHeight }}>
        {orderedCategories.map(cat => (
          <CategorySection key={cat} category={cat} items={grouped.get(cat)} os={os} assetType={assetType} />
        ))}
      </div>
      <p className="text-xs mt-2" style={{ color: 'var(--text-muted)' }}>
        « — » = indéterminé (droits insuffisants en lecture seule) — pas une non-conformité.
      </p>
    </div>
  )
}
