import { useState } from 'react'

const PRIORITY_STYLE = {
  immédiate: { background: 'rgba(248,81,73,0.15)',  color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' },
  haute:     { background: 'rgba(251,143,68,0.15)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.3)' },
  normale:   { background: 'rgba(88,166,255,0.15)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' },
  faible:    { background: 'rgba(63,185,80,0.15)',  color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)' },
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    })
  }
  return (
    <button onClick={copy} className="flex-shrink-0 px-2 py-0.5 text-xs rounded transition-colors"
      style={{ background: copied ? 'rgba(63,185,80,0.15)' : '#30363d', color: copied ? '#3fb950' : '#8b949e' }}>
      {copied ? '✓ Copié' : 'Copier'}
    </button>
  )
}

function Section({ title, color = '#8b949e', children }) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-wider mb-2.5" style={{ color }}>{title}</p>
      {children}
    </div>
  )
}

function InfoRow({ label, value, valueColor = '#e6edf3' }) {
  if (!value) return null
  return (
    <div className="flex items-start gap-3 py-1.5" style={{ borderBottom: '1px solid #21262d' }}>
      <span className="text-xs w-40 flex-shrink-0 pt-0.5" style={{ color: '#8b949e' }}>{label}</span>
      <span className="text-xs font-medium leading-relaxed" style={{ color: valueColor }}>{value}</span>
    </div>
  )
}

export default function AnalysisModal({ data, onClose }) {
  const { analysis, cve_id, description } = data
  const priorityStyle = PRIORITY_STYLE[analysis.priority] || { background: '#21262d', color: '#8b949e', border: '1px solid #30363d' }
  const rec  = analysis.recommendation
  const ctx  = analysis.contexte_technique
  const links = analysis.links || {}

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop"
      onClick={onClose}>
      <div className="max-w-2xl w-full max-h-[92vh] flex flex-col rounded-2xl animate-modal-in"
        style={{ background: '#161b22', border: '1px solid #30363d' }}
        onClick={e => e.stopPropagation()}>

        {/* ── Header ── */}
        <div className="px-6 py-4 flex items-start justify-between flex-shrink-0"
          style={{ borderBottom: '1px solid #30363d' }}>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="font-semibold text-lg font-mono" style={{ color: '#58a6ff' }}>{cve_id}</h2>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold" style={priorityStyle}>
                Priorité {analysis.priority}
              </span>
              {analysis.cvss_score > 0 && (
                <span className="text-xs font-bold px-2 py-0.5 rounded"
                  style={{ background: analysis.cvss_score >= 9 ? 'rgba(248,81,73,0.15)' : 'rgba(251,143,68,0.15)',
                           color: analysis.cvss_score >= 9 ? '#f85149' : '#fb8f44' }}>
                  CVSS {analysis.cvss_score?.toFixed(1)}
                </span>
              )}
            </div>
            {/* Liens CVE */}
            <div className="flex items-center gap-3 mt-2 flex-wrap">
              {links.nvd && (
                <a href={links.nvd} target="_blank" rel="noopener noreferrer"
                  className="flex items-center gap-1 text-xs hover:underline transition-colors"
                  style={{ color: '#58a6ff' }}>
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                  NVD
                </a>
              )}
              {links.msrc && (
                <a href={links.msrc} target="_blank" rel="noopener noreferrer"
                  className="flex items-center gap-1 text-xs hover:underline"
                  style={{ color: '#58a6ff' }}>
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                  MSRC Microsoft
                </a>
              )}
              {analysis.published_fr && (
                <span className="text-xs" style={{ color: '#484f58' }}>Publié le {analysis.published_fr}</span>
              )}
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg transition-colors ml-3 flex-shrink-0"
            style={{ color: '#8b949e' }}
            onMouseEnter={e => e.currentTarget.style.background = '#21262d'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* ── Body ── */}
        <div className="overflow-y-auto p-6 space-y-6 flex-1">

          {/* Description de la vulnérabilité */}
          {(description || analysis.description_fr || analysis.affected_product) && (
            <Section title="Description de la vulnérabilité">
              {/* Type + CWE */}
              {(analysis.description_fr || analysis.cwe) && (
                <div className="flex items-center gap-2 flex-wrap mb-3">
                  {analysis.description_fr && (
                    <span className="text-xs px-2.5 py-1 rounded-full font-medium"
                      style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.2)' }}>
                      {analysis.description_fr}
                    </span>
                  )}
                  {analysis.cwe && (
                    <span className="text-xs px-2.5 py-1 rounded-full font-medium"
                      style={{ background: 'rgba(163,113,247,0.1)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.2)' }}>
                      {analysis.cwe}
                    </span>
                  )}
                </div>
              )}
              {analysis.affected_product && (
                <p className="text-xs mb-2" style={{ color: '#8b949e' }}>
                  Composant affecté : <span style={{ color: '#c9d1d9' }}>{analysis.affected_product}</span>
                </p>
              )}
              {description && (
                <div className="p-3.5 rounded-xl text-sm leading-relaxed" style={{ background: '#21262d', color: '#c9d1d9', border: '1px solid #30363d' }}>
                  {description}
                </div>
              )}
            </Section>
          )}

          {/* Contexte technique */}
          {ctx && (
            <Section title="Détails techniques">
              <div className="rounded-xl overflow-hidden" style={{ border: '1px solid #30363d' }}>
                <InfoRow label="Vecteur d'accès"   value={ctx.acces} />
                <InfoRow label="Conditions"         value={ctx.conditions} />
                <InfoRow label="Impact"             value={ctx.impact} valueColor="#fb8f44" />
                <InfoRow label="Contexte score"     value={ctx.score_context} valueColor={analysis.cvss_score >= 9 ? '#f85149' : '#fb8f44'} />
                <InfoRow label="EPSS"               value={analysis.exploitation_probability} />
                <InfoRow label="Criticité actif"    value={analysis.criticite_asset} />
              </div>
            </Section>
          )}

          {/* Résumé priorisation */}
          <Section title="Évaluation de priorité">
            <div className="p-4 rounded-xl" style={{ background: '#21262d', border: '1px solid #30363d' }}>
              <p className="text-sm leading-relaxed" style={{ color: '#c9d1d9' }}>{analysis.summary}</p>
              <div className="flex items-center gap-2 mt-3 pt-3 flex-wrap" style={{ borderTop: '1px solid #30363d' }}>
                <span className="text-xs font-medium" style={{ color: '#8b949e' }}>{analysis.urgency}</span>
                {rec?.estimated_effort && (
                  <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: '#161b22', color: '#8b949e', border: '1px solid #30363d' }}>
                    ⏱ {rec.estimated_effort}
                  </span>
                )}
              </div>
            </div>
          </Section>

          {/* Actions recommandées */}
          {rec?.steps?.length > 0 && (
            <Section title="Actions recommandées" color="#3fb950">
              <ol className="space-y-2.5">
                {rec.steps.map((step, i) => (
                  <li key={i} className="flex gap-3 text-sm">
                    <span className="flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold mt-0.5"
                      style={{ background: 'rgba(63,185,80,0.15)', color: '#3fb950' }}>
                      {i + 1}
                    </span>
                    <span style={{ color: '#c9d1d9' }}>{step}</span>
                  </li>
                ))}
              </ol>

              {rec.reboot_required && (
                <div className="mt-3 flex items-center gap-2 text-xs px-3 py-2 rounded-lg"
                  style={{ background: 'rgba(248,81,73,0.08)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
                  <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M12 3a9 9 0 100 18A9 9 0 0012 3z" />
                  </svg>
                  Redémarrage requis après application du correctif
                </div>
              )}

              {rec.verification_cmd && (
                <div className="mt-3">
                  <p className="text-xs mb-1.5" style={{ color: '#8b949e' }}>Commande de vérification</p>
                  <div className="flex items-center gap-2 px-3 py-2 rounded-lg" style={{ background: '#0d1117', border: '1px solid #30363d' }}>
                    <code className="flex-1 text-xs font-mono overflow-x-auto" style={{ color: '#79c0ff' }}>{rec.verification_cmd}</code>
                    <CopyButton text={rec.verification_cmd} />
                  </div>
                </div>
              )}
            </Section>
          )}

          {/* Liens & Références */}
          {(Object.keys(links).length > 0 || rec?.references?.length > 0) && (
            <Section title="Références">
              <div className="space-y-1.5">
                {links.nvd && (
                  <a href={links.nvd} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-2 text-xs hover:underline"
                    style={{ color: '#58a6ff' }}>
                    <svg className="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                    NVD — National Vulnerability Database
                  </a>
                )}
                {links.msrc && (
                  <a href={links.msrc} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-2 text-xs hover:underline"
                    style={{ color: '#58a6ff' }}>
                    <svg className="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                    MSRC — Microsoft Security Response Center
                  </a>
                )}
                {rec?.references?.map((ref, i) => (
                  ref !== links.msrc && (
                    <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                      className="flex items-center gap-2 text-xs truncate hover:underline"
                      style={{ color: '#58a6ff' }}>
                      <svg className="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                      {ref}
                    </a>
                  )
                ))}
              </div>
            </Section>
          )}

          {/* CVSS breakdown */}
          {analysis.cvss_breakdown && Object.keys(analysis.cvss_breakdown).length > 0 && (
            <Section title="Décomposition CVSS">
              <div className="grid grid-cols-2 gap-2">
                {Object.entries(analysis.cvss_breakdown).map(([k, v]) => (
                  <div key={k} className="flex justify-between items-center px-3 py-2 rounded-lg text-xs"
                    style={{ background: '#21262d' }}>
                    <span style={{ color: '#8b949e' }}>{k}</span>
                    <span className="font-medium" style={{ color: '#e6edf3' }}>{v}</span>
                  </div>
                ))}
              </div>
            </Section>
          )}
        </div>

        {/* ── Footer ── */}
        <div className="px-6 py-3 flex justify-end flex-shrink-0" style={{ borderTop: '1px solid #30363d' }}>
          <button onClick={onClose}
            className="px-4 py-2 text-sm font-medium rounded-lg transition-colors"
            style={{ background: '#21262d', color: '#c9d1d9', border: '1px solid #30363d' }}
            onMouseEnter={e => e.currentTarget.style.background = '#30363d'}
            onMouseLeave={e => e.currentTarget.style.background = '#21262d'}>
            Fermer
          </button>
        </div>
      </div>
    </div>
  )
}
