// Couleurs de score pour les colonnes Score (CVSS) et EPSS du Dashboard (12/08/2026,
// demande utilisateur) — mêmes teintes que SeverityBadge.jsx (cohérence visuelle), mêmes
// seuils déjà utilisés côté backend (services/nvd_fetcher.py::_score_to_severity pour
// CVSS, services/claude_analyzer.py pour EPSS), pas de nouveaux seuils inventés ici.

export function cvssColor(score) {
  if (score == null) return 'var(--text-muted)'
  if (score >= 9) return '#f85149'  // CRITICAL
  if (score >= 7) return '#fb8f44'  // HIGH
  if (score >= 4) return '#d29922'  // MEDIUM
  return '#3fb950'                  // LOW
}

// EPSS : probabilité d'exploitation active sous 30 jours (0-1). Seuils repris de
// services/claude_analyzer.py (>=0.5 "exploitation active", >=0.1 "exploitation connue").
export function epssColor(epss) {
  if (epss == null) return 'var(--text-muted)'
  if (epss >= 0.5) return '#f85149'
  if (epss >= 0.1) return '#d29922'
  return '#3fb950'
}
