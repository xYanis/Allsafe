// Dashboard personnalisable (21/08/2026, demande explicite) — registre unique des tuiles
// réordonnables/redimensionnables (KPI + barre de Filtres + blocs de contenu) et dispositions
// prédéfinies. Cf. Dashboard.jsx (rendu piloté par ce registre) et DashboardLayoutContext.jsx
// (état + persistance localStorage).
//
// Un seul registre plutôt que deux séparés (KPI vs blocs, essayé d'abord le même jour) : `order`
// CSS ne réordonne qu'entre enfants d'un MÊME conteneur — deux grilles séparées empêchaient de
// faire glisser une tuile de part et d'autre de la barre de Filtres (retour utilisateur explicite).
// Échelle de span unifiée sur 24 colonnes — plus petit commun multiple des deux anciennes échelles
// (KPI : 1/8, 1/4, 1/2, plein ; blocs : 1/3, 1/2, plein) — pour que toute tuile, quelle que soit
// sa nature, puisse prendre n'importe laquelle des 5 tailles disponibles.
//
// Les bandeaux de statut (cycle en défaut, évènements agent non acquittés, progression de scan
// en cours) restent fixes en haut du Dashboard, hors registre : ce sont des statuts, pas des
// tuiles de contenu. "Filtres", lui, fait partie du registre (verrouillé, cf. LOCKED_WIDGETS) :
// les autres tuiles peuvent être déposées avant/après lui, mais lui-même ne se déplace/
// redimensionne pas — il doit rester lisible en une seule ligne quel que soit l'agencement choisi.
export const WIDGET_IDS = [
  'kpiExposedAssets', 'kpiOpenVulns', 'kpiAwaitingFix', 'kpiPatchRate', 'filtres',
  'auditFindings', 'sslCertificates', 'patchRateBySeverity', 'charts',
  'openVulns', 'awaitingFix', 'patchedVulns',
]

// Verrouillage retiré (21/08/2026, retour utilisateur — "la barre de filtre je ne peux pas la
// bouger") : "Filtres" était volontairement figé au 1er essai de grille unique, mais un widget
// verrouillé voit quand même son index bouger dès qu'un voisin est déplacé (juste ses propres
// boutons de déplacement/taille étaient masqués) — incohérent avec l'attente utilisateur d'un
// contrôle total. Tableau gardé vide (pas supprimé) : mécanisme réutilisable si un futur widget
// doit vraiment rester fixe.
export const LOCKED_WIDGETS = []

export const WIDGET_LABELS = {
  kpiExposedAssets: 'Actifs exposés',
  kpiOpenVulns: 'Vulnérabilités ouvertes',
  kpiAwaitingFix: 'En attente d’un patch',
  kpiPatchRate: 'Taux de correction global',
  filtres: 'Filtres',
  auditFindings: 'Findings d’audit non retestés',
  sslCertificates: 'Certificats SSL',
  patchRateBySeverity: 'Taux de correction par sévérité',
  charts: 'Graphiques',
  openVulns: 'Vulnérabilités à traiter',
  awaitingFix: 'Vulnérabilités en attente d’un patch',
  patchedVulns: 'Vulnérabilités traitées',
}

// 1/8, 1/4, 1/3, 1/2, plein — grille à 24 colonnes (cf. Dashboard.jsx), span exprimé directement.
export const SIZE_SPAN = { eighth: 3, quarter: 6, third: 8, half: 12, full: 24 }
export const SIZE_LABELS = { eighth: '1/8', quarter: '1/4', third: '1/3', half: '1/2', full: 'Plein' }

const DEFAULT_SIZES = {
  kpiExposedAssets: 'quarter', kpiOpenVulns: 'quarter', kpiAwaitingFix: 'quarter', kpiPatchRate: 'quarter',
  filtres: 'full',
  auditFindings: 'full', sslCertificates: 'full', patchRateBySeverity: 'full', charts: 'full',
  openVulns: 'full', awaitingFix: 'full', patchedVulns: 'full',
}

// 3 dispositions prédéfinies (Paramètres > Tableau de bord). "default" = comportement actuel
// exact (KPI en quart, tout le reste en pleine largeur, ordre d'origine) — zéro changement
// visuel tant que l'utilisateur ne personnalise pas lui-même.
export const DASHBOARD_PRESETS = {
  default: {
    label: 'Par défaut',
    desc: 'Ordre et tailles d’origine — tout en pleine largeur',
    order: [...WIDGET_IDS],
    sizes: { ...DEFAULT_SIZES },
  },
  compact: {
    label: 'Vue compacte',
    desc: 'Taux de correction et graphiques côte à côte, findings/SSL resserrés',
    order: [
      'kpiExposedAssets', 'kpiOpenVulns', 'kpiAwaitingFix', 'kpiPatchRate', 'filtres',
      'patchRateBySeverity', 'charts', 'auditFindings', 'sslCertificates', 'openVulns', 'awaitingFix', 'patchedVulns',
    ],
    sizes: {
      ...DEFAULT_SIZES,
      patchRateBySeverity: 'half',
      charts: 'half',
      auditFindings: 'third',
      sslCertificates: 'third',
    },
  },
  priorityFixes: {
    label: 'Priorité corrections',
    desc: 'Le tableau "à traiter" remonté juste après les KPI',
    order: [
      'kpiExposedAssets', 'kpiOpenVulns', 'kpiAwaitingFix', 'kpiPatchRate', 'filtres',
      'openVulns', 'auditFindings', 'sslCertificates', 'patchRateBySeverity', 'charts', 'awaitingFix', 'patchedVulns',
    ],
    sizes: { ...DEFAULT_SIZES },
  },
}

export const DEFAULT_LAYOUT = {
  order: DASHBOARD_PRESETS.default.order,
  sizes: DASHBOARD_PRESETS.default.sizes,
}
