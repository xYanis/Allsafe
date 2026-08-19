import { MODULES } from './modules.js'

// Arborescence Module > pages, pour le picker de droits d'accès (Administration >
// Utilisateurs) et le filtrage de la nav/des routes (Layout.jsx, Home.jsx, ProtectedRoute.jsx).
// Miroir de Layout.jsx::NAV_GROUPS (labels des items) et de backend/services/
// access_control.py::MODULE_PAGES — dupliqué plutôt qu'importé (les icônes de la sidebar
// vivent à part) : à maintenir manuellement en synchronisation si une page est ajoutée,
// renommée ou déplacée. `/settings` est volontairement absent : toujours accessible, jamais
// restreignable (cf. justification dans access_control.py).
export const MODULE_PAGE_TREE = [
  { key: 'cybervuln', label: 'CyberVuln', color: MODULES.cybervuln.color, pages: [
    { to: '/dashboard', label: 'Dashboard' },
    { to: '/vulnerabilities', label: 'Vulnérabilités' },
    { to: '/cves', label: 'CVE' },
  ]},
  { key: 'incidents', label: 'Incidents', color: MODULES.incidents.color, pages: [
    { to: '/incidents', label: 'Registre incidents' },
    { to: '/crises', label: 'Gestion de crise' },
  ]},
  { key: 'cyberveille', label: 'CyberVeille', color: MODULES.cyberveille.color, pages: [
    { to: '/veille', label: 'Veille technologique' },
    { to: '/fuite-de-donnees', label: 'Fuite de données' },
    { to: '/surveillance-identites', label: 'Surveillance Identités' },
  ]},
  { key: 'inventaire', label: 'Inventaire', color: MODULES.inventaire.color, pages: [
    { to: '/assets', label: 'Actifs' },
    { to: '/inventaire', label: 'Inventaire Complet' },
    { to: '/durcissement', label: 'Durcissement' },
    { to: '/agents', label: 'Agents' },
  ]},
  { key: 'securite', label: 'Sécurité', color: MODULES.securite.color, pages: [
    { to: '/audits', label: 'Audits' },
    { to: '/bastion', label: 'Bastion' },
  ]},
  { key: 'documentation', label: 'Gouvernance', color: MODULES.documentation.color, pages: [
    { to: '/documentation', label: 'Documentation Entreprise' },
    { to: '/notes', label: 'Notes' },
  ]},
  { key: 'rapports', label: 'Rapports', color: MODULES.rapports.color, pages: [
    { to: '/reports', label: 'Rapport exécutif CVE' },
    { to: '/rapport-veille', label: 'Rapport Veille' },
    { to: '/rapport-surveillance', label: 'Rapport Surveillance' },
    { to: '/rapport-incidents', label: 'Rapport Incidents' },
  ]},
]

export const ALL_PAGE_KEYS = MODULE_PAGE_TREE.flatMap(m => m.pages.map(p => p.to))
