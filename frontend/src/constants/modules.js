// Source de vérité unique des modules CBR (couleur + routes) — reprise par
// Layout.jsx (nav), Home.jsx (tuiles) et PageLoader.jsx (couleur déduite de la
// route active). Cf. principe scalable (CLAUDE.md) : un module ajouté ici reste
// cohérent partout sans re-synchroniser plusieurs fichiers à la main.
// `dark` : teinte quasi-noire de la même famille de couleur, utilisée comme texte sur un CTA
// rempli en `color` plein (cf. pattern Incidents.jsx/Documentation.jsx/Audits.jsx — un texte
// clair/blanc générique manque de contraste avec de la couleur plutôt que du gris, et un texte
// dans une teinte SANS RAPPORT avec `color` — vu en dur sur Incidents/Crises avant le 11/08/2026,
// copié depuis Audits sans être adapté — jure visiblement (cf. docs/FRONTEND.md § Tour visuel).
// Centralisé ici (11/08/2026, tour visuel) plutôt que recopié par page : `securite`/
// `documentation`/`incidents` avaient déjà cette valeur en dur, dupliquée par endroit.
export const MODULES = {
  cybervuln:      { label: 'CyberVuln',      color: '#f85149', dark: '#450a0a', paths: ['/dashboard', '/vulnerabilities', '/cves'] },
  cyberveille:    { label: 'CyberVeille',    color: '#58a6ff', dark: '#0c2a52', paths: ['/veille', '/fuite-de-donnees', '/surveillance-identites'] },
  // `/assets` rattaché à Inventaire (pas CyberVuln) : Actifs et Inventaire Complet
  // pointent vers le même parc, cohérent de les regrouper dans la nav (demande
  // utilisateur, 29/07/2026) — cf. CLAUDE.md § Inventaire pour la distinction
  // sécurité (Actifs) / patrimoine (Inventaire Complet).
  // `/agents`/`/durcissement` rattachés à Inventaire (pas Sécurité) depuis le 12/08/2026 —
  // demande utilisateur, plus cohérent : l'agent est une méthode de collecte du patrimoine
  // (au même titre que le compte de service), le durcissement une vue sur les données
  // collectées, pas une fonction de sécurité offensive/opérationnelle comme Audits/Bastion.
  inventaire:     { label: 'Inventaire',     color: '#39c5cf', dark: '#053338', paths: ['/assets', '/inventaire', '/durcissement', '/agents'] },
  securite:       { label: 'Sécurité',       color: '#3fb950', dark: '#04262a', paths: ['/audits', '/bastion'] },
  // Module ex-« Documentation », renommé « Gouvernance » le 18/08/2026 (demande utilisateur,
  // plus cohérent avec son contenu — PSSI/chartes/organigramme) — pur renommage d'affichage,
  // clé/routes/`documentation.py` inchangés (même principe que le rebranding CBR → Allsafe).
  documentation:  { label: 'Gouvernance',    color: '#e3b341', dark: '#3a2a04', paths: ['/documentation', '/notes'] },
  rapports:       { label: 'Rapports',       color: '#a371f7', dark: '#2e1065', paths: ['/reports', '/rapport-veille', '/rapport-surveillance', '/rapport-incidents'] },
  incidents:      { label: 'Incidents',      color: '#b5793a', dark: '#2b1c08', paths: ['/incidents', '/crises'] },
  parametres:     { label: 'Paramètres',     color: '#8b949e', dark: '#1c2128', paths: ['/settings'] },
  // Détaché de Paramètres (18/08/2026, demande explicite) — devient un module à part entière,
  // juste en dessous de Paramètres dans la nav (cf. Layout.jsx::NAV_GROUPS). Couleur rose,
  // seule teinte encore libre parmi les modules existants (rouge/bleu/cyan/vert/or/violet/
  // marron/gris déjà pris). Le scope "agent" des notes de version reste sur sa page dédiée
  // sous Inventaire (/agents/notes-de-version) — seul le scope "allsafe" bouge ici.
  notesDeVersion: { label: 'Notes de version', color: '#f778ba', dark: '#4a0e2a', paths: ['/notes-de-version'] },
}

const DEFAULT_COLOR = MODULES.cyberveille.color

// `/settings/administration` (Paramètres > Sécurité > Administration) matche `/settings`
// (le plus long préfixe l'emporte naturellement puisqu'un seul module a un préfixe `/settings`).
export function moduleColorForPath(pathname) {
  const mod = Object.values(MODULES).find(m => m.paths.some(p => pathname.startsWith(p)))
  return mod ? mod.color : DEFAULT_COLOR
}
