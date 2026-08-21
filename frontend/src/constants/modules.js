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
//
// Couleurs par thème (21/08/2026, demande explicite — "pas assez de changement entre les
// apparences") : `color` n'est plus un hex fixe mais résolu une fois ici selon le thème actif
// au chargement de la page (`THEME_COLORS[theme]`). ~180 fichiers consomment `MODULE_COLOR =
// MODULES.x.color` comme une CONSTANTE DE MODULE (hors composant, évaluée une seule fois à
// l'import) — les rendre réactifs en direct aurait exigé de retoucher chacun d'eux (et de
// convertir au passage ~80 usages `${MODULE_COLOR}1f` en color-mix(), cf. plan initial).
// Choix retenu à la place : lire le thème depuis localStorage à l'import (synchrone, avant
// tout rendu) plutôt que depuis l'attribut `data-theme` (posé par ThemeContext.jsx après le
// 1er rendu — trop tard pour ce fichier, importé par presque toutes les pages en amont).
// Conséquence acceptée : passer À ou DEPUIS Neutre/Cyberpunk recharge la page une fois
// (ThemeContext.jsx::setTheme) pour que ces ~180 fichiers relisent la bonne couleur — bascule
// dark/light, elle, reste instantanée (même jeu de couleurs pour les deux, cf. THEME_COLORS.base).
const THEME_COLORS = {
  // dark & light : couleurs vives d'origine, inchangées.
  base: {
    cybervuln: '#f85149', cyberveille: '#58a6ff', inventaire: '#39c5cf', securite: '#3fb950',
    documentation: '#e3b341', rapports: '#a371f7', incidents: '#b5793a', parametres: '#8b949e',
    notesDeVersion: '#f778ba',
  },
  // Neutre : chaque teinte désaturée à l'extrême (juste un souffle de la couleur d'origine,
  // pour rester identifiable module par module) — "majoritairement gris" sans être un gris
  // unique plat qui rendrait la nav illisible.
  neutral: {
    cybervuln: '#93807e', cyberveille: '#82909e', inventaire: '#7b9497', securite: '#7e9482',
    documentation: '#a89c7a', rapports: '#8f85a3', incidents: '#9c8b74', parametres: '#8b949e',
    notesDeVersion: '#a68996',
  },
  // Cyberpunk (rebaptisé "Néon" côté UI, 21/08/2026) — palette resserrée sur 3 familles
  // (bleu/vert/jaune, "pour relier"), adoucie une 2e fois (même date, retour utilisateur —
  // "trop flashy") : chaque teinte reste dans sa famille mais moins saturée à bloc.
  cyberpunk: {
    cyberveille:    '#1ec2e0', // bleu (signature)
    rapports:       '#1c9fd4', // même famille, un cran plus bleu
    parametres:     '#6b84a8', // bleu ardoise, mis en retrait (module secondaire)
    securite:       '#3ddb66', // vert (signature)
    inventaire:     '#1ec9a3', // vert-cyan
    notesDeVersion: '#6be0a3', // vert menthe
    documentation:  '#e0d422', // jaune (signature)
    cybervuln:      '#e0a015', // jaune ambré
    incidents:      '#e0b840', // jaune-orangé
  },
}

function currentThemeColors() {
  try {
    const stored = localStorage.getItem('theme')
    if (stored === 'neutral' || stored === 'cyberpunk') return THEME_COLORS[stored]
  } catch {
    // localStorage indisponible (SSR/tests) — repli sur base, sans casser l'import.
  }
  return THEME_COLORS.base
}

const C = currentThemeColors()

export const MODULES = {
  cybervuln:      { label: 'CyberVuln',      color: C.cybervuln, dark: '#450a0a', paths: ['/dashboard', '/vulnerabilities', '/cves'] },
  cyberveille:    { label: 'CyberVeille',    color: C.cyberveille, dark: '#0c2a52', paths: ['/veille', '/fuite-de-donnees', '/surveillance-identites'] },
  // `/assets` rattaché à Inventaire (pas CyberVuln) : Actifs et Inventaire Complet
  // pointent vers le même parc, cohérent de les regrouper dans la nav (demande
  // utilisateur, 29/07/2026) — cf. CLAUDE.md § Inventaire pour la distinction
  // sécurité (Actifs) / patrimoine (Inventaire Complet).
  // `/agents`/`/durcissement` rattachés à Inventaire (pas Sécurité) depuis le 12/08/2026 —
  // demande utilisateur, plus cohérent : l'agent est une méthode de collecte du patrimoine
  // (au même titre que le compte de service), le durcissement une vue sur les données
  // collectées, pas une fonction de sécurité offensive/opérationnelle comme Audits/Bastion.
  inventaire:     { label: 'Inventaire',     color: C.inventaire, dark: '#053338', paths: ['/assets', '/inventaire', '/durcissement', '/agents'] },
  securite:       { label: 'Sécurité',       color: C.securite, dark: '#04262a', paths: ['/audits', '/bastion'] },
  // Module ex-« Documentation », renommé « Gouvernance » le 18/08/2026 (demande utilisateur,
  // plus cohérent avec son contenu — PSSI/chartes/organigramme) — pur renommage d'affichage,
  // clé/routes/`documentation.py` inchangés (même principe que le rebranding CBR → Allsafe).
  documentation:  { label: 'Gouvernance',    color: C.documentation, dark: '#3a2a04', paths: ['/documentation', '/notes'] },
  rapports:       { label: 'Rapports',       color: C.rapports, dark: '#2e1065', paths: ['/reports', '/rapport-veille', '/rapport-surveillance', '/rapport-incidents'] },
  incidents:      { label: 'Incidents',      color: C.incidents, dark: '#2b1c08', paths: ['/incidents', '/crises'] },
  parametres:     { label: 'Paramètres',     color: C.parametres, dark: '#1c2128', paths: ['/settings'] },
  // Détaché de Paramètres (18/08/2026, demande explicite) — devient un module à part entière,
  // juste en dessous de Paramètres dans la nav (cf. Layout.jsx::NAV_GROUPS). Couleur rose,
  // seule teinte encore libre parmi les modules existants (rouge/bleu/cyan/vert/or/violet/
  // marron/gris déjà pris). Le scope "agent" des notes de version reste sur sa page dédiée
  // sous Inventaire (/agents/notes-de-version) — seul le scope "allsafe" bouge ici.
  notesDeVersion: { label: 'Notes de version', color: C.notesDeVersion, dark: '#4a0e2a', paths: ['/notes-de-version'] },
}

const DEFAULT_COLOR = MODULES.cyberveille.color

// `/settings/administration` (Paramètres > Sécurité > Administration) matche `/settings`
// (le plus long préfixe l'emporte naturellement puisqu'un seul module a un préfixe `/settings`).
export function moduleColorForPath(pathname) {
  const mod = Object.values(MODULES).find(m => m.paths.some(p => pathname.startsWith(p)))
  return mod ? mod.color : DEFAULT_COLOR
}

// Module complet (couleur + `dark`) pour une route — utilisé quand un `dark` est nécessaire
// (texte sur CTA rempli), ex. le bouton flottant PageGuide. `null` si aucun module ne matche.
export function moduleForPath(pathname) {
  return Object.values(MODULES).find(m => m.paths.some(p => pathname.startsWith(p))) || null
}
