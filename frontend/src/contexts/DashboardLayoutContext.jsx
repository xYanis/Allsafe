import { createContext, useContext, useEffect, useState } from 'react'
import { WIDGET_IDS, DASHBOARD_PRESETS, DEFAULT_LAYOUT } from '../constants/dashboardLayout.js'

// Dashboard personnalisable (21/08/2026, demande explicite) — préférence 100% client
// (localStorage), même patron que ThemeContext.jsx/GuidePreferenceContext.jsx/
// AnalystPreferenceContext.jsx : pas de colonne DB/endpoint, la disposition est propre à ce
// navigateur. `order`/`sizes` pilotent le rendu de Dashboard.jsx (grille unique à 24 colonnes,
// KPI + Filtres + blocs, cf. constants/dashboardLayout.js) ; `editMode` bascule l'affichage
// des poignées de drag/boutons de taille sur la page elle-même. Registre unique plutôt que
// deux séparés (KPI vs blocs, essayé d'abord le même jour, revenu en arrière — retour
// utilisateur : impossible de déplacer une tuile de part et d'autre de la barre de Filtres
// avec deux grilles distinctes, `order` CSS ne jouant qu'entre enfants d'un même conteneur).
const STORAGE_KEY = 'dashboard_layout'

function loadStoredLayout() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return DEFAULT_LAYOUT
    const parsed = JSON.parse(raw)
    // Validation minimale — un id de widget supprimé/renommé entre deux versions de l'app ne
    // doit jamais faire planter le Dashboard : repli sur la disposition par défaut si la
    // valeur stockée ne correspond plus au registre actuel (WIDGET_IDS).
    if (!Array.isArray(parsed?.order) || !parsed?.sizes) return DEFAULT_LAYOUT
    const validOrder = parsed.order.filter(id => WIDGET_IDS.includes(id))
    const missing = WIDGET_IDS.filter(id => !validOrder.includes(id))
    return { order: [...validOrder, ...missing], sizes: { ...DEFAULT_LAYOUT.sizes, ...parsed.sizes } }
  } catch {
    return DEFAULT_LAYOUT
  }
}

const DashboardLayoutContext = createContext({
  order: DEFAULT_LAYOUT.order,
  sizes: DEFAULT_LAYOUT.sizes,
  editMode: false,
  setEditMode: () => {},
  setWidgetSize: () => {},
  reorder: () => {},
  moveWidget: () => {},
  applyPreset: () => {},
  resetToDefault: () => {},
})

export function DashboardLayoutProvider({ children }) {
  const [layout, setLayout] = useState(loadStoredLayout)
  const [editMode, setEditMode] = useState(false)

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(layout))
  }, [layout])

  function setWidgetSize(id, size) {
    setLayout(l => ({ ...l, sizes: { ...l.sizes, [id]: size } }))
  }

  // Réordonne par glisser-déposer (drag-and-drop HTML5 natif, cf. Dashboard.jsx) : `fromId`
  // vient s'insérer juste avant `toId`. Fonctionne pour n'importe quelle paire de tuiles du
  // registre unique (KPI, Filtres, ou bloc de contenu) — un seul tableau `order` pour tout.
  function reorder(fromId, toId) {
    if (fromId === toId) return
    setLayout(l => {
      const next = l.order.filter(id => id !== fromId)
      const toIndex = next.indexOf(toId)
      next.splice(toIndex, 0, fromId)
      return { ...l, order: next }
    })
  }

  // Alternative au drag-and-drop natif (21/08/2026, retour utilisateur — "pour bouger entre eux
  // c'est compliqué") : boutons ◀/▶ dans la barre d'édition, échangent simplement la tuile avec
  // sa voisine immédiate dans `order`. Bien plus fiable qu'un glisser-déposer HTML5 (cible de
  // dépôt précise à viser, pas de retour visuel pendant le drag) — gardé en plus, pas à la place,
  // pour ne rien retirer à ceux qui préfèrent glisser.
  function moveWidget(id, delta) {
    setLayout(l => {
      const idx = l.order.indexOf(id)
      const target = idx + delta
      if (target < 0 || target >= l.order.length) return l
      const next = [...l.order]
      ;[next[idx], next[target]] = [next[target], next[idx]]
      return { ...l, order: next }
    })
  }

  function applyPreset(name) {
    const preset = DASHBOARD_PRESETS[name]
    if (!preset) return
    setLayout({ order: [...preset.order], sizes: { ...preset.sizes } })
  }

  function resetToDefault() {
    applyPreset('default')
  }

  return (
    <DashboardLayoutContext.Provider value={{
      order: layout.order, sizes: layout.sizes, editMode, setEditMode,
      setWidgetSize, reorder, moveWidget, applyPreset, resetToDefault,
    }}>
      {children}
    </DashboardLayoutContext.Provider>
  )
}

export const useDashboardLayout = () => useContext(DashboardLayoutContext)
