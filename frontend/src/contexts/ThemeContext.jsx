import { createContext, useContext, useEffect, useState } from 'react'

// 4 thèmes (21/08/2026, demande explicite — étendu depuis un simple booléen sombre/clair) :
// dark/light d'origine + neutral (gris quasi monochrome, présentation pro — base repassée en
// gris FONCÉ le même jour, 2e demande explicite) + cyberpunk (néons façon Night City). Un seul
// état `theme`, plus la simple bascule d'avant — `isDark` reste dérivé pour ses 2 seuls
// consommateurs (PageHero.jsx, Settings.jsx) : cyberpunk ET neutral héritent ainsi gratuitement
// des traitements "sombre" déjà en place (glow de titre, rouge plus vif...) — seul light reste
// "clair" désormais.
const THEMES = ['dark', 'light', 'neutral', 'cyberpunk']
const DEFAULT_THEME = 'dark'
// dark/light partagent le même jeu de couleurs de module (constants/modules.js::THEME_COLORS.base)
// — bascule entre les deux, instantanée. neutral/cyberpunk en ont un différent, mais lu une
// seule fois à l'import par ~180 fichiers (`const MODULE_COLOR = MODULES.x.color`, hors
// composant) : impossible à répercuter en direct sans les retoucher un par un. Un rechargement
// complet dès que Neutre/Cyberpunk entre ou sort du changement est le compromis retenu — ces
// ~180 fichiers relisent alors la bonne couleur au prochain import (cf. commentaire modules.js).
const VIVID_THEMES = new Set(['dark', 'light'])

const ThemeContext = createContext({ theme: DEFAULT_THEME, isDark: true, setTheme: () => {} })

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(() => {
    const stored = localStorage.getItem('theme')
    return THEMES.includes(stored) ? stored : DEFAULT_THEME
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  function setTheme(next) {
    if (!THEMES.includes(next) || next === theme) return
    const needsReload = !(VIVID_THEMES.has(theme) && VIVID_THEMES.has(next))
    if (needsReload) {
      // Écrit avant le reload (l'effet ci-dessus n'aura pas le temps de tourner) — modules.js
      // et tout le reste relisent cette valeur dès le prochain import, au chargement.
      localStorage.setItem('theme', next)
      window.location.reload()
      return
    }
    setThemeState(next)
  }

  // Neutre inclus (21/08/2026, suite au passage de sa base en gris foncé, demande explicite) —
  // seul light reste "clair" désormais, les 3 autres thèmes partagent un fond sombre.
  const isDark = theme !== 'light'

  return (
    <ThemeContext.Provider value={{ theme, isDark, setTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)
