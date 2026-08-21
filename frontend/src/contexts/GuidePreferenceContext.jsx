import { createContext, useContext, useEffect, useState } from 'react'

// "Masquer les guides d'aide sur toutes les pages" (19/08/2026, demande utilisateur) —
// préférence purement client (localStorage), même patron que AnalystPreferenceContext.jsx /
// ThemeContext.jsx. Contrôle la visibilité du bouton flottant PageGuide sur toutes les pages
// d'un seul point (bascule dans Paramètres > Apparence).
const GuidePreferenceContext = createContext({ guidesHidden: false, setGuidesHidden: () => {} })

export function GuidePreferenceProvider({ children }) {
  const [guidesHidden, setGuidesHidden] = useState(() => localStorage.getItem('guides_hidden') === 'true')

  useEffect(() => {
    localStorage.setItem('guides_hidden', guidesHidden ? 'true' : 'false')
  }, [guidesHidden])

  return (
    <GuidePreferenceContext.Provider value={{ guidesHidden, setGuidesHidden }}>
      {children}
    </GuidePreferenceContext.Provider>
  )
}

export const useGuidePreference = () => useContext(GuidePreferenceContext)
