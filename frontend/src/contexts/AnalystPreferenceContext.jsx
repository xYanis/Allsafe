import { createContext, useContext, useEffect, useState } from 'react'

// "Nom d'analyste par défaut" (14/08/2026, demande utilisateur) — préférence purement
// client (localStorage), même patron exact que ThemeContext.jsx/PresentationContext.jsx :
// lecture lazy au premier rendu, écriture par effet au changement. Volontairement séparé
// du registre `Analyst` (backend) et de `AnalystContext.jsx` (liste des noms) — ceci n'est
// qu'une préférence d'affichage locale, pas une donnée à synchroniser entre postes.
const AnalystPreferenceContext = createContext({ preferredAnalyst: '', setPreferredAnalyst: () => {} })

export function AnalystPreferenceProvider({ children }) {
  const [preferredAnalyst, setPreferredAnalyst] = useState(() => localStorage.getItem('preferred_analyst') || '')

  useEffect(() => {
    if (preferredAnalyst) localStorage.setItem('preferred_analyst', preferredAnalyst)
    else localStorage.removeItem('preferred_analyst')
  }, [preferredAnalyst])

  return (
    <AnalystPreferenceContext.Provider value={{ preferredAnalyst, setPreferredAnalyst }}>
      {children}
    </AnalystPreferenceContext.Provider>
  )
}

export const useAnalystPreference = () => useContext(AnalystPreferenceContext)
