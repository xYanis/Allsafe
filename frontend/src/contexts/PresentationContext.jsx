import { createContext, useContext, useEffect, useState } from 'react'

const PresentationContext = createContext({ isAnonymous: false, toggle: () => {} })

export function PresentationProvider({ children }) {
  const [isAnonymous, setIsAnonymous] = useState(() => localStorage.getItem('presentation_mode') === 'true')

  useEffect(() => {
    localStorage.setItem('presentation_mode', isAnonymous ? 'true' : 'false')
  }, [isAnonymous])

  return (
    <PresentationContext.Provider value={{ isAnonymous, toggle: () => setIsAnonymous(v => !v) }}>
      {children}
    </PresentationContext.Provider>
  )
}

export const usePresentation = () => useContext(PresentationContext)
