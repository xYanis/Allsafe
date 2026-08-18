import { useAuth } from '../contexts/AuthContext.jsx'
import PageHero from '../components/PageHero.jsx'
import ReleaseNotesPanel from '../components/ReleaseNotesPanel.jsx'
import { MODULES } from '../constants/modules.js'

const MODULE_COLOR = MODULES.notesDeVersion.color

// Détaché de Paramètres (18/08/2026, demande explicite) — module à part entière, plus un
// onglet parmi d'autres. Scope "allsafe" uniquement : le changelog de l'agent reste sur sa
// propre page sous Inventaire (/agents/notes-de-version, cf. AgentReleaseNotes.jsx).
export default function ReleaseNotesPage() {
  const { user } = useAuth()
  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"
        title="Notes de version"
        color={MODULE_COLOR}
        subtitle="Nouveautés et correctifs d'Allsafe, par version"
      />

      <ReleaseNotesPanel scope="allsafe" color={MODULE_COLOR} isAdmin={user?.role === 'admin'} showVersionField />
    </div>
  )
}
