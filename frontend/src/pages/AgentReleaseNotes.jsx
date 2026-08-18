import { Link } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext.jsx'
import PageHero from '../components/PageHero.jsx'
import ReleaseNotesPanel from '../components/ReleaseNotesPanel.jsx'
import { MODULES } from '../constants/modules.js'

const MODULE_COLOR = MODULES.inventaire.color

// Notes de version de l'agent allsafe-agent (18/08/2026, demande explicite) — même esprit
// que AgentHistory.jsx ("dernier contact") repris ici : lien retour discret, PageHero couleur
// Inventaire, cartes teintées. `version` prend ici le vrai sens du semver du binaire (cf.
// CURRENT_AGENT_VERSION, routers/agents.py) — contrairement au scope "allsafe" (Paramètres),
// où la version n'a pas d'équivalent aussi précis, ReleaseNotesPanel::showVersionField
// n'apparaît que pour ce scope-ci.
export default function AgentReleaseNotes() {
  const { user } = useAuth()
  return (
    <div className="p-6 space-y-5">
      <Link to="/agents" className="text-xs inline-block" style={{ color: MODULE_COLOR }}>← Retour aux agents</Link>

      <PageHero
        icon="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"
        title="Notes de version — Agent"
        color={MODULE_COLOR}
        subtitle="Nouveautés et correctifs du binaire allsafe-agent, par version"
      />

      <ReleaseNotesPanel scope="agent" color={MODULE_COLOR} isAdmin={user?.role === 'admin'} showVersionField />
    </div>
  )
}
