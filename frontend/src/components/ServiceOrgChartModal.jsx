import ServiceIcon from './ServiceIcon.jsx'

// Une boîte-poste du mini organigramme (rectangle relié à son N+1 par un trait, cf. OrgNode
// ci-dessous). Couleur reprise du service — l'organigramme reste lisible même sans branding riche.
function NodeBox({ role, color }) {
  return (
    <div className="rounded-xl px-3 py-2 whitespace-nowrap"
      style={{ background: 'var(--bg-card)', border: `1px solid ${color}59`, minWidth: 120, maxWidth: 180 }}>
      <p className="text-[10px] font-semibold uppercase tracking-wide truncate" style={{ color }}>{role.position}</p>
      <p className="text-xs font-medium truncate mt-0.5" style={{ color: 'var(--text-primary)' }}>{role.name}</p>
    </div>
  )
}

// Nœud récursif : boîte + traits vers ses subordonnés directs (pattern CSS classique
// d'organigramme — trait vertical descendant, trait horizontal reliant les enfants entre eux,
// trait vertical vers chaque boîte enfant). `visited` : garde-fou de rendu contre un cycle
// résiduel (empêché côté API, mais on ne veut jamais boucler indéfiniment ici en cas d'anomalie).
function OrgNode({ role, childrenByManager, color, visited }) {
  if (visited.has(role.id)) return null
  const nextVisited = new Set(visited)
  nextVisited.add(role.id)
  const kids = childrenByManager.get(role.id) || []

  return (
    <div className="flex flex-col items-center">
      <NodeBox role={role} color={color} />
      {kids.length > 0 && (
        <>
          <div style={{ width: 1, height: 14, background: `${color}59` }} />
          <div className="flex items-start">
            {kids.map((k, i) => (
              <div key={k.id} className="relative flex flex-col items-center px-3">
                <span className="absolute top-0 h-px" style={{
                  left: i === 0 ? '50%' : 0,
                  right: i === kids.length - 1 ? '50%' : 0,
                  background: `${color}59`,
                }} />
                <div style={{ width: 1, height: 14, background: `${color}59` }} />
                <OrgNode role={k} childrenByManager={childrenByManager} color={color} visited={nextVisited} />
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

// Mini organigramme d'un service (31/07/2026) — hiérarchie construite depuis
// OrganizationRole.reports_to_id. Un poste dont le supérieur est rattaché à un AUTRE service (ou
// n'a pas de supérieur) est traité comme racine ici : cette vue ne montre que la hiérarchie interne
// au service, pas la chaîne complète jusqu'à la direction générale.
export default function ServiceOrgChartModal({ service, roles, onClose }) {
  const serviceRoles = roles.filter(r => r.service_id === service.id)
  const idSet = new Set(serviceRoles.map(r => r.id))

  const childrenByManager = new Map()
  for (const r of serviceRoles) {
    if (r.reports_to_id && idSet.has(r.reports_to_id)) {
      if (!childrenByManager.has(r.reports_to_id)) childrenByManager.set(r.reports_to_id, [])
      childrenByManager.get(r.reports_to_id).push(r)
    }
  }
  const roots = serviceRoles.filter(r => !r.reports_to_id || !idSet.has(r.reports_to_id))

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-3xl w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', maxHeight: '85vh' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
              style={{ background: `${service.color}22`, color: service.color }}>
              <ServiceIcon icon={service.icon} size={15} />
            </div>
            <h2 className="font-semibold" style={{ color: service.color }}>Organigramme — {service.name}</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 overflow-auto">
          {serviceRoles.length === 0 ? (
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucun poste rattaché à ce service.</p>
          ) : (
            <div className="flex items-start justify-center gap-8 min-w-fit mx-auto">
              {roots.map(r => (
                <OrgNode key={r.id} role={r} childrenByManager={childrenByManager} color={service.color} visited={new Set()} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
