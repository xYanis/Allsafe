import { useState, useEffect, useMemo } from 'react'
import { watchProfile, saveWatchProfile, previewProfileTerm } from '../api/client.js'

const CARD = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px' }

// Repli si l'API ne répond pas encore avec `categories` (compat pendant un
// déploiement à chaud) — reflète PROFILE_CATEGORIES côté backend
// (services/watch_profile.py), qui reste la source de vérité.
const FALLBACK_CATEGORIES = [
  { kind: 'os', label: "Systèmes d'exploitation", from_inventory: true },
  { kind: 'software', label: 'Logiciels', from_inventory: true },
  { kind: 'firewall', label: 'Firewall / Équipements réseau', from_inventory: false },
  { kind: 'saas', label: 'SaaS / Services cloud', from_inventory: false },
  { kind: 'hardware', label: 'Matériel / Constructeurs', from_inventory: true },
]

// Configuration du profil de veille : ce que le parc utilise réellement, pour
// mettre en avant les éléments de veille qui le concernent — jamais pour
// filtrer la collecte ni retirer quoi que ce soit du registre NIS 2, qui doit
// rester complet (cf. modèle WatchProfileItem).
//
// Deux natures de catégorie, pilotées par `from_inventory` (venu du backend,
// cf. PROFILE_CATEGORIES) :
// - **OS / Logiciels** : proposés depuis l'inventaire réel (Actifs + Inventaire
//   complet) et cochés par l'analyste, jamais importés en bloc (un parc Debian
//   remonte ~300 paquets, quasi tous du bruit).
// - **Firewall / SaaS / Matériel** (session 22/07/2026) : CBR ne scanne que les
//   VM du parc — un pare-feu, un service cloud ou le constructeur d'un serveur
//   n'apparaissent dans aucun relevé automatique. Saisie manuelle uniquement,
//   via la section "Ajouter un terme" en bas, qui cible la catégorie choisie.
export default function WatchProfileModal({ onClose, onSaved }) {
  const [loading, setLoading]   = useState(true)
  const [saving, setSaving]     = useState(false)
  const [error, setError]       = useState('')
  const [categories, setCategories] = useState(FALLBACK_CATEGORIES)
  const [suggestions, setSuggestions] = useState({ os: [], software: [] })
  // Sélection courante : Set de "kind::value", indépendante de l'ordre d'affichage
  const [selected, setSelected] = useState(new Set())
  // Termes hors suggestions d'inventaire, groupés par catégorie — pour OS/
  // Logiciels ce sont les termes saisis à la main ou désinstallés depuis ;
  // pour Firewall/SaaS/Matériel, c'est simplement TOUT ce qui a été ajouté,
  // ces catégories n'ayant aucune suggestion possible.
  const [manualByKind, setManualByKind] = useState({})
  const [search, setSearch]   = useState('')
  const [newTerm, setNewTerm] = useState('')
  const [newTermKind, setNewTermKind] = useState('firewall')
  // Confirmation en direct pendant la saisie (session 22/07/2026) : combien
  // d'éléments du registre correspondent déjà à ce terme. `preview` mémorise
  // le terme réellement vérifié (`preview.term`) pour ne jamais afficher un
  // compte périmé pendant qu'une frappe plus récente est encore en vérification.
  const [preview, setPreview] = useState(null)
  const [previewLoading, setPreviewLoading] = useState(false)

  // Débounce 350ms — sinon chaque frappe interroge le backend, qui doit relire
  // tout le registre (~1600 éléments) pour compter les correspondances.
  useEffect(() => {
    const term = newTerm.trim()
    if (term.length < 2) { setPreview(null); setPreviewLoading(false); return }
    setPreviewLoading(true)
    const handle = setTimeout(() => {
      previewProfileTerm(term)
        .then(r => setPreview(r.data))
        .catch(() => setPreview(null))
        .finally(() => setPreviewLoading(false))
    }, 350)
    return () => clearTimeout(handle)
  }, [newTerm])

  useEffect(() => {
    watchProfile()
      .then(r => {
        const cats = r.data.categories?.length ? r.data.categories : FALLBACK_CATEGORIES
        setCategories(cats)
        setSuggestions(r.data.suggestions || { os: [], software: [] })

        const inventoryKinds = new Set(cats.filter(c => c.from_inventory).map(c => c.kind))
        const known = new Set()
        for (const kind of inventoryKinds) {
          for (const s of (r.data.suggestions?.[kind] || [])) known.add(`${kind}::${s.value.toLowerCase()}`)
        }
        // Un terme enregistré absent de l'inventoire (saisi à la main, ou
        // logiciel désinstallé depuis) doit rester visible et coché — sinon il
        // disparaîtrait silencieusement à la prochaine ouverture.
        const sel = new Set()
        const grouped = {}
        for (const it of (r.data.items || [])) {
          const key = `${it.kind}::${it.value.toLowerCase()}`
          sel.add(key)
          if (!known.has(key)) (grouped[it.kind] ||= []).push(it)
        }
        setSelected(sel)
        setManualByKind(grouped)

        // Cible par défaut du champ "Ajouter un terme" : la première catégorie
        // manuelle-only, plutôt qu'une valeur en dur qui ne survivrait pas à
        // l'ajout d'une 6e catégorie.
        const firstManualOnly = cats.find(c => !c.from_inventory)
        if (firstManualOnly) setNewTermKind(firstManualOnly.kind)
      })
      .catch(() => setError('Impossible de charger le profil de veille.'))
      .finally(() => setLoading(false))
  }, [])

  function toggle(kind, value) {
    const key = `${kind}::${value.toLowerCase()}`
    setSelected(s => {
      const n = new Set(s)
      n.has(key) ? n.delete(key) : n.add(key)
      return n
    })
  }

  function addManual() {
    const value = newTerm.trim()
    if (!value) return
    const key = `${newTermKind}::${value.toLowerCase()}`
    if (!selected.has(key)) {
      setManualByKind(m => ({ ...m, [newTermKind]: [...(m[newTermKind] || []), { kind: newTermKind, value, origin: 'manual' }] }))
      setSelected(s => new Set(s).add(key))
    }
    setNewTerm('')
  }

  // Actifs couverts par les OS cochés. Les suggestions portent déjà la liste des
  // actifs où chaque terme a été vu — le recoupement se fait donc côté client,
  // sans appel supplémentaire.
  const osScopedAssets = useMemo(() => {
    const sel = (suggestions.os || []).filter(o => selected.has(`os::${o.value.toLowerCase()}`))
    if (sel.length === 0) return null              // aucun OS coché = pas de restriction
    return new Set(sel.flatMap(o => o.assets || []))
  }, [suggestions, selected])

  // Logiciels affichés : restreints aux machines des OS cochés, puis à la
  // recherche. Un logiciel déjà coché reste visible même hors périmètre — sinon
  // il disparaîtrait de l'écran tout en restant dans le profil, donc
  // impossible à décocher.
  const filteredSoftware = useMemo(() => {
    const q = search.trim().toLowerCase()
    let list = suggestions.software || []
    if (osScopedAssets) {
      list = list.filter(sw =>
        selected.has(`software::${sw.value.toLowerCase()}`) ||
        (sw.assets || []).some(a => osScopedAssets.has(a))
      )
    }
    return q ? list.filter(s => s.value.toLowerCase().includes(q)) : list
  }, [suggestions, search, osScopedAssets, selected])

  // Tout sélectionner / tout retirer, sur la liste **affichée** (donc filtrée par
  // OS et par recherche) — et non sur toutes les suggestions, ce qui serait un
  // piège : le bouton doit agir sur ce que l'utilisateur a sous les yeux.
  const allShownSelected = filteredSoftware.length > 0
    && filteredSoftware.every(sw => selected.has(`software::${sw.value.toLowerCase()}`))

  function toggleAllShown() {
    setSelected(s => {
      const n = new Set(s)
      for (const sw of filteredSoftware) {
        const key = `software::${sw.value.toLowerCase()}`
        allShownSelected ? n.delete(key) : n.add(key)
      }
      return n
    })
  }

  async function handleSave() {
    setSaving(true)
    setError('')
    // Reconstruit la liste finale depuis la sélection : suggestions cochées
    // (origin=inventory) + termes manuels encore cochés, toutes catégories.
    const items = []
    for (const kind of Object.keys(suggestions)) {
      for (const s of (suggestions[kind] || [])) {
        if (selected.has(`${kind}::${s.value.toLowerCase()}`)) {
          items.push({ kind, value: s.value, origin: 'inventory' })
        }
      }
    }
    for (const list of Object.values(manualByKind)) {
      for (const m of list) {
        if (selected.has(`${m.kind}::${m.value.toLowerCase()}`)) {
          items.push({ kind: m.kind, value: m.value, origin: 'manual' })
        }
      }
    }
    try {
      await saveWatchProfile(items)
      onSaved?.(items.length)
      onClose()
    } catch {
      setError('Erreur lors de l\'enregistrement du profil.')
      setSaving(false)
    }
  }

  const count = selected.size

  function Chip({ kind, value, assets, origin }) {
    const key = `${kind}::${value.toLowerCase()}`
    const on = selected.has(key)
    return (
      <button
        onClick={() => toggle(kind, value)}
        title={assets?.length ? `Détecté sur : ${assets.join(', ')}` : (origin === 'manual' ? 'Ajouté à la main' : undefined)}
        className="text-xs px-2.5 py-1 rounded-lg font-medium transition-colors"
        style={on
          ? { background: 'rgba(88,166,255,0.28)', color: '#79c0ff', border: '1px solid #58a6ff' }
          : { background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
      >
        {on ? '✓ ' : ''}{value}
        {origin === 'manual' && <span className="ml-1 opacity-60">·</span>}
      </button>
    )
  }

  // Section générique pour une catégorie manuelle-only (Firewall/SaaS/
  // Matériel) : pas de suggestion possible, juste les termes déjà ajoutés
  // (via la section "Ajouter un terme") — cochés par construction, tout ce qui
  // y figure a été explicitement saisi par l'analyste.
  function ManualOnlySection({ category }) {
    const items = manualByKind[category.kind] || []
    return (
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>
          {category.label} <span className="font-normal">— saisie manuelle, aucun scan disponible pour cette catégorie</span>
        </p>
        {items.length === 0 ? (
          <p className="text-xs" style={{ color: 'var(--text-faint)' }}>Aucun terme ajouté — utilisez "Ajouter un terme" ci-dessous.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {items.map(m => <Chip key={m.value} {...m} />)}
          </div>
        )}
      </div>
    )
  }

  const manualOnlyCategories = categories.filter(c => !c.from_inventory)

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={onClose}>
      <div className="max-w-3xl w-full max-h-[85vh] flex flex-col rounded-2xl animate-modal-in"
        style={CARD} onClick={e => e.stopPropagation()}>

        <div className="px-6 py-4 flex items-start justify-between gap-4" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="font-semibold text-lg" style={{ color: 'var(--text-primary)' }}>Profil de veille</h2>
            <p className="text-xs mt-1 leading-relaxed" style={{ color: 'var(--text-muted)' }}>
              Cochez ou ajoutez ce que le parc utilise réellement — OS et logiciels proposés depuis
              votre inventaire, le reste (pare-feu, SaaS, constructeurs) saisi à la main. Les éléments
              de veille qui les mentionnent seront marqués
              « <span style={{ color: '#58a6ff' }}>Concerne mon parc</span> » et filtrables.
              <br />
              <strong style={{ color: 'var(--text-secondary)' }}>Rien n'est jamais masqué ni écarté de la collecte</strong> :
              le registre NIS 2 reste complet, le profil sert seulement à trier.
            </p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg flex-shrink-0" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        <div className="overflow-y-auto flex-1 px-6 py-4 space-y-5">
          {error && (
            <div className="text-sm px-4 py-3 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
              {error}
            </div>
          )}

          {loading ? (
            <p className="text-sm text-center py-8" style={{ color: 'var(--text-muted)' }}>Chargement de l'inventaire…</p>
          ) : (
            <>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>
                  Systèmes d'exploitation <span className="font-normal">— détectés sur vos actifs</span>
                </p>
                <div className="flex flex-wrap gap-2">
                  {(suggestions.os || []).length === 0
                    ? <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Aucun OS détecté — lancez un scan d'actif.</span>
                    : suggestions.os.map(o => <Chip key={o.value} kind="os" {...o} />)}
                </div>
                <p className="text-xs mt-1.5" style={{ color: 'var(--text-faint)' }}>
                  {osScopedAssets
                    ? 'La liste des logiciels ci-dessous est restreinte aux machines de ces OS.'
                    : 'Cochez un OS pour ne voir que les logiciels de ces machines.'}
                </p>
              </div>

              <div>
                <div className="flex items-center justify-between gap-3 mb-2 flex-wrap">
                  <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
                    Logiciels{' '}
                    <span className="font-normal">
                      — {filteredSoftware.length}
                      {osScopedAssets
                        ? ' sur les machines des OS cochés'
                        : ` détecté${(suggestions.software || []).length > 1 ? 's' : ''} dans l'inventaire`}
                    </span>
                  </p>
                  <div className="flex items-center gap-2">
                    <button onClick={toggleAllShown} disabled={filteredSoftware.length === 0}
                      className="text-xs px-2.5 py-1.5 rounded-lg font-medium disabled:opacity-40"
                      style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                      {allShownSelected ? 'Tout retirer' : 'Tout sélectionner'}
                    </button>
                    <input
                      value={search} onChange={e => setSearch(e.target.value)}
                      placeholder="Rechercher un logiciel…"
                      className="text-xs rounded-lg px-2.5 py-1.5 outline-none"
                      style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', minWidth: 180 }}
                    />
                  </div>
                </div>
                <div className="flex flex-wrap gap-2 max-h-56 overflow-y-auto p-1">
                  {filteredSoftware.length === 0
                    ? <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Aucun résultat.</span>
                    : filteredSoftware.map(sw => <Chip key={sw.value} kind="software" {...sw} />)}
                </div>
              </div>

              {(manualByKind.os?.length > 0 || manualByKind.software?.length > 0) && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>
                    Ajoutés à la main <span className="font-normal">— absents de l'inventaire</span>
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {[...(manualByKind.os || []), ...(manualByKind.software || [])].map(m => <Chip key={`${m.kind}-${m.value}`} {...m} />)}
                  </div>
                </div>
              )}

              {/* Firewall / SaaS / Matériel — aucune source d'inventoire possible,
                  cf. PROFILE_CATEGORIES côté backend. */}
              {manualOnlyCategories.map(cat => <ManualOnlySection key={cat.kind} category={cat} />)}

              <div>
                <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>
                  Ajouter un terme <span className="font-normal">— pour ce qui n'apparaît dans aucun scan</span>
                </p>
                <div className="flex gap-2">
                  <select
                    value={newTermKind}
                    onChange={e => setNewTermKind(e.target.value)}
                    className="text-sm rounded-lg px-2.5 py-2 outline-none"
                    style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
                  >
                    {categories.map(c => <option key={c.kind} value={c.kind}>{c.label}</option>)}
                  </select>
                  <input
                    value={newTerm}
                    onChange={e => setNewTerm(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addManual() } }}
                    placeholder="Ex : Fortinet, Microsoft 365, Dell…"
                    className="flex-1 text-sm rounded-lg px-3 py-2 outline-none"
                    style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
                  />
                  <button onClick={addManual} disabled={!newTerm.trim()}
                    className="text-sm px-3 py-2 rounded-lg font-medium disabled:opacity-40"
                    style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' }}>
                    Ajouter
                  </button>
                </div>
                {/* Confirmation en direct — jamais bloquante : « 0 correspondance »
                    veut dire « rien pour l'instant », pas « terme invalide ». Le
                    terme peut concerner un pare-feu tout juste acheté, pas encore
                    couvert par la veille collectée. */}
                {newTerm.trim().length >= 2 && (
                  <p className="text-xs mt-1.5 flex items-center gap-1.5"
                    style={{ color: previewLoading || preview?.term !== newTerm.trim() ? 'var(--text-faint)' : (preview.count > 0 ? '#3fb950' : '#d29922') }}>
                    {previewLoading || preview?.term !== newTerm.trim() ? (
                      <>Vérification…</>
                    ) : preview.count > 0 ? (
                      <>✓ {preview.count} élément{preview.count > 1 ? 's' : ''} du registre correspond{preview.count > 1 ? 'ent' : ''} déjà à ce terme</>
                    ) : (
                      <>⚠ Aucune correspondance pour l'instant dans le registre — sera quand même ajouté, pour les futurs éléments</>
                    )}
                  </p>
                )}
              </div>
            </>
          )}
        </div>

        <div className="px-6 py-4 flex items-center justify-between gap-3" style={{ borderTop: '1px solid var(--border)' }}>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            {count} terme{count > 1 ? 's' : ''} sélectionné{count > 1 ? 's' : ''}
          </span>
          <div className="flex gap-2">
            <button onClick={onClose}
              className="text-sm px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
              Annuler
            </button>
            <button onClick={handleSave} disabled={saving || loading}
              className="text-sm px-4 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: 'var(--accent-blue)', color: '#fff', border: 'none' }}>
              {saving ? 'Enregistrement…' : 'Enregistrer le profil'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
