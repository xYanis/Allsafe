import { useState } from 'react'
import { sourceColor } from '../utils/watchVisuals.js'

// Favicon du site source (23/08/2026, demande explicite — "les vrais logos des sites") via
// le service public Google (image statique, chargée par le NAVIGATEUR — jamais par notre
// backend, même principe que `image_url` : aucune requête serveur ajoutée ici). Dérivé de
// `item.url` plutôt que d'une liste de domaines codée en dur par source : marche aussi bien
// pour CERT-FR/ANSSI que pour une source RSS personnalisée ajoutée par l'utilisateur, sans
// rien à maintenir quand une nouvelle source apparaît (cf. CLAUDE.md § penser scalable).
// `null` si `item.url` est une urn: de repli (pas de lien réel, cf. watch_fetcher.py
// ::_stable_url) ou un domaine invalide.
function faviconUrl(item) {
  try {
    const u = new URL(item.url)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    if (!u.hostname) return null
    return `https://www.google.com/s2/favicons?sz=64&domain=${u.hostname}`
  } catch {
    return null
  }
}

// Vignette d'un item de veille : l'image du flux source si le flux en fournit une (cf.
// backend/services/watch_fetcher.py::_extract_image — jamais de requête HTTP dédiée côté
// serveur), sinon le favicon du site source, sinon une pastille colorée à l'initiale de la
// source. Fond CERT-FR/ANSSI quasi toujours ce 2e ou 3e cas (bulletins texte sans image) —
// le repli n'est pas un état d'erreur, c'est le cas normal pour la majorité des sources.
// `onError` fait redescendre d'un cran (image → favicon → initiale) si un palier échoue.
export default function WatchThumbnail({ item, size = 40, rounded = 10 }) {
  const [imageErrored, setImageErrored] = useState(false)
  const [faviconErrored, setFaviconErrored] = useState(false)
  const color = sourceColor(item.source)

  if (item.image_url && !imageErrored) {
    return (
      <img
        src={item.image_url} alt="" loading="lazy" onError={() => setImageErrored(true)}
        style={{
          width: size, height: size, borderRadius: rounded, objectFit: 'cover',
          flexShrink: 0, background: 'var(--bg-secondary)', border: '1px solid var(--border)',
        }}
      />
    )
  }

  const favicon = faviconUrl(item)
  if (favicon && !faviconErrored) {
    return (
      <span style={{
        width: size, height: size, borderRadius: rounded, flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
      }}>
        {/* Favicon quasi toujours plus petit que la vignette (16-64px selon le site) —
            volontairement PAS étiré à `size` (objectFit: contain, pas cover) : un favicon
            flou en plein cadre serait pire qu'une petite icône nette et centrée. */}
        <img src={favicon} alt="" loading="lazy" onError={() => setFaviconErrored(true)}
          style={{ width: '60%', height: '60%', objectFit: 'contain' }} />
      </span>
    )
  }

  const initial = (item.source_label || item.source || '?').trim().charAt(0).toUpperCase()
  return (
    <span
      style={{
        width: size, height: size, borderRadius: rounded, flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: `color-mix(in srgb, ${color} 18%, transparent)`, color,
        fontWeight: 700, fontSize: Math.round(size * 0.4), fontFamily: 'var(--font-mono)',
      }}
    >
      {initial}
    </span>
  )
}
