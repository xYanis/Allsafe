// Rendu d'un rapport (résumé exécutif, rapports hebdomadaires figés) : markdown
// → React pour l'écran, et markdown → HTML imprimable pour l'export PDF.
//
// Extrait de Reports.jsx le 22/07/2026, avant l'ajout des rapports Veille et
// Surveillance : les trois pages de rapport ont besoin des mêmes briques, et le
// code enfermé dans une page aurait été dupliqué à chaque nouveau rapport (cf.
// la modale de patch check, dupliquée entre Dashboard.jsx et Vulnerabilities.jsx
// — toute évolution doit y être appliquée deux fois, cf. STATUS.md). Déplacé
// tel quel, sans changement de comportement.
//
// Volontairement **pas** basé sur MarkdownNote.jsx (`marked` + `dompurify`, qui
// sert aux annotations d'analyste) : ce rendu-ci colore les mots de sévérité
// (CRITICAL/ÉLEVÉ/…) et doit produire une seconde sortie HTML autonome pour
// l'impression, deux besoins que `marked` ne couvre pas ici.

// Même échelle que SeverityBadge.jsx (CRITICAL/HIGH/MEDIUM/LOW), étendue aux
// niveaux de risque global du résumé exécutif (CRITIQUE/ÉLEVÉ/MODÉRÉ/FAIBLE).
export const SEVERITY_COLORS = {
  CRITICAL: '#f85149', HIGH: '#fb8f44', MEDIUM: '#d29922', LOW: '#3fb950',
  CRITIQUE: '#f85149', 'ÉLEVÉ': '#fb8f44', 'MODÉRÉ': '#d29922', FAIBLE: '#3fb950',
}
// (?<!\p{L})...(?!\p{L}) plutôt que \b : \b se base sur \w (ASCII uniquement),
// qui ne reconnaît pas les lettres accentuées ("É") comme caractères de mot —
// sans ce correctif, "ÉLEVÉ"/"MODÉRÉ" ne matcheraient jamais en mot entier.
const SEVERITY_REGEX = new RegExp(`(?<![\\p{L}])(${Object.keys(SEVERITY_COLORS).join('|')})(?![\\p{L}])`, 'gu')

function colorizeSeverity(text, keyPrefix) {
  if (!text) return text
  const out = []
  let last = 0
  let m
  let i = 0
  SEVERITY_REGEX.lastIndex = 0
  while ((m = SEVERITY_REGEX.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index))
    out.push(
      <span key={`${keyPrefix}-${i++}`} style={{ color: SEVERITY_COLORS[m[1]], fontWeight: 700 }}>{m[1]}</span>
    )
    last = SEVERITY_REGEX.lastIndex
  }
  if (last < text.length) out.push(text.slice(last))
  return out.length ? out : text
}

// Rendu inline **gras**, *italique* et [texte](url) (liens — pièces jointes du
// rapport Incidents, cf. incident_report.py) + coloration des mots de
// sévérité/risque (CRITICAL/HIGH/.../FAIBLE), y compris à l'intérieur d'un
// passage en gras (ex: "**Niveau de risque global : FAIBLE**"). Les liens ne
// sont interprétés que pour l'affichage à l'écran (`renderMd`) — `exportPdf`
// ci-dessous reste volontairement inchangé, une fenêtre d'impression statique
// n'a pas d'usage réel pour un lien de téléchargement relatif à l'app.
function Inline({ text }) {
  const regex = /\*\*(.*?)\*\*|\*(.*?)\*|\[([^\]]+)\]\(([^)]+)\)/g
  const parts = []
  let last = 0
  let m
  let key = 0
  while ((m = regex.exec(text))) {
    if (m.index > last) parts.push(<span key={key++}>{colorizeSeverity(text.slice(last, m.index), `n${key}`)}</span>)
    if (m[1] !== undefined) {
      parts.push(<strong key={key++} style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{colorizeSeverity(m[1], `b${key}`)}</strong>)
    } else if (m[2] !== undefined) {
      parts.push(<em key={key++} style={{ color: 'var(--text-muted)' }}>{colorizeSeverity(m[2], `i${key}`)}</em>)
    } else {
      parts.push(<a key={key++} href={m[4]} target="_blank" rel="noopener noreferrer" className="hover:underline" style={{ color: '#58a6ff' }}>{m[3]}</a>)
    }
    last = regex.lastIndex
  }
  if (last < text.length) parts.push(<span key={key++}>{colorizeSeverity(text.slice(last), `n${key}`)}</span>)
  return parts
}

const isTableSeparator = line => /^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(line.trim())
const parseTableRow = line => line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim())

function MdTable({ headerCells, rows }) {
  return (
    <div className="overflow-x-auto mb-3 rounded-lg" style={{ border: '1px solid var(--border)' }}>
      <table className="w-full text-xs">
        <thead>
          <tr style={{ background: 'var(--bg-secondary)' }}>
            {headerCells.map((h, i) => (
              <th key={i} className="text-left px-3 py-2 font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, ri) => (
            <tr key={ri} style={{ borderTop: '1px solid var(--border-subtle)' }}>
              {row.map((cell, ci) => (
                <td key={ci} className="px-3 py-2 align-top" style={{ color: 'var(--text-secondary)' }}><Inline text={cell} /></td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function renderMd(text) {
  const lines = text.split('\n')
  const elements = []
  let listItems = []
  let key = 0

  function flushList() {
    if (listItems.length === 0) return
    elements.push(
      <ul key={key++} className="space-y-1 mb-3 pl-5" style={{ listStyleType: 'disc', color: 'var(--text-secondary)' }}>
        {listItems}
      </ul>
    )
    listItems = []
  }

  let i = 0
  while (i < lines.length) {
    const line = lines[i].trimEnd()

    // Tableau markdown : ligne d'en-tête "| a | b |" suivie d'un séparateur "|---|---|"
    if (line.trim().startsWith('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
      flushList()
      const headerCells = parseTableRow(line)
      i += 2
      const rows = []
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        rows.push(parseTableRow(lines[i]))
        i++
      }
      elements.push(<MdTable key={key++} headerCells={headerCells} rows={rows} />)
      continue
    }

    if (line.startsWith('### ')) {
      flushList()
      elements.push(<h3 key={key++} className="text-sm font-semibold mt-3 mb-1" style={{ color: 'var(--text-secondary)' }}><Inline text={line.slice(4)} /></h3>)
    } else if (line.startsWith('## ')) {
      flushList()
      elements.push(<h2 key={key++} className="text-base font-semibold mt-5 mb-2 pb-1" style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-subtle)' }}><Inline text={line.slice(3)} /></h2>)
    } else if (line.startsWith('# ')) {
      flushList()
      elements.push(<h1 key={key++} className="text-xl font-bold mt-1 mb-3 pb-2" style={{ color: 'var(--text-primary)', borderBottom: '1px solid var(--border)' }}><Inline text={line.slice(2)} /></h1>)
    } else if (line.startsWith('- ') || line.startsWith('* ')) {
      listItems.push(<li key={key++} className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}><Inline text={line.slice(2)} /></li>)
    } else if (line.trim() === '') {
      flushList()
    } else {
      flushList()
      elements.push(<p key={key++} className="text-sm leading-relaxed mb-2" style={{ color: 'var(--text-secondary)' }}><Inline text={line} /></p>)
    }
    i++
  }
  flushList()
  return elements
}

export function exportPdf(markdownText) {
  const date = new Date().toLocaleDateString('fr-FR')
  const colorizeHtml = s => s.replace(
    SEVERITY_REGEX, m => `<span style="color:${SEVERITY_COLORS[m]};font-weight:700">${m}</span>`
  )
  const inline = s => colorizeHtml(s)
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')

  const lines = markdownText.split('\n')
  const htmlParts = []
  let i = 0
  while (i < lines.length) {
    const l = lines[i].trimEnd()

    if (l.trim().startsWith('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
      const header = parseTableRow(l)
      i += 2
      const rows = []
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        rows.push(parseTableRow(lines[i]))
        i++
      }
      htmlParts.push(
        '<table><thead><tr>' +
        header.map(h => `<th>${inline(h)}</th>`).join('') +
        '</tr></thead><tbody>' +
        rows.map(r => '<tr>' + r.map(c => `<td>${inline(c)}</td>`).join('') + '</tr>').join('') +
        '</tbody></table>'
      )
      continue
    }

    if (l.startsWith('# '))        htmlParts.push(`<h1>${inline(l.slice(2))}</h1>`)
    else if (l.startsWith('## '))  htmlParts.push(`<h2>${inline(l.slice(3))}</h2>`)
    else if (l.startsWith('### ')) htmlParts.push(`<h3>${inline(l.slice(4))}</h3>`)
    else if (l.startsWith('- ') || l.startsWith('* ')) htmlParts.push(`<li>${inline(l.slice(2))}</li>`)
    else if (l.trim() === '') htmlParts.push('<br>')
    else htmlParts.push(`<p>${inline(l)}</p>`)
    i++
  }
  const bodyHtml = htmlParts.join('\n').replace(/(<li>[\s\S]*?<\/li>(\n|<br>)*)+/g, m => `<ul>${m}</ul>`)

  const html = `<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
<title>Rapport CyberVuln — ${date}</title>
<style>
  @page { margin: 20mm 18mm; }
  body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 11pt; color: #1a1a2e; line-height: 1.6; }
  h1 { font-size: 18pt; color: #0d1b4b; border-bottom: 2px solid #1f6feb; padding-bottom: 6px; margin-top: 0; }
  h2 { font-size: 13pt; color: #1a1a2e; border-bottom: 1px solid #d0d7de; padding-bottom: 4px; margin-top: 20px; }
  h3 { font-size: 11pt; color: #333; margin-top: 14px; }
  p  { margin: 4px 0 8px; } ul { padding-left: 18px; margin: 4px 0 10px; } li { margin-bottom: 3px; }
  strong { color: #0d1b4b; } em { color: #555; font-style: italic; }
  table { width: 100%; border-collapse: collapse; margin: 6px 0 14px; font-size: 9.5pt; }
  th, td { border: 1px solid #d0d7de; padding: 4px 8px; text-align: left; vertical-align: top; }
  th { background: #f3f4f6; font-weight: 600; }
  .header { display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; padding-bottom:12px; border-bottom:3px solid #1f6feb; }
  .header-logo { font-size:16pt; font-weight:700; color:#1f6feb; } .header-date { font-size:9pt; color:#666; }
</style></head><body>
<div class="header"><div class="header-logo">CyberVuln</div><div class="header-date">Généré le ${date}</div></div>
${bodyHtml}</body></html>`

  // `window.open` renvoie null si le navigateur bloque la fenêtre (bloqueur de
  // pop-up, très courant sur une fenêtre dimensionnée comme celle-ci). Sans ce
  // garde-fou, `w.document` lève un TypeError et le bouton "Exporter PDF" ne
  // fait *rien* de visible — l'utilisateur n'a aucun moyen de comprendre pourquoi.
  const w = window.open('', '_blank', 'width=900,height=700')
  if (!w) return false
  w.document.write(html)
  w.document.close()
  w.focus()
  setTimeout(() => { w.print() }, 400)
  return true
}
