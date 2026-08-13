import { marked } from 'marked'
import DOMPurify from 'dompurify'

marked.setOptions({ breaks: true })

// Rendu Markdown des annotations d'analyste (notes libres saisies dans
// AnnotationModal). Sanitizé via DOMPurify avant dangerouslySetInnerHTML :
// plusieurs analystes se partagent ces notes, une note ne doit pas pouvoir
// exécuter du script dans le navigateur d'un collègue.
export default function MarkdownNote({ text, className = 'text-sm', style }) {
  if (!text) return null
  const html = DOMPurify.sanitize(marked.parse(text))
  return (
    <div
      className={`markdown-note ${className}`}
      style={{ color: 'var(--text-secondary)', ...style }}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  )
}
