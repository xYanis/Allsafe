"""
services/document_storage.py
Documents de gouvernance (module Documentation, conformité NIS 2) — validation pure (aucune I/O),
et constantes de stockage sur disque partagées avec routers/documents.py.

Le fichier est toujours renommé ({uuid4()}{ext}) avant écriture sur disque — le nom fourni par le
client (`filename`) n'est conservé qu'en métadonnée pour l'affichage/téléchargement, jamais
utilisé comme chemin réel (path traversal). Même principe qu'incident_attachments.py, étendu à
plusieurs formats (PDF, Word, Excel, PNG/JPEG — un organigramme est souvent une image) plutôt
qu'un seul.

Prévisualisation navigateur (31/07/2026) : PDF et images s'affichent nativement dans un
navigateur, Word/Excel non (aucune API web ne peut déclencher l'application native depuis une
page — ça demanderait une intégration WOPI/Office Online, hors de portée ici). `PREVIEWABLE`
distingue les deux pour `routers/documents.py` (Content-Disposition inline vs attachment).
"""

import os

MAX_SIZE = 10 * 1024 * 1024  # 10 Mo — documents de gouvernance avec schémas/organigrammes
DOCUMENTS_ROOT = "/app/documents"

# Signature de fichier (magic bytes) par extension — un renommage grossier d'un fichier
# quelconque en .pdf/.docx ne suffit pas à passer (même garde-fou que validate_pdf existant).
# .docx/.xlsx (Office Open XML) sont des archives ZIP ; .doc/.xls legacy sont des containers OLE2.
_ZIP_MAGIC = b"PK\x03\x04"
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ALLOWED_SIGNATURES = {
    ".pdf": b"%PDF-",
    ".docx": _ZIP_MAGIC,
    ".xlsx": _ZIP_MAGIC,
    ".doc": _OLE2_MAGIC,
    ".xls": _OLE2_MAGIC,
    ".png": b"\x89PNG\r\n\x1a\n",
    ".jpg": b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
}

# Formats que le navigateur affiche nativement (Content-Disposition: inline possible) — les
# autres restent en "attachment" (téléchargement forcé, ouverts ensuite par l'OS via l'appli
# associée). Type MIME explicite : plus fiable que la déduction automatique de Starlette.
CONTENT_TYPES = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".doc": "application/msword",
    ".xls": "application/vnd.ms-excel",
}
PREVIEWABLE = {".pdf", ".png", ".jpg", ".jpeg"}


def validate_document(content: bytes, filename: str) -> str:
    """Lève ValueError si le contenu n'est pas exploitable :
    - taille nulle ou > 10 Mo
    - extension hors PDF/Word/Excel/PNG/JPEG
    - signature de fichier absente/incorrecte pour l'extension déclarée
    Retourne l'extension validée (en minuscules, avec le point) — pour construire
    `stored_filename` côté appelant."""
    if not content:
        raise ValueError("Fichier vide.")
    if len(content) > MAX_SIZE:
        raise ValueError(f"Fichier trop volumineux ({len(content) / 1024 / 1024:.1f} Mo) — 10 Mo maximum.")
    ext = os.path.splitext(filename.lower())[1]
    magic = ALLOWED_SIGNATURES.get(ext)
    if magic is None:
        raise ValueError("Formats acceptés : PDF, Word (.doc/.docx), Excel (.xls/.xlsx), image (.png/.jpg/.jpeg).")
    if not content.startswith(magic):
        raise ValueError(f"Le contenu du fichier ne correspond pas à un {ext} valide.")
    return ext


def document_type_dir(document_type_id: str) -> str:
    return os.path.join(DOCUMENTS_ROOT, str(document_type_id))


def ensure_document_type_dir(document_type_id: str) -> str:
    path = document_type_dir(document_type_id)
    os.makedirs(path, exist_ok=True)
    return path
