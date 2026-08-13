"""
services/note_images.py
Images insérées dans un sujet du module Notes — validation pure (aucune I/O) et
constantes de stockage sur disque, même principe que document_storage.py restreint
aux formats image (un sujet de cours n'a pas besoin de Word/Excel/PDF en pièce
jointe, seulement des captures d'écran/schémas insérés inline via Markdown).
"""

import os

MAX_SIZE = 5 * 1024 * 1024  # 5 Mo — captures d'écran/schémas, pas de gros scans
NOTE_IMAGES_ROOT = "/app/note_images"

ALLOWED_SIGNATURES = {
    ".png": b"\x89PNG\r\n\x1a\n",
    ".jpg": b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
    ".gif": b"GIF8",
    ".webp": b"RIFF",  # RIFF....WEBP — préfixe RIFF suffisant, "WEBP" est à l'offset 8
}
CONTENT_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
}


def validate_note_image(content: bytes, filename: str) -> str:
    """Lève ValueError si le contenu n'est pas exploitable. Retourne l'extension
    validée (en minuscules, avec le point)."""
    if not content:
        raise ValueError("Fichier vide.")
    if len(content) > MAX_SIZE:
        raise ValueError(f"Image trop volumineuse ({len(content) / 1024 / 1024:.1f} Mo) — 5 Mo maximum.")
    ext = os.path.splitext(filename.lower())[1]
    magic = ALLOWED_SIGNATURES.get(ext)
    if magic is None:
        raise ValueError("Formats acceptés : PNG, JPEG, GIF, WebP.")
    if not content.startswith(magic):
        raise ValueError(f"Le contenu du fichier ne correspond pas à un {ext} valide.")
    return ext


def ensure_note_images_dir() -> str:
    os.makedirs(NOTE_IMAGES_ROOT, exist_ok=True)
    return NOTE_IMAGES_ROOT
