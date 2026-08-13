"""
services/audit_attachments.py
Pièces jointes du module Audits — validation pure (aucune I/O), et constantes de stockage
sur disque partagées avec routers/audits.py. Deux usages de la même table (AuditAttachment) :
le mandat écrit d'un audit, les captures d'écran de preuve d'un finding.

Calqué sur services/incident_attachments.py (limite de taille, renommage systématique du
fichier avant écriture — path traversal) mais étendu à PNG/JPEG en plus du PDF, comme
services/document_storage.py : un mandat scanné ou une capture d'écran de preuve sont
souvent des images, pas seulement des PDF.
"""

import os

MAX_SIZE = 5 * 1024 * 1024  # 5 Mo, même limite qu'incident_attachments.py
ATTACHMENTS_ROOT = "/app/audit_attachments"

ALLOWED_SIGNATURES = {
    ".pdf": b"%PDF-",
    ".png": b"\x89PNG\r\n\x1a\n",
    ".jpg": b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
}


def validate_attachment(content: bytes, filename: str) -> str:
    """Lève ValueError si le contenu n'est pas exploitable :
    - taille nulle ou > 5 Mo
    - extension hors PDF/PNG/JPEG
    - signature de fichier absente/incorrecte pour l'extension déclarée (un renommage
      grossier d'un fichier quelconque ne suffit pas à passer).
    Retourne l'extension validée (en minuscules, avec le point)."""
    if not content:
        raise ValueError("Fichier vide.")
    if len(content) > MAX_SIZE:
        raise ValueError(f"Fichier trop volumineux ({len(content) / 1024 / 1024:.1f} Mo) — 5 Mo maximum.")
    ext = os.path.splitext(filename.lower())[1]
    magic = ALLOWED_SIGNATURES.get(ext)
    if magic is None:
        raise ValueError("Formats acceptés : PDF, image (.png/.jpg/.jpeg).")
    if not content.startswith(magic):
        raise ValueError(f"Le contenu du fichier ne correspond pas à un {ext} valide.")
    return ext


def audit_dir(audit_id: str) -> str:
    return os.path.join(ATTACHMENTS_ROOT, str(audit_id))


def ensure_audit_dir(audit_id: str) -> str:
    path = audit_dir(audit_id)
    os.makedirs(path, exist_ok=True)
    return path
