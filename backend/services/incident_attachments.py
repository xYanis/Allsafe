"""
services/incident_attachments.py
Pièces jointes PDF du rapport final d'un incident — validation pure (aucune I/O), et
constantes de stockage sur disque partagées avec routers/incidents.py.

Le fichier est toujours renommé ({uuid4()}.pdf) avant écriture sur disque — le nom fourni
par le client (`filename`) n'est conservé qu'en métadonnée pour l'affichage/téléchargement,
jamais utilisé comme chemin réel (path traversal).
"""

import os

MAX_SIZE = 5 * 1024 * 1024  # 5 Mo
ATTACHMENTS_ROOT = "/app/incident_attachments"
PDF_MAGIC = b"%PDF-"


def validate_pdf(content: bytes, filename: str) -> None:
    """Lève ValueError si le contenu n'est pas un PDF exploitable :
    - taille nulle ou > 5 Mo
    - pas d'extension .pdf
    - signature de fichier absente (les 5 premiers octets doivent être "%PDF-" — un
      renommage grossier d'un fichier texte/exécutable en .pdf ne suffit pas à passer)."""
    if not content:
        raise ValueError("Fichier vide.")
    if len(content) > MAX_SIZE:
        raise ValueError(f"Fichier trop volumineux ({len(content) / 1024 / 1024:.1f} Mo) — 5 Mo maximum.")
    if not filename.lower().endswith(".pdf"):
        raise ValueError("Seuls les fichiers .pdf sont acceptés.")
    if not content.startswith(PDF_MAGIC):
        raise ValueError("Le contenu du fichier ne correspond pas à un PDF valide.")


def incident_dir(incident_id: str) -> str:
    return os.path.join(ATTACHMENTS_ROOT, str(incident_id))


def ensure_incident_dir(incident_id: str) -> str:
    path = incident_dir(incident_id)
    os.makedirs(path, exist_ok=True)
    return path
