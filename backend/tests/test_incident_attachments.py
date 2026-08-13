"""
tests/test_incident_attachments.py
Validation des pièces jointes PDF du rapport final (services/incident_attachments.py) —
5 Mo max, signature de fichier obligatoire. Tests unitaires purs : contenu en mémoire,
aucune I/O disque réelle (cf. test_nis2_deadlines.py pour les mêmes conventions).
"""

import pytest

from services.incident_attachments import validate_pdf, MAX_SIZE, PDF_MAGIC


def _pdf_bytes(size: int) -> bytes:
    body = PDF_MAGIC + b"\n" + b"0" * max(0, size - len(PDF_MAGIC) - 1)
    return body[:size] if size >= len(PDF_MAGIC) else PDF_MAGIC


class TestValidatePdf:
    def test_valid_pdf_accepted(self):
        validate_pdf(PDF_MAGIC + b"%%EOF small valid-looking pdf content", "rapport.pdf")

    def test_empty_content_rejected(self):
        with pytest.raises(ValueError, match="vide"):
            validate_pdf(b"", "rapport.pdf")

    def test_oversized_content_rejected(self):
        content = _pdf_bytes(MAX_SIZE + 1)
        with pytest.raises(ValueError, match="volumineux"):
            validate_pdf(content, "rapport.pdf")

    def test_exactly_max_size_accepted(self):
        content = _pdf_bytes(MAX_SIZE)
        validate_pdf(content, "rapport.pdf")

    def test_non_pdf_extension_rejected(self):
        with pytest.raises(ValueError, match=r"\.pdf"):
            validate_pdf(PDF_MAGIC + b"content", "rapport.txt")

    def test_renamed_non_pdf_rejected(self):
        """Un fichier texte/exécutable renommé en .pdf ne passe pas la signature."""
        with pytest.raises(ValueError, match="PDF valide"):
            validate_pdf(b"this is plain text, not a pdf", "rapport.pdf")

    def test_case_insensitive_extension(self):
        validate_pdf(PDF_MAGIC + b"content", "RAPPORT.PDF")
