"""
tests/test_audit_attachments.py
Validation des pièces jointes du module Audits (services/audit_attachments.py) — mandat
d'audit ou preuve de finding, PDF/PNG/JPEG, 5 Mo max, signature de fichier obligatoire.
Tests unitaires purs : contenu en mémoire, aucune I/O disque réelle (mêmes conventions
que test_incident_attachments.py).
"""

import pytest

from services.audit_attachments import validate_attachment, MAX_SIZE, ALLOWED_SIGNATURES


def _content_for(ext: str, size: int | None = None) -> bytes:
    magic = ALLOWED_SIGNATURES[ext]
    body = magic + b"0" * 32
    if size is None:
        return body
    if size < len(magic):
        return magic[:size]
    return magic + b"0" * (size - len(magic))


class TestValidateAttachment:
    @pytest.mark.parametrize("ext", sorted(ALLOWED_SIGNATURES))
    def test_valid_content_accepted_for_each_format(self, ext):
        returned = validate_attachment(_content_for(ext), f"preuve{ext}")
        assert returned == ext

    @pytest.mark.parametrize("ext", sorted(ALLOWED_SIGNATURES))
    def test_case_insensitive_extension(self, ext):
        validate_attachment(_content_for(ext), f"PREUVE{ext.upper()}")

    def test_empty_content_rejected(self):
        with pytest.raises(ValueError, match="vide"):
            validate_attachment(b"", "mandat.pdf")

    def test_oversized_content_rejected(self):
        content = _content_for(".pdf", MAX_SIZE + 1)
        with pytest.raises(ValueError, match="volumineux"):
            validate_attachment(content, "mandat.pdf")

    def test_exactly_max_size_accepted(self):
        content = _content_for(".pdf", MAX_SIZE)
        validate_attachment(content, "mandat.pdf")

    def test_unknown_extension_rejected(self):
        with pytest.raises(ValueError, match="PDF, image"):
            validate_attachment(b"%PDF-content", "mandat.docx")

    def test_renamed_non_matching_content_rejected(self):
        """Un fichier renommé avec la bonne extension mais le mauvais contenu ne passe pas
        la signature (ex. texte brut renommé en .pdf, PDF renommé en .png)."""
        with pytest.raises(ValueError, match="ne correspond pas"):
            validate_attachment(b"this is plain text, not a pdf", "mandat.pdf")
        with pytest.raises(ValueError, match="ne correspond pas"):
            validate_attachment(_content_for(".pdf"), "preuve.png")

    def test_missing_extension_rejected(self):
        with pytest.raises(ValueError, match="PDF, image"):
            validate_attachment(b"%PDF-content", "mandat")
