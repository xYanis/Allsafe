"""
tests/test_document_storage.py
Validation des documents de gouvernance (services/document_storage.py) — PDF/Word/Excel/
PNG/JPEG, 10 Mo max, signature de fichier obligatoire par format (ZIP OOXML pour
docx/xlsx, OLE2 legacy pour doc/xls). Tests unitaires purs : contenu en mémoire, aucune
I/O disque réelle (mêmes conventions que test_incident_attachments.py).
"""

import pytest

from services.document_storage import validate_document, MAX_SIZE, ALLOWED_SIGNATURES


def _content_for(ext: str, size: int | None = None) -> bytes:
    magic = ALLOWED_SIGNATURES[ext]
    body = magic + b"0" * 32
    if size is None:
        return body
    if size < len(magic):
        return magic[:size]
    return magic + b"0" * (size - len(magic))


class TestValidateDocument:
    @pytest.mark.parametrize("ext", sorted(ALLOWED_SIGNATURES))
    def test_valid_content_accepted_for_each_format(self, ext):
        returned = validate_document(_content_for(ext), f"organigramme{ext}")
        assert returned == ext

    @pytest.mark.parametrize("ext", sorted(ALLOWED_SIGNATURES))
    def test_case_insensitive_extension(self, ext):
        validate_document(_content_for(ext), f"ORGANIGRAMME{ext.upper()}")

    def test_empty_content_rejected(self):
        with pytest.raises(ValueError, match="vide"):
            validate_document(b"", "pssi.pdf")

    def test_oversized_content_rejected(self):
        content = _content_for(".pdf", MAX_SIZE + 1)
        with pytest.raises(ValueError, match="volumineux"):
            validate_document(content, "pssi.pdf")

    def test_exactly_max_size_accepted(self):
        content = _content_for(".pdf", MAX_SIZE)
        validate_document(content, "pssi.pdf")

    def test_unknown_extension_rejected(self):
        with pytest.raises(ValueError, match="PDF, Word"):
            validate_document(b"%PDF-content", "pssi.txt")

    def test_renamed_non_matching_content_rejected(self):
        """Un fichier renommé avec la bonne extension mais le mauvais contenu ne passe pas
        la signature (texte brut en .pdf, ZIP OOXML .docx renommé en .xlsx reste accepté
        car la signature ZIP est partagée — c'est .doc/.xls OLE2 qui doit rejeter un ZIP)."""
        with pytest.raises(ValueError, match="ne correspond pas"):
            validate_document(b"this is plain text, not a pdf", "pssi.pdf")
        with pytest.raises(ValueError, match="ne correspond pas"):
            validate_document(_content_for(".pdf"), "organigramme.png")
        with pytest.raises(ValueError, match="ne correspond pas"):
            validate_document(_content_for(".docx"), "charte.doc")

    def test_missing_extension_rejected(self):
        with pytest.raises(ValueError, match="PDF, Word"):
            validate_document(b"%PDF-content", "pssi")
