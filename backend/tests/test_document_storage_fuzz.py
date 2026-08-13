"""
tests/test_document_storage_fuzz.py
Fuzzing par propriétés (hypothesis) de services/document_storage.py — validation
des documents uploadés (magic bytes, taille, extension).
"""
from hypothesis import HealthCheck, assume, given, settings, strategies as st

from services.document_storage import ALLOWED_SIGNATURES, MAX_SIZE, validate_document


@given(content=st.binary(max_size=2000), filename=st.text(max_size=100))
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_never_crashes_on_arbitrary_input(content, filename):
    """Contenu et nom de fichier arbitraires (binaire quelconque, unicode exotique,
    sans extension, extension inconnue...) : jamais d'exception autre que ValueError.
    Invariant si accepté : le contenu commence bien par la signature de l'extension
    retournée, et la taille respecte les bornes annoncées."""
    try:
        ext = validate_document(content, filename)
        assert content.startswith(ALLOWED_SIGNATURES[ext])
        assert 0 < len(content) <= MAX_SIZE
    except ValueError:
        pass


@given(ext=st.sampled_from(sorted(ALLOWED_SIGNATURES)), garbage=st.binary(max_size=50))
@settings(max_examples=300)
def test_wrong_signature_always_rejected(ext, garbage):
    """Un contenu qui ne commence pas par la signature attendue pour l'extension
    déclarée est toujours rejeté."""
    magic = ALLOWED_SIGNATURES[ext]
    assume(not garbage.startswith(magic) and garbage != b"")
    try:
        validate_document(garbage, f"file{ext}")
        assert False, "aurait dû être rejeté (signature incorrecte)"
    except ValueError:
        pass
