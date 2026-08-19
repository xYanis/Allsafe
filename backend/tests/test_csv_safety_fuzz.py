"""
tests/test_csv_safety_fuzz.py
Fuzzing par propriétés (hypothesis) de services/csv_safety.py — neutralisation de
l'injection de formule CSV/Excel (cf. audit/AUDIT_SECURITE.md #7).
"""
from hypothesis import given, settings, strategies as st

from services.csv_safety import csv_safe

_DANGEROUS_FIRST_CHARS = ("=", "+", "-", "@", "\t", "\r")


@given(value=st.text(max_size=500))
@settings(max_examples=500)
def test_output_never_starts_with_dangerous_char(value):
    """Propriété centrale : quelle que soit l'entrée, le premier caractère du
    résultat n'est jamais un déclencheur de formule pour Excel/LibreOffice."""
    result = csv_safe(value)
    if result:
        assert result[0] not in _DANGEROUS_FIRST_CHARS


@given(value=st.text(max_size=500))
@settings(max_examples=500)
def test_content_recoverable(value):
    """Le contenu original reste retrouvable après neutralisation — soit inchangé
    (pas de préfixe dangereux au départ), soit précédé d'exactement une apostrophe."""
    result = csv_safe(value)
    assert result == value or result == f"'{value}"


@given(value=st.one_of(
    st.none(), st.integers(), st.floats(allow_nan=False, allow_infinity=False), st.booleans(),
))
def test_non_string_types_never_crash(value):
    """Colonnes non textuelles (scores, dates, booléens...) : jamais de plantage,
    conversion str() implicite comme documenté."""
    csv_safe(value)
