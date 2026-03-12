import pytest
from exe_triage.analyzers.file_validator import validate, ValidationError


def test_valid_pe_passes(valid_pe32):
    result = validate(str(valid_pe32))
    assert result == valid_pe32


def test_nonexistent_file_raises():
    with pytest.raises(ValidationError, match="não encontrado"):
        validate("/nonexistent/path/file.exe")


def test_empty_file_raises(empty_file):
    with pytest.raises(ValidationError, match="vazio"):
        validate(str(empty_file))


def test_non_pe_file_raises(non_pe_file):
    with pytest.raises(ValidationError, match="PE válido"):
        validate(str(non_pe_file))


def test_truncated_pe_passes_validation(truncated_pe):
    # file_validator only checks MZ bytes, not full PE structure
    result = validate(str(truncated_pe))
    assert result == truncated_pe
