import pytest
from exe_triage.models import AnalysisResult
from exe_triage.analyzers import pe_analyzer
from exe_triage.analyzers.pe_analyzer import PEAnalysisError


def test_pe32_analysis(valid_pe32):
    result = AnalysisResult()
    pe_analyzer.analyze(valid_pe32, result)
    assert result.file_type == "PE32"
    assert result.architecture == "x86"
    assert len(result.pe_info.sections) >= 1
    assert result.pe_info.sections[0].name == ".text"


def test_pe32plus_analysis(valid_pe32plus):
    result = AnalysisResult()
    pe_analyzer.analyze(valid_pe32plus, result)
    assert result.file_type == "PE32+"
    assert result.architecture == "x64"


def test_sections_have_entropy(valid_pe32):
    result = AnalysisResult()
    pe_analyzer.analyze(valid_pe32, result)
    for section in result.pe_info.sections:
        assert isinstance(section.entropy, float)
        assert 0.0 <= section.entropy <= 8.0


def test_truncated_pe_raises_fatal(truncated_pe):
    result = AnalysisResult()
    with pytest.raises(PEAnalysisError):
        pe_analyzer.analyze(truncated_pe, result)


def test_pe_without_imports_records_error(valid_pe32):
    """A PE without imports should not fatal, but record error."""
    result = AnalysisResult()
    pe_analyzer.analyze(valid_pe32, result)
    # No imports in minimal PE — error should be recorded
    assert result.pe_info.imports == {}
    assert len(result.errors) >= 1
