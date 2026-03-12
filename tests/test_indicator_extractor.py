from exe_triage.models import AnalysisResult, PEInfo
from exe_triage.analyzers.indicator_extractor import extract


def make_result_with_imports(imports: dict) -> AnalysisResult:
    result = AnalysisResult()
    result.pe_info = PEInfo(sections=[], imports=imports)
    return result


def test_detect_createremotethread():
    result = make_result_with_imports({"KERNEL32.dll": ["CreateRemoteThread", "CreateFile"]})
    indicators = extract(result, [])
    names = [i.name for i in indicators]
    assert "CreateRemoteThread" in names


def test_detect_urldownloadtofile():
    result = make_result_with_imports({"WININET.dll": ["URLDownloadToFileW"]})
    indicators = extract(result, [])
    assert any("URLDownloadToFile" in i.name for i in indicators)


def test_detect_encodedcommand_in_strings():
    result = make_result_with_imports({})
    strings = ["powershell -EncodedCommand SGVsbG8="]
    indicators = extract(result, strings)
    names = [i.name for i in indicators]
    assert "EncodedCommand" in names


def test_detect_executionpolicy_bypass():
    result = make_result_with_imports({})
    strings = ["powershell -ExecutionPolicy Bypass -File script.ps1"]
    indicators = extract(result, strings)
    names = [i.name for i in indicators]
    assert "ExecutionPolicy Bypass" in names


def test_no_indicators_for_clean():
    result = make_result_with_imports({"KERNEL32.dll": ["CreateFile", "ReadFile", "WriteFile"]})
    indicators = extract(result, ["Hello world", "normal string"])
    assert len(indicators) == 0
