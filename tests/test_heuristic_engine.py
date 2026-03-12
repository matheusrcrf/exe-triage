import pytest
from exe_triage.models import AnalysisResult, PEInfo, IOCResult, Indicator, SignatureInfo
from exe_triage.analyzers.heuristic_engine import score


def clean_result() -> AnalysisResult:
    result = AnalysisResult()
    result.signature = SignatureInfo(signed=True, signature_status="present")
    return result


def test_empty_result_is_low():
    result = clean_result()
    score(result)
    assert result.risk_score.level == "baixo"
    assert result.risk_score.total == 0


def test_only_weak_signals_max_medium():
    result = AnalysisResult()
    result.signature = SignatureInfo(signed=False, signature_status="absent")
    result.iocs = IOCResult(file_paths=["%Temp%\\file.exe", "%AppData%\\data"], urls=["http://a.com"] * 5)
    result.indicators = []
    score(result)
    # Even with weak signals, score should be capped and level should not exceed "médio"
    # unless total >= 45
    assert result.risk_score.level in ("baixo", "médio")


def test_createremotethread_minimum_alto():
    result = AnalysisResult()
    result.signature = SignatureInfo(signed=True, signature_status="present")
    result.pe_info = PEInfo(
        sections=[],
        imports={"KERNEL32.dll": ["CreateRemoteThread"]},
    )
    result.indicators = [
        Indicator(name="CreateRemoteThread", source="imports", category="process_injection", value="CreateRemoteThread in KERNEL32.dll")
    ]
    score(result)
    # CreateRemoteThread alone (weight 35) → level should be at least "alto" due to elevation
    assert result.risk_score.level in ("alto", "crítico")


def test_injection_obfuscation_download_critico():
    result = AnalysisResult()
    result.signature = SignatureInfo(signed=False, signature_status="absent")
    result.pe_info = PEInfo(
        sections=[],
        imports={
            "KERNEL32.dll": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"],
            "WININET.dll": ["URLDownloadToFileW"],
        },
    )
    result.indicators = [
        Indicator(name="CreateRemoteThread", source="imports", category="process_injection", value="x"),
        Indicator(name="WriteProcessMemory", source="imports", category="process_injection", value="x"),
        Indicator(name="VirtualAllocEx", source="imports", category="process_injection", value="x"),
        Indicator(name="URLDownloadToFileW", source="imports", category="remote_download", value="x"),
        Indicator(name="EncodedCommand", source="strings", category="obfuscation", value="-EncodedCommand base64"),
    ]
    result.iocs = IOCResult(urls=["http://evil.com/payload.bin"] * 5)
    # Add strings for heuristic matching
    score(result)
    assert result.risk_score.level == "crítico"
    assert "Não executar" in " ".join(result.recommendations)


def test_weak_context_cap():
    """Weak context signals should be capped at 20 points total."""
    result = AnalysisResult()
    result.signature = SignatureInfo(signed=False, signature_status="absent")
    # Add many weak signals
    result.iocs = IOCResult(
        file_paths=["%Temp%\\a", "%AppData%\\b", "%Startup%\\c"],
        urls=["http://a.com"] * 5,  # triggers WEAK_MULTIPLE_URLS
    )
    score(result)
    # Weak context points should not exceed 20
    weak_score = result.risk_score.breakdown.get("weak_context", 0)
    assert weak_score <= 20
