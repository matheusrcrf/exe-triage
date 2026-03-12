import json
import pytest
from exe_triage.models import AnalysisResult, PEInfo, SectionInfo, SignatureInfo, TechnologyInfo, IOCResult, RiskScore
from exe_triage.reporting.json_reporter import render

REQUIRED_FIELDS = [
    "file_name", "file_path", "sha256", "file_size", "file_type",
    "architecture", "compile_timestamp", "technology", "signature",
    "sections", "imports_summary", "iocs", "indicators", "findings",
    "risk_score", "risk_level", "recommendations", "errors", "analysis_version",
]


def make_full_result() -> AnalysisResult:
    result = AnalysisResult(
        file_name="test.exe",
        file_path="C:\\test.exe",
        file_size=1024,
        sha256="a" * 64,
        file_type="PE32",
        architecture="x86",
        compile_timestamp="2024-01-01T00:00:00",
    )
    result.pe_info = PEInfo(
        sections=[SectionInfo(name=".text", virtual_size=0x1000, raw_size=0x1000, entropy=5.0)],
        imports={"KERNEL32.dll": ["CreateFile"]},
    )
    result.signature = SignatureInfo(signed=False, signature_status="absent")
    result.technology = TechnologyInfo(detected="unknown", confidence="low", evidence=[])
    result.iocs = IOCResult()
    result.risk_score = RiskScore(total=0, level="low", breakdown={})
    return result


def test_all_required_fields_present():
    result = make_full_result()
    json_str = render(result)
    data = json.loads(json_str)
    for field in REQUIRED_FIELDS:
        assert field in data, f"Missing required field: {field}"


def test_raw_strings_not_in_output():
    """Raw strings must never appear in JSON output."""
    result = make_full_result()
    json_str = render(result)
    data = json.loads(json_str)
    assert "strings" not in data


def test_valid_json_output():
    result = make_full_result()
    json_str = render(result)
    # Should not raise
    data = json.loads(json_str)
    assert isinstance(data, dict)


def test_iocs_structure():
    result = make_full_result()
    result.iocs = IOCResult(
        urls=["http://test.com"],
        domains=["test.com"],
        ips=["8.8.8.8"],
    )
    data = json.loads(render(result))
    assert "iocs" in data
    assert "urls" in data["iocs"]
    assert "domains" in data["iocs"]
    assert "ips" in data["iocs"]


def test_findings_structure():
    from exe_triage.models import HeuristicFinding
    result = make_full_result()
    result.findings = [
        HeuristicFinding(
            rule_id="TEST_RULE",
            category="process_injection",
            description="Test finding",
            weight=35,
            evidence="test evidence",
        )
    ]
    data = json.loads(render(result))
    assert len(data["findings"]) == 1
    finding = data["findings"][0]
    assert "rule_id" in finding
    assert "category" in finding
    assert "weight" in finding
    assert "evidence" in finding
