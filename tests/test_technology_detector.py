from exe_triage.models import AnalysisResult, PEInfo, SectionInfo
from exe_triage.analyzers.technology_detector import detect


def make_result_with_sections(section_names):
    result = AnalysisResult()
    result.pe_info = PEInfo(
        sections=[SectionInfo(name=n, virtual_size=0x1000, raw_size=0x1000, entropy=5.0) for n in section_names],
        imports={},
    )
    return result


def test_detect_upx_by_sections():
    result = make_result_with_sections(["UPX0", "UPX1", "UPX2"])
    tech = detect(result, [])
    assert tech.detected == "UPX"
    assert tech.confidence == "high"


def test_detect_upx_by_string():
    result = make_result_with_sections([".text"])
    tech = detect(result, ["UPX! packed binary", "some other string"])
    assert tech.detected == "UPX"


def test_detect_dotnet():
    result = make_result_with_sections([".text"])
    result.pe_info.imports = {"mscoree.dll": ["_CorExeMain"]}
    tech = detect(result, [])
    assert tech.detected == ".NET"
    assert tech.confidence == "high"


def test_detect_pyinstaller():
    result = make_result_with_sections([".text", ".pydata"])
    tech = detect(result, ["_MEIPASS2 path", "PYZ archive"])
    assert tech.detected == "PyInstaller"
    assert tech.confidence == "high"


def test_detect_nsis():
    result = make_result_with_sections([".text"])
    tech = detect(result, ["Nullsoft Install System"])
    assert tech.detected == "NSIS"


def test_detect_inno_setup():
    result = make_result_with_sections([".text"])
    tech = detect(result, ["Inno Setup installer"])
    assert tech.detected == "Inno Setup"


def test_detect_unknown():
    result = make_result_with_sections([".text", ".data", ".rdata"])
    tech = detect(result, ["some random strings"])
    assert tech.detected == "unknown"
