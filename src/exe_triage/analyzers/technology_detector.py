from exe_triage.models import AnalysisResult, TechnologyInfo


def detect(result: AnalysisResult, strings: list[str]) -> TechnologyInfo:
    """Detect packer/technology from PE sections, imports and strings."""
    strings_set = {s.lower() for s in strings}
    section_names = {s.name for s in result.pe_info.sections}
    all_imports = {
        func.lower()
        for funcs in result.pe_info.imports.values()
        for func in funcs
    }
    import_dlls = {dll.lower() for dll in result.pe_info.imports}

    # UPX detection (highest priority for packers)
    upx_evidence = []
    if any(name in section_names for name in ("UPX0", "UPX1", "UPX2")):
        upx_evidence.append("UPX section names found (UPX0/UPX1/UPX2)")
    if any("upx!" in s.lower() for s in strings):
        upx_evidence.append("UPX! signature found in strings")
    if upx_evidence:
        return TechnologyInfo(detected="UPX", confidence="high", evidence=upx_evidence)

    # .NET detection
    dotnet_evidence = []
    if "mscoree.dll" in import_dlls:
        dotnet_evidence.append("mscoree.dll in imports")
    if "_corexemain" in all_imports:
        dotnet_evidence.append("_CorExeMain in imports")
    if dotnet_evidence and len(dotnet_evidence) >= 1:
        confidence = "high" if len(dotnet_evidence) >= 2 else "medium"
        return TechnologyInfo(detected=".NET", confidence=confidence, evidence=dotnet_evidence)

    # PyInstaller detection
    pyinstaller_evidence = []
    if any("_meipass" in s.lower() for s in strings):
        pyinstaller_evidence.append("_MEIPASS found in strings")
    if any("pyz" in s for s in strings):
        pyinstaller_evidence.append("PYZ found in strings")
    if ".pydata" in section_names:
        pyinstaller_evidence.append(".pydata section present")
    if pyinstaller_evidence:
        confidence = "high" if len(pyinstaller_evidence) >= 2 else "medium"
        return TechnologyInfo(detected="PyInstaller", confidence=confidence, evidence=pyinstaller_evidence)

    # NSIS detection
    nsis_evidence = []
    if any("nullsoft" in s.lower() for s in strings):
        nsis_evidence.append("Nullsoft found in strings")
    if any("nsis" in s.lower() for s in strings):
        nsis_evidence.append("NSIS found in strings")
    if nsis_evidence:
        return TechnologyInfo(detected="NSIS", confidence="medium", evidence=nsis_evidence)

    # Inno Setup detection
    inno_evidence = []
    if any("inno setup" in s.lower() for s in strings):
        inno_evidence.append("Inno Setup found in strings")
    if any("isetup" in s.lower() for s in strings):
        inno_evidence.append("ISetup found in strings")
    if inno_evidence:
        return TechnologyInfo(detected="Inno Setup", confidence="medium", evidence=inno_evidence)

    return TechnologyInfo(detected="unknown", confidence="low", evidence=[])
