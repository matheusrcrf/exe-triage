import re

from exe_triage.models import AnalysisResult, Indicator

SUSPICIOUS_IMPORTS = {
    "CreateRemoteThread": "process_injection",
    "WriteProcessMemory": "process_injection",
    "VirtualAllocEx": "process_injection",
    "URLDownloadToFile": "remote_download",
    "URLDownloadToFileA": "remote_download",
    "URLDownloadToFileW": "remote_download",
    "OpenProcess": "process_injection",
    "NtCreateSection": "process_injection",
    "NtMapViewOfSection": "process_injection",
    "ZwCreateSection": "process_injection",
}

SUSPICIOUS_STRINGS = [
    (re.compile(r"ExecutionPolicy\s+Bypass", re.IGNORECASE), "obfuscation", "ExecutionPolicy Bypass"),
    (re.compile(r"-EncodedCommand", re.IGNORECASE), "obfuscation", "EncodedCommand"),
    (re.compile(r"frombase64string", re.IGNORECASE), "obfuscation", "FromBase64String"),
    (re.compile(r"decompress", re.IGNORECASE), "obfuscation", "Decompress"),
    (re.compile(r"taskkill", re.IGNORECASE), "suspicious_automation", "taskkill"),
    (re.compile(r"schtasks", re.IGNORECASE), "suspicious_automation", "schtasks"),
    (re.compile(r"crack|keygen|serial\s+key|activat", re.IGNORECASE), "suspicious_context", "crack/keygen/serial/activat"),
]


def extract(result: AnalysisResult, strings: list[str]) -> list[Indicator]:
    """Detect technical signals from imports and strings."""
    indicators: list[Indicator] = []
    seen_names: set[str] = set()

    # Check imports
    for dll, funcs in result.pe_info.imports.items():
        for func in funcs:
            # Check exact and case-insensitive matches
            matched_key = None
            for key in SUSPICIOUS_IMPORTS:
                if func.lower() == key.lower() or func.endswith(key):
                    matched_key = key
                    break
            if matched_key and matched_key not in seen_names:
                seen_names.add(matched_key)
                indicators.append(
                    Indicator(
                        name=matched_key,
                        source="imports",
                        category=SUSPICIOUS_IMPORTS[matched_key],
                        value=f"{func} in {dll}",
                    )
                )

    # Check strings
    for s in strings:
        for pattern, category, name in SUSPICIOUS_STRINGS:
            if name not in seen_names and pattern.search(s):
                seen_names.add(name)
                indicators.append(
                    Indicator(
                        name=name,
                        source="strings",
                        category=category,
                        value=s[:200],  # truncate very long strings
                    )
                )

    return indicators
