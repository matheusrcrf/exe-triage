from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class HeuristicRule:
    id: str
    category: str
    weight: int
    description: str
    signal: str | None = None
    signal_regex: str | None = None
    source: str = "strings"


HEURISTIC_RULES: list[HeuristicRule] = [
    # -- STRONG SIGNALS -------------------------------------------------------

    # Process Injection
    HeuristicRule(
        id="INJ_CREATEREMOTETHREAD",
        signal="CreateRemoteThread",
        source="imports",
        category="process_injection",
        weight=35,
        description="CreateRemoteThread import — code injection into a remote process",
    ),
    HeuristicRule(
        id="INJ_WRITEPROCESSMEMORY",
        signal="WriteProcessMemory",
        source="imports",
        category="process_injection",
        weight=30,
        description="WriteProcessMemory import — writing to memory of an external process",
    ),
    HeuristicRule(
        id="INJ_VIRTUALALLOCEX",
        signal="VirtualAllocEx",
        source="imports",
        category="process_injection",
        weight=30,
        description="VirtualAllocEx import — memory allocation in a remote process",
    ),

    # Remote download
    HeuristicRule(
        id="DL_URLDOWNLOADTOFILE",
        signal="URLDownloadToFile",
        source="imports",
        category="remote_download",
        weight=25,
        description="URLDownloadToFile import — remote file download",
    ),

    # Obfuscated PowerShell
    HeuristicRule(
        id="PS_ENCODEDCOMMAND",
        signal="EncodedCommand",
        source="strings",
        category="obfuscation",
        weight=30,
        description="EncodedCommand — PowerShell with Base64-encoded payload",
    ),
    HeuristicRule(
        id="PS_EXECUTIONPOLICY_BYPASS",
        signal="ExecutionPolicy Bypass",
        source="strings",
        category="obfuscation",
        weight=25,
        description="ExecutionPolicy Bypass — evading PowerShell execution policy",
    ),

    # -- MEDIUM SIGNALS -------------------------------------------------------

    HeuristicRule(
        id="PERSIST_RUN",
        signal="CurrentVersion\\Run",
        source="strings",
        category="persistence",
        weight=20,
        description="Reference to Run registry key — possible persistence mechanism",
    ),
    HeuristicRule(
        id="PERSIST_RUNONCE",
        signal="CurrentVersion\\RunOnce",
        source="strings",
        category="persistence",
        weight=20,
        description="Reference to RunOnce registry key — possible persistence mechanism",
    ),
    HeuristicRule(
        id="AUTO_POWERSHELL",
        signal="powershell",
        source="strings",
        category="suspicious_automation",
        weight=15,
        description="Reference to powershell in strings",
    ),
    HeuristicRule(
        id="AUTO_SCHTASKS",
        signal="schtasks",
        source="strings",
        category="suspicious_automation",
        weight=15,
        description="Reference to schtasks — scheduled task creation",
    ),
    HeuristicRule(
        id="CTX_CRACK",
        signal_regex=r"crack|keygen|serial\s+key|activat",
        source="strings",
        category="suspicious_context",
        weight=20,
        description="Strings associated with cracks, keygens, or illegitimate activations",
    ),

    # -- WEAK / CONTEXTUAL SIGNALS --------------------------------------------
    HeuristicRule(
        id="WEAK_UNSIGNED",
        signal="unsigned",
        source="signature",
        category="weak_context",
        weight=10,
        description="Executable has no digital signature",
    ),
    HeuristicRule(
        id="WEAK_APPDATA",
        signal="%AppData%",
        source="strings",
        category="weak_context",
        weight=5,
        description="Reference to %AppData%",
    ),
    HeuristicRule(
        id="WEAK_TEMP",
        signal="%Temp%",
        source="strings",
        category="weak_context",
        weight=5,
        description="Reference to %Temp%",
    ),
    HeuristicRule(
        id="WEAK_STARTUP",
        signal="%Startup%",
        source="strings",
        category="weak_context",
        weight=8,
        description="Reference to Startup folder",
    ),
    HeuristicRule(
        id="WEAK_TASKKILL",
        signal="taskkill",
        source="strings",
        category="weak_context",
        weight=5,
        description="Reference to taskkill",
    ),
    HeuristicRule(
        id="WEAK_MULTIPLE_URLS",
        signal="url_count > 3",
        source="iocs",
        category="weak_context",
        weight=8,
        description="Multiple URLs detected",
    ),
]

WEAK_CONTEXT_CAP = 20

RECOMMENDATIONS_BY_CATEGORY = {
    "process_injection": "Process injection imports detected. High risk of code injection into other processes.",
    "remote_download": "Remote download via URLDownloadToFile detected. Binary may fetch additional payloads.",
    "obfuscation": "Obfuscation indicators detected (encoded/bypass PowerShell). Sandbox analysis recommended.",
    "persistence": "References to persistence registry keys (Run/RunOnce) detected. Possible persistence mechanism.",
    "suspicious_automation": "References to suspicious automation tools detected (schtasks, taskkill, powershell).",
    "suspicious_context": "Strings associated with illegitimate software detected (crack, keygen, serial).",
    "weak_context": "Contextual indicators detected. May be legitimate depending on use context.",
}
