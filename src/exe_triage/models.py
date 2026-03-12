from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class SectionInfo:
    name: str
    virtual_size: int
    raw_size: int
    entropy: float


@dataclass
class PEInfo:
    sections: list[SectionInfo] = field(default_factory=list)
    imports: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class SignatureInfo:
    signed: bool = False
    signature_status: str = "absent"  # "present" | "absent" | "unreadable"
    publisher: str | None = None
    notes: str | None = None


@dataclass
class TechnologyInfo:
    detected: str = "unknown"  # "UPX" | ".NET" | "PyInstaller" | "NSIS" | "Inno Setup" | "unknown"
    confidence: str = "low"   # "high" | "medium" | "low"
    evidence: list[str] = field(default_factory=list)


@dataclass
class IOCResult:
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    process_names: list[str] = field(default_factory=list)


@dataclass
class Indicator:
    name: str
    source: str   # "imports" | "strings" | "iocs"
    category: str  # "process_injection" | "suspicious_command" | etc.
    value: str    # the concrete detected value


@dataclass
class HeuristicFinding:
    rule_id: str
    category: str
    description: str
    weight: int
    evidence: str


@dataclass
class RiskScore:
    total: int = 0
    level: str = "low"  # "low" | "medium" | "high" | "critical"
    breakdown: dict[str, int] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    file_name: str = ""
    file_path: str = ""
    file_size: int = 0
    sha256: str = ""
    file_type: str = ""           # "PE32" | "PE32+"
    architecture: str = ""        # "x86" | "x64"
    compile_timestamp: str | None = None
    pe_info: PEInfo = field(default_factory=PEInfo)
    signature: SignatureInfo = field(default_factory=SignatureInfo)
    technology: TechnologyInfo = field(default_factory=TechnologyInfo)
    iocs: IOCResult = field(default_factory=IOCResult)
    indicators: list[Indicator] = field(default_factory=list)
    findings: list[HeuristicFinding] = field(default_factory=list)
    risk_score: RiskScore = field(default_factory=RiskScore)
    recommendations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    analysis_version: str = "1.0.0"
