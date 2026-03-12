import json
from dataclasses import asdict
from exe_triage.models import AnalysisResult


def render(result: AnalysisResult) -> str:
    """Serialize AnalysisResult to JSON string per contract. Excludes raw strings."""
    data = asdict(result)

    # Flatten pe_info.sections to top-level for contract compliance
    pe_info = data.pop("pe_info", {})
    data["sections"] = pe_info.get("sections", [])
    data["imports_summary"] = pe_info.get("imports", {})

    # risk_score fields flattened
    risk_score = data.pop("risk_score", {})
    data["risk_score"] = risk_score.get("total", 0)
    data["risk_level"] = risk_score.get("level", "low")
    data["risk_breakdown"] = risk_score.get("breakdown", {})

    return json.dumps(data, ensure_ascii=False, indent=2)
