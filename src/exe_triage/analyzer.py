from pathlib import Path

from exe_triage.models import AnalysisResult
from exe_triage.analyzers.file_validator import ValidationError, validate
from exe_triage.analyzers.hash_service import compute as compute_hash
from exe_triage.analyzers import pe_analyzer
from exe_triage.analyzers.pe_analyzer import PEAnalysisError
from exe_triage.analyzers import signature_analyzer
from exe_triage.analyzers import strings_extractor
from exe_triage.analyzers import technology_detector
from exe_triage.analyzers import ioc_extractor
from exe_triage.analyzers import indicator_extractor
from exe_triage.analyzers import heuristic_engine


def analyze(path: str) -> AnalysisResult:
    """
    Run the full analysis pipeline on a .exe file.
    Raises ValidationError or PEAnalysisError for fatal failures.
    Non-fatal errors are recorded in result.errors.
    """
    # Step 1: Validate file (FATAL)
    validated_path: Path = validate(path)

    # Initialize result
    result = AnalysisResult(
        file_name=validated_path.name,
        file_path=str(validated_path.resolve()),
        file_size=validated_path.stat().st_size,
    )

    # Step 2: Hash (non-fatal — shouldn't fail but be safe)
    try:
        result.sha256 = compute_hash(validated_path)
    except Exception as e:
        result.errors.append(f"hash_service: {e}")

    # Step 3: PE Analysis (FATAL)
    pe_analyzer.analyze(validated_path, result)  # raises PEAnalysisError if fatal

    # Step 4: Signature Analysis (non-fatal)
    try:
        signature_analyzer.analyze(validated_path, result)
    except Exception as e:
        result.errors.append(f"signature_analyzer: {e}")

    # Step 5: String Extraction (non-fatal, internal use)
    strings: list[str] = []
    try:
        strings = strings_extractor.extract(validated_path)
    except Exception as e:
        result.errors.append(f"strings_extractor: {e}")

    # Step 6: Technology Detection (non-fatal)
    try:
        result.technology = technology_detector.detect(result, strings)
    except Exception as e:
        result.errors.append(f"technology_detector: {e}")

    # Step 7: IOC Extraction (non-fatal)
    try:
        result.iocs = ioc_extractor.extract(strings)
    except Exception as e:
        result.errors.append(f"ioc_extractor: {e}")

    # Step 8: Indicator Extraction (non-fatal)
    try:
        result.indicators = indicator_extractor.extract(result, strings)
    except Exception as e:
        result.errors.append(f"indicator_extractor: {e}")

    # Step 9: Heuristic Scoring (non-fatal)
    try:
        heuristic_engine.score(result)
    except Exception as e:
        result.errors.append(f"heuristic_engine: {e}")

    return result
