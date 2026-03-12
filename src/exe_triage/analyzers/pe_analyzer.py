import math
from datetime import datetime, timezone
from pathlib import Path

import pefile

from exe_triage.models import AnalysisResult, PEInfo, SectionInfo


class PEAnalysisError(Exception):
    pass


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def analyze(path: Path, result: AnalysisResult) -> None:
    """Parse PE structure and populate result. Raises PEAnalysisError on fatal failure."""
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except pefile.PEFormatError as e:
        raise PEAnalysisError(f"Failed to parse PE: {e}") from e
    except Exception as e:
        raise PEAnalysisError(f"Unexpected error parsing PE: {e}") from e

    try:
        # File type and architecture
        magic = pe.OPTIONAL_HEADER.Magic
        result.file_type = "PE32+" if magic == 0x20b else "PE32"

        machine = pe.FILE_HEADER.Machine
        result.architecture = "x64" if machine == 0x8664 else "x86"

        # Compile timestamp
        ts = pe.FILE_HEADER.TimeDateStamp
        if ts and ts != 0:
            try:
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                result.compile_timestamp = dt.strftime("%Y-%m-%dT%H:%M:%S")
            except (OSError, OverflowError, ValueError):
                result.compile_timestamp = None
        else:
            result.compile_timestamp = None

        # Sections with entropy
        sections = []
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            data = section.get_data()
            entropy = _calculate_entropy(data)
            sections.append(
                SectionInfo(
                    name=name,
                    virtual_size=section.Misc_VirtualSize,
                    raw_size=section.SizeOfRawData,
                    entropy=entropy,
                )
            )
        result.pe_info = PEInfo(sections=sections, imports={})

        # Imports grouped by DLL
        imports: dict[str, list[str]] = {}
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else "unknown"
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode("utf-8", errors="replace"))
                    elif imp.ordinal is not None:
                        funcs.append(f"Ordinal_{imp.ordinal}")
                imports[dll_name] = funcs
            result.pe_info.imports = imports
        else:
            result.errors.append("PE has no import table (possibly packed or malformed)")

    except PEAnalysisError:
        raise
    except Exception as e:
        raise PEAnalysisError(f"Error extracting PE information: {e}") from e
    finally:
        pe.close()
