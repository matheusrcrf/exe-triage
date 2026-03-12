import re
from pathlib import Path

MIN_LENGTH = 5
MAX_STRINGS = 10000

# ASCII printable strings pattern
ASCII_PATTERN = re.compile(rb"[\x20-\x7e]{" + str(MIN_LENGTH).encode() + rb",}")

# UTF-16LE pattern (two-byte chars in printable range)
UTF16_PATTERN = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(MIN_LENGTH).encode() + rb",}")


def extract(path: Path) -> list[str]:
    """Extract printable ASCII and UTF-16LE strings from binary. Internal use only."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []

    strings: list[str] = []

    # ASCII strings
    for match in ASCII_PATTERN.finditer(data):
        strings.append(match.group().decode("ascii", errors="ignore"))
        if len(strings) >= MAX_STRINGS:
            break

    # UTF-16LE strings (only add if we have room)
    if len(strings) < MAX_STRINGS:
        for match in UTF16_PATTERN.finditer(data):
            s = match.group().decode("utf-16-le", errors="ignore").strip("\x00")
            if len(s) >= MIN_LENGTH:
                strings.append(s)
                if len(strings) >= MAX_STRINGS:
                    break

    return strings
