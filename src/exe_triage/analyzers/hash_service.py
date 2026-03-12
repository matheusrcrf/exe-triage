import hashlib
from pathlib import Path

CHUNK_SIZE = 8192


def compute(path: Path) -> str:
    """Compute SHA-256 hash of a file in chunks to avoid OOM on large files."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
    return sha256.hexdigest()
