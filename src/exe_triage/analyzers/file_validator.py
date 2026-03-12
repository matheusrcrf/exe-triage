from pathlib import Path


class ValidationError(Exception):
    pass


def validate(path: str) -> Path:
    """Validate that path points to a valid PE file. Raises ValidationError (fatal) on failure."""
    p = Path(path)

    if not p.exists():
        raise ValidationError(f"File not found: {path}")

    if not p.is_file():
        raise ValidationError(f"Path is not a file: {path}")

    if p.stat().st_size == 0:
        raise ValidationError(f"File is empty: {path}")

    # Check MZ magic bytes
    try:
        with open(p, "rb") as f:
            magic = f.read(2)
    except OSError as e:
        raise ValidationError(f"Could not read file: {e}") from e

    if magic != b"MZ":
        raise ValidationError(
            f"Not a valid PE executable (invalid magic bytes): {path}"
        )

    return p
