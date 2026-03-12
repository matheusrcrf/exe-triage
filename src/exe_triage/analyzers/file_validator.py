from pathlib import Path


class ValidationError(Exception):
    pass


def validate(path: str) -> Path:
    """Validate that path points to a valid PE file. Raises ValidationError (fatal) on failure."""
    p = Path(path)

    if not p.exists():
        raise ValidationError(f"Arquivo não encontrado: {path}")

    if not p.is_file():
        raise ValidationError(f"Caminho não é um arquivo: {path}")

    if p.stat().st_size == 0:
        raise ValidationError(f"Arquivo vazio: {path}")

    # Check MZ magic bytes
    try:
        with open(p, "rb") as f:
            magic = f.read(2)
    except OSError as e:
        raise ValidationError(f"Não foi possível ler o arquivo: {e}") from e

    if magic != b"MZ":
        raise ValidationError(
            f"Não é um executável PE válido (magic bytes inválidos): {path}"
        )

    return p
