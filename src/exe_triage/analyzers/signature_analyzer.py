import warnings
from pathlib import Path

import pefile

from exe_triage.models import AnalysisResult, SignatureInfo

# Optional dependency
try:
    from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
    from cryptography import x509
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


SECURITY_DIRECTORY_INDEX = 4  # IMAGE_DIRECTORY_ENTRY_SECURITY


def analyze(path: Path, result: AnalysisResult) -> None:
    """Detect signature presence and extract basic metadata. Always non-fatal."""
    try:
        pe = pefile.PE(str(path), fast_load=True)
        try:
            _analyze_signature(pe, path, result)
        finally:
            pe.close()
    except Exception as e:
        result.signature = SignatureInfo(
            signed=False,
            signature_status="unreadable",
            publisher=None,
            notes=f"Error reading signature: {e}",
        )
        result.errors.append(f"signature_analyzer: {e}")


def _analyze_signature(pe: pefile.PE, path: Path, result: AnalysisResult) -> None:
    # Check for Security Directory
    if not hasattr(pe, "OPTIONAL_HEADER") or not hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
        result.signature = SignatureInfo(
            signed=False,
            signature_status="absent",
            notes="PE has no DATA_DIRECTORY",
        )
        return

    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if len(dirs) <= SECURITY_DIRECTORY_INDEX:
        result.signature = SignatureInfo(signed=False, signature_status="absent")
        return

    sec_dir = dirs[SECURITY_DIRECTORY_INDEX]
    if sec_dir.VirtualAddress == 0 or sec_dir.Size == 0:
        result.signature = SignatureInfo(signed=False, signature_status="absent")
        return

    # Security directory found — try to extract publisher
    publisher = _extract_publisher(path, sec_dir.VirtualAddress, sec_dir.Size)

    result.signature = SignatureInfo(
        signed=True,
        signature_status="present",
        publisher=publisher,
        notes=(
            "Signature detected. WARNING: v1 only detects signature presence and extracts basic "
            "metadata. It does not validate the certificate chain, revocation, or timestamp. "
            "'signed: true' means a certificate block was found in the PE structure, not that "
            "Windows or any CA would consider the signature valid."
        ),
    )


def _extract_publisher(path: Path, offset: int, size: int) -> str | None:
    if not CRYPTOGRAPHY_AVAILABLE:
        return None

    try:
        with open(path, "rb") as f:
            f.seek(offset + 8)  # skip WIN_CERTIFICATE header (8 bytes)
            cert_data = f.read(size - 8)

        if not cert_data:
            return None

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            certs = load_der_pkcs7_certificates(cert_data)
        if not certs:
            return None

        # Use the last certificate (typically the signing certificate)
        cert = certs[-1]
        subject = cert.subject
        try:
            cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn:
                return cn[0].value
            org = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            if org:
                return org[0].value
        except Exception:
            pass

        return None
    except Exception:
        return None
