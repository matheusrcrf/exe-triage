import hashlib
from exe_triage.analyzers.hash_service import compute


def test_hash_correct(tmp_path):
    f = tmp_path / "test.bin"
    data = b"hello world"
    f.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert compute(f) == expected


def test_hash_large_file(tmp_path):
    """Test that hashing works for files larger than chunk size."""
    f = tmp_path / "large.bin"
    data = b"A" * (1024 * 1024)  # 1MB
    f.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert compute(f) == expected
