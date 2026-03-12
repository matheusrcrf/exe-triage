# Test Fixtures

Binary samples are **not committed** to this repository.

## How tests work

All unit tests generate the PE files they need programmatically — see `tests/conftest.py` for the `create_minimal_pe()` helper that produces valid PE32/PE32+ binaries via `struct.pack`. High-risk heuristic scenarios are tested by constructing `AnalysisResult` objects directly in test code.

## Optional: local integration testing

To test against real binaries, place them here locally. This directory is in `.gitignore` for `.exe`/`.dll`/`.bin` files. Suggested samples (obtain locally from trusted sources):

| File | Description | Where to obtain |
|---|---|---|
| `clean_signed.exe` | Signed Windows binary | `C:\Windows\System32\notepad.exe` |
| `dotnet_sample.exe` | Any .NET application | Any .NET executable from a trusted source |
| `upx_packed.exe` | UPX-packed benign binary | Pack any small binary with `upx` |

Do **not** add malware samples to this directory. Heuristic tests for high-risk scores use synthetic `AnalysisResult` objects — no malicious binaries are needed.
