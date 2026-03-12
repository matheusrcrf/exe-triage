# exe-triage

**Local, offline static triage tool for Windows PE executables (`.exe`).**

exe-triage analyzes `.exe` files without executing them, without sending data anywhere, and without requiring an antivirus engine. It extracts PE structure, IOCs, and technical indicators, then scores risk heuristically and produces a clear, structured report.

> **This tool is not an antivirus.** It does not guarantee that a file is safe or malicious. It identifies indicators that warrant closer inspection and provides a starting point for human analysis.

---

## Use cases

- Quick triage of unknown `.exe` files before deciding whether to investigate further
- Offline inspection of suspicious samples in air-gapped or restricted environments
- Generating structured JSON reports for manual review or documentation
- Educational use for learning PE internals, import analysis, and static heuristics

---

## What it does

- Parses the PE structure: sections with entropy, import table, file type (PE32/PE32+), architecture, compile timestamp
- Computes SHA-256 hash
- Detects digital signature presence and extracts publisher name when available
- Detects packer/technology: UPX, .NET, PyInstaller, NSIS, Inno Setup
- Extracts observable IOCs: URLs, IPs, domains, Windows paths, registry keys, process names
- Identifies technical indicators: suspicious imports (process injection, remote download) and suspicious strings
- Scores risk heuristically based on 17 rules and produces a final risk level: `low` / `medium` / `high` / `critical`
- Outputs a color-coded terminal report or a structured JSON file

## What it does not do

- Does not execute the file
- Does not send data to any external service
- Does not validate certificate trust chains or revocation
- Does not detect runtime-only behavior (encrypted strings, API hashing, reflective loading)
- Does not unpack packed executables before analysis — analysis of a UPX-packed binary reflects the stub, not the payload
- Does not replace sandbox analysis, dynamic analysis, or antivirus

---

## Installation

Requires Python 3.11+.

**Linux / macOS**

```bash
git clone https://github.com/matheusrcrf/exe-triage.git
cd exe-triage
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install .
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/matheusrcrf/exe-triage.git
cd exe-triage
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install .
```

**For development (adds pytest, ruff):**

```bash
pip install -e ".[dev]"
```

---

## Usage

```bash
# Terminal report (default)
exe-triage analyze suspicious.exe

# JSON output to stdout
exe-triage analyze suspicious.exe --json

# JSON output to file
exe-triage analyze suspicious.exe --json --output report.json

# Terminal report + save JSON to file
exe-triage analyze suspicious.exe --output report.json
```

### Help

```bash
exe-triage --help
exe-triage analyze --help
```

---

## Example output

```
╭─────────────────────────────────────────────────────╮
│  exe-triage v1.0  |  installer.exe                  │
╰─────────────────────────────────────────────────────╯
  SHA-256       a3f1c2d4...abcdef01
  Size          2.34 MB
  Type          PE32+ / x64
  Compiled      2024-03-15T10:22:00
  Technology    PyInstaller (high)
  Signature     ABSENT

╭─────────────────────────────────────────────────────╮
│  RISK: CRITICAL  |  Score: 95                       │
╰─────────────────────────────────────────────────────╯

  Weight  Category               Description
  [35]    process_injection      CreateRemoteThread import detected
  [25]    remote_download        URLDownloadToFile import detected
  [25]    obfuscation            ExecutionPolicy Bypass found in strings

  IOCs: 1 URL(s), 1 IP(s), 2 path(s), 1 registry key(s)

  Recommendations:
  • Process injection imports detected. High risk of code injection into other processes.
  • Remote download via URLDownloadToFile detected. Binary may fetch additional payloads.
  • Do not execute. Analyze in an isolated environment.
```

---

## Risk score

The heuristic engine evaluates 17 rules grouped into categories:

| Category | Examples | Type |
|---|---|---|
| `process_injection` | `CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx` | Strong |
| `remote_download` | `URLDownloadToFile` | Strong |
| `obfuscation` | `EncodedCommand`, `ExecutionPolicy Bypass` | Strong |
| `persistence` | `CurrentVersion\Run` registry keys | Medium |
| `suspicious_automation` | `schtasks`, `powershell` in strings | Medium |
| `suspicious_context` | crack/keygen/serial strings | Medium |
| `weak_context` | unsigned binary, `%Temp%`, `%AppData%` references | Weak (capped) |

**Score thresholds:** 0–19 = `low`, 20–44 = `medium`, 45–79 = `high`, 80+ = `critical`.

Weak-context signals are capped at 20 points total, so they cannot push a file to `high` or `critical` on their own. Reaching `high` requires at least one strong signal (process injection, obfuscation, or remote download).

**Important:** legitimate admin tools (Sysinternals, PsExec, Process Hacker) may trigger injection/automation heuristics. Each finding includes concrete evidence — always interpret results in context.

---

## JSON output contract

The `--json` flag outputs a structured report. Key fields:

```json
{
  "file_name": "...",
  "sha256": "...",
  "file_type": "PE32+",
  "architecture": "x64",
  "technology": { "detected": "PyInstaller", "confidence": "high", "evidence": [...] },
  "signature": { "signed": false, "signature_status": "absent", "publisher": null },
  "sections": [ { "name": ".text", "virtual_size": 0, "raw_size": 0, "entropy": 6.12 } ],
  "imports_summary": { "KERNEL32.dll": ["CreateFile", "..."] },
  "iocs": { "urls": [], "ips": [], "domains": [], "file_paths": [], "registry_keys": [], "process_names": [] },
  "indicators": [ { "name": "...", "source": "imports", "category": "...", "value": "..." } ],
  "findings": [ { "rule_id": "...", "category": "...", "weight": 35, "evidence": "..." } ],
  "risk_score": 95,
  "risk_level": "critical",
  "recommendations": [...],
  "errors": [],
  "analysis_version": "1.0.0"
}
```

Raw strings extracted from the binary are **never** included in the output.

---

## Limitations

- **Static only.** Behavior only observable at runtime is invisible to this tool.
- **Signature detection is presence-only.** `signed: true` means a certificate block was found in the PE. It does not mean the certificate is valid, trusted, or unrevoked. Full chain validation requires the Windows API (`wintrust`) and is not implemented.
- **Packed binaries.** Analysis of a UPX-packed file shows the unpacker stub's imports and strings, not the payload's. The payload is opaque to static analysis without unpacking.
- **No context awareness.** A high-risk score on a well-known system binary would likely indicate a heuristic calibration issue; the same score on an unknown binary from an untrusted source is a meaningful signal. The tool has no way to distinguish these contexts automatically.
- **False positives.** Installers (NSIS, Inno Setup) legitimately reference `%Temp%`, `schtasks`, and similar paths. Admin tools legitimately import process injection APIs.
- **False negatives.** Malware that encrypts strings, uses API hashing, or loads code dynamically will produce a low score.

---

## Development

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run a single test file
python3 -m pytest tests/test_heuristic_engine.py -v

# Run a single test
python3 -m pytest tests/test_heuristic_engine.py::test_createremotethread_minimum_alto -v

# Lint
ruff check src/ tests/

# Format
ruff format src/ tests/
```

### Test fixtures

All tests run without real binary samples. Minimal PE32/PE32+ files are generated programmatically in `tests/conftest.py`. High-risk heuristic scenarios are tested by constructing `AnalysisResult` objects directly — no malware samples are needed or committed.

If you want to test against real binaries locally, place them in `tests/fixtures/` (excluded from version control by `.gitignore`) and write integration tests that reference them by path.

---

## Roadmap

Planned for v2:

- VS_VERSION_INFO extraction (company, product, version)
- HTML report output
- External rule files (YAML/TOML) without editing source
- Broader packer detection (Themida, MPRESS, Enigma Protector via byte signatures)
- Optional YARA rule support
- `.dll` file support
- Full certificate validation via Windows API (`wintrust`)

---

## Contributing

Issues and pull requests are welcome. Keep changes focused and minimal — one concern per PR. For significant changes, open an issue first to discuss the approach.

---

## License

MIT — see [LICENSE](LICENSE).
