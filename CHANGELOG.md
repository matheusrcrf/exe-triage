# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] — 2026-03-12

Initial release.

### Added
- Static PE parsing: sections with entropy, imports by DLL, file type (PE32/PE32+), architecture (x86/x64), compile timestamp
- SHA-256 hash computation
- Digital signature detection: presence of Security Directory + publisher extraction via PKCS#7
- Technology/packer detection: UPX, .NET, PyInstaller, NSIS, Inno Setup
- IOC extraction via regex: URLs, IPs, domains, Windows paths, registry keys, process names
- Indicator extraction: suspicious imports and strings mapped to named categories
- Heuristic scoring engine with 17 rules, weak-signal cap (20 pts), and category-based elevation rules
- Terminal output with color-coded risk levels via `rich`
- JSON output conforming to documented contract
- CLI: `exe-triage analyze <file> [--json] [--output <path>]`
