# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for exe-triage
#
# Build (from project root, with package installed):
#   pip install -e ".[build]"
#   pyinstaller exe_triage.spec --noconfirm
#
# Output: dist/exe-triage/exe-triage.exe

a = Analysis(
    ["src/exe_triage/cli.py"],
    pathex=["src"],
    binaries=[],
    datas=[],
    hiddenimports=[
        "cryptography.hazmat.primitives.serialization.pkcs7",
        "cryptography.x509",
        "cryptography.hazmat.backends.openssl",
        "cryptography.hazmat.backends.openssl.backend",
        "cryptography.hazmat.bindings._rust",
        "pefile",
        "rich.console",
        "rich.table",
        "rich.panel",
        "rich.text",
        "rich.box",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "unittest", "email", "html", "http", "xml", "xmlrpc"],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="exe-triage",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="exe-triage",
)
