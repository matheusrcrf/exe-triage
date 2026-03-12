import struct
import pytest
from pathlib import Path


def create_minimal_pe(path: Path, pe32plus: bool = False) -> None:
    """Create a minimal valid PE file for testing."""
    # DOS header
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    # e_lfanew at offset 60
    pe_offset = 0x40
    struct.pack_into('<I', dos_header, 60, pe_offset)

    # PE signature
    pe_sig = b'PE\x00\x00'

    # COFF header (20 bytes)
    machine = 0x8664 if pe32plus else 0x014c  # x64 or x86
    num_sections = 1
    timestamp = 0x65f0a000
    # SizeOfOptionalHeader: PE32+ = 112+128=240=0xf0, PE32 = 96+128=224=0xe0
    size_of_optional = 0xf0 if pe32plus else 0xe0
    coff = struct.pack('<HHIIIHH',
        machine,           # Machine
        num_sections,      # NumberOfSections
        timestamp,         # TimeDateStamp
        0,                 # PointerToSymbolTable
        0,                 # NumberOfSymbols
        size_of_optional,  # SizeOfOptionalHeader
        0x0002,            # Characteristics (executable)
    )

    # Optional header
    magic = 0x020b if pe32plus else 0x010b  # PE32+ or PE32
    if pe32plus:
        # PE32+ optional header: ImageBase is Q (8 bytes), no BaseOfData field
        # Fields: Magic(H) MajLinker(B) MinLinker(B) SizeCode(I) SizeInitData(I) SizeUninitData(I)
        #         AddressOfEntry(I) BaseOfCode(I) ImageBase(Q) SectionAlign(I) FileAlign(I)
        #         MajOS(H) MinOS(H) MajImg(H) MinImg(H) MajSub(H) MinSub(H)
        #         Win32V(I) SizeImage(I) SizeHeaders(I) CheckSum(I) Subsystem(H) DllChars(H)
        #         StackReserve(Q) StackCommit(Q) HeapReserve(Q) HeapCommit(Q)
        #         LoaderFlags(I) NumRvas(I)
        optional = struct.pack('<HBBIIIIIQIIHHHHHHIIIIHHQQQQII',
            magic, 14, 0,
            0x1000, 0, 0,
            0x1000, 0x1000,
            0x400000,
            0x1000, 0x200,
            6, 0, 0, 0, 6, 0,
            0, 0x10000, 0x400, 0,
            3, 0,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16,
        )  # 29 values -- Win32VersionValue is included in the I*4 block above as the first 0
        # Append 16 data directories (128 bytes of zeros)
        optional += b'\x00' * 128
    else:
        optional = struct.pack('<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII',
            magic, 14, 0,                    # Magic, MajorLinkerVersion, MinorLinkerVersion
            0x1000,                           # SizeOfCode
            0,                                # SizeOfInitializedData
            0,                                # SizeOfUninitializedData
            0x1000,                           # AddressOfEntryPoint
            0x1000,                           # BaseOfCode
            0,                                # BaseOfData
            0x400000,                         # ImageBase
            0x1000,                           # SectionAlignment
            0x200,                            # FileAlignment
            6, 0,                             # MajorOperatingSystemVersion, Minor
            0, 0,                             # MajorImageVersion, Minor
            6, 0,                             # MajorSubsystemVersion, Minor
            0,                                # Win32VersionValue
            0x10000,                          # SizeOfImage
            0x400,                            # SizeOfHeaders
            0,                                # CheckSum
            3,                                # Subsystem (GUI)
            0,                                # DllCharacteristics
            0x100000, 0x1000,                 # SizeOfStackReserve, Commit
            0x100000, 0x1000,                 # SizeOfHeapReserve, Commit
            0,                                # LoaderFlags
            16,                               # NumberOfRvaAndSizes
        )
        # Add 16 data directories (128 bytes of zeros)
        optional += b'\x00' * 128

    # Section header (.text)
    section_name = b'.text\x00\x00\x00'  # 8 bytes
    section_header = struct.pack('<8sIIIIIIHHI',
        section_name,
        0x1000,  # VirtualSize
        0x1000,  # VirtualAddress
        0x200,   # SizeOfRawData
        0x400,   # PointerToRawData
        0,       # PointerToRelocations
        0,       # PointerToLinenumbers
        0,       # NumberOfRelocations
        0,       # NumberOfLinenumbers
        0x60000020,  # Characteristics (code, execute, read)
    )

    # Section data (512 bytes of NOPs)
    section_data = b'\x90' * 512

    # Assemble PE
    pe_data = bytearray()
    pe_data.extend(dos_header)
    # Pad to pe_offset
    pe_data.extend(b'\x00' * (pe_offset - len(pe_data)))
    pe_data.extend(pe_sig)
    pe_data.extend(coff)
    pe_data.extend(optional)
    pe_data.extend(section_header)
    # Pad to section data
    pe_data.extend(b'\x00' * (0x400 - len(pe_data)))
    pe_data.extend(section_data)

    path.write_bytes(bytes(pe_data))


@pytest.fixture
def tmp_dir(tmp_path):
    return tmp_path


@pytest.fixture
def valid_pe32(tmp_path):
    path = tmp_path / "test_pe32.exe"
    create_minimal_pe(path, pe32plus=False)
    return path


@pytest.fixture
def valid_pe32plus(tmp_path):
    path = tmp_path / "test_pe32plus.exe"
    create_minimal_pe(path, pe32plus=True)
    return path


@pytest.fixture
def non_pe_file(tmp_path):
    path = tmp_path / "invalid.txt"
    path.write_bytes(b"This is not a PE file")
    return path


@pytest.fixture
def empty_file(tmp_path):
    path = tmp_path / "empty.exe"
    path.write_bytes(b"")
    return path


@pytest.fixture
def truncated_pe(tmp_path):
    path = tmp_path / "truncated.exe"
    path.write_bytes(b"MZ" + b"\x00" * 10)  # MZ but no valid PE structure
    return path
