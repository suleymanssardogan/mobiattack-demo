"""Deterministic Mach-O Binary Analyzer for MobiAttack V2.

Analyzes iOS Mach-O executables safely without binary execution or code loading.
Extracts architecture, 32/64-bitness, linked dynamic libraries, UUID, and encryption
metadata using native Python binary parsing with optional macOS system tool verification.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import struct
import subprocess
from typing import Any

# Mach-O Magic constants
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

# CPU Types
CPU_TYPE_X86 = 7
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_ARM64_32 = 0x0200000C

CPU_TYPE_NAMES = {
    CPU_TYPE_X86: "i386",
    CPU_TYPE_X86_64: "x86_64",
    CPU_TYPE_ARM: "armv7",
    CPU_TYPE_ARM64: "arm64",
    CPU_TYPE_ARM64_32: "arm64_32",
}

# Mach-O File Types
MH_EXECUTE = 0x2
MH_DYLIB = 0x6
MH_BUNDLE = 0x8

FILE_TYPE_NAMES = {
    MH_EXECUTE: "Mach-O executable",
    MH_DYLIB: "Mach-O dynamically linked shared library",
    MH_BUNDLE: "Mach-O bundle",
}

# Load Command Types
LC_REQ_DYLD = 0x80000000
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_UUID = 0x1B
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C


def validate_macho_magic(file_path: str | Path) -> dict[str, Any]:
    """Inspects file header magic bytes to verify if a file is a valid Mach-O binary.

    Args:
        file_path: Path to candidate binary.

    Returns:
        Dictionary containing is_macho (bool), is_fat (bool), magic (int or None).
    """
    p = Path(file_path)
    if not p.is_file() or p.stat().st_size < 4:
        return {"is_macho": False, "is_fat": False, "magic": None}

    try:
        with open(p, "rb") as f:
            magic_bytes = f.read(4)
        if len(magic_bytes) < 4:
            return {"is_macho": False, "is_fat": False, "magic": None}

        magic = struct.unpack(">I", magic_bytes)[0]
        is_fat = magic in (FAT_MAGIC, FAT_CIGAM)
        is_thin = magic in (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64)

        return {
            "is_macho": bool(is_fat or is_thin),
            "is_fat": is_fat,
            "magic": hex(magic),
        }
    except Exception:
        return {"is_macho": False, "is_fat": False, "magic": None}


def parse_macho_native(file_path: str | Path) -> dict[str, Any]:
    """Pure Python deterministic parser for Mach-O binary headers and load commands.

    Does not depend on external tools, ensuring platform portability.
    """
    p = Path(file_path)
    result: dict[str, Any] = {
        "is_macho": False,
        "architectures": [],
        "bitness": None,
        "file_type": None,
        "uuid": None,
        "encryption_info": None,
        "linked_libraries": [],
    }

    try:
        with open(p, "rb") as f:
            data = f.read(65536)  # Read first 64KB for headers and load commands
    except Exception:
        return result

    if len(data) < 4:
        return result

    magic = struct.unpack(">I", data[:4])[0]

    # Handle Universal / FAT Binary
    if magic in (FAT_MAGIC, FAT_CIGAM):
        endian = ">" if magic == FAT_MAGIC else "<"
        if len(data) < 8:
            return result
        nfat_arch = struct.unpack(f"{endian}I", data[4:8])[0]
        archs = []
        bitness = 64

        offset = 8
        for _ in range(min(nfat_arch, 16)):
            if offset + 20 > len(data):
                break
            cputype, cpusubtype, arch_offset, arch_size, align = struct.unpack(
                f"{endian}IIIII", data[offset : offset + 20]
            )
            arch_name = CPU_TYPE_NAMES.get(cputype, f"unknown_{hex(cputype)}")
            archs.append(arch_name)
            offset += 20

        result["is_macho"] = True
        result["architectures"] = archs
        result["bitness"] = 64 if any("64" in a for a in archs) else 32
        result["file_type"] = "Mach-O universal binary"
        result["macho_type"] = result["file_type"]
        return result

    # Handle Thin Mach-O (32-bit or 64-bit)
    is_64 = magic in (MH_MAGIC_64, MH_CIGAM_64)
    is_32 = magic in (MH_MAGIC, MH_CIGAM)

    if not (is_64 or is_32):
        return result

    endian = "<" if magic in (MH_CIGAM, MH_CIGAM_64) else ">"
    header_size = 32 if is_64 else 28

    if len(data) < header_size:
        return result

    if is_64:
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack(
            f"{endian}IIIIIII", data[4:32]
        )
    else:
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(
            f"{endian}IIIIII", data[4:28]
        )

    arch_name = CPU_TYPE_NAMES.get(cputype, f"cpu_{hex(cputype)}")
    result["is_macho"] = True
    result["architectures"] = [arch_name]
    result["bitness"] = 64 if is_64 else 32
    result["file_type"] = FILE_TYPE_NAMES.get(filetype, f"Mach-O filetype {hex(filetype)}")
    result["macho_type"] = result["file_type"]

    # Parse Load Commands
    cmd_offset = header_size
    linked_libs = []
    uuid_str = None
    enc_info = None

    for _ in range(min(ncmds, 256)):
        if cmd_offset + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack(f"{endian}II", data[cmd_offset : cmd_offset + 8])
        if cmdsize < 8 or cmd_offset + cmdsize > len(data):
            break

        # LC_LOAD_DYLIB or LC_LOAD_WEAK_DYLIB
        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
            if cmd_offset + 24 <= len(data):
                stroffset = struct.unpack(f"{endian}I", data[cmd_offset + 8 : cmd_offset + 12])[0]
                if stroffset < cmdsize:
                    name_bytes = data[cmd_offset + stroffset : cmd_offset + cmdsize]
                    name_str = name_bytes.split(b"\x00")[0].decode("utf-8", errors="replace")
                    if name_str:
                        linked_libs.append(name_str)

        # LC_UUID
        elif cmd == LC_UUID and cmdsize >= 24:
            uuid_bytes = data[cmd_offset + 8 : cmd_offset + 24]
            if len(uuid_bytes) == 16:
                uuid_str = (
                    f"{uuid_bytes[0:4].hex().upper()}-"
                    f"{uuid_bytes[4:6].hex().upper()}-"
                    f"{uuid_bytes[6:8].hex().upper()}-"
                    f"{uuid_bytes[8:10].hex().upper()}-"
                    f"{uuid_bytes[10:16].hex().upper()}"
                )

        # LC_ENCRYPTION_INFO or LC_ENCRYPTION_INFO_64
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64) and cmdsize >= 16:
            cmd_name = "LC_ENCRYPTION_INFO_64" if cmd == LC_ENCRYPTION_INFO_64 else "LC_ENCRYPTION_INFO"
            cryptoff, cryptsize, cryptid = struct.unpack(
                f"{endian}III", data[cmd_offset + 8 : cmd_offset + 20]
            )
            # Factual binary property extraction (not a vulnerability or security verdict)
            enc_info = {
                "cryptid": cryptid,
                "crypt_id": cryptid,  # backward compat
                "encryption_state": "encrypted" if cryptid != 0 else "unencrypted",
                "crypt_offset": cryptoff,
                "crypt_size": cryptsize,
                "load_command": cmd_name,
                "evidence": {
                    "source": "macho_load_command",
                    "command": cmd_name,
                    "command_id": hex(cmd),
                    "cryptid_raw": cryptid,
                    "nature": "factual_binary_property",
                },
            }

        cmd_offset += cmdsize

    result["linked_libraries"] = linked_libs
    result["uuid"] = uuid_str
    result["encryption_info"] = enc_info
    return result


def analyze_macho_executable(
    executable_path: str | Path,
    use_system_tools: bool = True,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Analyzes a Mach-O executable safely using Python parsing and optional macOS tools.

    Strict rules:
      - Never executes the binary.
      - Uses argument lists with shell=False for all tool invocations.
      - Distinguishes: tool_failed, unsupported, not_found.

    Args:
        executable_path: Path to candidate executable file.
        use_system_tools: If True, queries macOS otool if available on the system.
        timeout_seconds: Subprocess timeout ceiling.

    Returns:
        Structured Mach-O analysis dictionary.
    """
    p = Path(executable_path).resolve()
    if not p.is_file():
        return {
            "status": "not_found",
            "is_macho": False,
            "error": f"Executable not found: '{executable_path}'",
        }

    # 1. Native Python Parser
    native_facts = parse_macho_native(p)
    if not native_facts["is_macho"]:
        return {
            "status": "invalid_input",
            "is_macho": False,
            "error": f"File is not a valid Mach-O binary: '{p.name}'",
        }

    tools_used: list[dict[str, Any]] = [
        {"tool": "native_python_struct", "status": "success"}
    ]

    linked_libraries = list(native_facts["linked_libraries"])

    # 2. Optional macOS System Tool: otool -L
    if use_system_tools and shutil.which("otool"):
        try:
            cmd = ["otool", "-L", str(p)]
            proc = subprocess.run(
                cmd,
                shell=False,
                timeout=timeout_seconds,
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode == 0:
                tools_used.append({"tool": "otool", "status": "success"})
                # Parse otool -L lines
                otool_libs = []
                for line in proc.stdout.splitlines()[1:]:  # First line is binary name
                    stripped = line.strip()
                    if stripped:
                        lib_name = stripped.split(" (compatibility")[0].strip()
                        if lib_name:
                            otool_libs.append(lib_name)
                if otool_libs:
                    # Merge unique libraries preserving order
                    for lib in otool_libs:
                        if lib not in linked_libraries:
                            linked_libraries.append(lib)
            else:
                tools_used.append({
                    "tool": "otool",
                    "status": "tool_failed",
                    "returncode": proc.returncode,
                    "stderr": proc.stderr.strip(),
                })
        except subprocess.TimeoutExpired:
            tools_used.append({"tool": "otool", "status": "tool_failed", "error": "timeout"})
        except Exception as exc:
            tools_used.append({"tool": "otool", "status": "tool_failed", "error": str(exc)})
    elif use_system_tools:
        tools_used.append({"tool": "otool", "status": "unsupported", "reason": "tool_not_found_on_host"})

    enc_info = native_facts.get("encryption_info")
    cryptid = enc_info.get("cryptid") if isinstance(enc_info, dict) else None
    encryption_state = enc_info.get("encryption_state", "not_specified") if isinstance(enc_info, dict) else "not_specified"

    return {
        "status": "success",
        "is_macho": True,
        "name": p.name,
        "architectures": native_facts["architectures"],
        "bitness": native_facts["bitness"],
        "file_type": native_facts["file_type"],
        "macho_type": native_facts.get("file_type"),
        "linked_libraries": linked_libraries,
        "linked_library_count": len(linked_libraries),
        "uuid": native_facts["uuid"],
        "cryptid": cryptid,
        "encryption_state": encryption_state,
        "encryption_info": native_facts["encryption_info"],
        "tools_used": tools_used,
    }
