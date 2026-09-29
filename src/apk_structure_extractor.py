"""APK Structure / File Inventory Extractor.

Extracts deterministic structural facts from raw APK extraction and Apktool output:
- dex_files: Top-level DEX files (e.g. classes.dex, classes2.dex)
- dex_count: Total count of DEX files
- is_multidex: True if dex_count > 1
- native_libraries: Relative paths of .so shared libraries under lib/
- has_native_code: True if at least one native library exists
- assets: Relative paths of files under assets/
- smali_roots: Root smali directories in Apktool output (e.g. smali, smali_classes2)
- has_kotlin_metadata: True if Kotlin metadata indicators are present in the APK.

Semantic Note on has_kotlin_metadata:
    has_kotlin_metadata indicates strictly that Kotlin metadata indicators (.kotlin_module,
    kotlin/ directory, or .kotlin_builtins) were found in the APK filesystem.
    It does NOT prove that the application itself was authored in Kotlin, as these
    artifacts may originate from bundled third-party dependencies or libraries.
"""

from pathlib import Path
import re

DEX_PATTERN = re.compile(r"^classes(\d+)?\.dex$")
SMALI_ROOT_PATTERN = re.compile(r"^smali(_classes\d+)?$")


def extract_apk_structure(
    raw_apk_dir: str | Path,
    apktool_dir: str | Path,
) -> dict:
    """Extract deterministic structural inventory from raw APK and Apktool directories.

    Args:
        raw_apk_dir: Directory containing unpacked raw APK contents.
        apktool_dir: Directory containing decoded Apktool output.

    Returns:
        dict matching the schema:
            {
                "dex_files": list[str],
                "dex_count": int,
                "is_multidex": bool,
                "native_libraries": list[str],
                "has_native_code": bool,
                "assets": list[str],
                "smali_roots": list[str],
                "has_kotlin_metadata": bool,
            }

    Raises:
        FileNotFoundError: If raw_apk_dir or apktool_dir does not exist.
        NotADirectoryError: If raw_apk_dir or apktool_dir is not a directory.
    """
    raw_path = Path(raw_apk_dir)
    if not raw_path.exists():
        raise FileNotFoundError(f"Raw APK directory not found: {raw_apk_dir}")
    if not raw_path.is_dir():
        raise NotADirectoryError(f"Raw APK path is not a directory: {raw_apk_dir}")

    apktool_path = Path(apktool_dir)
    if not apktool_path.exists():
        raise FileNotFoundError(f"Apktool directory not found: {apktool_dir}")
    if not apktool_path.is_dir():
        raise NotADirectoryError(f"Apktool path is not a directory: {apktool_dir}")

    # 1. DEX detection (strict: classes.dex, classes2.dex, etc. at raw_path root)
    dex_files_set = set()
    for entry in raw_path.iterdir():
        if entry.is_file() and DEX_PATTERN.match(entry.name):
            dex_files_set.add(entry.name)
    dex_files = sorted(dex_files_set)
    dex_count = len(dex_files)
    is_multidex = dex_count > 1

    # 2. Native library detection (.so files under lib/)
    native_libs_set = set()
    lib_dir = raw_path / "lib"
    if lib_dir.is_dir():
        for file_path in lib_dir.rglob("*.so"):
            if file_path.is_file():
                rel_path = file_path.relative_to(raw_path).as_posix()
                native_libs_set.add(rel_path)
    native_libraries = sorted(native_libs_set)
    has_native_code = len(native_libraries) > 0

    # 3. Assets extraction (all files under assets/)
    assets_set = set()
    assets_dir = raw_path / "assets"
    if assets_dir.is_dir():
        for file_path in assets_dir.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(raw_path).as_posix()
                assets_set.add(rel_path)
    assets = sorted(assets_set)

    # 4. Smali root detection in Apktool output (smali, smali_classes2, etc.)
    smali_roots_set = set()
    for entry in apktool_path.iterdir():
        if entry.is_dir() and SMALI_ROOT_PATTERN.match(entry.name):
            smali_roots_set.add(entry.name)
    smali_roots = sorted(smali_roots_set)

    # 5. Kotlin metadata detection
    # Checks for kotlin/ directory, *.kotlin_module files, or *.kotlin_builtins files.
    # Note: Indicates presence of Kotlin artifacts, which may come from bundled dependencies.
    has_kotlin_metadata = False
    if (raw_path / "kotlin").is_dir():
        has_kotlin_metadata = True
    else:
        for file_path in raw_path.rglob("*"):
            if file_path.is_file():
                name_lower = file_path.name.lower()
                if name_lower.endswith(".kotlin_module") or name_lower.endswith(".kotlin_builtins"):
                    has_kotlin_metadata = True
                    break

    return {
        "dex_files": dex_files,
        "dex_count": dex_count,
        "is_multidex": is_multidex,
        "native_libraries": native_libraries,
        "has_native_code": has_native_code,
        "assets": assets,
        "smali_roots": smali_roots,
        "has_kotlin_metadata": has_kotlin_metadata,
    }
