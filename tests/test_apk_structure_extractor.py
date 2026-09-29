"""Unit and integration tests for APK Structure / File Inventory Extractor."""

from pathlib import Path
import tempfile
import unittest

from src.apk_structure_extractor import extract_apk_structure


class TestApkStructureExtractorUnit(unittest.TestCase):
    """Synthetic unit tests for APK structure extraction."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.raw_apk = self.base_path / "raw_apk"
        self.apktool = self.base_path / "apktool_out"
        self.raw_apk.mkdir()
        self.apktool.mkdir()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_single_dex(self):
        (self.raw_apk / "classes.dex").write_text("dummy", encoding="utf-8")
        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertEqual(result["dex_files"], ["classes.dex"])
        self.assertEqual(result["dex_count"], 1)
        self.assertFalse(result["is_multidex"])

    def test_02_multidex(self):
        (self.raw_apk / "classes.dex").write_text("d1", encoding="utf-8")
        (self.raw_apk / "classes2.dex").write_text("d2", encoding="utf-8")
        (self.raw_apk / "classes3.dex").write_text("d3", encoding="utf-8")
        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertEqual(result["dex_files"], ["classes.dex", "classes2.dex", "classes3.dex"])
        self.assertEqual(result["dex_count"], 3)
        self.assertTrue(result["is_multidex"])

    def test_03_no_dex(self):
        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertEqual(result["dex_files"], [])
        self.assertEqual(result["dex_count"], 0)
        self.assertFalse(result["is_multidex"])

    def test_04_native_library_detection(self):
        arm_dir = self.raw_apk / "lib" / "arm64-v8a"
        arm_dir.mkdir(parents=True)
        (arm_dir / "libtest.so").write_text("elf", encoding="utf-8")

        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertEqual(result["native_libraries"], ["lib/arm64-v8a/libtest.so"])
        self.assertTrue(result["has_native_code"])

    def test_05_multiple_abi_directories(self):
        abis = ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]
        for abi in abis:
            abi_dir = self.raw_apk / "lib" / abi
            abi_dir.mkdir(parents=True)
            (abi_dir / f"lib{abi}.so").write_text("elf", encoding="utf-8")

        result = extract_apk_structure(self.raw_apk, self.apktool)
        expected = [
            "lib/arm64-v8a/libarm64-v8a.so",
            "lib/armeabi-v7a/libarmeabi-v7a.so",
            "lib/x86/libx86.so",
            "lib/x86_64/libx86_64.so",
        ]
        self.assertEqual(result["native_libraries"], sorted(expected))
        self.assertTrue(result["has_native_code"])

    def test_06_no_native_libraries(self):
        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertEqual(result["native_libraries"], [])
        self.assertFalse(result["has_native_code"])

    def test_07_asset_extraction(self):
        assets_dir = self.raw_apk / "assets" / "sub"
        assets_dir.mkdir(parents=True)
        (assets_dir / "config.json").write_text("{}", encoding="utf-8")
        (self.raw_apk / "assets" / "root.txt").write_text("hello", encoding="utf-8")

        result = extract_apk_structure(self.raw_apk, self.apktool)
        expected = ["assets/root.txt", "assets/sub/config.json"]
        self.assertEqual(result["assets"], expected)

    def test_08_no_assets(self):
        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertEqual(result["assets"], [])

    def test_09_smali_root_detection(self):
        (self.apktool / "smali").mkdir()
        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertEqual(result["smali_roots"], ["smali"])

    def test_10_multiple_smali_roots(self):
        (self.apktool / "smali").mkdir()
        (self.apktool / "smali_classes2").mkdir()
        (self.apktool / "smali_classes3").mkdir()

        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertEqual(result["smali_roots"], ["smali", "smali_classes2", "smali_classes3"])

    def test_11_no_smali_roots(self):
        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertEqual(result["smali_roots"], [])

    def test_12_kotlin_metadata_present_via_directory(self):
        (self.raw_apk / "kotlin").mkdir()
        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertTrue(result["has_kotlin_metadata"])

    def test_12b_kotlin_metadata_present_via_module_file(self):
        meta_dir = self.raw_apk / "META-INF"
        meta_dir.mkdir()
        (meta_dir / "lib.kotlin_module").write_text("data", encoding="utf-8")
        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertTrue(result["has_kotlin_metadata"])

    def test_13_kotlin_metadata_absent(self):
        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertFalse(result["has_kotlin_metadata"])

    def test_14_missing_raw_apk_directory(self):
        non_existent = self.base_path / "non_existent_raw"
        with self.assertRaises(FileNotFoundError):
            extract_apk_structure(non_existent, self.apktool)

    def test_15_missing_apktool_directory(self):
        non_existent = self.base_path / "non_existent_apktool"
        with self.assertRaises(FileNotFoundError):
            extract_apk_structure(self.raw_apk, non_existent)

    def test_16_deterministic_sorting(self):
        # Create un-sorted files
        (self.raw_apk / "classes3.dex").write_text("d", encoding="utf-8")
        (self.raw_apk / "classes.dex").write_text("d", encoding="utf-8")
        (self.raw_apk / "classes2.dex").write_text("d", encoding="utf-8")

        (self.apktool / "smali_classes3").mkdir()
        (self.apktool / "smali").mkdir()
        (self.apktool / "smali_classes2").mkdir()

        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertEqual(result["dex_files"], ["classes.dex", "classes2.dex", "classes3.dex"])
        self.assertEqual(result["smali_roots"], ["smali", "smali_classes2", "smali_classes3"])

    def test_17_duplicate_prevention(self):
        (self.raw_apk / "classes.dex").write_text("d", encoding="utf-8")
        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertEqual(len(result["dex_files"]), len(set(result["dex_files"])))

    def test_18_strict_dex_name_rejection(self):
        # Loose patterns like classes*.dex might match these; strict pattern must reject them
        (self.raw_apk / "classes_backup.dex").write_text("d", encoding="utf-8")
        (self.raw_apk / "classes_old.dex").write_text("d", encoding="utf-8")
        (self.raw_apk / "my_classes.dex").write_text("d", encoding="utf-8")
        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertEqual(result["dex_files"], [])
        self.assertEqual(result["dex_count"], 0)

    def test_19_strict_smali_root_rejection(self):
        (self.apktool / "smali_backup").mkdir()
        (self.apktool / "smali_temp").mkdir()
        (self.apktool / "not_smali").mkdir()
        result = extract_apk_structure(self.raw_apk, self.apktool)
        self.assertEqual(result["smali_roots"], [])


class TestRealOwaspApkStructureIntegration(unittest.TestCase):
    """Integration test against actual OWASP raw_apk and apktool_out directories."""

    def test_owasp_ground_truth(self):
        repo_root = Path(__file__).resolve().parent.parent if (Path(__file__).resolve().parent.parent / "MSTG-Android-Kotlin.apk").is_file() else Path(__file__).resolve().parent.parent.parent
        raw_apk_dir = repo_root / "apk_lab" / "raw_apk"
        apktool_dir = repo_root / "apk_lab" / "apktool_out"

        self.assertTrue(raw_apk_dir.is_dir(), f"raw_apk not found at {raw_apk_dir}")
        self.assertTrue(apktool_dir.is_dir(), f"apktool_out not found at {apktool_dir}")

        result = extract_apk_structure(raw_apk_dir, apktool_dir)

        # Ground truth assertions:
        self.assertEqual(result["dex_files"], ["classes.dex"])
        self.assertEqual(result["dex_count"], 1)
        self.assertFalse(result["is_multidex"])
        self.assertEqual(result["native_libraries"], [])
        self.assertFalse(result["has_native_code"])
        self.assertEqual(result["assets"], ["assets/unsafe_content.html"])
        self.assertEqual(result["smali_roots"], ["smali"])
        self.assertTrue(result["has_kotlin_metadata"])


if __name__ == "__main__":
    unittest.main()
