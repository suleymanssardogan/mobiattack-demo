"""Unit and integration tests for Android Manifest parser."""

from pathlib import Path
import tempfile
import unittest

from src.manifest_parser import normalize_activity_name, parse_manifest


class TestActivityNormalization(unittest.TestCase):
    """Test activity name normalization edge cases."""

    def test_relative_activity_with_dot(self):
        # Case 1: .MainActivity -> com.example.app.MainActivity
        self.assertEqual(
            normalize_activity_name(".MainActivity", "com.example.app"),
            "com.example.app.MainActivity",
        )

    def test_short_activity_without_dot(self):
        # Case 2: MainActivity -> com.example.app.MainActivity
        self.assertEqual(
            normalize_activity_name("MainActivity", "com.example.app"),
            "com.example.app.MainActivity",
        )

    def test_fully_qualified_activity(self):
        # Case 3: com.other.ExampleActivity -> com.other.ExampleActivity
        self.assertEqual(
            normalize_activity_name("com.other.ExampleActivity", "com.example.app"),
            "com.other.ExampleActivity",
        )

    def test_empty_activity_name(self):
        self.assertEqual(normalize_activity_name("", "com.example.app"), "")


class TestManifestParserUnit(unittest.TestCase):
    """Synthetic unit tests covering parser edge cases."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_manifest(self, content: str) -> Path:
        file_path = self.dir_path / "AndroidManifest.xml"
        file_path.write_text(content.strip(), encoding="utf-8")
        return file_path

    def test_01_normal_manifest_parsing(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">
            <uses-permission android:name="android.permission.INTERNET" />
            <application>
                <activity android:name=".MainActivity">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN" />
                        <category android:name="android.intent.category.LAUNCHER" />
                    </intent-filter>
                </activity>
            </application>
        </manifest>"""
        path = self._write_manifest(xml)
        result = parse_manifest(path)
        self.assertEqual(result["package_name"], "com.test.app")
        self.assertEqual(result["permissions"], ["android.permission.INTERNET"])
        self.assertEqual(result["activities"], ["com.test.app.MainActivity"])
        self.assertEqual(result["launcher_activity"], "com.test.app.MainActivity")

    def test_02_android_namespace_handling(self):
        # Verify that android:name attribute is parsed via namespace rather than literal string
        xml = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.ns">
            <uses-permission android:name="android.permission.CAMERA" />
            <application>
                <activity android:name="com.test.ns.CameraActivity" />
            </application>
        </manifest>"""
        path = self._write_manifest(xml)
        result = parse_manifest(path)
        self.assertEqual(result["permissions"], ["android.permission.CAMERA"])
        self.assertEqual(result["activities"], ["com.test.ns.CameraActivity"])

    def test_03_permission_extraction(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.perms">
            <uses-permission android:name="android.permission.INTERNET" />
            <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
            <uses-permission android:name="android.permission.INTERNET" />
            <application />
        </manifest>"""
        path = self._write_manifest(xml)
        result = parse_manifest(path)
        # Verify deduplication and proper list extraction
        self.assertEqual(
            result["permissions"],
            ["android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"],
        )

    def test_04_multiple_activities(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.multi">
            <application>
                <activity android:name=".FirstActivity" />
                <activity android:name=".SecondActivity" />
                <activity android:name="ThirdActivity" />
            </application>
        </manifest>"""
        path = self._write_manifest(xml)
        result = parse_manifest(path)
        expected = [
            "com.test.multi.FirstActivity",
            "com.test.multi.SecondActivity",
            "com.test.multi.ThirdActivity",
        ]
        self.assertEqual(result["activities"], expected)

    def test_05_main_and_launcher_detection(self):
        # Launcher requires BOTH MAIN and LAUNCHER in the SAME intent-filter
        xml = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.launcher">
            <application>
                <activity android:name=".SplitFilterActivity">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN" />
                    </intent-filter>
                    <intent-filter>
                        <category android:name="android.intent.category.LAUNCHER" />
                    </intent-filter>
                </activity>
                <activity android:name=".RealLauncherActivity">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN" />
                        <category android:name="android.intent.category.LAUNCHER" />
                    </intent-filter>
                </activity>
            </application>
        </manifest>"""
        path = self._write_manifest(xml)
        result = parse_manifest(path)
        self.assertEqual(result["launcher_activity"], "com.test.launcher.RealLauncherActivity")

    def test_06_relative_activity_name(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.rel">
            <application>
                <activity android:name=".MainActivity" />
            </application>
        </manifest>"""
        path = self._write_manifest(xml)
        result = parse_manifest(path)
        self.assertEqual(result["activities"], ["com.example.rel.MainActivity"])

    def test_07_short_activity_name(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.shortname">
            <application>
                <activity android:name="MainActivity" />
            </application>
        </manifest>"""
        path = self._write_manifest(xml)
        result = parse_manifest(path)
        self.assertEqual(result["activities"], ["com.example.shortname.MainActivity"])

    def test_08_fully_qualified_activity_name(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
            <application>
                <activity android:name="org.external.library.SdkActivity" />
            </application>
        </manifest>"""
        path = self._write_manifest(xml)
        result = parse_manifest(path)
        self.assertEqual(result["activities"], ["org.external.library.SdkActivity"])

    def test_09_missing_application_node(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.emptyapp">
            <uses-permission android:name="android.permission.INTERNET" />
        </manifest>"""
        path = self._write_manifest(xml)
        result = parse_manifest(path)
        self.assertEqual(result["package_name"], "com.example.emptyapp")
        self.assertEqual(result["permissions"], ["android.permission.INTERNET"])
        self.assertEqual(result["activities"], [])
        self.assertIsNone(result["launcher_activity"])

    def test_10_missing_manifest_file(self):
        non_existent = self.dir_path / "non_existent.xml"
        with self.assertRaises(FileNotFoundError):
            parse_manifest(non_existent)

    def test_11_activity_missing_android_name(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.noname">
            <application>
                <activity />
                <activity android:name=".ValidActivity" />
            </application>
        </manifest>"""
        path = self._write_manifest(xml)
        result = parse_manifest(path)
        self.assertEqual(result["activities"], ["com.example.noname.ValidActivity"])

    def test_12_no_launcher_activity(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.nolauncher">
            <application>
                <activity android:name=".NormalActivity">
                    <intent-filter>
                        <action android:name="android.intent.action.VIEW" />
                    </intent-filter>
                </activity>
            </application>
        </manifest>"""
        path = self._write_manifest(xml)
        result = parse_manifest(path)
        self.assertIsNone(result["launcher_activity"])

    def test_invalid_xml_raises_value_error(self):
        malformed = self._write_manifest("<not valid xml")
        with self.assertRaises(ValueError):
            parse_manifest(malformed)

    def test_wrong_root_tag_raises_value_error(self):
        xml = "<configuration><app /></configuration>"
        path = self._write_manifest(xml)
        with self.assertRaises(ValueError):
            parse_manifest(path)


class TestRealOwaspManifestIntegration(unittest.TestCase):
    """Integration test against the actual decoded OWASP test application Manifest."""

    def test_owasp_ground_truth(self):
        # Deterministically locate repo fixture relative to this test file
        repo_root = Path(__file__).resolve().parent.parent if (Path(__file__).resolve().parent.parent / "MSTG-Android-Kotlin.apk").is_file() else Path(__file__).resolve().parent.parent.parent
        manifest_path = repo_root / "apk_lab" / "apktool_out" / "AndroidManifest.xml"

        self.assertTrue(
            manifest_path.is_file(),
            f"Decoded OWASP AndroidManifest.xml not found at expected path: {manifest_path}",
        )

        result = parse_manifest(manifest_path)

        # Ground truth assertions:
        # 1. package_name
        self.assertEqual(result["package_name"], "sg.vantagepoint.mstgkotlin")

        # 2. permissions
        self.assertEqual(result["permissions"], ["android.permission.INTERNET"])

        # 3. launcher_activity
        self.assertEqual(
            result["launcher_activity"],
            "sg.vantagepoint.mstgkotlin.MainActivity",
        )

        # 4. activities
        expected_activities = [
            "sg.vantagepoint.mstgkotlin.MainActivity",
            "sg.vantagepoint.mstgkotlin.RegisterActivity",
            "sg.vantagepoint.mstgkotlin.MenuActivity",
            "sg.vantagepoint.mstgkotlin.SecureWebViewActivity",
            "sg.vantagepoint.mstgkotlin.InsecureWebViewActivity",
        ]
        self.assertEqual(result["activities"], expected_activities)


if __name__ == "__main__":
    unittest.main()
