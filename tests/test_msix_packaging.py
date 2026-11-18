"""tests/test_msix_packaging.py - Unit tests for MSIX packaging, WinGet, Velopack, and Updater.
"""

import os
import sys
import xml.etree.ElementTree as ET
import yaml
import pytest
from unittest.mock import MagicMock, patch
from PIL import Image

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import homie_updater


class TestHomieUpdater:
    def test_version_and_availability(self):
        ver = homie_updater.get_current_version()
        assert isinstance(ver, str)
        assert len(ver) > 0
        avail = homie_updater.is_velopack_available()
        assert isinstance(avail, bool)

    def test_check_for_update_stub(self):
        res = homie_updater.check_for_update("https://fake.url/releases")
        assert res is not None
        assert "current_version" in res
        assert "target_version" in res
        assert "is_available" in res

    def test_apply_update_stub(self):
        res = homie_updater.apply_update()
        assert res is True

    def test_updater_with_mocked_velopack(self):
        mock_vel = MagicMock()
        mock_mgr_cls = MagicMock()
        mock_mgr = MagicMock()
        mock_mgr_cls.return_value = mock_mgr

        mock_update_info = MagicMock()
        mock_release = MagicMock()
        mock_release.version = "1.2.0"
        mock_update_info.target_full_release = mock_release
        mock_mgr.check_for_updates.return_value = mock_update_info

        with patch.dict("sys.modules", {"velopack": mock_vel}):
            with patch("homie_updater._VELOPACK_AVAILABLE", True), \
                 patch("homie_updater._UpdateManager", mock_mgr_cls):
                updater = homie_updater.HomieUpdater(update_url="https://test.update.url")
                check_res = updater.check_for_update()
                assert check_res is not None
                assert check_res["is_available"] is True
                assert check_res["target_version"] == "1.2.0"

                apply_res = updater.apply_update(check_res, restart=True)
                assert apply_res is True
                assert mock_mgr.download_updates.called
                assert mock_mgr.apply_updates_and_restart.called


class TestAppxManifest:
    @pytest.fixture
    def manifest_xml(self):
        path = os.path.join(BASE_DIR, "packaging", "AppxManifest.xml")
        assert os.path.isfile(path), f"AppxManifest.xml not found at {path}"
        tree = ET.parse(path)
        return tree.getroot()

    def test_manifest_identity(self, manifest_xml):
        identity = None
        for elem in manifest_xml.iter():
            if elem.tag.endswith("Identity"):
                identity = elem
                break
        assert identity is not None, "Missing <Identity> tag"
        assert identity.get("Name") == "Homie.DesktopAI"
        assert "CN=" in identity.get("Publisher", "")
        assert identity.get("Version") is not None
        assert identity.get("ProcessorArchitecture") == "x64"

    def test_manifest_capabilities(self, manifest_xml):
        caps = []
        for elem in manifest_xml.iter():
            if elem.tag.endswith("Capability"):
                caps.append(elem.get("Name"))
        assert "runFullTrust" in caps, "Missing runFullTrust capability"

    def test_manifest_visual_elements(self, manifest_xml):
        visual_elem = None
        for elem in manifest_xml.iter():
            if elem.tag.endswith("VisualElements"):
                visual_elem = elem
                break
        assert visual_elem is not None, "Missing <uap:VisualElements>"
        assert visual_elem.get("Square150x150Logo") is not None
        assert visual_elem.get("Square44x44Logo") is not None
        assert visual_elem.get("DisplayName") is not None

    def test_manifest_file_type_associations(self, manifest_xml):
        file_types = []
        for elem in manifest_xml.iter():
            if elem.tag.endswith("FileType"):
                file_types.append(elem.text)
        assert ".homie" in file_types
        assert ".hnote" in file_types


class TestWinGetManifest:
    @pytest.fixture
    def winget_yaml(self):
        path = os.path.join(BASE_DIR, "packaging", "winget", "Homie.yaml")
        assert os.path.isfile(path), f"Homie.yaml not found at {path}"
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def test_winget_fields(self, winget_yaml):
        assert winget_yaml.get("PackageIdentifier") in ["Homie.Homie", "Homie.DesktopAI"]
        assert winget_yaml.get("PackageVersion") is not None
        installers = winget_yaml.get("Installers", [])
        assert len(installers) >= 1
        installer = installers[0]
        assert installer.get("InstallerType") == "msix"
        assert installer.get("InstallerUrl") is not None
        assert "InstallerSha256" in installer


class TestVisualAssets:
    def test_png_icons_dimensions(self):
        assets_dir = os.path.join(BASE_DIR, "packaging", "assets")
        expected = {
            "Square44x44Logo.png": (44, 44),
            "Square150x150Logo.png": (150, 150),
            "Square310x310Logo.png": (310, 310),
            "StoreLogo.png": (50, 50),
            "Wide310x150Logo.png": (310, 150),
            "SplashScreen.png": (620, 300),
        }
        for filename, (expected_w, expected_h) in expected.items():
            path = os.path.join(assets_dir, filename)
            assert os.path.isfile(path), f"Asset {filename} does not exist"
            with Image.open(path) as img:
                assert img.size == (expected_w, expected_h), f"{filename} dimensions {img.size} != {(expected_w, expected_h)}"
