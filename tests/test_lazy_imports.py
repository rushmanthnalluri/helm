"""tests/test_lazy_imports.py - Unit test suite for Helm lazy import engine and background pre-warming.

Verifies:
1. LazyModule defers importing the target module until first attribute access.
2. Background preload thread starts properly with priority ordering.
3. Accessing existing attributes works without AttributeError.
4. Nonexistent attributes properly raise AttributeError.
5. Exported lazy stubs (torch, sentence_transformers, faster_whisper, winrt, cryptography, openpyxl).
"""

import os
import sys
import threading
import time
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from helm_lazy import (
    LazyModule,
    preload_in_background,
    get_preload_status,
    is_preloading,
    torch,
    sentence_transformers,
    faster_whisper,
    winrt,
    cryptography,
    openpyxl,
)


class TestLazyImports(unittest.TestCase):
    """Test suite for LazyModule proxying and deferred loading."""

    def test_lazy_module_defers_import(self):
        """Test that LazyModule does not import the module at instantiation."""
        # Use a fresh, unimported dummy or standard module name
        lazy_mod = LazyModule("decimal")
        self.assertFalse(lazy_mod.is_loaded)
        self.assertIsNone(lazy_mod._mod)
        self.assertIn("deferred", repr(lazy_mod))

    def test_no_attribute_error_on_lazy_access(self):
        """Test that accessing valid attributes resolves transparently without AttributeError."""
        lazy_json = LazyModule("json")
        self.assertIsNone(lazy_json._mod)

        # Access valid attribute: dumps
        result = lazy_json.dumps({"helm": "fast_start"})
        self.assertEqual(result, '{"helm": "fast_start"}')

        # Verify underlying module is now loaded
        self.assertTrue(lazy_json.is_loaded)
        self.assertIsNotNone(lazy_json._mod)
        self.assertIn("loaded", repr(lazy_json))

        # Access another attribute on already loaded module
        parsed = lazy_json.loads(result)
        self.assertEqual(parsed, {"helm": "fast_start"})

    def test_attribute_error_on_nonexistent_attribute(self):
        """Test that accessing a nonexistent attribute raises AttributeError."""
        lazy_math = LazyModule("math")
        with self.assertRaises(AttributeError):
            _ = lazy_math.completely_nonexistent_helm_attribute_12345

    def test_background_preload_thread_starts(self):
        """Test that preload_in_background spins up a daemon Thread that executes preloads."""
        completed_flag = threading.Event()

        def on_done():
            completed_flag.set()

        # Preload lightweight test modules via priority queue
        targets = [
            (1, "math"),
            (2, "statistics"),
            (3, "urllib.parse"),
        ]
        thread = preload_in_background(priority_order=targets, on_complete=on_done)

        self.assertIsNotNone(thread)
        self.assertIsInstance(thread, threading.Thread)
        self.assertTrue(thread.daemon)

        # Wait for preload thread to complete
        thread.join(timeout=10.0)
        self.assertFalse(thread.is_alive())
        self.assertTrue(completed_flag.is_set())

        # Check recorded status
        status = get_preload_status()
        self.assertIn("math", status)
        self.assertTrue(status["math"]["ok"])
        self.assertIn("statistics", status)
        self.assertTrue(status["statistics"]["ok"])
        self.assertIn("urllib.parse", status)
        self.assertTrue(status["urllib.parse"]["ok"])

    def test_exported_stubs_are_lazy_modules(self):
        """Verify that exported heavy stubs are instances of LazyModule."""
        for stub, name in [
            (torch, "torch"),
            (sentence_transformers, "sentence_transformers"),
            (faster_whisper, "faster_whisper"),
            (winrt, "winrt"),
            (cryptography, "cryptography"),
            (openpyxl, "openpyxl"),
        ]:
            self.assertIsInstance(stub, LazyModule)
            self.assertEqual(stub._name, name)

    def test_lazy_dir_and_repr(self):
        """Test __dir__ and __repr__ functionality on LazyModule."""
        lazy_re = LazyModule("re")
        self.assertIn("deferred", repr(lazy_re))
        dir_entries = dir(lazy_re)
        self.assertIn("compile", dir_entries)
        self.assertIn("search", dir_entries)
        self.assertTrue(lazy_re.is_loaded)
        self.assertIn("loaded", repr(lazy_re))


if __name__ == "__main__":
    unittest.main()
