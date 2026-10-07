from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable.adapters import load_adapter_class


class DynamicAdapterLoaderTests(unittest.TestCase):
    def test_ctfd_browser_dataclass_loads_with_registered_module(self) -> None:
        module_name = "rookery_adapter_ctfd_browser"
        previous = sys.modules.get(module_name)
        try:
            adapter_class = load_adapter_class(ROOKERY_ROOT, "ctfd_browser")
            self.assertEqual(adapter_class.__name__, "CTFdBrowserAdapter")
            self.assertIs(sys.modules[module_name].CTFdBrowserAdapter, adapter_class)
        finally:
            if previous is None:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = previous

    def test_failed_import_restores_prior_module(self) -> None:
        module_name = "rookery_adapter_broken_loader_test"
        prior = types.ModuleType(module_name)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = root / "adapters" / "broken_loader_test"
            bundle.mkdir(parents=True)
            (bundle / "adapter.json").write_text(
                json.dumps({"id": "broken_loader_test"}), encoding="utf-8"
            )
            (bundle / "adapter.py").write_text(
                "import sys\n"
                "assert __name__ in sys.modules\n"
                "raise RuntimeError('fixture import failure')\n",
                encoding="utf-8",
            )
            previous = sys.modules.get(module_name)
            sys.modules[module_name] = prior
            try:
                with self.assertRaisesRegex(RuntimeError, "fixture import failure"):
                    load_adapter_class(root, "broken_loader_test")
                self.assertIs(sys.modules[module_name], prior)
            finally:
                if previous is None:
                    sys.modules.pop(module_name, None)
                else:
                    sys.modules[module_name] = previous

    def test_invalid_class_removes_partial_module(self) -> None:
        module_name = "rookery_adapter_invalid_loader_test"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = root / "adapters" / "invalid_loader_test"
            bundle.mkdir(parents=True)
            (bundle / "adapter.json").write_text(
                json.dumps({"id": "invalid_loader_test"}), encoding="utf-8"
            )
            (bundle / "adapter.py").write_text(
                "class AdapterImplementation: pass\n", encoding="utf-8"
            )
            previous = sys.modules.pop(module_name, None)
            try:
                with self.assertRaisesRegex(TypeError, "not a Rookery Adapter"):
                    load_adapter_class(root, "invalid_loader_test")
                self.assertNotIn(module_name, sys.modules)
            finally:
                if previous is not None:
                    sys.modules[module_name] = previous


if __name__ == "__main__":
    unittest.main()
