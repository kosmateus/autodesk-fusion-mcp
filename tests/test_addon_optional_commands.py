"""Actual addon wiring with socket-free ports and an observable commands import."""

import importlib.abc
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "_optional_commands_fixture"


class OptionalCommandsTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.retired = None
        package = types.ModuleType(PACKAGE)
        package.__path__ = [str(ROOT)]
        bridge = types.ModuleType(PACKAGE + ".fusion_bridge")
        bridge.runtime = types.SimpleNamespace(
            log=lambda *a: None, start=Mock(return_value=True),
            stop=self.defer_retirement)
        library = types.ModuleType(PACKAGE + ".lib")
        library.fusionAddInUtils = types.SimpleNamespace(
            clear_handlers=lambda: self.events.append("clear-handlers"),
            handle_error=Mock())
        modules = {
            PACKAGE: package, PACKAGE + ".fusion_bridge": bridge,
            PACKAGE + ".lib": library,
            PACKAGE + ".settings": types.SimpleNamespace(
                MCP_AUTO_CONNECT=True, MCP_SERVER_PORT=8765),
        }
        sys.modules.update(modules)
        self.addCleanup(self.remove_modules)
        events = self.events

        class CommandsImport(importlib.abc.MetaPathFinder, importlib.abc.Loader):
            def find_spec(self, fullname, path=None, target=None):
                if fullname == PACKAGE + ".commands":
                    events.append("import-commands")
                    return importlib.util.spec_from_loader(fullname, self)
                return None

            def create_module(self, spec):
                return None

            def exec_module(self, module):
                module.start = lambda: events.append("start-commands")
                module.stop = lambda: events.append("stop-commands")

        finder = CommandsImport()
        sys.meta_path.insert(0, finder)
        self.addCleanup(sys.meta_path.remove, finder)
        spec = importlib.util.spec_from_file_location(
            PACKAGE + ".addon_runtime", ROOT / "addon_runtime.py")
        self.addon = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.addon
        spec.loader.exec_module(self.addon)
        self.runtime = bridge.runtime
        self.futil = library.fusionAddInUtils

    def remove_modules(self):
        for name in list(sys.modules):
            if name == PACKAGE or name.startswith(PACKAGE + "."):
                del sys.modules[name]

    def defer_retirement(self, *, on_retired):
        self.retired = on_retired

    def test_ordinary_start_loads_commands_and_stop_waits_for_retirement(self):
        self.assertEqual(self.events, [], "Module import must not load commands")
        self.assertTrue(self.addon.run(None))
        self.runtime.start.assert_called_once_with()
        self.assertEqual(self.events, ["import-commands", "start-commands"])
        self.addon.stop(None)
        self.assertEqual(self.events, ["import-commands", "start-commands"])
        self.retired()
        self.assertEqual(self.events, [
            "import-commands", "start-commands", "stop-commands", "clear-handlers"])
        self.futil.handle_error.assert_not_called()

    def test_controlled_start_and_stop_do_not_load_commands(self):
        bootstrap = object()
        self.assertTrue(self.addon.run(None, bootstrap=bootstrap))
        self.runtime.start.assert_called_once_with(bootstrap=bootstrap)
        self.addon.stop(None)
        self.retired()
        self.assertEqual(self.events, ["clear-handlers"])
        self.assertNotIn(PACKAGE + ".commands", sys.modules)
        self.futil.handle_error.assert_not_called()

    def test_failed_ordinary_runtime_start_does_not_load_commands(self):
        self.runtime.start.return_value = False
        self.assertFalse(self.addon.run(None))
        self.assertEqual(self.events, [])
        self.assertNotIn(PACKAGE + ".commands", sys.modules)
