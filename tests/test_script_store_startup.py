"""The default script store must not mutate an already observed source tree."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def snapshot(root):
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.stat()
        result[path.relative_to(root).as_posix()] = (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
        )
    return result


def manager_from(root):
    # Logging is the only external port; execute the original whole store module.
    name = "_script_store_fixture.fusion_bridge"
    parent = types.ModuleType("_script_store_fixture")
    parent.__path__ = [str(root)]
    package = types.ModuleType(name)
    package.__path__ = [str(root / "fusion_bridge")]
    dispatch = types.ModuleType(name + ".dispatch")
    dispatch.log = lambda *args: None
    spec = importlib.util.spec_from_file_location(
        name + ".script_store", root / "fusion_bridge" / "script_store.py")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        with patch.dict(sys.modules, {
            "_script_store_fixture": parent, name: package,
            name + ".dispatch": dispatch,
        }):
            spec.loader.exec_module(module)
            return module.ScriptManager()
    finally:
        sys.dont_write_bytecode = previous


class ScriptStoreStartupTests(unittest.TestCase):
    def source_fixture(self, root):
        (root / "fusion_bridge").mkdir(parents=True)
        (root / "fusion_bridge" / "script_store.py").write_bytes(
            (ROOT / "fusion_bridge" / "script_store.py").read_bytes())

    def test_distributed_store_exists_before_source_observation(self):
        marker = ROOT / "user_scripts" / ".gitkeep"
        self.assertTrue(marker.is_file(), "Distribution must provision its default store")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.source_fixture(root)
            (root / "user_scripts").mkdir()
            (root / "user_scripts" / ".gitkeep").write_bytes(marker.read_bytes())
            before = snapshot(root)
            manager = manager_from(root)
            self.assertEqual(Path(manager.directory), root / "user_scripts")
            self.assertEqual(snapshot(root), before)

    def test_unprovisioned_store_reproduces_startup_directory_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.source_fixture(root)
            before = snapshot(root)
            manager_from(root)
            after = snapshot(root)
            self.assertEqual(set(after) - set(before), {"user_scripts"})
            self.assertEqual(
                after["fusion_bridge/script_store.py"],
                before["fusion_bridge/script_store.py"])

    def test_existing_saved_scripts_are_not_changed_by_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.source_fixture(root)
            (root / "user_scripts").mkdir()
            saved = root / "user_scripts" / "existing.py"
            saved.write_text("print('preserve user data')\n", encoding="utf-8")
            before = snapshot(root)
            manager_from(root)
            self.assertEqual(snapshot(root), before)


if __name__ == "__main__":
    unittest.main()
