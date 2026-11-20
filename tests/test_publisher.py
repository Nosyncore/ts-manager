import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from ts_manager.common import ManagerError, sha256


if sys.platform == "linux":
    from ts_manager.publisher import Publisher


LUAC = os.environ.get("TS_TEST_LUAC") or shutil.which("luac") or shutil.which("luac5.4")
SCRIPT = "spells/pilot.lua"
BASE = b"return 'base'\n"
EDIT_A = b"return 'dev-a'\n"
EDIT_B = b"return 'dev-b'\n"


@unittest.skipUnless(sys.platform == "linux" and LUAC, "Requer Linux e luac real")
class PublisherTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for folder in ("target", "dev-a", "dev-b"):
            path = self.root / folder / SCRIPT
            path.parent.mkdir(parents=True)
            path.write_bytes(BASE)
        for folder in ("state", "staging"):
            (self.root / folder).mkdir()
        config = self.root / "publisher.toml"
        config.write_text(
            'target = "target"\nstate = "state"\nstaging = "staging"\n'
            f'validator = "{LUAC}"\nallowed = ["{SCRIPT}"]\n'
            '[workspaces]\ndev-a = "dev-a"\ndev-b = "dev-b"\n',
            encoding="utf-8",
        )
        self.publisher = Publisher(config)
        self.base = self.publisher.initialize(SCRIPT, "operator")["revision"]
        self.target = self.root / "target" / SCRIPT
        self.source_a = self.root / "dev-a" / SCRIPT
        self.source_b = self.root / "dev-b" / SCRIPT

    def publish_a(self):
        self.source_a.write_bytes(EDIT_A)
        return self.publisher.publish(SCRIPT, "dev-a", sha256(EDIT_A))

    def test_publish_conflict_manual_adoption_and_restore(self):
        self.target.chmod(0o640)
        self.source_b.write_bytes(EDIT_B)
        published = self.publish_a()
        revision = published["revision"]
        self.assertEqual(self.target.read_bytes(), EDIT_A)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.root / "state" / "snapshots" / sha256(BASE)).read_bytes(), BASE)
        with sqlite3.connect(self.root / "state" / "revisions.sqlite3") as db:
            row = db.execute("SELECT actor, operation, state FROM revisions WHERE id = ?", (revision,)).fetchone()
            self.assertEqual(row, ("dev-a", "publish", "applied"))
        self.assertEqual(self.publisher.status(SCRIPT, "dev-a")["base"], revision)
        self.assertEqual(self.publisher.status(SCRIPT, "dev-b")["base"], self.base)
        self.assertFalse(self.publish_a()["changed"])
        with self.assertRaisesRegex(ManagerError, "Conflito"):
            self.publisher.publish(SCRIPT, "dev-b", sha256(EDIT_B))
        self.publisher.adopt(SCRIPT, "dev-b", revision)
        self.assertEqual(self.source_b.read_bytes(), EDIT_B)
        self.publisher.rollback(SCRIPT, "operator", revision)
        self.assertEqual(self.target.read_bytes(), BASE)
        self.assertEqual(self.source_a.read_bytes(), EDIT_A)
        self.assertEqual(self.source_b.read_bytes(), EDIT_B)

    def test_invalid_source_and_stale_sync_preserve_destination(self):
        self.source_a.write_bytes(b"local =\n")
        with self.assertRaisesRegex(ManagerError, "Sintaxe Lua inválida"):
            self.publisher.publish(SCRIPT, "dev-a", sha256(b"local =\n"))
        with self.assertRaisesRegex(ManagerError, "SHA-256 local"):
            self.publisher.publish(SCRIPT, "dev-a", sha256(EDIT_A))
        self.source_a.unlink()
        with self.assertRaisesRegex(ManagerError, "ausente"):
            self.publisher.publish(SCRIPT, "dev-a", sha256(EDIT_A))
        self.assertEqual(self.target.read_bytes(), BASE)

    def test_allowlist_and_symlinks_including_workspace_root(self):
        for path in ("../pilot.lua", "/pilot.lua", "spells//pilot.lua", "unlisted.lua"):
            with self.subTest(path=path), self.assertRaises(ManagerError):
                self.publisher.publish(path, "dev-a", sha256(BASE))
        self.source_a.unlink()
        self.source_a.symlink_to(self.target)
        with self.assertRaisesRegex(ManagerError, "contém um link"):
            self.publisher.publish(SCRIPT, "dev-a", sha256(BASE))
        self.source_a.unlink()
        workspace = self.root / "dev-a"
        workspace.rename(self.root / "moved")
        workspace.symlink_to(self.root / "target", target_is_directory=True)
        with self.assertRaisesRegex(ManagerError, "contém um link"):
            self.publisher.publish(SCRIPT, "dev-a", sha256(BASE))

    def test_external_edit_is_refused(self):
        self.target.write_bytes(EDIT_B)
        with self.assertRaisesRegex(ManagerError, "edição externa"):
            self.publish_a()
        self.assertEqual(self.target.read_bytes(), EDIT_B)

    def test_two_publishers_serialize_against_the_same_base(self):
        self.source_b.write_bytes(EDIT_B)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.publish_a), pool.submit(self.publisher.publish, SCRIPT, "dev-b", sha256(EDIT_B))]
        self.assertEqual(sum(future.exception() is None for future in futures), 1)
        failure = next(future.exception() for future in futures if future.exception() is not None)
        self.assertIsInstance(failure, ManagerError)
        self.assertIn("Conflito", str(failure))
        self.assertIn(self.target.read_bytes(), (EDIT_A, EDIT_B))

    def test_recovery_before_replacement(self):
        original = os.replace

        def fail_before_replace(source, target, **kwargs):
            if "dst_dir_fd" in kwargs:
                raise OSError("falha antes da troca")
            return original(source, target, **kwargs)

        with patch("ts_manager.publisher.os.replace", side_effect=fail_before_replace), self.assertRaises(OSError):
            self.publish_a()
        self.assertEqual(self.target.read_bytes(), BASE)
        self.assertEqual(self.publisher.status(SCRIPT, "dev-a")["revision"], self.base)
        self.assertTrue(self.publish_a()["changed"])

    def test_recovery_after_replacement(self):
        with patch.object(self.publisher, "_finish", side_effect=OSError("falha após a troca")), self.assertRaises(OSError):
            self.publish_a()
        self.assertEqual(self.target.read_bytes(), EDIT_A)
        status = self.publisher.status(SCRIPT, "dev-a")
        self.assertNotEqual(status["revision"], self.base)
        self.assertEqual(status["revision"], status["base"])
        self.assertFalse(self.publish_a()["changed"])

    def test_recovery_blocks_third_content(self):
        with patch.object(self.publisher, "_finish", side_effect=OSError), self.assertRaises(OSError):
            self.publish_a()
        self.target.write_bytes(EDIT_B)
        with self.assertRaisesRegex(ManagerError, "terceiro conteúdo"):
            self.publisher.status(SCRIPT, "dev-a")
        self.assertEqual(self.target.read_bytes(), EDIT_B)
