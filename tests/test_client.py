import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ts_manager.__main__ import parser, remote
from ts_manager.common import ManagerError, sha256


class ClientTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.data = b"return 10\n"
        (self.root / "pilot.lua").write_bytes(self.data)
        self.arguments = parser().parse_args(
            ["publish", "pilot.lua", "--host", "ts-publish", "--session", "ts-dev-a", "--workspace", str(self.root)]
        )
        self.session = {
            "alpha": {"connected": True, "path": str(self.root)},
            "beta": {"connected": True, "path": "/tmp/remote", "host": "ts-dev-a"},
            "successfulCycles": 1,
        }

    def test_publish_checks_session_and_sends_local_hash_over_ssh(self):
        result = {"path": "pilot.lua", "revision": 2, "sha256": sha256(self.data)}
        with patch(
            "ts_manager.__main__.run_tool", side_effect=[b"", json.dumps([self.session]), json.dumps({"result": result})]
        ) as execute:
            self.assertEqual(remote(self.arguments), result)
        self.assertEqual(execute.call_args_list[0].args[0], ["mutagen", "sync", "flush", "--", "ts-dev-a"])
        self.assertEqual(execute.call_args.args[0][-1], "ts-publish")
        self.assertEqual(
            json.loads(execute.call_args.kwargs["data"]),
            {"operation": "publish", "path": "pilot.lua", "sha256": sha256(self.data)},
        )

    def test_mutagen_conflict_stops_before_ssh(self):
        self.session["conflicts"] = [{"root": "pilot.lua"}]
        with patch("ts_manager.__main__.run_tool", side_effect=[b"", json.dumps([self.session])]) as execute:
            with self.assertRaisesRegex(ManagerError, "conflitos"):
                remote(self.arguments)
        self.assertEqual(execute.call_count, 2)
