import importlib
import os
import stat
import sys
import tempfile
import types
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "agent"))
sys.path.insert(0, os.path.join(ROOT, "sentinel"))


class OfflineTests(unittest.TestCase):
    def test_sensitive_read_is_redacted(self):
        import tools

        with tempfile.TemporaryDirectory() as td:
            secret = os.path.join(td, "secret.txt")
            cfg = os.path.join(td, "config.yaml")
            with open(secret, "w") as f:
                f.write("super-secret")
            with open(cfg, "w") as f:
                f.write("sensitive_paths:\n  - %s\n" % secret)

            old = os.environ.get("SENTINEL_CONFIG")
            os.environ["SENTINEL_CONFIG"] = cfg
            try:
                importlib.reload(tools)
                out = tools.read_file(secret)
            finally:
                if old is None:
                    os.environ.pop("SENTINEL_CONFIG", None)
                else:
                    os.environ["SENTINEL_CONFIG"] = old
                importlib.reload(tools)

        self.assertIn("內容已遮蔽", out)
        self.assertNotIn("super-secret", out)

    def test_jsonl_writer_uses_private_permissions(self):
        import main

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "events.jsonl")
            writer = main.JsonlWriter(path)
            writer.write({"ok": True})
            writer.close()
            mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o600)

    def test_late_intent_upgrades_sensitive_alert(self):
        from correlator import Correlator

        alerts = []
        c = Correlator(500, ["shadow"], lineage=None, on_alert=alerts.append)
        evt = {
            "type": "open",
            "ts_ns": 1_000_000_000,
            "pid": 123,
            "comm": "python3",
            "uid": 0,
            "path": "/etc/shadow",
            "flags_str": "O_RDONLY",
        }
        c.on_action(evt, True)
        c.add_intent(999_900_000, "ACTION: read_file(/etc/shadow)", "response")

        self.assertGreaterEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["verdict"], "SENSITIVE_ACCESS")
        self.assertEqual(alerts[-1]["verdict"], "INJECTION_PRIVILEGE_ESCALATION")

    def test_normalize_open_event_resolves_absolute_path(self):
        import normalizer

        event = types.SimpleNamespace(
            type=normalizer.EVT_OPEN,
            pid=os.getpid(),
            ppid=0,
            uid=os.getuid(),
            timestamp=123,
            flags=os.O_RDONLY,
            comm=b"python3\x00",
            path=b"/tmp/../tmp/test.txt\x00",
        )
        out = normalizer.normalize(event)
        self.assertEqual(out["path"], "/tmp/test.txt")
        self.assertEqual(out["flags_str"], "O_RDONLY")


if __name__ == "__main__":
    unittest.main()
