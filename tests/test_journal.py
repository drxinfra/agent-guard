"""Journal hook and CLI tests: python3 -m unittest discover -s tests"""
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS = os.path.join(ROOT, "hooks")
sys.path.insert(0, HOOKS)
import journal  # noqa: E402

PW = "PASS" + "WORD"
VALUE = "Zz" + "9secret"


def run(args, payload=None, env=None):
    e = dict(os.environ)
    for k in list(e):
        if k.startswith("AGENT_GUARD_"):
            del e[k]
    e.update(env or {})
    p = subprocess.Popen([sys.executable, os.path.join(HOOKS, "journal.py")] + list(args), stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e)
    out, err = p.communicate(json.dumps(payload).encode("utf-8") if payload is not None else b"")
    return p.returncode, out.decode("utf-8"), err.decode("utf-8")


class JournalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {"CLAUDE_PLUGIN_DATA": self.tmp, "HOME": self.tmp}
        self.path = os.path.join(self.tmp, "journal.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def lines(self):
        with open(self.path, encoding="utf-8") as f:
            return [json.loads(x) for x in f]

    def test_hook_appends_masked_record_without_output(self):
        payload = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "abc123", "cwd": self.tmp,
                   "tool_input": {"command": "PG" + PW + "=" + VALUE + " psql -c 'drop table t'"},
                   "tool_response": {"stdout": "SECRET OUTPUT", "stderr": "", "interrupted": False}}
        rc, out, err = run(["--hook"], payload, self.env)
        self.assertEqual((rc, out), (0, ""))
        rec = self.lines()[0]
        self.assertEqual(rec["session_id"], "abc123")
        self.assertNotIn(VALUE, rec["command"])
        self.assertIn("drop table t", rec["command"])
        self.assertTrue(rec["asked"])
        self.assertIs(rec["interrupted"], False)
        self.assertIs(rec["failed"], False)
        self.assertNotIn("SECRET OUTPUT", json.dumps(rec))
        self.assertTrue(rec["ts"].endswith("Z"))
        self.assertEqual(oct(os.stat(self.path).st_mode & 0o777), oct(0o600))

    def test_failure_event_and_exit_code(self):
        payload = {"hook_event_name": "PostToolUseFailure", "tool_name": "Bash", "session_id": "s2", "cwd": self.tmp,
                   "tool_input": {"command": "false"}, "error": "Exit code 1\n"}
        run(["--hook"], payload, self.env)
        rec = self.lines()[0]
        self.assertEqual((rec["failed"], rec["exit"], rec["asked"]), (True, 1, False))

    def test_off_and_other_tools(self):
        payload = {"tool_name": "Bash", "cwd": self.tmp, "tool_input": {"command": "ls"}}
        env = dict(self.env, AGENT_GUARD_JOURNAL="off")
        run(["--hook"], payload, env)
        run(["--hook"], {"tool_name": "Read", "cwd": self.tmp, "tool_input": {}}, self.env)
        self.assertFalse(os.path.exists(self.path))

    def test_rotation(self):
        with open(self.path, "wb") as f:
            f.write(b"x" * journal.MAX_BYTES)
        journal.append({"ts": "2026-01-01T00:00:00Z", "command": "ls"}, self.path)
        self.assertTrue(os.path.exists(self.path + ".1"))
        self.assertEqual(len(self.lines()), 1)

    def test_cli_filters(self):
        now = datetime.datetime(2026, 11, 5, 12, 0, 0)
        old = (now - datetime.timedelta(hours=3)).strftime(journal.TS_FORMAT)
        new = (now - datetime.timedelta(minutes=10)).strftime(journal.TS_FORMAT)
        recs = [{"ts": old, "command": "kubectl get pods", "session_id": "aaa", "asked": False},
                {"ts": new, "command": "kubectl delete pod x", "session_id": "bbb", "asked": True},
                {"ts": new, "command": "ls", "session_id": "bbb", "asked": False, "exit": 2}]
        since = journal.parse_since("1h", now)
        self.assertEqual([r["command"] for r in journal.select(recs, since=since)], ["kubectl delete pod x", "ls"])
        self.assertEqual(len(list(journal.select(recs, grep="KUBECTL"))), 2)
        self.assertEqual(len(list(journal.select(recs, asked=True))), 1)
        self.assertEqual(len(list(journal.select(recs, session="bb"))), 2)
        self.assertEqual([r["command"] for r in journal.select(recs, failed=True)], ["ls"])
        self.assertEqual(journal.parse_since("2026-11-05T10:30"), datetime.datetime(2026, 11, 5, 10, 30))

    def test_cli_reads_file(self):
        for cmd in ("systemctl status x", "systemctl restart x"):
            run(["--hook"], {"tool_name": "Bash", "session_id": "s", "cwd": self.tmp, "tool_input": {"command": cmd}}, self.env)
        rc, out, err = run(["--grep", "restart"], env=self.env)
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(out.strip().splitlines()), 1)
        self.assertIn("[ASKED]", out)
        rc, out, err = run(["--json", "--last", "1"], env=self.env)
        self.assertEqual(json.loads(out)["command"], "systemctl restart x")


if __name__ == "__main__":
    unittest.main()
