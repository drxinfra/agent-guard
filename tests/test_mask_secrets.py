"""Secret masker and masking hook tests: python3 -m unittest discover -s tests

Every secret-looking sample is assembled from parts at run time, so this file
contains nothing a secret scanner would take for a real credential.
"""
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS = os.path.join(ROOT, "hooks")
sys.path.insert(0, HOOKS)
import mask_secrets  # noqa: E402

M = mask_secrets.MASK
PW = "PASS" + "WORD"
V1, V2, V3 = "Qw" + "erty_123", "abc" + "DEF123456", "hun" + "ter2"


def masked(text):
    return mask_secrets.mask(text)[0]


def run(script, payload, env=None, raw=None):
    e = dict(os.environ)
    for k in list(e):
        if k.startswith("AGENT_GUARD_"):
            del e[k]
    e.update(env or {})
    p = subprocess.Popen([sys.executable, os.path.join(HOOKS, script)], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e)
    out, _ = p.communicate(raw if raw is not None else json.dumps(payload).encode("utf-8"))
    return p.returncode, out.decode("utf-8")


class MaskTest(unittest.TestCase):
    def hidden(self, text, *secrets):
        out = masked(text)
        for s in secrets:
            self.assertNotIn(s, out, out)
        self.assertIn(M, out, out)
        return out

    def kept(self, text):
        self.assertEqual(masked(text), text)

    def test_yaml_and_env(self):
        out = self.hidden(
            "variables:\n"
            "  DATABASE_ENGINE: 'postgres'\n"
            "  CONNECTION_STRING: 'Host=db;Port=5432;Database=app;Username=app;Password=" + V3 + "'\n"
            "  RABBITMQ_" + PW + ": \"" + V1 + "\"\n"
            "  STORAGE_SECRET_KEY: " + V2 + "  # storage key\n",
            V3, V1, V2)
        self.assertIn("DATABASE_ENGINE: 'postgres'", out)
        self.assertIn("Username=app;", out)
        self.assertIn("# storage key", out)
        self.hidden("export PG" + PW + "=" + V3, V3)

    def test_not_secrets(self):
        self.kept("password_policy: strict\nPASSWORD_MIN_LENGTH: 12\ntoken_lifetime: 3600\n"
                  "max_tokens: 2048\nkeystore_path: /etc/ssl/ks.jks\nTOKEN_URL: https://idp/token\n")
        self.kept("RABBITMQ_" + PW + ": ${RABBITMQ_" + PW + "}\nDB_" + PW + ": '{{ vault_db_password }}'\n"
                  "password: " + M + "\n")
        self.kept("select usename, passwd is not null from pg_shadow;\n")

    def test_json_xml(self):
        self.hidden('{"user": "app", "password": "' + V1 + '", "token_ttl": 60}', V1)
        self.assertIn('"token_ttl": 60', masked('{"password": "' + V1 + '", "token_ttl": 60}'))
        self.hidden('<var name="DATABASE_' + PW + '" value="' + V2 + '" />', V2)
        self.hidden('<add key="ServicePassword" value="' + V2 + '"/>', V2)
        self.hidden("<Password>" + V2 + "</Password>", V2)

    def test_conn_url_auth(self):
        self.hidden("Server=sql01;Database=app;User Id=sa;Pwd=" + V1 + ";", V1)
        self.hidden("amqp://app:" + V1 + "@mq:5672/", V1)
        out = self.hidden("curl -u elastic:" + V2 + " https://es:9200/_cluster/health", V2)
        self.assertIn("-u elastic:", out)
        basic = "cnhfdXNl" + "cjpweA=="
        self.hidden("Authorization: Basic " + basic, basic)
        self.hidden("psql --password=" + V2 + " -h db", V2)

    def test_tokens_pem_k8s(self):
        jwt = ".".join(["eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0",
                        "dozjgNryP4J3jVmNHl0w5N" + "_XgL0n3I9PlFUP0THsR8U"])
        self.hidden("token in log: " + jwt, jwt)
        gl = "glp" + "at-" + "ABCDEFGHIJ" + "KLMNOPQRSTUV"
        self.hidden(gl, gl)
        kind = "RSA " + "PRIVATE KEY"
        body = "MIIEpAIB" + "AAKCAQEA1"
        pem = "-----BEGIN %s-----\n%s\n-----END %s-----" % (kind, body, kind)
        self.hidden("key:\n" + pem, body)
        out = self.hidden("apiVersion: v1\nkind: Secret\ndata:\n  db-user: cng=\n  db-pass: c2VjcmV0\n"
                          "metadata:\n  name: app\n", "cng=", "c2VjcmV0")
        self.assertIn("name: app", out)

    def test_inline_sql_mc(self):
        self.hidden("cd /backup && PG" + PW + "=" + V1 + " pg_dump -h db app", V1)
        self.hidden("env AWS_SECRET_ACCESS_KEY=" + V2 + " wal-g backup-push", V2)
        self.hidden("ALTER ROLE app WITH " + PW + " '" + V1 + "';", V1)
        ak, sk = "AKIA" + "KEY0001", "SeCrEt" + "0001"
        out = self.hidden("mc alias set s3 https://s3.example " + ak + " " + sk, ak, sk)
        self.assertIn("https://s3.example", out)
        self.kept("PG" + PW + "=$PGPASS pg_dump app\n")
        out = self.hidden("PG" + PW + "=" + V3 + " pg_dump -h db app\n", V3)
        self.assertIn("pg_dump -h db app", out)

    def test_cli(self):
        script = os.path.join(HOOKS, "mask_secrets.py")
        data = ("DB_" + PW + "=" + V3 + "\nport=5432\n").encode()
        p = subprocess.Popen([sys.executable, script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = p.communicate(data)
        self.assertEqual(p.returncode, 0)
        self.assertIn(M, out.decode("utf-8"))
        self.assertIn("port=5432", out.decode("utf-8"))
        p = subprocess.Popen([sys.executable, script, "--check"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.communicate(data)
        self.assertEqual(p.returncode, 1)


class MaskHookTest(unittest.TestCase):
    def test_bash_output_masked(self):
        resp = {"stdout": "DB_" + PW + "=" + V3 + "\nport=5432\n", "stderr": "", "interrupted": False,
                "isImage": False, "noOutputExpected": False}
        rc, out = run("mask_output.py", {"tool_name": "Bash", "tool_response": resp})
        self.assertEqual(rc, 0)
        h = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(h["hookEventName"], "PostToolUse")
        upd = h["updatedToolOutput"]
        self.assertEqual(set(upd), set(resp))
        self.assertNotIn(V3, upd["stdout"])
        self.assertIn("port=5432", upd["stdout"])
        self.assertIs(upd["interrupted"], False)
        self.assertIn("agent-guard", h["additionalContext"])

    def test_read_shape(self):
        resp = {"type": "text", "file": {"filePath": "/etc/app/.env", "content": "RABBITMQ_" + PW + "=" + V1 + "\n",
                                         "numLines": 1, "startLine": 1, "totalLines": 1}}
        rc, out = run("mask_output.py", {"tool_name": "Read", "tool_response": resp})
        upd = json.loads(out)["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(upd["file"]["filePath"], "/etc/app/.env")
        self.assertNotIn(V1, upd["file"]["content"])
        self.assertEqual(upd["file"]["numLines"], 1)

    def test_grep_shape(self):
        resp = {"mode": "content", "numFiles": 1, "filenames": ["conf/app.yml"],
                "content": "conf/app.yml:3:  db_" + PW.lower() + ": " + V2, "numLines": 1}
        rc, out = run("mask_output.py", {"tool_name": "Grep", "tool_response": resp})
        upd = json.loads(out)["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(upd["filenames"], ["conf/app.yml"])
        self.assertNotIn(V2, upd["content"])
        self.assertEqual(upd["mode"], "content")

    def test_clean_and_off(self):
        self.assertEqual(run("mask_output.py", {"tool_name": "Bash", "tool_response": {"stdout": "ok\n", "stderr": ""}}), (0, ""))
        payload = {"tool_name": "Bash", "tool_response": {"stdout": PW + "=" + V3}}
        self.assertEqual(run("mask_output.py", payload, {"AGENT_GUARD_MASK": "off"}), (0, ""))
        self.assertEqual(run("mask_output.py", None, raw=b"not json"), (0, ""))

    def test_c_locale_non_ascii(self):
        payload = {"tool_name": "Bash", "tool_response": {"stdout": "пароль\n" + PW + "=" + V3 + "\n"}}
        rc, out = run("mask_output.py", payload, {"LANG": "C", "LC_ALL": "C", "PYTHONIOENCODING": ""})
        self.assertEqual(rc, 0)
        self.assertIn("пароль", json.loads(out)["hookSpecificOutput"]["updatedToolOutput"]["stdout"])


if __name__ == "__main__":
    unittest.main()
