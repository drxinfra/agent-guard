"""Guard hook tests: python3 -m unittest discover -s tests"""
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
import config  # noqa: E402
import guard  # noqa: E402

# Credentials are assembled from parts so the file holds nothing that looks like a real secret.
CRED = "guest" + ":" + "guest"

# Destructive: asked in prod and in test.
DESTRUCTIVE = [
    "rm -rf /var/lib/postgresql/16/main/pg_wal/0000*",
    "sudo rm -r /opt/app/releases/old",
    "rm -rf ~/backups",
    "find /var/log/app -name '*.gz' -delete",
    "kubectl -n app delete pod web-0",
    "helm uninstall app -n app",
    "docker rm -f web",
    "docker system prune -af",
    "docker volume rm pgdata",
    "docker image prune -a",
    "docker compose down -v",
    "terraform destroy -auto-approve",
    "terraform -chdir=infra apply -destroy",
    "tofu state rm aws_instance.web",
    "terragrunt run-all destroy",
    "pulumi destroy --yes",
    "aws ec2 terminate-instances --instance-ids i-0123",
    "aws --profile prod s3 rm s3://bucket/key --recursive",
    "aws s3 rb s3://bucket --force",
    "aws rds delete-db-instance --db-instance-identifier db1",
    "yc compute instance delete vm1",
    "gcloud compute instances delete vm1 --zone europe-west1-b",
    "gcloud storage rm gs://bucket/obj",
    "az group delete -n rg1 --yes",
    "az vm delete -g rg1 -n vm1",
    "git push --force origin main",
    "git push -f",
    "git push origin main -f",
    "psql -c 'drop table users'",
    "psql -U postgres -c \"delete from sessions\"",
    "mysql -e 'TRUNCATE TABLE logs' app",
    "sqlcmd -S db -Q \"DROP DATABASE app\"",
    "mysqladmin -u root drop app",
    "dropdb app",
    "mongosh app --eval 'db.users.drop()'",
    "mongosh --eval \"db.sessions.deleteMany({})\"",
    "redis-cli FLUSHALL",
    "redis-cli -h cache -n 2 flushdb",
    "redis-cli --scan --pattern 'sess:*' | xargs redis-cli del",
    "redis-cli DEL user:1",
    "rabbitmqctl purge_queue q1",
    "curl -X DELETE http://es:9200/idx",
    "apt-get purge -y nginx",
    "userdel -r olduser",
    "iptables -F",
    "lvremove /dev/vg0/data",
    "crontab -r",
    "echo profile=off > .agent-guard",
    "rm .agent-guard",
]

# State changes: asked in prod only.
CHANGE = [
    "sudo systemctl restart nginx",
    "systemctl --now disable worker",
    "docker compose -f /opt/app/compose.yml up -d",
    "podman restart pg",
    "kubectl rollout restart deploy/web -n app",
    "kubectl apply -f deploy.yaml",
    "helm upgrade app ./chart -n app",
    "terraform apply -auto-approve",
    "terraform import aws_instance.web i-0123",
    "pulumi up --yes",
    "ansible-playbook site.yml -i inventory",
    "ansible all -i hosts -m ansible.builtin.service -a 'name=nginx state=restarted'",
    "aws ec2 stop-instances --instance-ids i-0123",
    "aws s3 cp backup.tar s3://bucket/",
    "aws ssm put-parameter --name x --value y",
    "aws ec2 modify-instance-attribute --instance-id i-1",
    "yc compute instance stop vm1",
    "yc compute instance create --name vm2",
    "gcloud compute instances create vm2",
    "gcloud run deploy api --image img",
    "az vm restart -g rg1 -n vm1",
    "az keyvault secret set --vault-name kv --name x --value y",
    "psql -U postgres -c 'select pg_terminate_backend(123)'",
    "psql -c \"update users set x=1 where id=2\"",
    "docker exec pg psql -c 'vacuum analyze'",
    "mysql -e \"insert into t values (1)\"",
    "mongosh --eval 'db.users.updateOne({a:1},{$set:{b:2}})'",
    "redis-cli CONFIG SET maxmemory 2gb",
    "redis-cli set feature:x on",
    "pg_ctl -D /var/lib/postgresql/data restart",
    "rabbitmqctl set_policy expire '^tmp' '{\"expires\":3600000}' --apply-to queues",
    "curl -XPUT localhost:9200/_cluster/settings -H 'Content-Type: application/json' -d '{}'",
    "curl -u " + CRED + " -d '{}' http://mq:15672/api/policies/%2f/p",
    "apt-get install -y nginx",
    "kill -9 1234",
    "sed -i 's/a/b/' /etc/nginx/nginx.conf",
    "echo '10.0.0.5 db' >> /etc/hosts",
    "rm /etc/nginx/sites-enabled/default",
    "crontab -e",
    "find . -name '*.pyc' -delete",
    "crontab jobs.txt",
    "umount /mnt/backup",
    "mount -o remount,rw /data",
    "ssh app01 'sudo systemctl restart nginx'",
]

DENY = [
    "mkfs.ext4 /dev/sdb1",
    "dd if=/dev/zero of=/dev/sda bs=1M",
    "rm -rf /",
    "sudo rm -rf --no-preserve-root /",
    "wipefs -a /dev/sdb",
]

SAFE = [
    "systemctl status nginx",
    "systemctl list-units --failed",
    "journalctl -u nginx --since -1h | tail -50",
    "docker ps -a",
    "docker logs web --tail 100 2>&1 | grep -i error",
    "docker compose ps",
    "docker compose down",  # prod asks, but it is not destructive
    "kubectl get pods -A",
    "kubectl -n app describe pod web-0",
    "kubectl logs deploy/web --since=1h",
    "helm list -A",
    "terraform plan -out tf.plan",
    "terraform state list",
    "terraform init",
    "tofu validate",
    "pulumi preview",
    "ansible-playbook site.yml --check --diff",
    "ansible all -m ping",
    "aws ec2 describe-instances --filters Name=tag:role,Values=start-web",
    "aws s3 ls s3://bucket/",
    "yc compute instance list",
    "gcloud compute instances list --filter='name~delete'",
    "gcloud config set project p1",
    "az vm list -o table",
    "az account set -s sub1",
    "git push origin main",
    "git push --force-with-lease origin feature",
    "git push --follow-tags",
    "git reset --hard HEAD~1",
    "git log --oneline -5",
    "psql -c 'select count(*) from pg_stat_activity'",
    "psql -c \"select pid, state from pg_stat_activity where state = 'idle in transaction'\"",
    "mysql -e 'show processlist'",
    "mongosh --eval 'db.users.find().limit(5)'",
    "redis-cli info memory",
    "redis-cli -h set.example.com get settings",
    "redis-cli keys 'sess:*'",
    "rabbitmqctl list_queues name messages consumers",
    "curl -s http://es:9200/_cluster/health?pretty",
    "curl -s -X POST http://es:9200/docs/_search -H 'Content-Type: application/json' -d '{\"size\":0}'",
    "curl -s -u " + CRED + " http://mq:15672/api/queues",
    "rm -rf ./node_modules build/",
    "rm /tmp/x.log",
    "rm -f build.log; cat /etc/hosts",
    "ls -la /etc > /tmp/etc.txt",
    "grep -ri password /etc/app 2>/dev/null",
    "cat /etc/hosts",
    "cat .agent-guard",
    "crontab -l",
    "kill -l",
    "mount | grep data",
    "df -h && free -m && ss -ltnp",
]


def run_hook(name, payload, env=None, args=()):
    e = dict(os.environ)
    for k in list(e):
        if k.startswith("AGENT_GUARD_"):
            del e[k]
    e.update(env or {})
    p = subprocess.Popen([sys.executable, os.path.join(HOOKS, name)] + list(args),
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e)
    out, err = p.communicate(json.dumps(payload).encode("utf-8"))
    out = out.decode("utf-8")
    return p.returncode, (json.loads(out) if out.strip() else None)


class ClassifyTest(unittest.TestCase):
    def test_deny(self):
        for profile in ("prod", "test"):
            for cmd in DENY:
                self.assertEqual(guard.classify(cmd, profile)[0], "deny", cmd)

    def test_destructive_asked_in_both(self):
        for profile in ("prod", "test"):
            for cmd in DESTRUCTIVE:
                self.assertEqual(guard.classify(cmd, profile)[0], "ask", "%s: %s" % (profile, cmd))

    def test_change_asked_in_prod_only(self):
        for cmd in CHANGE:
            self.assertEqual(guard.classify(cmd, "prod")[0], "ask", cmd)
            self.assertEqual(guard.classify(cmd, "test"), (None, []), "test: " + cmd)

    def test_safe(self):
        for cmd in SAFE:
            expect = "ask" if cmd == "docker compose down" else None
            self.assertEqual(guard.classify(cmd, "prod")[0], expect, cmd)
            self.assertEqual(guard.classify(cmd, "test"), (None, []), cmd)

    def test_off(self):
        for cmd in DENY + DESTRUCTIVE + CHANGE:
            self.assertEqual(guard.classify(cmd, "off"), (None, []), cmd)

    def test_edit(self):
        self.assertEqual(guard.classify_edit("/etc/nginx/nginx.conf", "/home/u/proj", "prod")[0], "ask")
        self.assertEqual(guard.classify_edit("/etc/nginx/nginx.conf", "/home/u/proj", "test")[0], None)
        self.assertEqual(guard.classify_edit("/opt/proj/src/a.py", "/opt/proj", "prod")[0], None)
        self.assertEqual(guard.classify_edit("/home/u/proj/a.py", "/home/u/proj", "prod")[0], None)
        self.assertEqual(guard.classify_edit("/home/u/proj/.agent-guard", "/home/u/proj", "test")[0], "ask")


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.sub = os.path.join(self.tmp, "a", "b")
        os.makedirs(self.sub)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_defaults_and_env(self):
        c = config.load(self.sub, {})
        self.assertEqual((c["profile"], c["mask"], c["journal"]), ("prod", True, True))
        c = config.load(self.sub, {"AGENT_GUARD_PROFILE": "test", "AGENT_GUARD_MASK": "off", "AGENT_GUARD_JOURNAL": "off"})
        self.assertEqual((c["profile"], c["mask"], c["journal"]), ("test", False, False))
        self.assertEqual(config.load(self.sub, {"AGENT_GUARD_PROFILE": "bogus"})["profile"], "prod")

    def test_project_file_wins(self):
        with open(os.path.join(self.tmp, ".agent-guard"), "w") as f:
            f.write("# staging box\nprofile = test\njournal=off\n")
        c = config.load(self.sub, {"AGENT_GUARD_PROFILE": "prod"})
        self.assertEqual((c["profile"], c["journal"], c["mask"]), ("test", False, True))
        self.assertTrue(c["source"].endswith(".agent-guard"))


class HookProtocolTest(unittest.TestCase):
    def test_ask(self):
        rc, out = run_hook("guard.py", {"tool_name": "Bash", "tool_input": {"command": "systemctl restart nginx"}})
        self.assertEqual(rc, 0)
        h = out["hookSpecificOutput"]
        self.assertEqual((h["hookEventName"], h["permissionDecision"]), ("PreToolUse", "ask"))
        self.assertIn("agent-guard", h["permissionDecisionReason"])

    def test_safe_and_profiles(self):
        bash = lambda c: {"tool_name": "Bash", "tool_input": {"command": c}}  # noqa: E731
        self.assertEqual(run_hook("guard.py", bash("systemctl status nginx")), (0, None))
        self.assertEqual(run_hook("guard.py", bash("systemctl restart x"), {"AGENT_GUARD_PROFILE": "off"}), (0, None))
        self.assertEqual(run_hook("guard.py", bash("systemctl restart x"), {"AGENT_GUARD_PROFILE": "test"}), (0, None))
        rc, out = run_hook("guard.py", bash("kubectl delete ns app"), {"AGENT_GUARD_PROFILE": "test"})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")
        rc, out = run_hook("guard.py", bash("mkfs.ext4 /dev/sdb"), {"AGENT_GUARD_PROFILE": "test"})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_project_file_from_cwd(self):
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, ".agent-guard"), "w") as f:
                f.write("profile=off\n")
            sub = os.path.join(tmp, "src")
            os.makedirs(sub)
            payload = {"tool_name": "Bash", "cwd": sub, "tool_input": {"command": "kubectl delete ns app"}}
            self.assertEqual(run_hook("guard.py", payload), (0, None))
        finally:
            shutil.rmtree(tmp)

    def test_write_tool(self):
        payload = {"tool_name": "Write", "cwd": "/home/u/proj",
                   "tool_input": {"file_path": "/home/u/proj/.agent-guard", "content": "profile=off\n"}}
        rc, out = run_hook("guard.py", payload)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_non_ascii_c_locale(self):
        payload = {"tool_name": "Bash", "tool_input": {"command": "echo 'привет' && systemctl restart nginx"}}
        rc, out = run_hook("guard.py", payload, {"LANG": "C", "LC_ALL": "C", "PYTHONIOENCODING": ""})
        self.assertEqual(rc, 0)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")


if __name__ == "__main__":
    unittest.main()


class HeredocTest(unittest.TestCase):
    def test_file_heredoc_is_data(self):
        mk = "mk" + "fs"
        cmd = "cat > page.html <<'EOF'\n<p>%s.ext4 /dev/sdb1 and systemctl restart x</p>\nEOF" % mk
        self.assertEqual(guard.classify(cmd)[0], None)
        self.assertEqual(guard.classify("tee notes.md <<EOF\nrm -rf /var/lib/x\nEOF")[0], None)

    def test_shell_heredoc_is_checked(self):
        self.assertEqual(guard.classify("bash <<'EOF'\nsystemctl restart nginx\nEOF")[0], "ask")
        self.assertEqual(guard.classify("ssh srv <<EOF\nsystemctl restart nginx\nEOF")[0], "ask")
        self.assertEqual(guard.classify("psql <<'SQL'\ndrop table x;\nSQL")[0], "ask")
        self.assertEqual(guard.classify("cat <<'EOF' | bash\nsystemctl restart nginx\nEOF")[0], "ask")
