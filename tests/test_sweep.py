"""End-to-end test of repos/sweep.py against local git remotes, a fake `gh` and
a fake Forgejo API (response shapes from Forgejo's swagger spec).
Fake markers only. Run: python3 -m unittest tests/test_sweep.py"""
import http.server, json, os, shutil, subprocess, sys, tempfile, threading, unittest, urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SWEEP = os.path.join(ROOT, "repos", "sweep.py")
MARK = "global.o='5-1902-" + "du';var _$_8" + "ec1=(function(q,w){return q})('',1);"
HDR = "import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\n"
CLEAN_CFG = "export default {\n  plugins: {},\n};\n"
INFECTED_CFG = HDR + "export default {\n  plugins: {},\n};" + " " * 220 + MARK + "\n"
RECENT, OLD = "2099-01-01T00:00:00Z", "2001-01-01T00:00:00Z"

FAKE_GH = r'''#!/usr/bin/env python3
import json, os, re, subprocess, sys
fx = os.environ["FAKE_FIXTURE"]; meta = json.load(open(os.path.join(fx, "meta.json")))
open(os.path.join(fx, "gh-calls.log"), "a").write(" ".join(sys.argv[1:3]) + "\n")
a = sys.argv[1:]
if a[:2] == ["auth", "token"]: print("fake-token"); sys.exit()
def fields():
    d = {}
    for i, x in enumerate(a):
        if x == "-f": k, _, v = a[i + 1].partition("="); d[k] = v
    return d
def node(full):
    m = meta["github"][full]; path = os.path.join(fx, "remotes", full + ".git")
    out = subprocess.run(["git", "-C", path, "for-each-ref", "--format=%(refname:short) %(objectname)", "refs/heads"],
                         capture_output=True, text=True).stdout.split("\n")
    refs = [{"name": l.split()[0], "target": {"oid": l.split()[1]}} for l in out if l]
    return {"nameWithOwner": full, "url": "file://" + os.path.join(fx, "remotes", full), "isArchived": m["archived"],
            "pushedAt": m["pushedAt"], "defaultBranchRef": {"name": "main"},
            "refs": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": refs}}
if a[:2] == ["api", "graphql"]:
    f = fields(); q = f["query"]
    if "repositoryOwner" in q:
        names = sorted(meta["github"], key=lambda n: meta["github"][n]["pushedAt"], reverse=True)
        print(json.dumps({"data": {"repositoryOwner": {"repositories": {
            "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [node(n) for n in names]}}}}))
    else:
        pairs = re.findall(r'(r\d+): repository\(owner: "([^"]+)", name: "([^"]+)"\)', q)
        print(json.dumps({"data": {al: node(o + "/" + n) for al, o, n in pairs}}))
    sys.exit()
if a[:3] == ["api", "-X", "GET"]:
    path = a[3]
    if path == "notifications": print(json.dumps(meta.get("gh_notifications", [])))
    elif path.endswith("/activity"): print(json.dumps(meta["activity"].get(path.split("/")[1] + "/" + path.split("/")[2], [])))
    sys.exit()
sys.exit("fake gh: unhandled " + " ".join(a))
'''


def git(cwd, *a):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
                           "-c", "init.defaultBranch=main", *a], cwd=cwd, check=True, capture_output=True,
                          text=True).stdout.strip()


class FakeForgejo(http.server.BaseHTTPRequestHandler):
    meta = None
    calls = []

    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = dict(urllib.parse.parse_qsl(u.query))
        FakeForgejo.calls.append(u.path)
        m = self.meta["forgejo"]
        if u.path == "/api/v1/orgs/acme":
            body = {"id": 7, "username": "acme"}
        elif u.path == "/api/v1/repos/search":
            assert q["uid"] == "7" and q["sort"] == "updated" and q["order"] == "desc", q
            repos = sorted(m.values(), key=lambda r: r["updated_at"], reverse=True)
            body = {"ok": True, "data": repos if q.get("page") == "1" else []}
        elif u.path == "/api/v1/notifications":
            body = []
        elif u.path.startswith("/api/v1/repos/"):
            body = m[u.path[len("/api/v1/repos/"):]]
        else:
            self.send_error(404); return
        data = json.dumps(body).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def log_message(self, *a):
        pass


class SweepTest(unittest.TestCase):
    def setUp(self):
        self.fx = tempfile.mkdtemp(prefix="sweep-fx-")
        self.addCleanup(shutil.rmtree, self.fx)
        self.meta = {"github": {}, "forgejo": {}, "activity": {}}
        self.befores = {}
        # GitHub acme/app: main force-pushed with the worm (clean original kept), a clean
        # feature branch, and a rewritten merge that lost its second parent
        app = self.remote("acme/app", RECENT)
        w = self.work(app)
        self.commit(w, "postcss.config.js", CLEAN_CFG, "init")
        git(w, "push", "-q", "origin", "main")
        git(w, "checkout", "-qb", "feature"); self.commit(w, "f.txt", "f\n", "feature work")
        git(w, "push", "-q", "origin", "feature"); git(w, "checkout", "-q", "main")
        self.commit(w, "x.txt", "x\n", "real work")
        git(w, "push", "-q", "origin", "main")
        before = git(w, "rev-parse", "HEAD")
        git(w, "reset", "-q", "--soft", "HEAD~1")
        self.commit(w, "postcss.config.js", INFECTED_CFG, "real work", also=("x.txt", "x\n"))
        git(w, "push", "-qf", "origin", "main")
        self.meta["activity"]["acme/app"] = [{"ref": "refs/heads/main", "before": before,
                                               "after": git(w, "rev-parse", "HEAD")}]
        self.befores["app"] = before
        git(w, "checkout", "-qb", "mergey", "main~1")
        self.commit(w, "postcss.config.js", INFECTED_CFG, "Merge pull request #9 from acme/side")
        git(w, "push", "-q", "origin", "mergey")
        # acme/old: infected but last pushed long ago; acme/arch: infected but archived
        for name, pushed, archived in (("acme/old", OLD, False), ("acme/arch", RECENT, True)):
            r = self.remote(name, pushed, archived)
            w = self.work(r); self.commit(w, "postcss.config.js", INFECTED_CFG, "x"); git(w, "push", "-q", "origin", "main")
        # Forgejo acme/site: infected main
        site = self.remote("acme/site", None, forge="forgejo")
        w = self.work(site); self.commit(w, "svelte.config.js", INFECTED_CFG, "site"); git(w, "push", "-q", "origin", "main")
        self.save()
        bindir = os.path.join(self.fx, "bin"); os.makedirs(bindir)
        with open(os.path.join(bindir, "gh"), "w") as f:
            f.write(FAKE_GH)
        os.chmod(os.path.join(bindir, "gh"), 0o755)
        FakeForgejo.meta = self.meta; FakeForgejo.calls = []
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeForgejo)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"], FAKE_FIXTURE=self.fx,
                        FORGEJO_TOKEN="fj-token")
        self.run_dir = os.path.join(self.fx, "run"); os.makedirs(self.run_dir)

    # -- fixture helpers
    def remote(self, full, pushed, archived=False, forge="github"):
        path = os.path.join(self.fx, "remotes", full + ".git")
        os.makedirs(path); git(path, "init", "-q", "--bare")
        git(path, "config", "uploadpack.allowAnySHA1InWant", "true")
        if forge == "github":
            self.meta["github"][full] = {"pushedAt": pushed, "archived": archived}
        else:
            self.meta["forgejo"][full] = {"full_name": full, "clone_url": "file://" + path, "updated_at": RECENT,
                                          "archived": False, "default_branch": "main"}
        return path

    def work(self, remote):
        w = tempfile.mkdtemp(dir=self.fx); git(w, "init", "-q"); git(w, "remote", "add", "origin", "file://" + remote)
        return w

    def commit(self, w, path, content, msg, also=None):
        for p, c in [(path, content)] + ([also] if also else []):
            with open(os.path.join(w, p), "w") as f:
                f.write(c)
            git(w, "add", p)
        git(w, "commit", "-qm", msg)

    def save(self):
        with open(os.path.join(self.fx, "meta.json"), "w") as f:
            json.dump(self.meta, f)

    def sweep(self, *args):
        r = subprocess.run([sys.executable, "-I", SWEEP, *args], cwd=self.run_dir, env=self.env,
                           capture_output=True, text=True)
        return r.returncode, r.stderr

    def scan(self, *extra):
        return self.sweep("scan", "--github", "acme", "--forgejo", f"http://127.0.0.1:{self.srv.server_port}/acme",
                          "--since", "2050-01-01", *extra)

    def findings(self):
        with open(os.path.join(self.run_dir, "findings.json")) as f:
            return {(x["repo"], x["branch"]): x for x in json.load(f)}

    def tip(self, full, branch):
        return git(os.path.join(self.fx, "remotes", full + ".git"), "rev-parse", "refs/heads/" + branch)

    def show(self, full, rev, path):
        return git(os.path.join(self.fx, "remotes", full + ".git"), "show", f"{rev}:{path}") + "\n"

    # -- tests
    def test_scan_detects_and_limits_api_calls(self):
        rc, err = self.scan()
        self.assertEqual(rc, 1, err)
        f = self.findings()
        self.assertEqual(f[("acme/app", "main")]["level"], "HIGH")
        self.assertFalse(f[("acme/app", "main")]["signed"])
        self.assertTrue(f[("acme/app", "mergey")]["forged_merge"])
        self.assertTrue(f[("acme/arch", "main")]["archived"])
        self.assertEqual(f[("acme/site", "main")]["forge"], "forgejo")
        self.assertNotIn(("acme/app", "feature"), f)
        self.assertNotIn(("acme/old", "main"), f, "repo pushed before --since must be skipped")
        self.assertIn("github_graphql=1, github_rest=0, forgejo_api=2", err)

        rc, err = self.scan()                      # second run: every tip is cached
        self.assertIn("git_fetch=0", err)
        self.assertEqual(len(self.findings()), 4)

    def test_notifications_pull_in_old_repo(self):
        self.meta["gh_notifications"] = [{"repository": {"full_name": "acme/old"}, "updated_at": RECENT,
                                          "subject": {"type": "CheckSuite", "title": "Build failed"}}]
        self.save()
        rc, err = self.scan("--notifications")
        f = self.findings()
        self.assertIn(("acme/old", "main"), f, err)
        self.assertIn("CheckSuite: Build failed", f[("acme/old", "main")]["hint"][0])
        self.assertIn("github_graphql=2", err)    # one owner page + one aliased batch for hinted repos

    def test_clean_dry_run_then_apply(self):
        self.scan()
        infected = {k: self.tip(k[0], k[1]) for k in [("acme/app", "main"), ("acme/app", "mergey"), ("acme/site", "main")]}
        rc, err = self.sweep("clean", "findings.json")
        self.assertIn("DRY ", err)
        for (full, b), sha in infected.items():
            self.assertEqual(self.tip(full, b), sha, "dry run must not push")

        rc, err = self.sweep("clean", "findings.json", "--apply")
        self.assertEqual(rc, 0, err)
        # restored to the exact pre-force-push commit
        self.assertEqual(self.tip("acme/app", "main"), self.befores["app"], err)
        # no activity entry for mergey, Forgejo has no activity log: cleanup commits on top
        for full, b, p in (("acme/app", "mergey", "postcss.config.js"), ("acme/site", "main", "svelte.config.js")):
            new = self.tip(full, b)
            self.assertEqual(git(os.path.join(self.fx, "remotes", full + ".git"), "rev-parse", new + "^"),
                             infected[(full, b)], "cleanup commit goes on top, no history rewrite")
            self.assertEqual(self.show(full, new, p), CLEAN_CFG)
        self.assertIn("SKIP github acme/arch main: archived", err)
        rc, err = self.scan()
        self.assertEqual({k for k, v in self.findings().items() if v["level"] == "HIGH"}, {("acme/arch", "main")}, err)

    def test_clean_skips_branch_moved_since_scan(self):
        self.scan()
        w = self.work(os.path.join(self.fx, "remotes", "acme/app.git"))
        git(w, "fetch", "-q", "origin", "main"); git(w, "checkout", "-q", "-b", "main", "FETCH_HEAD")
        self.commit(w, "y.txt", "y\n", "someone pushed"); git(w, "push", "-q", "origin", "main")
        moved = self.tip("acme/app", "main")
        rc, err = self.sweep("clean", "findings.json", "--apply")
        self.assertIn("SKIP github acme/app main: branch moved since the scan", err)
        self.assertEqual(self.tip("acme/app", "main"), moved)


if __name__ == "__main__":
    unittest.main()
