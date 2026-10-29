#!/usr/bin/env python3
"""Find and remove the "global.o='N-NNNN-du'" git worm across GitHub and Forgejo.

The worm rewrites the tip commit of every branch it can push to and keeps the
original commit dates, so commit dates cannot be trusted. Instead, "recent" is
decided by the server-side push time of each repository (GitHub pushedAt,
Forgejo updated_at), and then every branch tip of those repositories is checked.

API use is kept small:
  GitHub   one GraphQL query per 50 repos, returning their branch tips too
           (+1 per repo with more than 100 branches), repos sorted by push time
           so paging stops at --since; notifications: one call per 50.
  Forgejo  one call for the org id, one per 50 repos (sorted by update time,
           stops at --since); notifications: one call per 50.
  Branch contents are fetched with plain git (depth 1, only tips not already
  in --state), which does not use the REST/GraphQL rate limits.
  restore: one GitHub REST call per infected repo (force-push activity log).

Nothing fetched is ever executed: repositories are bare, nothing is checked
out, and git runs with hooks and fsmonitor disabled.

  sweep.py scan  [--github OWNER]... [--forgejo https://HOST/ORG]... [--since 45d]
                 [--notifications]                   -> findings.json, findings.tsv
  sweep.py clean findings.json [--mode clean|restore] [--author "Name <email>"]
                                                     # dry run
  sweep.py clean findings.json ... --apply           # push

Auth: GitHub through `gh` (gh auth login); Forgejo through $FORGEJO_TOKEN
(--forgejo-token-env to change the variable). Run it from a clean machine.
"""
import argparse, base64, datetime as dt, json, os, re, subprocess, sys, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
IOCS = os.path.join(HERE, "..", "iocs")
CALLS = {"github_graphql": 0, "github_rest": 0, "forgejo_api": 0, "git_fetch": 0}

PAYLOAD_RE = re.compile(rb"[ \t]{100,}(?:eval\(\"global\.[A-Za-z_$]+=|global\.o=)[^\n]*")
HDR = b"import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\n"
MERGE_RE = re.compile(r"^Merge (pull request #\d+ from |branch |remote-tracking branch )")
CLEAN_MSG = "security: remove injected git-worm loader (global.o=N-NNNN-du)"


def patterns(name):
    with open(os.path.join(IOCS, name)) as f:
        return [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]


HIGH = patterns("high-confidence.regex")
HEUR = patterns("heuristic.regex")
HIGH_RE = re.compile("|".join(HIGH).encode())
HEUR_RE = re.compile("|".join(HEUR).encode())


def log(*a):
    print(*a, file=sys.stderr, flush=True)


# ----------------------------------------------------------------- git


class Git:
    """git with repository-controlled code paths off and per-host auth headers."""

    def __init__(self, auth):
        cfg = [("core.hooksPath", "/dev/null"), ("core.fsmonitor", ""), ("fetch.recurseSubmodules", "false"),
               ("protocol.version", "2")]
        cfg += [(f"http.{prefix}.extraHeader", header) for prefix, header in auth]
        # GIT_CONFIG_* keeps tokens out of the process list
        self.env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_COUNT=str(len(cfg)))
        for i, (k, v) in enumerate(cfg):
            self.env[f"GIT_CONFIG_KEY_{i}"], self.env[f"GIT_CONFIG_VALUE_{i}"] = k, v

    def __call__(self, repo, *args, inp=None, check=True):
        r = subprocess.run(["git", "-C", repo, *args], input=inp, capture_output=True, env=self.env)
        if check and r.returncode:
            raise RuntimeError(f"git {' '.join(args[:3])}: {r.stderr.decode(errors='replace').strip()[-300:]}")
        return r.stdout

    def bare(self, path, url):
        if not os.path.isdir(path):
            os.makedirs(path)
            self(path, "init", "-q", "--bare")
            self(path, "remote", "add", "origin", url)
        return path

    def ls_remote(self, path, ref=None):
        out = self(path, "ls-remote", "origin", *([ref] if ref else ["refs/heads/*"])).decode()
        return {l.split("\t")[1]: l.split("\t")[0] for l in out.splitlines() if "\t" in l}

    def fetch_tips(self, path, branches):
        """Fetch only these branch tips, depth 1. Returns {branch: sha} actually fetched."""
        got = {}
        names = sorted(branches)
        for i in range(0, len(names), 200):
            spec = "".join(f"+refs/heads/{b}:refs/sweep/{b}\n" for b in names[i:i + 200])
            CALLS["git_fetch"] += 1
            self(path, "fetch", "-q", "--depth=1", "--no-tags", "--stdin", "origin", inp=spec.encode())
        out = self(path, "for-each-ref", "--format=%(objectname) %(refname)", "refs/sweep/").decode()
        for line in out.splitlines():
            sha, ref = line.split(" ", 1)
            got[ref[len("refs/sweep/"):]] = sha
        return {b: got[b] for b in names if b in got}


def inspect(git, path, sha):
    """Classify one commit: which files carry indicators, plus forgery signals."""
    raw = git(path, "cat-file", "commit", sha).decode(errors="replace")
    head, _, msg = raw.partition("\n\n")
    hits = git(path, "grep", "-IlE", "-f", IOC_FILE, sha, "--", check=False).decode().splitlines()
    files, level = [], None
    for h in hits:
        p = h.split(":", 1)[1]
        blob = git(path, "show", f"{sha}:{p}")
        lv = "HIGH" if HIGH_RE.search(blob) else "WARN"
        files.append({"path": p, "level": lv})
        level = "HIGH" if lv == "HIGH" or level == "HIGH" else "WARN"
    parents = sum(1 for l in head.splitlines() if l.startswith("parent "))
    subject = msg.splitlines()[0] if msg else ""
    forged_merge = parents == 1 and bool(MERGE_RE.match(subject))
    if forged_merge and level is None:
        level = "WARN"
    return {"level": level, "files": files, "signed": "\ngpgsig " in head, "parents": parents,
            "subject": subject[:100], "forged_merge": forged_merge}


# ----------------------------------------------------------------- GitHub

REPOS_Q = """query($owner: String!, $after: String) {
  repositoryOwner(login: $owner) {
    repositories(first: 50, after: $after, orderBy: {field: PUSHED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes { ...R }
    }
  }
}
fragment R on Repository {
  nameWithOwner url isArchived pushedAt
  defaultBranchRef { name }
  refs(refPrefix: "refs/heads/", first: 100) {
    pageInfo { hasNextPage endCursor }
    nodes { name target { oid } }
  }
}"""

MORE_REFS_Q = """query($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    refs(refPrefix: "refs/heads/", first: 100, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes { name target { oid } }
    }
  }
}"""


def gh(*args):
    r = subprocess.run(["gh", *args], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"gh {' '.join(args[:2])}: {r.stderr.strip()[-300:]}")
    return r.stdout


def gh_graphql(query, **variables):
    CALLS["github_graphql"] += 1
    args = ["api", "graphql", "-f", f"query={query}"]
    for k, v in variables.items():
        if v is not None:
            args += ["-f", f"{k}={v}"]
    return json.loads(gh(*args))["data"]


def gh_rest(path, **params):
    CALLS["github_rest"] += 1
    args = ["api", "-X", "GET", path] + [x for k, v in params.items() for x in ("-f", f"{k}={v}")]
    return json.loads(gh(*args))


def gh_repo(node):
    owner, name = node["nameWithOwner"].split("/")
    refs = node["refs"]
    tips = {r["name"]: r["target"]["oid"] for r in refs["nodes"]}
    after = refs["pageInfo"]["endCursor"] if refs["pageInfo"]["hasNextPage"] else None
    while after:
        more = gh_graphql(MORE_REFS_Q, owner=owner, name=name, after=after)["repository"]["refs"]
        tips.update({r["name"]: r["target"]["oid"] for r in more["nodes"]})
        after = more["pageInfo"]["endCursor"] if more["pageInfo"]["hasNextPage"] else None
    return {"forge": "github", "repo": node["nameWithOwner"], "url": node["url"] + ".git",
            "archived": node["isArchived"], "pushed_at": node["pushedAt"],
            "default": (node["defaultBranchRef"] or {}).get("name"), "tips": tips}


def github_recent(owner, since):
    out, after = [], None
    while True:
        page = gh_graphql(REPOS_Q, owner=owner, after=after)["repositoryOwner"]
        if page is None:
            raise RuntimeError(f"GitHub owner {owner!r} not found or not visible")
        repos = page["repositories"]
        for node in repos["nodes"]:
            if not node["pushedAt"]:
                continue
            if node["pushedAt"] < since:
                return out            # sorted by push time: everything after this is older
            out.append(gh_repo(node))
        if not repos["pageInfo"]["hasNextPage"]:
            return out
        after = repos["pageInfo"]["endCursor"]


def github_repos_by_name(names):
    """Branch tips for specific repos (notification hints), 20 per query via aliases."""
    out = []
    names = sorted(names)
    for i in range(0, len(names), 20):
        chunk = names[i:i + 20]
        parts = [f'r{j}: repository(owner: {json.dumps(n.split("/")[0])}, name: {json.dumps(n.split("/")[1])}) {{ ...R }}'
                 for j, n in enumerate(chunk)]
        q = "query {\n  " + "\n  ".join(parts) + "\n}\n" + REPOS_Q[REPOS_Q.index("fragment R"):]
        data = gh_graphql(q)
        out += [gh_repo(data[f"r{j}"]) for j in range(len(chunk)) if data.get(f"r{j}")]
    return out


def github_notifications(since):
    hints, page = {}, 1
    while True:
        batch = gh_rest("notifications", all="true", since=since, per_page=50, page=page)
        for n in batch:
            hints.setdefault(n["repository"]["full_name"], []).append(
                f'{n["subject"]["type"]}: {n["subject"]["title"]} ({n["updated_at"]})')
        if len(batch) < 50:
            return hints
        page += 1


# ----------------------------------------------------------------- Forgejo


class Forgejo:
    def __init__(self, spec, token):
        u = urllib.parse.urlparse(spec.rstrip("/"))
        self.base = f"{u.scheme}://{u.netloc}"
        self.org = u.path.strip("/")
        self.token = token

    def api(self, path, **params):
        CALLS["forgejo_api"] += 1
        url = f"{self.base}/api/v1{path}" + ("?" + urllib.parse.urlencode(params) if params else "")
        req = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   **({"Authorization": f"token {self.token}"} if self.token else {})})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)

    def recent(self, git, workdir, since):
        uid = self.api(f"/orgs/{urllib.parse.quote(self.org)}")["id"]
        out, page = [], 1
        while True:
            res = self.api("/repos/search", uid=uid, exclusive="true", sort="updated", order="desc",
                           limit=50, page=page)["data"]
            for r in res:
                if r["updated_at"] < since:
                    return out
                out.append(self.repo(git, workdir, r))
            if len(res) < 50:
                return out
            page += 1

    def repo(self, git, workdir, r):
        path = git.bare(os.path.join(workdir, "forgejo", r["full_name"].replace("/", "__") + ".git"), r["clone_url"])
        tips = {ref[len("refs/heads/"):]: sha for ref, sha in git.ls_remote(path).items()}  # git, not API
        return {"forge": "forgejo", "repo": r["full_name"], "url": r["clone_url"], "archived": r["archived"],
                "pushed_at": r["updated_at"], "default": r.get("default_branch"), "tips": tips, "base": self.base}

    def by_name(self, git, workdir, names):
        return [self.repo(git, workdir, self.api(f"/repos/{n}")) for n in sorted(names)]

    def notifications(self, since):
        hints, page = {}, 1
        while True:
            batch = self.api("/notifications", all="true", since=since, limit=50, page=page)
            for n in batch:
                hints.setdefault(n["repository"]["full_name"], []).append(
                    f'{n["subject"]["type"]}: {n["subject"]["title"]} ({n["updated_at"]})')
            if len(batch) < 50:
                return hints
            page += 1


# ----------------------------------------------------------------- scan


def since_ts(s):
    m = re.fullmatch(r"(\d+)d", s)
    t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=int(m.group(1))) if m else \
        dt.datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def auth_headers(args):
    auth = []
    if args.github:
        tok = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True).stdout.strip()  # local, no API
        if tok:
            b = base64.b64encode(f"x-access-token:{tok}".encode()).decode()
            auth.append(("https://github.com/", f"Authorization: Basic {b}"))
    tok = os.environ.get(args.forgejo_token_env, "")
    for spec in args.forgejo:
        if tok:
            b = base64.b64encode(f"git:{tok}".encode()).decode()
            auth.append((Forgejo(spec, tok).base + "/", f"Authorization: Basic {b}"))
    return auth


def write_ioc_file(workdir):
    global IOC_FILE
    os.makedirs(workdir, exist_ok=True)
    IOC_FILE = os.path.join(workdir, "iocs.ere")
    with open(IOC_FILE, "w") as f:
        f.write("\n".join(HIGH + HEUR) + "\n")


def scan(args):
    since = since_ts(args.since)
    work = os.path.abspath(args.workdir)
    write_ioc_file(work)
    git = Git(auth_headers(args))
    state = json.load(open(args.state)) if os.path.exists(args.state) else {}
    tok = os.environ.get(args.forgejo_token_env, "")
    forgejos = [Forgejo(s, tok) for s in args.forgejo]

    repos, hints = {}, {}
    if args.notifications:
        if args.github:
            hints.update({("github", k): v for k, v in github_notifications(since).items()})
        for fj in forgejos:
            hints.update({("forgejo", k): v for k, v in fj.notifications(since).items()})
        log(f"notifications point at {len(hints)} repos")
    for owner in args.github:
        for r in github_recent(owner, since):
            repos[("github", r["repo"])] = r
    for fj in forgejos:
        for r in fj.recent(git, work, since):
            repos[("forgejo", r["repo"])] = r
    missing_gh = [n for f, n in hints if f == "github" and ("github", n) not in repos]
    for r in github_repos_by_name(missing_gh) if missing_gh else []:
        repos[("github", r["repo"])] = r
    for fj in forgejos:
        missing = [n for f, n in hints if f == "forgejo" and ("forgejo", n) not in repos
                   and n.split("/")[0] == fj.org]
        for r in fj.by_name(git, work, missing) if missing else []:
            repos[("forgejo", r["repo"])] = r
    log(f"{len(repos)} repos to check (pushed since {since} or named in notifications)")

    findings = []
    # notification-hinted repos first: they are the likeliest to be infected
    for key in sorted(repos, key=lambda k: (k not in hints, k)):
        r = repos[key]
        path = git.bare(os.path.join(work, r["forge"], r["repo"].replace("/", "__") + ".git"), r["url"])
        todo = {b: s for b, s in r["tips"].items() if f'{r["forge"]}|{r["repo"]}|{s}' not in state}
        if todo:
            try:
                fetched = git.fetch_tips(path, todo)
            except RuntimeError as e:
                log(f"!! {r['repo']}: {e}"); continue
            for b, sha in fetched.items():
                r["tips"][b] = sha
                state[f'{r["forge"]}|{r["repo"]}|{sha}'] = inspect(git, path, sha)
        for b, sha in sorted(r["tips"].items()):
            res = state.get(f'{r["forge"]}|{r["repo"]}|{sha}')
            if res and res["level"]:
                findings.append({"forge": r["forge"], "repo": r["repo"], "url": r["url"], "base": r.get("base"),
                                 "branch": b, "sha": sha,
                                 "default": b == r["default"], "archived": r["archived"],
                                 "hint": hints.get(key, [])[:3], **res})
                log(f'{res["level"]:4} {r["forge"]} {r["repo"]} {b} {sha[:10]} '
                    f'{"signed" if res["signed"] else "unsigned"}{" forged-merge" if res["forged_merge"] else ""} '
                    f'{",".join(f["path"] for f in res["files"])}')
        with open(args.state, "w") as f:
            json.dump(state, f)

    with open("findings.json", "w") as f:
        json.dump(findings, f, indent=1)
    with open("findings.tsv", "w") as f:
        f.write("level\tforge\trepo\tbranch\tsha\tdefault\tarchived\tsigned\tforged_merge\tfiles\thint\n")
        for x in findings:
            f.write("\t".join(str(v) for v in (x["level"], x["forge"], x["repo"], x["branch"], x["sha"], x["default"],
                                               x["archived"], x["signed"], x["forged_merge"],
                                               " ".join(p["path"] for p in x["files"]), " | ".join(x["hint"]))) + "\n")
    high = [x for x in findings if x["level"] == "HIGH"]
    log(f"\n{len(high)} infected branches in {len({(x['forge'], x['repo']) for x in high})} repos, "
        f"{len(findings) - len(high)} suspicious -> findings.json / findings.tsv")
    log("API calls: " + ", ".join(f"{k}={v}" for k, v in CALLS.items()))
    return 1 if findings else 0


# ----------------------------------------------------------------- clean


def clean_commit(git, path, tip, files, author):
    idx = os.path.join(path, "sweep.index")
    env_backup = git.env
    git.env = dict(git.env, GIT_INDEX_FILE=idx)
    name, email = re.fullmatch(r"(.+?)\s*<(.+)>", author).groups()
    git.env.update(GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email, GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email)
    try:
        git(path, "read-tree", tip)
        for p in files:
            data = git(path, "show", f"{tip}:{p}")
            c, n = PAYLOAD_RE.subn(b"", data)
            c = c.replace(HDR, b"", 1)
            if n != 1 or HIGH_RE.search(c):
                raise RuntimeError(f"{p}: payload not in the expected shape, clean it by hand")
            sha = git(path, "hash-object", "-w", "--stdin", inp=c).decode().strip()
            mode = git(path, "ls-tree", tip, "--", p).decode().split()[0]
            git(path, "update-index", "--cacheinfo", f"{mode},{sha},{p}")
        tree = git(path, "write-tree").decode().strip()
        return git(path, "commit-tree", tree, "-p", tip, "-m", CLEAN_MSG).decode().strip()
    finally:
        git.env = env_backup
        if os.path.exists(idx):
            os.remove(idx)


def clean(args):
    work = os.path.abspath(args.workdir)
    write_ioc_file(work)
    findings = [x for x in json.load(open(args.findings)) if x["level"] == "HIGH"]
    forges = {x["forge"] for x in findings}
    ns = argparse.Namespace(github=["x"] if "github" in forges else [],
                            forgejo=sorted({x["base"] + "/x" for x in findings if x["forge"] == "forgejo"}),
                            forgejo_token_env=args.forgejo_token_env)
    git = Git(auth_headers(ns))
    activity = {}
    rc = 0
    for x in findings:
        label = f'{x["forge"]} {x["repo"]} {x["branch"]}'
        if x["archived"]:
            log(f"SKIP {label}: archived (unarchive it first)"); continue
        path = git.bare(os.path.join(work, x["forge"], x["repo"].replace("/", "__") + ".git"), x["url"])
        ref = f'refs/heads/{x["branch"]}'
        live = git.ls_remote(path, ref).get(ref)
        if live != x["sha"]:
            log(f"SKIP {label}: branch moved since the scan ({x['sha'][:10]} -> {(live or 'gone')[:10]}), rescan"); continue
        new, how = None, None
        if args.mode == "restore" and x["forge"] == "github":
            if x["repo"] not in activity:
                activity[x["repo"]] = gh_rest(f'repos/{x["repo"]}/activity', activity_type="force_push", per_page=100)
            before = next((e["before"] for e in activity[x["repo"]]
                           if e["ref"] == ref and e["after"] == x["sha"]), None)
            if before:
                CALLS["git_fetch"] += 1
                # depth 2: a pushed tip must not itself be a shallow boundary ("shallow update not allowed")
                git(path, "fetch", "-q", "--depth=2", "origin", before, check=False)
                have = subprocess.run(["git", "-C", path, "cat-file", "-e", before + "^{commit}"],
                                      capture_output=True).returncode == 0
                if have and not git(path, "grep", "-IlE", "-f", IOC_FILE, before, "--", check=False).strip():
                    new, how = before, "restore pre-force-push commit"
                elif not have:
                    log(f"     {label}: pre-push commit {before[:10]} not fetchable, falling back to cleanup commit")
        if new is None:
            try:
                git.fetch_tips(path, {x["branch"]: x["sha"]})
                new = clean_commit(git, path, x["sha"], [f["path"] for f in x["files"] if f["level"] == "HIGH"],
                                   args.author)
                how = "cleanup commit"
            except RuntimeError as e:
                log(f"SKIP {label}: {e}"); rc = 1; continue
        if git(path, "grep", "-IlE", "-f", IOC_FILE, new, "--", check=False).strip():
            log(f"SKIP {label}: replacement {new[:10]} still matches indicators"); rc = 1; continue
        log(f'{"PUSH" if args.apply else "DRY "} {label}: {x["sha"][:10]} -> {new[:10]} ({how})')
        if args.apply:
            try:
                git(path, "push", "-q", f"--force-with-lease={ref}:{x['sha']}", "origin", f"{new}:{ref}")
            except RuntimeError as e:
                log(f"     FAILED: {e}"); rc = 1
    log("API calls: " + ", ".join(f"{k}={v}" for k, v in CALLS.items()))
    return rc


IOC_FILE = None

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sp = ap.add_subparsers(dest="cmd", required=True)
    for p in (sp.add_parser("scan"), sp.add_parser("clean")):
        p.add_argument("--workdir", default="sweep-work")
        p.add_argument("--forgejo-token-env", default="FORGEJO_TOKEN")
    s = sp.choices["scan"]
    s.add_argument("--github", action="append", default=[], metavar="OWNER")
    s.add_argument("--forgejo", action="append", default=[], metavar="https://HOST/ORG")
    s.add_argument("--since", default="45d", help="Nd or an ISO date; repos pushed earlier are skipped")
    s.add_argument("--notifications", action="store_true", help="also check repos named in your notifications")
    s.add_argument("--state", default="sweep-state.json", help="cache of already-checked tips")
    c = sp.choices["clean"]
    c.add_argument("findings")
    c.add_argument("--mode", choices=["clean", "restore"], default="restore",
                   help="restore: GitHub branches go back to the commit before the forced push when it is clean "
                        "(falls back to clean); clean: add a cleanup commit on top")
    c.add_argument("--author", default="security-cleanup <security-cleanup@localhost>")
    c.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    if a.cmd == "scan" and not (a.github or a.forgejo):
        ap.error("give at least one --github OWNER or --forgejo https://HOST/ORG")
    sys.exit(scan(a) if a.cmd == "scan" else clean(a))
