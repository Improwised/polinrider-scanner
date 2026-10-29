#!/usr/bin/env python3
"""Detect and remove the "global.o='N-NNNN-du'" git worm from a GitHub org.

The worm amends the tip commit of every branch it can push to: it pads a line
of a JS/TS config or entry file with spaces and appends an obfuscated loader,
keeps the original message/author/committer/dates, and force-pushes. Forged
tips are unsigned even where the original was a GitHub-signed merge.

Nothing in a scanned repository is ever executed: repos are bare mirrors, no
checkout, no npm. Requires git, python3 and an authenticated `gh` (org admin)
on a machine that is NOT the infected laptop.

  irkit.py scan  ORG [--repo NAME] [--since-days 30]  -> plan.json, plan.tsv
  irkit.py apply plan.json            # dry run: prints what it would push
  irkit.py apply plan.json --apply    # pushes
"""
import argparse, json, os, re, subprocess, sys, time

WORK = os.path.abspath("irkit-mirrors")
IOCS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "iocs")


def _patterns(name):
    with open(os.path.join(IOCS, name)) as f:
        return [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]


# Same indicator files scan.sh uses; heuristics too, so new variants still surface
IOC_FILE = os.path.join(WORK, "iocs.ere")
IOC_RE = re.compile("|".join(_patterns("high-confidence.regex")).encode())
PAYLOAD_RE = re.compile(rb"[ \t]{100,}(?:eval\(\"global\.[A-Za-z_$]+=|global\.o=)[^\n]*")
HDR = b"import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\n"
CLEAN_MSG = "security: remove injected git-worm loader (global.o=N-NNNN-du)"


def run(*cmd, cwd=None, inp=None, check=True, env=None):
    r = subprocess.run(cmd, cwd=cwd, input=inp, capture_output=True, env=env)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def git(repo, *a, **kw):
    return run("git", "-C", repo, *a, **kw)


def infected_paths(repo, rev):
    if not os.path.exists(IOC_FILE):
        os.makedirs(WORK, exist_ok=True)
        with open(IOC_FILE, "w") as f:
            f.write("\n".join(_patterns("high-confidence.regex") + _patterns("heuristic.regex")) + "\n")
    out = git(repo, "grep", "-IlE", "-f", IOC_FILE, rev, "--", check=False).decode()
    return [l.split(":", 1)[1] for l in out.splitlines() if ":" in l]


def is_signed(repo, rev):
    return b"\ngpgsig " in git(repo, "cat-file", "commit", rev)


def have(repo, sha):
    return subprocess.run(["git", "-C", repo, "cat-file", "-e", sha + "^{commit}"], capture_output=True).returncode == 0


def mirror(full):
    path = os.path.join(WORK, full.replace("/", "__") + ".git")
    if os.path.isdir(path):
        git(path, "remote", "update", "--prune")
    else:
        os.makedirs(WORK, exist_ok=True)
        run("gh", "repo", "clone", full, path, "--", "--mirror", "--quiet")
    # never let a mirrored repo's config or hooks run anything
    git(path, "config", "core.hooksPath", "/dev/null")
    return path


def force_pushes(full, since):
    out = run("gh", "api", "--paginate", f"repos/{full}/activity?activity_type=force_push&per_page=100",
              "--jq", ".[] | {ref, before, after, timestamp, actor: .actor.login}", check=False).decode()
    ev = [json.loads(l) for l in out.splitlines() if l.strip()]
    return [e for e in ev if e["timestamp"] >= since]


def clean_blob(data):
    c, n = PAYLOAD_RE.subn(b"", data)
    if n != 1:
        return None
    c = c.replace(HDR, b"", 1)
    return None if IOC_RE.search(c) else c


def scan(args):
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - args.since_days * 86400))
    repos = json.loads(run("gh", "repo", "list", args.org, "--limit", "5000", "--json", "nameWithOwner,isArchived"))
    if args.repo:
        repos = [r for r in repos if r["nameWithOwner"].split("/")[1].lower() == args.repo.lower()]
    plan = []
    for r in repos:
        full = r["nameWithOwner"]
        try:
            m = mirror(full)
        except RuntimeError as e:
            print(f"!! {full}: {e}", file=sys.stderr); continue
        fps = force_pushes(full, since)
        refs = git(m, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/pull").decode().split("\n")
        for line in filter(None, refs):
            ref, tip = line.split()
            bad = infected_paths(m, tip)
            if not bad:
                continue
            row = {"repo": full, "ref": ref, "tip": tip, "files": bad, "tip_signed": is_signed(m, tip),
                   "archived": r["isArchived"], "pushed_by": None, "pushed_at": None, "before": None, "action": None, "note": ""}
            ev = [e for e in fps if e["ref"] == ref and e["after"] == tip]
            if ev:
                e = ev[-1]
                row.update(pushed_by=e["actor"], pushed_at=e["timestamp"], before=e["before"])
                if not have(m, e["before"]):
                    git(m, "fetch", "--quiet", "origin", e["before"], check=False)
            if ref.startswith("refs/pull/"):
                row["action"] = "report-only"; row["note"] = "PR head ref; fix the source branch"
            elif row["before"] and have(m, row["before"]) and not infected_paths(m, row["before"]):
                extra = [p for p in git(m, "diff", "--name-only", row["before"], tip).decode().split() if p not in bad]
                row["action"] = "restore"
                if extra:
                    row["note"] = "forged commit also changes: " + ", ".join(extra)
            else:
                row["action"] = "clean-commit"
                row["note"] = "no clean pre-push SHA found; will add a cleanup commit on top"
            plan.append(row)
            print(f"INFECTED {full} {ref} {tip[:8]} -> {row['action']} {row['note']}")
    json.dump(plan, open("plan.json", "w"), indent=1)
    with open("plan.tsv", "w") as f:
        f.write("repo\tref\ttip\tsigned\tpushed_by\tpushed_at\tbefore\taction\tfiles\tnote\n")
        for p in plan:
            f.write("\t".join(str(x) for x in (p["repo"], p["ref"], p["tip"], p["tip_signed"], p["pushed_by"], p["pushed_at"],
                                               p["before"], p["action"], " ".join(p["files"]), p["note"])) + "\n")
    print(f"\n{len(plan)} infected refs across {len({p['repo'] for p in plan})} repos -> plan.json / plan.tsv")


def build_clean_commit(m, tip, files):
    idx = os.path.join(m, "irkit.index")
    env = dict(os.environ, GIT_INDEX_FILE=idx)
    try:
        git(m, "read-tree", tip, env=env)
        for p in files:
            c = clean_blob(git(m, "show", f"{tip}:{p}"))
            if c is None:
                raise RuntimeError(f"{p}: payload not in the expected shape, fix by hand")
            sha = git(m, "hash-object", "-w", "--stdin", inp=c).decode().strip()
            mode = git(m, "ls-tree", tip, "--", p).decode().split()[0]
            git(m, "update-index", "--cacheinfo", f"{mode},{sha},{p}", env=env)
        tree = git(m, "write-tree", env=env).decode().strip()
        return git(m, "commit-tree", tree, "-p", tip, "-m", CLEAN_MSG).decode().strip()
    finally:
        if os.path.exists(idx):
            os.remove(idx)


def apply(args):
    plan = json.load(open(args.plan))
    for p in plan:
        if p["action"] not in ("restore", "clean-commit") or p["archived"]:
            continue
        m = os.path.join(WORK, p["repo"].replace("/", "__") + ".git")
        branch = p["ref"][len("refs/heads/"):]
        live = git(m, "ls-remote", "origin", p["ref"]).decode().split()
        if not live or live[0] != p["tip"]:
            print(f"SKIP {p['repo']} {branch}: remote moved since scan, rescan"); continue
        new = p["before"] if p["action"] == "restore" else build_clean_commit(m, p["tip"], p["files"])
        if infected_paths(m, new):
            print(f"SKIP {p['repo']} {branch}: replacement {new[:8]} still matches IOCs"); continue
        cmd = ["git", "-C", m, "push", f"--force-with-lease={p['ref']}:{p['tip']}", "origin", f"{new}:{p['ref']}"]
        print(("PUSH " if args.apply else "DRY  ") + f"{p['repo']} {branch}: {p['tip'][:8]} -> {new[:8]} ({p['action']})")
        if args.apply:
            r = subprocess.run(cmd, capture_output=True, text=True)
            print("     ok" if r.returncode == 0 else "     FAILED: " + r.stderr.strip().splitlines()[-1])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("scan"); s.add_argument("org"); s.add_argument("--repo"); s.add_argument("--since-days", type=int, default=30)
    a = sp.add_parser("apply"); a.add_argument("plan"); a.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    {"scan": scan, "apply": apply}[args.cmd](args)
