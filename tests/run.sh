#!/usr/bin/env bash
# Builds a throwaway fixture (fake markers only, no real payload) and checks
# that scan.sh flags exactly what it should. Usage: tests/run.sh
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd -P)
FX=$(mktemp -d "${TMPDIR:-/tmp}/worm-fixture.XXXXXX")
trap 'rm -rf "$FX"' EXIT

# Built by concatenation so this file does not itself carry the indicators
MARK="global.o='5-1902-""du';var _\$_8""ec1=0;"
PAD=$(printf '%220s' '')
G() { git -c user.name=t -c user.email=t@t -c init.defaultBranch=main -c commit.gpgsign=false "$@"; }

# 1. repo whose working tree is clean but one branch tip carries the worm
R="$FX/home/proj"; mkdir -p "$R"; G -C "$R" init -q
printf 'export default {\n  plugins: {},\n}\n' > "$R/postcss.config.js"
printf "import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\nexport const x = require('x');\n" > "$R/legit.mjs"
printf 'const a = 1;%s}\n' "$PAD" > "$R/padding-only.js"
G -C "$R" add -A; G -C "$R" commit -qm clean
G -C "$R" checkout -qb feature
printf "import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\nexport default {\n  plugins: {},\n};%s%s\n" "$PAD" "$MARK" > "$R/postcss.config.js"
G -C "$R" commit -qam "forged tip"
G -C "$R" checkout -q main
# a genuine two-parent merge, and a rewritten one that kept the message but lost a parent
G -C "$R" checkout -qb side; echo s > "$R/s.txt"; G -C "$R" add s.txt; G -C "$R" commit -qm side
G -C "$R" checkout -qb realmerge main; G -C "$R" merge -q --no-ff -m "Merge pull request #8 from org/side" side
G -C "$R" checkout -qb forgedmerge main; echo f > "$R/f.txt"; G -C "$R" add f.txt; G -C "$R" commit -qm "Merge pull request #9 from org/side"
G -C "$R" checkout -q main
# repo config persistence vector
G -C "$R" config core.fsmonitor "touch $FX/pwned-fsmonitor"
# hook carrying a marker
printf '#!/bin/sh\ntouch "%s/pwned-hook"\n# %s\n' "$FX" "$MARK" > "$R/.git/hooks/post-checkout"; chmod +x "$R/.git/hooks/post-checkout"

# 2. infected file on disk (outside git)
mkdir -p "$FX/home/app"
printf 'export default defineNuxtConfig({});%seval("glob''al.o=%s;"+atob(%s))\n' "$PAD" "'5-1604-""du'" "'dmFyIF8""kXzQ1NDQ9'" > "$FX/home/app/nuxt.config.ts"
# obfuscator string table on its own is only heuristic
printf 'var _$_%s=(function(q,w){return q})("",1);\n' "a349" > "$FX/home/app/obf.js"

# 3. heuristic-only hit: references a C2 RPC endpoint
printf 'const rpc = "https://bsc-dataseed.binance.or''g";\n' > "$FX/home/app/web3.js"

# 4. bare mirror whose only branch is infected
G clone -q --bare "$R" "$FX/home/mirror.git"
G -C "$FX/home/mirror.git" update-ref refs/heads/main "$(G -C "$R" rev-parse feature)"

# 5. node_modules is skipped unless --deep
mkdir -p "$FX/home/app/node_modules/pkg"; printf '%s%s\n' "$PAD" "$MARK" > "$FX/home/app/node_modules/pkg/index.js"

fail=0
check() { # description expected-count tsv grep-args...
  local d=$1 want=$2 tsv=$3; shift 3
  local got; got=$(grep -cE "$@" "$tsv" || true)
  if [ "$got" = "$want" ]; then echo "ok   $d"; else echo "FAIL $d: want $want got $got"; fail=1; fi
}

# a running payload process: argv carries the v2 command-line marker, it only sleeps
mkdir -p "$FX/clean-host"
# stage-3 drop artifacts (empty stand-ins) in the fake home and tmp
mkdir -p "$FX/home/.node_modules/socket.io-client" "$FX/tmp/.pip/secretstorage" "$FX/home/.local/lib/python3.12/site-packages"
: > "$FX/tmp/get-pip.py"
B64=$(id -un | tr -d '\n' | base64 -w0); : > "$FX/tmp/$B64"
printf '// %s\n' "$MARK" > "$FX/home/.npm-init.js"
printf 'init-module=/tmp/x.js\n' > "$FX/home/.npmrc"
PROC_ARG="global.i='5-1604-du';glob""al.r=require;"
bash -c 'sleep 60; :' "$PROC_ARG" < /dev/null > /dev/null 2>&1 & FAKE=$!
set +e
HOME="$FX/home" WORM_SCAN_TMP="$FX/tmp" "$HERE/scan.sh" --root "$FX/clean-host" --tsv "$FX/host.tsv" > "$FX/host.txt" 2>&1
kill $(pgrep -P $FAKE 2>/dev/null) $FAKE 2>/dev/null
"$HERE/scan.sh" --root "$FX/home" --no-host --tsv "$FX/out.tsv" > "$FX/out.txt"; rc=$?
"$HERE/scan.sh" --root "$FX/home" --no-host --deep --tsv "$FX/deep.tsv" > /dev/null
mkdir -p "$FX/clean"; printf 'console.log(1)\n' > "$FX/clean/a.js"
"$HERE/scan.sh" --root "$FX/clean" --no-host > /dev/null; rc_clean=$?
set -e
cat "$FX/out.txt"; echo

[ $rc = 1 ] && echo "ok   exit 1 when infected" || { echo "FAIL exit code $rc"; fail=1; }
[ $rc_clean = 0 ] && echo "ok   exit 0 when clean" || { echo "FAIL clean exit $rc_clean"; fail=1; }
rc_self=0; (cd "$HERE" && ./scan.sh --root . --no-host > /dev/null) || rc_self=$?
[ $rc_self = 0 ] && echo "ok   scanner ignores its own IOC files" || { echo "FAIL self-scan exit $rc_self"; fail=1; }
# The repository itself must not match its own rules (no reliance on self-exclusion),
# or every org scan reports it and teaches people to ignore HIGH findings.
self_hits=$(cd "$HERE" && git ls-files -z 2>/dev/null | xargs -0 grep -IlE -f <(grep -hvE '^[[:space:]]*(#|$)' iocs/*.regex) 2>/dev/null || true)
[ -z "$self_hits" ] && echo "ok   repository does not match its own rules" || { echo "FAIL repository matches its own rules: $self_hits"; fail=1; }
check "infected file on disk"                 1 "$FX/out.tsv" '^HIGH	file	.*/app/nuxt.config.ts'
check "heuristic RPC reference is WARN"       1 "$FX/out.tsv" '^WARN	file	.*/app/web3.js'
check "obfuscator table alone is WARN"        1 "$FX/out.tsv" '^WARN	file	.*/app/obf.js'
check "running payload process"               1 "$FX/host.tsv" "^HIGH	process	pid $FAKE "
check "scanner does not flag itself"          0 "$FX/host.tsv" 'scan.sh'
check "per-user .node_modules drop folder"    1 "$FX/host.tsv" '^HIGH	artifact	.*/home/.node_modules	contains socket.io-client'
check "tmp pip toolkit"                       1 "$FX/host.tsv" '^HIGH	artifact	.*/tmp/.pip	credential-theft toolkit: secretstorage'
check "get-pip.py in tmp"                     1 "$FX/host.tsv" '^WARN	artifact	.*/tmp/get-pip.py'
check "base64 username marker"                1 "$FX/host.tsv" "^HIGH	artifact	.*/tmp/$B64	"
check "infected npm init script"              1 "$FX/host.tsv" '^HIGH	persistence	.*/home/.npm-init.js'
check "npmrc init-module"                     1 "$FX/host.tsv" '^WARN	persistence	.*/home/.npmrc'
check "forged branch tip in work repo"        1 "$FX/out.tsv" '^HIGH	git	.*/home/proj  refs/heads/feature .*\(unsigned\): postcss.config.js'
check "infected branch in bare mirror"        1 "$FX/out.tsv" '^HIGH	git	.*/mirror.git  refs/heads/main'
check "clean main branch not flagged"         0 "$FX/out.tsv" 'proj  refs/heads/main'
check "single-parent 'merge' is flagged"     1 "$FX/out.tsv" '^WARN	forged-merge	.*proj  refs/heads/forgedmerge'
check "real two-parent merge not flagged"     0 "$FX/out.tsv" 'refs/heads/realmerge'
check "malicious hook"                        1 "$FX/out.tsv" '^HIGH	git-hook	.*post-checkout'
check "fsmonitor in repo config"              1 "$FX/out.tsv" '^WARN	git-config'
check "legit createRequire not flagged"       0 "$FX/out.tsv" 'legit.mjs'
check "padding without code not flagged"      0 "$FX/out.tsv" 'padding-only.js'
check "node_modules skipped by default"       0 "$FX/out.tsv" 'node_modules'
check "node_modules scanned with --deep"      1 "$FX/deep.tsv" '^HIGH	file	.*node_modules/pkg/index.js'
[ ! -e "$FX/pwned-fsmonitor" ] && [ ! -e "$FX/pwned-hook" ] && echo "ok   repo fsmonitor/hooks never executed" || { echo "FAIL repo code executed"; fail=1; }
exit $fail
