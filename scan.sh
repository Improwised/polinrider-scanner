#!/usr/bin/env bash
# Scan a Linux machine for the "global.o='N-NNNN-du'" git worm.
#
# Read-only: it never executes code from the scanned repositories (git runs
# with hooks and fsmonitor disabled) and never prints secret values.
#
# Usage: ./scan.sh [--root DIR]... [--deep] [--no-heuristic] [--no-host] [--tsv FILE]
#   --root DIR      where to look for files and git repos (default: $HOME; repeatable)
#   --deep          also scan node_modules and package-manager caches (slow)
#   --no-heuristic  only report high-confidence indicators
#   --no-host       skip process, network, persistence and credential checks
#   --tsv FILE      also write findings as tab-separated values
#
# Exit status: 0 clean, 1 indicators found, 2 usage error.

set -u
LC_ALL=C; export LC_ALL

SELF=$(cd "$(dirname "$0")" && pwd -P)
ROOTS=()
DEEP=0
HEURISTIC=1
HOST=1
TSV=""

while [ $# -gt 0 ]; do
  case "$1" in
    --root) [ $# -ge 2 ] || { echo "--root needs a directory" >&2; exit 2; }
            # absolute physical path, so results (and the self-exclusion) are unambiguous
            ROOTS+=("$(cd "$2" 2>/dev/null && pwd -P || printf '%s' "$2")"); shift 2 ;;
    --deep) DEEP=1; shift ;;
    --no-heuristic) HEURISTIC=0; shift ;;
    --no-host) HOST=0; shift ;;
    --tsv) [ $# -ge 2 ] || { echo "--tsv needs a file" >&2; exit 2; }; TSV="$2"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ ${#ROOTS[@]} -gt 0 ] || ROOTS=("$(cd "$HOME" && pwd -P)")

TMP=$(mktemp -d "${TMPDIR:-/tmp}/worm-scan.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

# grep -f has no comment syntax, so strip comments and blank lines first
strip() { grep -vE '^[[:space:]]*(#|$)' "$1"; }
strip "$SELF/iocs/high-confidence.regex" > "$TMP/high"
if [ $HEURISTIC = 1 ]; then strip "$SELF/iocs/heuristic.regex" > "$TMP/heur"; else : > "$TMP/heur"; fi
cat "$TMP/high" "$TMP/heur" > "$TMP/all"

HIGH=0; WARN=0; INFO=0
[ -n "$TSV" ] && printf 'level\tcategory\tlocation\tdetail\n' > "$TSV"

emit() { # level category location detail
  case "$1" in HIGH) HIGH=$((HIGH+1)) ;; WARN) WARN=$((WARN+1)) ;; *) INFO=$((INFO+1)) ;; esac
  printf '[%-4s] %-11s %s\n' "$1" "$2" "$3"
  [ -n "$4" ] && printf '       %s\n' "$4"
  [ -n "$TSV" ] && printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$TSV"
  return 0
}

# First matching line, with the padding collapsed so the hidden code is visible
snippet() { # pattern-file file
  grep -nE -f "$1" "$2" 2>/dev/null | head -n 1 | sed -E 's/[ ]{20,}/ <...spaces...> /' | cut -c1-200
}

classify_file() { # file category
  if grep -qE -f "$TMP/high" "$1" 2>/dev/null; then
    emit HIGH "$2" "$1" "$(snippet "$TMP/high" "$1")"
  elif [ -s "$TMP/heur" ] && grep -qE -f "$TMP/heur" "$1" 2>/dev/null; then
    emit WARN "$2" "$1" "$(snippet "$TMP/heur" "$1")"
  fi
}

inside_self() { case "$1" in "$SELF"|"$SELF"/*) return 0 ;; esac; return 1; }

# Git with everything that could run repository-controlled code switched off
g() {
  GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 git --no-pager \
    -c core.fsmonitor= -c core.hooksPath=/dev/null -c safe.directory='*' -c core.pager=cat \
    -C "$REPO" "$@"
}

PRUNE=(-name .cache)
[ $DEEP = 1 ] || PRUNE+=(-o -name node_modules -o -name .npm -o -name .pnpm-store -o -name .yarn)

echo "== worm scan $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname) as $(id -un)"
echo "   roots: ${ROOTS[*]}  deep=$DEEP heuristic=$HEURISTIC host=$HOST"

# ---------------------------------------------------------------- files
echo "== files on disk"
EXCL=(--exclude-dir=.git --exclude-dir=.cache)
[ $DEEP = 1 ] || EXCL+=(--exclude-dir=node_modules --exclude-dir=.npm --exclude-dir=.pnpm-store --exclude-dir=.yarn)
for root in "${ROOTS[@]}"; do
  [ -d "$root" ] || echo "   skip $root (not a directory)"
done
while IFS= read -r f; do
  inside_self "$f" || classify_file "$f" file
done < <(for root in "${ROOTS[@]}"; do
  [ -d "$root" ] && grep -rIlE "${EXCL[@]}" -f "$TMP/all" "$root" 2>/dev/null
done | sort -u)

# ---------------------------------------------------------------- git
echo "== git repositories (all branches, tags, stashes, recent HEAD reflog)"
for root in "${ROOTS[@]}"; do
  [ -d "$root" ] || continue
  find "$root" \( "${PRUNE[@]}" \) -prune -o \( -name .git -print \) -o \
       \( -type d -name '*.git' -exec test -d '{}/objects' \; -print -prune \) 2>/dev/null
done | sort -u > "$TMP/gitdirs"

NREPO=0
while IFS= read -r gd; do
  case "$gd" in */.git) REPO=$(dirname "$gd") ;; *) REPO="$gd" ;; esac
  inside_self "$REPO" && continue
  NREPO=$((NREPO+1))
  CONF="$gd/config"; [ -f "$gd" ] && CONF=""   # worktree/submodule .git file: config lives elsewhere
  if [ -n "$CONF" ] && [ -f "$CONF" ] && grep -qiE '^[[:space:]]*(fsmonitor|hookspath|sshcommand)[[:space:]]*=' "$CONF"; then
    emit WARN git-config "$CONF" "$(grep -iE '^[[:space:]]*(fsmonitor|hookspath|sshcommand)[[:space:]]*=' "$CONF" | tr -s ' \t' ' ' | head -n 3 | tr '\n' ';')"
  fi
  if [ -d "$gd/hooks" ]; then
    for h in "$gd"/hooks/*; do
      [ -f "$h" ] || continue
      case "$h" in *.sample) continue ;; esac
      classify_file "$h" git-hook
    done
  fi
  { g for-each-ref --format='%(objectname) %(refname)' 2>/dev/null
    g reflog -n 30 --format='%H HEAD-reflog' 2>/dev/null; } > "$TMP/refs"
  # Grep each distinct tree once, but report every ref that points at it, so
  # no infected branch is hidden behind another one with the same content.
  rm -rf "$TMP/tc"; mkdir "$TMP/tc"; : > "$TMP/seen"
  while read -r sha ref; do
    if [ "$ref" = HEAD-reflog ]; then grep -qx "$sha" "$TMP/seen" && continue; fi
    # The worm re-creates a tip commit with a single parent, so a rewritten
    # merge keeps its "Merge ..." message but loses its second parent.
    if [ "$ref" != HEAD-reflog ] && ! grep -qx "$sha" "$TMP/seen"; then
      np=$(( $(g rev-list --parents -n 1 "$sha" 2>/dev/null | wc -w) - 1 ))
      subj=$(g log -1 --format=%s "$sha" 2>/dev/null)
      if [ "$np" = 1 ] && printf '%s\n' "$subj" | grep -qE '^Merge (pull request #[0-9]+ from |branch |remote-tracking branch )'; then
        emit WARN forged-merge "$REPO  $ref @ ${sha:0:12}" "\"$(printf '%s' "$subj" | cut -c1-80)\" has one parent; a real merge has two"
      fi
    fi
    echo "$sha" >> "$TMP/seen"
    tree=$(g rev-parse --verify -q "$sha^{tree}" 2>/dev/null) || continue
    if [ ! -f "$TMP/tc/$tree" ]; then
      while IFS= read -r p; do
        if g show "$tree:$p" 2>/dev/null | grep -qE -f "$TMP/high"; then lvl=HIGH; pf="$TMP/high"; else lvl=WARN; pf="$TMP/heur"; fi
        printf '%s\t%s\t%s\n' "$lvl" "$p" \
          "$(g show "$tree:$p" 2>/dev/null | grep -nE -f "$pf" | head -n 1 | sed -E 's/[ ]{20,}/ <...spaces...> /' | tr '\t' ' ' | cut -c1-200)"
      done < <(g grep -IlE -f "$TMP/all" "$tree" -- 2>/dev/null | sed "s|^$tree:||") > "$TMP/tc/$tree"
    fi
    [ -s "$TMP/tc/$tree" ] || continue
    signed=unsigned; g cat-file commit "$sha" 2>/dev/null | grep -q '^gpgsig' && signed=signed
    while IFS="$(printf '\t')" read -r lvl p snip; do
      emit "$lvl" git "$REPO  $ref @ ${sha:0:12} ($signed): $p" "$snip"
    done < "$TMP/tc/$tree"
  done < "$TMP/refs"
done < "$TMP/gitdirs"
echo "   $NREPO repositories checked"

# ---------------------------------------------------------------- host
if [ $HOST = 1 ]; then
  echo "== persistence locations and shell startup files"
  for p in "$HOME"/.bashrc "$HOME"/.bash_profile "$HOME"/.profile "$HOME"/.zshrc "$HOME"/.zprofile "$HOME"/.zshenv \
           "$HOME"/.config/fish/config.fish "$HOME"/.gitconfig "$HOME"/.config/git/config "$HOME"/.npmrc \
           "$HOME"/.config/autostart "$HOME"/.config/systemd/user /etc/systemd/system /etc/cron.d /etc/crontab \
           /etc/profile.d /etc/xdg/autostart \
           "$HOME"/.vscode/extensions "$HOME"/.cursor/extensions "$HOME"/.vscode-server/extensions; do
    [ -e "$p" ] || continue
    while IFS= read -r f; do classify_file "$f" persistence; done < <(grep -rIlE -f "$TMP/all" "$p" 2>/dev/null)
    case "$p" in */autostart|*/systemd/*|*/cron.d)
      while IFS= read -r f; do
        emit INFO persistence "$f" "modified in the last 14 days, review it"
      done < <(find "$p" -maxdepth 2 -type f -mtime -14 2>/dev/null) ;;
    esac
  done
  if command -v crontab >/dev/null 2>&1; then
    crontab -l 2>/dev/null > "$TMP/crontab" && [ -s "$TMP/crontab" ] && {
      grep -qE -f "$TMP/all" "$TMP/crontab" && emit HIGH persistence "crontab -l" "$(grep -E -f "$TMP/all" "$TMP/crontab" | head -n 1 | cut -c1-200)"
      grep -qiE 'node|bun|deno|npx' "$TMP/crontab" && emit INFO persistence "crontab -l" "has entries running node/bun/deno, review them"
    }
  fi
  for k in core.hooksPath core.fsmonitor init.templateDir core.sshCommand; do
    v=$(git config --global --get "$k" 2>/dev/null) && emit WARN git-global "git config --global $k" "$v"
  done

  echo "== running JavaScript processes and blockchain RPC connections"
  # -ww: full command lines; the 5-1604-du variant runs as a detached `node -e "<payload>"`
  ps -axww -o pid=,user=,command= 2>/dev/null > "$TMP/ps"
  while read -r pid user cmd; do
    [ "$pid" = "$$" ] && continue
    if printf '%s\n' "$cmd" | grep -qE -f "$TMP/high"; then
      emit HIGH process "pid $pid ($user)" "running worm payload: $(printf '%s' "$cmd" | cut -c1-160)"
    elif printf '%s\n' "$cmd" | grep -qE '(^|/)(node|node\.exe|bun|deno)[[:space:]]+(-e|--eval|-p|--print)[[:space:]]' && [ ${#cmd} -gt 500 ]; then
      emit WARN process "pid $pid ($user)" "long inline-eval command line (${#cmd} chars): $(printf '%s' "$cmd" | cut -c1-160)"
    elif printf '%s\n' "$cmd" | grep -qE '(^|[/ ])(node|bun|deno)( |$)'; then
      emit INFO process "pid $pid ($user)" "$(printf '%s' "$cmd" | cut -c1-200)"
    fi
  done < "$TMP/ps"
  C2_IPS="193.32.162.52"
  RPC="ethereum-rpc.publicnode.com eth.drpc.org eth-mainnet.public.blastapi.io rpc.mevblocker.io bsc-dataseed.binance.org bsc-rpc.publicnode.com"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1{print $1, $2, $9}' > "$TMP/conns"
    for h in $RPC; do
      while read -r ip; do
        while read -r c pid peer; do
          emit HIGH network "$c pid $pid -> $peer" "connected to $h (worm C2 RPC; may be shared CDN IP, confirm)"
        done < <(grep -F -- "->$ip:" "$TMP/conns")
      done < <(getent ahosts "$h" 2>/dev/null \
               | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
    done
    # stage-3 C2 reported publicly for the 5-1604-du variant
    for ip in $C2_IPS; do
      while read -r c pid peer; do
        emit HIGH network "$c pid $pid -> $peer" "connected to known worm C2 $ip"
      done < <(grep -F -- "->$ip:" "$TMP/conns")
    done
  fi
  for hist in "$HOME"/.bash_history "$HOME"/.zsh_history "$HOME"/.local/share/fish/fish_history; do
    [ -f "$hist" ] && grep -qE -f "$TMP/all" "$hist" 2>/dev/null && emit WARN history "$hist" "mentions an indicator"
  done

  # Files the stage-3 payload drops, as reported publicly for the 5-1604-du
  # variant (not observed directly). npm itself is never run: the payload is
  # reported to re-trigger through npm's init script.
  echo "== stage-3 artifacts"
  TMPD=${WORM_SCAN_TMP:-/tmp}
  if [ -d "$HOME/.node_modules" ]; then
    mods=$(find "$HOME/.node_modules" -mindepth 1 -maxdepth 1 \( -name axios -o -name socket.io-client \) -printf '%f ' 2>/dev/null)
    if [ -n "$mods" ]; then emit HIGH artifact "$HOME/.node_modules" "contains ${mods}(stage-3 drop folder)"
    else emit WARN artifact "$HOME/.node_modules" "legacy per-user module folder, review its contents"; fi
  fi
  if [ -d "$TMPD/.pip" ]; then
    pk=$(find "$TMPD/.pip" -maxdepth 4 -type d \( -iname 'secretstorage' -o -iname 'jeepney' -o -iname 'pyzipper*' -o -iname 'Cryptodome*' \) -printf '%f ' 2>/dev/null)
    if [ -n "$pk" ]; then emit HIGH artifact "$TMPD/.pip" "credential-theft toolkit: $pk"
    else emit WARN artifact "$TMPD/.pip" "hidden pip install target in $TMPD"; fi
  fi
  [ -f "$TMPD/get-pip.py" ] && emit WARN artifact "$TMPD/get-pip.py" "pip bootstrapper dropped in $TMPD"
  u=$(id -un)
  b64=$(printf '%s' "$u" | base64 -w0)
  for m in $(printf '%s\n%s\n' "$b64" "${b64%%=*}" | sort -u); do
    [ -e "$TMPD/$m" ] && emit HIGH artifact "$TMPD/$m" "marker file named after the base64 of user $u"
  done
  ntmp=$(find "$TMPD" -maxdepth 1 -name 'tmp*.tmp' -user "$u" 2>/dev/null | wc -l)
  [ "$ntmp" -gt 0 ] && emit INFO artifact "$TMPD/tmp*.tmp" "$ntmp file(s) owned by $u; the payload is reported to create these"
  if [ -f "$HOME/.npm-init.js" ]; then
    if grep -qE -f "$TMP/all" "$HOME/.npm-init.js" 2>/dev/null; then classify_file "$HOME/.npm-init.js" persistence
    else emit WARN persistence "$HOME/.npm-init.js" "npm init script present (reported persistence location), review it"; fi
  fi
  if [ -f "$HOME/.npmrc" ] && grep -qiE '^[[:space:]]*(init-module|init\.module|onload-script|node-options)[[:space:]]*=' "$HOME/.npmrc"; then
    emit WARN persistence "$HOME/.npmrc" "$(grep -iE '^[[:space:]]*(init-module|init\.module|onload-script|node-options)[[:space:]]*=' "$HOME/.npmrc" | head -n 2 | tr '\n' ';')"
  fi
  for sp in "$HOME"/.local/lib/python3*/site-packages; do
    [ -d "$sp/secretstorage" ] && [ -d "$sp/jeepney" ] && [ -d "$sp/pyzipper" ] && \
      emit WARN artifact "$sp" "secretstorage + jeepney + pyzipper installed per-user (matches the reported toolkit)"
  done

  echo "== credentials stored on this machine (rotate all of them if anything above is HIGH)"
  for c in "$HOME"/.config/gh/hosts.yml "$HOME"/.git-credentials "$HOME"/.npmrc "$HOME"/.yarnrc.yml \
           "$HOME"/.aws/credentials "$HOME"/.docker/config.json "$HOME"/.kube/config "$HOME"/.netrc \
           "$HOME"/.config/gcloud/credentials.db "$HOME"/.azure/msal_token_cache.json; do
    [ -f "$c" ] && emit INFO credential "$c" "present"
  done
  for k in "$HOME"/.ssh/id_*; do
    case "$k" in *.pub) continue ;; esac
    [ -f "$k" ] && emit INFO credential "$k" "SSH private key"
  done
  helper=$(git config --global --get credential.helper 2>/dev/null) && emit INFO credential "git credential.helper" "$helper"
fi

echo "== summary: $HIGH high-confidence, $WARN suspicious, $INFO informational"
if [ $HIGH -gt 0 ]; then
  echo "   INFECTED: treat this machine and every credential on it as compromised."
  exit 1
fi
[ $WARN -gt 0 ] && { echo "   Review the suspicious findings above."; exit 1; }
exit 0
