# malware-detection

This repo detects, and helps remove, the `global.o='N-NNNN-du'` git worm. The worm amends the newest commit on every branch it can push to, hides an obfuscated Node.js loader at the end of a padded line in a build config file, and force-pushes the result.

| Tool | What it's for |
|---|---|
| `scan.sh` | Scan one **Linux computer**: files, every git repo, running processes, persistence, stored credentials |
| `iocs/*.regex` | The detection rules, shared by every tool here |
| `github/irkit.py` | Scan a whole **GitHub org** and put forged branches back on their original commits |
| `analysis/deobfuscate.py` | Unpack a sample statically, for new variants |

Nothing here executes code from what it scans. Git runs with hooks and fsmonitor disabled, nothing is checked out, and nothing is installed.

## Scan a computer

```sh
git clone <this repo> && cd git-worm-scanner
./scan.sh                                   # scans $HOME
./scan.sh --root ~/code --root /srv/work    # extra places to look
./scan.sh --deep --tsv findings.tsv         # also node_modules and package caches; save findings
```

- Run it **as each user who develops on the machine**, without `sudo`. The host checks look at that user's `$HOME` (shell startup files, systemd user units, autostart entries, credentials).
- Run it before anyone runs `npm install`, `dev`, `build` or `test` on that machine again.

| Exit code | Meaning |
|---|---|
| 0 | Clean |
| 1 | Indicators found (`HIGH` or `WARN`) |
| 2 | Usage error |

| Level | Meaning |
|---|---|
| `HIGH` | Worm present. The machine and every credential on it are compromised. |
| `WARN` | Suspicious. Review it. These are the heuristics; they catch new variants but can hit legitimate code. |
| `INFO` | Context: JavaScript processes, recently changed autostart entries, credentials present on the machine. |

What it checks:

- **Files.** Every text file under the roots. It skips `node_modules` and package caches unless `--deep` is given.
- **Git repositories.** Every branch, remote-tracking ref, tag, stash and recent `HEAD` reflog entry of every repo under the roots, including bare mirrors. For each infected ref it shows whether the commit is signed.
  - It flags *forged merges*: a commit whose message says "Merge …" but has a single parent. The worm drops the second parent when it rewrites a merge.
  - It flags repo `core.fsmonitor`, `core.hooksPath` and `core.sshCommand` settings, and hooks carrying indicators.
- **Processes.** Variants `5-1604-du` and `5-1614-du` start a **detached `node -e "global.i='…';global.r=require;…"`** process, which keeps running after the npm command that started it exits. It is reported as `HIGH`. Any unusually long `node -e` command line is `WARN`.
- **Network.** It reports established connections to the blockchain RPC hosts the loaders use to find their C2. Those hosts sit behind shared CDN IPs, so confirm any hit.
- **Persistence.** Shell rc files, `~/.gitconfig`, `~/.npmrc`, crontab, systemd (system and user), XDG autostart (user and system), `/etc/profile.d`, and VS Code and Cursor extensions. Autostart entries changed in the last 14 days are listed.
- **Credentials to rotate.** It lists the paths of gh, git, npm, AWS, Docker, kube, gcloud and Azure credential files and SSH private keys. It never prints their contents.

### If a machine is `HIGH`

1. Disconnect it from the network. Don't try to clean it; reimage it.
2. From a **different, clean** machine, revoke and rotate everything the scan listed under `credential`, plus anything else that machine could reach: GitHub PATs, SSH and GPG keys, OAuth apps and sessions, npm tokens, cloud keys, `.env` secrets, kube contexts.
3. Treat every branch that machine's GitHub account could push to as suspect, and run the org scan below.

Under WSL2, the newer variants also launch `node.exe` on the Windows host. `scan.sh` only covers Linux. On such machines, check the Windows host by hand for `node.exe` processes whose command line contains `global.i=`, and scan the Windows user's source folders from WSL with `--root /mnt/c/Users/<name>`.

## Clean the GitHub org

Run this from a clean machine with `gh` logged in as an org admin.

```sh
python3 github/irkit.py scan <org>            # read-only: bare mirrors, every branch and PR head -> plan.json / plan.tsv
python3 github/irkit.py apply plan.json        # dry run: prints each push it would make
python3 github/irkit.py apply plan.json --apply
```

- **Restore.** For each infected branch, `scan` looks up GitHub's force-push activity log, finds the commit the branch pointed to **before** the forged push, and checks that commit is clean. `apply` then moves the branch back to it with `--force-with-lease` against the forged tip, so a branch that changed since the scan is skipped.
- **Cleanup commit.** Where no clean original exists, it adds a cleanup commit on top instead, removing the loader and its `createRequire` header.
- **Before `--apply`:** allow admin force-pushes on protected branches. Restore the protection afterwards.
- PR head refs (`refs/pull/*`) are reported only. Fix the source branch.

## Indicators

| Variant | C2 wallet substring | How stage 3 is fetched |
|---|---|---|
| `5-1902-du` | `596dcc9fda875309ff85eba09cf5a97d` | The Ethereum tx `to` field points at a BSC transaction. Its input is XOR-decrypted with `8l%Sljl>J>U61O,n` and passed to `eval`. |
| `5-1604-du`, `5-1614-du` | `33ff3edaf55a8e03dcbc7cb40d498a49` | The Ethereum tx `to` field encodes `IP:port`. It fetches `http://IP:port/boot` (header `X: <wallet>:<id>`), then `eval`s it **and** spawns a detached `node -e` (plus `node.exe` on WSL2). |

- The obfuscator is polymorphic: table names, seeds and constants change with every build. `iocs/high-confidence.regex` targets what all variants share:
  - the `global.o='N-NNNN-du'` marker
  - `atob('dmFyIF8kX` (base64 of `var _$_`)
  - `_$jsoIter`
  - the wallets, the XOR key and the spawned process's command line
- Injected files seen so far: `nuxt.config.ts`, `svelte.config.js`, `postcss.config.js`, `server.ts`, `scripts/*.ts` and `scripts/*.js`. That is, files that run on `npm install`, `dev`, `build` or `test`.

To add an indicator, add a line to one of the `iocs/*.regex` files: a POSIX extended regex (`grep -E`), with `#` comments allowed. Then run `tests/run.sh`.

## New variants

```sh
python3 -I analysis/deobfuscate.py path/to/infected.config.js out/
```

It finds the payload in the file and unpacks every layer without executing anything. It writes `out/stage{1,2}.js.INERT` and `out/stage2_clear.js.INERT` (with the string table inlined), and prints the marker, wallet, RPC hosts and XOR key as JSON. Tested on all three variants above.

## Tests

```sh
tests/run.sh
```

The fixture is built at run time and contains fake markers only, never a real payload. The tests check:
- detections in files, branches, bare mirrors, hooks, repo config, `--deep` and a live payload process
- forged-merge detection
- false-positive controls: legitimate `createRequire`, padding with no code, real two-parent merges
- that hooks and fsmonitor in a scanned repo never run

Requirements: Linux with bash 4+, GNU grep, git and coreutils; `lsof` and `getent` for the network check; python3 for `github/` and `analysis/`.
