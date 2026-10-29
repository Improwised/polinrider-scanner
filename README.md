# malware-detection

This repo detects, and helps remove, the `global.o='N-NNNN-du'` git worm. The worm amends the newest commit on every branch it can push to, hides an obfuscated Node.js loader at the end of a padded line in a build config file, and force-pushes the result.

| Tool | What it's for |
|---|---|
| `scan.sh` | Scan one **Linux computer**: files, every git repo, running processes, persistence, stored credentials |
| `iocs/*.regex` | The detection rules, shared by every tool here |
| `repos/sweep.py` | Scan recently pushed **GitHub and Forgejo** repositories and remove the worm from them |
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
- Run it before anyone runs `npm install`, `dev`, `build` or `test` on that machine again. The payload is reported to re-trigger through npm itself, so **don't run any `npm` command on a suspect machine**, not even `npm config`. `scan.sh` never calls npm.

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
- **Processes.** Variants `5-1604-du` and `5-1614-du` start a **detached `node -e` process whose script begins by setting `global.i` and assigning `require` to `global.r`**, which keeps running after the npm command that started it exits. It is reported as `HIGH`. Any unusually long `node -e` command line is `WARN`.
- **Network.** It reports established connections to the known stage-3 C2 address `193.32.162[.]52`, and to the blockchain RPC hosts the loaders use to find their C2. The RPC hosts sit behind shared CDN IPs, so confirm any hit on them.
- **Stage-3 artifacts.** These come from a public third-party analysis of the `5-1604-du` variant and were not observed here directly:
  - `~/.node_modules` containing `axios` or `socket.io-client`
  - `/tmp/.pip` holding a credential-theft toolkit (`secretstorage`, `jeepney`, `pyzipper`, `pycryptodomex`) and `/tmp/get-pip.py`
  - a marker file at `/tmp/<base64 of the user name>`
  - an infected `~/.npm-init.js`, or `init-module` / `onload-script` / `node-options` set in `~/.npmrc`
  - The same toolkit installed per-user under `~/.local` is reported as `WARN`.
- **Persistence.** Shell rc files, `~/.gitconfig`, `~/.npmrc`, crontab, systemd (system and user), XDG autostart (user and system), `/etc/profile.d`, and VS Code and Cursor extensions. Autostart entries changed in the last 14 days are listed.
- **Credentials to rotate.** It lists the paths of gh, git, npm, AWS, Docker, kube, gcloud and Azure credential files and SSH private keys. It never prints their contents.

### If a machine is `HIGH`

1. Disconnect it from the network. Don't try to clean it; reimage it.
2. From a **different, clean** machine, revoke and rotate everything the scan listed under `credential`, plus anything else that machine could reach: GitHub PATs, SSH and GPG keys, OAuth apps and sessions, npm tokens, cloud keys, `.env` secrets, kube contexts.
3. Treat every branch that machine's GitHub account could push to as suspect, and run the org scan below.

Under WSL2, the newer variants also launch `node.exe` on the Windows host. `scan.sh` only covers Linux. On such machines, check the Windows host by hand for `node.exe` processes whose command line contains `global.i=`, and scan the Windows user's source folders from WSL with `--root /mnt/c/Users/<name>`.

## Clean GitHub and Forgejo repositories

Run this from a clean machine. GitHub access goes through `gh` (`gh auth login` as an org admin). Forgejo access uses a token in `$FORGEJO_TOKEN` with repository read/write on the org.

```sh
# read-only; repeat --github / --forgejo for every owner
python3 repos/sweep.py scan --github <org> --forgejo https://<forgejo-host>/<org> --since 45d --notifications
python3 repos/sweep.py clean findings.json            # dry run: prints each push it would make
python3 repos/sweep.py clean findings.json --apply
```

**What counts as recent.** The worm keeps the original commit dates, so commit dates are useless here. "Recent" is decided by the server's own push time instead: GitHub `pushedAt`, Forgejo `updated_at`. Every branch tip of every repository pushed since `--since` gets checked.

**Notifications as hints.** `--notifications` reads your GitHub and Forgejo notifications since `--since`, for example CI runs failing after a forced push. Repositories named there are checked first, even if they were pushed before `--since`. On GitHub this includes any owner; on Forgejo, only the listed orgs. GitHub needs the `notifications` or `repo` token scope for this. Each finding shows the notifications that point at it.

**API calls.** The script prints its call counts at the end.

| Platform | Calls |
|---|---|
| GitHub | one GraphQL query per 50 repositories, which also returns their branch tips; repos are sorted by push time, so paging stops at `--since` |
| GitHub, extra | one query per repository with more than 100 branches, one per 20 notification-named repositories, one REST call per 50 notifications |
| Forgejo | one call for the org id, one per 50 repositories (sorted by update time, stopping at `--since`), one per 50 notifications |
| `clean --mode restore` | one GitHub REST call per infected repository |
| No API calls | branch tips on Forgejo (`git ls-remote`) and all file contents (depth-1 git fetches) |

`sweep-state.json` remembers every tip already checked, so a rerun only fetches branches that changed since.

**Cleaning.**
- **`restore` (default).** On GitHub, each infected branch goes back to the commit it pointed to **before** the forced push, taken from the repository's force-push activity log. This only happens if that commit is clean.
- **`clean`, and the fallback.** Forgejo, or GitHub when no clean original exists, gets a cleanup commit on top that removes the loader and its `createRequire` header. The cleanup commit uses the identity from `--author`.
- **Pushes are guarded.** Every push uses `--force-with-lease` against the infected tip found by the scan, so a branch that moved since then is skipped. Archived repositories are reported, not touched.
- **Before `--apply`:** allow admin pushes on protected branches, and force-pushes too for `restore`. Put the protection back afterwards.

## Indicators

| Variant | C2 wallet substring | How stage 3 is fetched |
|---|---|---|
| `5-1902-du` | `596dcc9fda875309ff85eba09cf5a97[d]` | The Ethereum tx `to` field points at a BSC transaction. Its input is XOR-decrypted with `8l%Sljl>J>U61O,[n]` and passed to `eval`. |
| `5-1604-du`, `5-1614-du` | `33ff3edaf55a8e03dcbc7cb40d498a4[9]` | The Ethereum tx `to` field encodes `IP:port`. It fetches `http://IP:port/boot` (header `X: <wallet>:<id>`), then `eval`s it **and** spawns a detached `node -e` (plus `node.exe` on WSL2). |

The `N-NNNN` part of the marker differs between infected machines. In the cases where the pushing account could be identified, each marker matched exactly one account. So it looks like a per-victim ID that the C2 hands out, and a marker found in a repository points to the machine that pushed it.

- The obfuscator is polymorphic: table names, seeds and constants change with every build. `iocs/high-confidence.regex` targets what all variants share:
  - the `global.o='N-NNNN-du'` marker
  - an `atob(...)` argument starting with `dmFyIF8kX` (base64 of `var _$_`)
  - the `_$jsoIte[r]` helper
  - the wallets, the XOR key and the spawned process's command line
- Injected files seen so far: `nuxt.config.ts`, `svelte.config.js`, `postcss.config.js`, `server.ts`, `scripts/*.ts` and `scripts/*.js`. That is, files that run on `npm install`, `dev`, `build` or `test`.

Values shown here are **defanged**, so this repository doesn't match its own rules: `[d]` stands for `d` and `[.]` for `.`. The exact patterns are in `iocs/`.

To add an indicator, add a line to one of the `iocs/*.regex` files: a POSIX extended regex (`grep -E`), with `#` comments allowed.
- Write each line so it can't match itself: escape a character, or wrap one in `[]`.
- Keep the exact strings out of comments, docs and tests.
- `tests/run.sh` fails if any file in the repository matches the rules.

## New variants

```sh
python3 -I analysis/deobfuscate.py path/to/infected.config.js out/
```

It finds the payload in the file and unpacks every layer without executing anything. It writes `out/stage{1,2}.js.INERT` and `out/stage2_clear.js.INERT` (with the string table inlined), and prints the marker, wallet, RPC hosts and XOR key as JSON. Tested on all three variants above.

## Tests

```sh
tests/run.sh                                  # scan.sh
python3 -m unittest tests/test_sweep.py       # repos/sweep.py against local git remotes, a fake gh and a fake Forgejo API
```

The fixture is built at run time and contains fake markers only, never a real payload. The tests check:
- detections in files, branches, bare mirrors, hooks, repo config, `--deep` and a live payload process
- forged-merge detection
- false-positive controls: legitimate `createRequire`, padding with no code, real two-parent merges
- that hooks and fsmonitor in a scanned repo never run

Requirements: Linux with bash 4+, GNU grep, git and coreutils; `lsof` and `getent` for the network check; python3 for `repos/` and `analysis/`. The GraphQL queries in `repos/sweep.py` are validated against GitHub's published schema, and the Forgejo calls follow Forgejo's API spec. Neither has been run against a live instance from this repository's tests.
