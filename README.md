# terminal-guard.sh

Stops you from accidentally printing secrets to the terminal.

> **Disclaimer:** this is a mitigation tool, not a security guarantee.
> It has known limits (see [Ways around the guard](#ways-around-the-guard)).
> Its main job is to keep misbehaving AI coding agents from reading your
> `.env`, private keys, or credentials and sending them to a remote model.
> It won't stop a person who knows what they're doing.

---

## Install

Pick your shell's profile file and add one line:

| Shell | File |
|---|---|
| Bash | `~/.bashrc` |
| Zsh | `~/.zshrc` |

```bash
source /path/to/terminal-guard.sh
```

Open a new terminal. The guard is on.

---

## What gets blocked

Any attempt to read, copy, move, archive, or edit these files:

| Kind | Patterns |
|---|---|
| Dotenv | `.env`, `.env.prod`, `.env.local`, `.envrc` |
| Private keys | `id_rsa`, `id_ed25519`, `*.pem`, `*.key` |
| Certs | `*.crt`, `*.cer`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore` |
| Credentials | `.git-credentials`, `.netrc`, `.dockercfg`, `.npmrc`, `.pypirc` |
| Cloud / infra | `.aws/*`, `kubeconfig`, `*.tfvars`, `*.tfstate` |
| App secrets | `appsettings.*.json`, `secrets.yml`, `secrets.properties` |
| SSH dir | `~/.ssh/*` (except `known_hosts`, `config`, `authorized_keys`) |
| Databases / vaults | `*.db`, `*.sqlite`, `*.kdbx`, `vault.yml`, `*.gpg` |
| Tokens | `*.token`, filenames containing `token` |

Commands caught:

- **Read:** `cat`, `less`, `head`, `tail`, `grep`, `bat`, `more`, `nl`, `od`, `xxd`, `vim`, `nvim`, `nano`, `code`, `open`, `view`, `rg`, `awk`, `sed`
- **Copy/move:** `cp`, `mv`, `ln`, `tee`, `dd`, `rsync`, `scp`, `install`
- **Archive:** `tar`, `gzip`, `zip`, `unzip`, `gpg`
- **Delete/edit:** `rm`, `touch`, `chmod`, `chown`, `chattr`, `truncate`

Also blocked:

- `env` and `printenv` with no arguments (would dump everything)
- `echo $SOME_VAR` and `printf "$TOKEN"` (Bash blocks it, Zsh warns)

---

## What you can do

### Check if a variable exists

```bash
$ guard_check SONAR_TOKEN
✅ SONAR_TOKEN: set (has value)

$ guard_check MISSING_VAR
❌ MISSING_VAR: not found in .env or environment
```

Searches `.env`, `.env.local`, `.env.development`, `.env.prod`, `.env.production`,
plus the current shell environment. Never prints values.

Exit codes: `0` = all found, `1` = something missing or empty, `2` = no args given.

### Load secrets without printing anything

```bash
source .env
. .env
```

Variables go straight into the shell. Nothing appears on screen. Then use
them as `$VAR_NAME` like normal.

---

## Profiles and the guard script are protected

These files can't be modified while the guard is active:

- `.bashrc`, `.zshrc`, `.bash_profile`, `.zprofile`, `.profile`
- `.zshenv`, `.zlogin`, `.zlogout`, `.bash_logout`, `.bash_aliases`
- `terminal-guard.sh` itself

This stops someone from editing a profile to remove the `source` line.

---

## Ways around the guard

The guard is a seatbelt, not a safe. Here's what it can't stop and what
you can do about it.

### Can't be fixed from inside the script

| Bypass | Why it works |
|---|---|
| `bash --norc`, `zsh -f` | Starts a shell without loading any profiles. No guard. |
| GUI apps (Finder, TextEdit, VSCode) | They read files directly through the OS, not the shell. |
| `sudo`, root access | Root can do anything: read files, edit profiles, delete the guard. |
| Another terminal / SSH session | The guard only applies to the one shell it was sourced in. |
| `ps e -p $$`, `/proc/self/environ`, `pargs $$` | Reads the process environment table from the OS — not a shell command. |
| `scp` / `rsync` to a remote host | The guard wraps the local command, but if the file is already elsewhere… |
| Non-interactive contexts (scripts, `cron`) | The `DEBUG` trap only fires in interactive shells. `guard_check` and function wrappers still work if sourced, but no pre-exec hooks. |
| Fish, dash, sh, ksh | These shells don't support the features the guard needs. Only Bash and Zsh are protected. |

**Zsh is weaker than Bash.** Zsh's `preexec` hook can warn but can't block
commands. Five protections that actually block in Bash only produce a
warning in Zsh: `echo $VAR`, full-path bypasses (`/bin/cat .env`), shell
redirects (`exec 3< .env`), interpreter invocations (`python3 -c "..."`),
and `printf "$VAR"`.

### What you can harden

All of these reduce attack surface. None eliminate it entirely.

Lock down the files themselves:

```bash
chmod 600 .env
chmod 700 .ssh
chmod 600 ~/.git-credentials ~/.netrc ~/.aws/credentials
```

Make the guard and profiles immutable:

**Linux (`chattr`):**

```bash
sudo chattr +i terminal-guard.sh ~/.bashrc
# To edit: sudo chattr -i terminal-guard.sh, make changes, then +i again
```

**macOS (`chflags`):**

```bash
sudo chflags schg terminal-guard.sh ~/.zshrc
# To edit: sudo chflags noschg terminal-guard.sh, make changes, then schg again
```

Check flags:

```bash
lsattr terminal-guard.sh     # Linux: look for "i"
ls -lO terminal-guard.sh     # macOS: look for "schg" or "uchg"
```

Tighten ownership:

```bash
sudo chown root:root terminal-guard.sh
sudo chmod 644 terminal-guard.sh   # only root can write
```

### Other layers

- Encrypt your disk (FileVault on macOS, LUKS on Linux).
- Encrypt your home directory if it's on a separate volume.
- Keep secrets in a password manager or vault, not in plain `.env` files.

---

## Shell support

| Shell | File ops | Copy ops | Profiles | `env`/`printenv` | `echo $VAR` |
|---|---|---|---|---|---|
| Bash 4.0+ | ✅ blocked | ✅ blocked | ✅ blocked | ✅ blocked | ✅ blocked |
| Zsh 5.0+ | ✅ blocked | ✅ blocked | ✅ blocked | ✅ blocked | ⚠️ warned |
| Fish | ❌ no | ❌ no | ❌ no | ❌ no | ❌ no |
| Dash / sh | ❌ no | ❌ no | ❌ no | ❌ no | ❌ no |
| ksh | ❌ no | ❌ no | ❌ no | ❌ no | ❌ no |

Fish and POSIX shells (dash, sh, ksh) don't have the features the guard needs:
function wrapping via `eval`, `[[` tests, arrays, and shell hooks.

In Zsh, `preexec` can see `echo $VAR` commands but can't stop them — a
warning is the best it can do. Bash's `extdebug` + `DEBUG` trap can actually
block the command before it runs.

---

## Quick reference

| What | Command | Result |
|---|---|---|
| Check a variable | `guard_check VAR` | ✅ ok |
| Load secrets silently | `source .env` | ✅ ok |
| Normal file ops | `cat README.md` | ✅ ok |
| Read a secret file | `cat .env` | ❌ blocked |
| Copy a secret file | `cp .env /tmp/x` | ❌ blocked |
| Edit a secret file | `vim id_rsa` | ❌ blocked |
| Archive secrets | `tar cf x.tar .env` | ❌ blocked |
| Dump all env vars | `env` | ❌ blocked |
| Print an env var | `echo $TOKEN` | ❌ blocked |
| Edit your profile | `vim ~/.bashrc` | ❌ blocked |
| Delete the guard | `rm terminal-guard.sh` | ❌ blocked |

---

## License

MIT — see [LICENSE](LICENSE) for the full text.
