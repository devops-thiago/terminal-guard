#!/usr/bin/env bash
# =============================================================================
# terminal-guard.sh — Source this to prevent accidental secret leakage.
#
# Blocks:
#   1. Reading / copying / archiving secret-bearing files.
#   2. Running env / printenv without args.
#   3. Using echo / printf to print env var values.
#   4. Modifying profile files (.bashrc, .zshrc, etc.) and the guard itself.
#
# Usage:
#   source terminal-guard.sh           # enable guard (permanent)
#   guard_check VAR1 [VAR2 ...]        # check if var exists & has value (safe)
#   source .env                        # load secrets into env (no stdout)
#
# Add to your .bashrc / .zshrc:
#   source /path/to/terminal-guard.sh
# =============================================================================

# ---- helpers ---------------------------------------------------------------

_guard_is_on() {
  return 0  # always on — no off switch
}

_guard_block() {
  local reason="$1"
  printf '\033[1;31m🛡️  GUARD BLOCKED:\033[0m %s\n' "$reason" >&2
}

# Check whether any positional arg looks like a path to a secret-bearing file.
# Covers patterns from gitignore templates, gitleaks, truffleHog, and GitHub
# secret scanning documentation.
_guard_has_secret_file_arg() {
  local arg base
  for arg in "$@"; do
    # skip flags (start with -)
    [[ "$arg" == -* ]] && continue
    base="${arg##*/}"

    # --- env / dotenv files ---
    [[ "$arg" == */.env* || "$arg" == .env* ]] && return 0
    [[ "$base" == .envrc ]] && return 0

    # --- private keys & certificates ---
    [[ "$arg" == *.pem   || "$arg" == *.key  || "$arg" == *.crt  ]] && return 0
    [[ "$arg" == *.cer   || "$arg" == *.der  || "$arg" == *.csr  ]] && return 0
    [[ "$arg" == *.p12   || "$arg" == *.pfx  ]] && return 0
    [[ "$arg" == *.jks   || "$arg" == *.keystore || "$arg" == *.truststore ]] && return 0
    [[ "$base" == id_rsa      || "$base" == id_rsa.*      ]] && return 0
    [[ "$base" == id_ed25519  || "$base" == id_ed25519.*  ]] && return 0
    [[ "$base" == id_ecdsa    || "$base" == id_ecdsa.*    ]] && return 0
    [[ "$base" == id_dsa      || "$base" == id_dsa.*      ]] && return 0
    [[ "$base" == *private_key* || "$base" == *privatekey* ]] && return 0
    [[ "$base" == *.private    || "$base" == *.secret      ]] && return 0

    # --- credential / config files ---
    [[ "$base" == credentials  || "$base" == credentials.* ]] && return 0
    [[ "$base" == .git-credentials  ]] && return 0
    [[ "$base" == .netrc            ]] && return 0
    [[ "$base" == .dockercfg        ]] && return 0
    [[ "$arg" == */.docker/config.json  ]] && return 0
    [[ "$base" == .npmrc            ]] && return 0
    [[ "$base" == .pypirc           ]] && return 0
    [[ "$base" == connectionStrings.config ]] && return 0

    # --- cloud / infra config files ---
    [[ "$base" == .aws-credentials  ]] && return 0
    [[ "$base" == credentials       && "$arg" == */.aws/* ]] && return 0
    [[ "$base" == config            && "$arg" == */.aws/* ]] && return 0
    [[ "$base" == kubeconfig        ]] && return 0
    [[ "$base" == config            && "$arg" == */.kube/* ]] && return 0
    [[ "$base" == terraform.tfvars  ]] && return 0
    [[ "$base" == *.auto.tfvars     ]] && return 0
    [[ "$base" == terraform.tfstate ]] && return 0
    [[ "$arg" == */.terraform/*     ]] && return 0
    [[ "$base" == serviceAccountKey.json ]] && return 0

    # --- app secrets config ---
    [[ "$base" == appsettings.*.json && "$base" != appsettings.Example.json ]] && return 0
    [[ "$base" == local.settings.json  ]] && return 0
    [[ "$base" == secrets.yml     || "$base" == secrets.yaml     ]] && return 0
    [[ "$base" == secrets.properties  ]] && return 0
    [[ "$base" == secret.properties   ]] && return 0
    [[ "$base" == .streamlit/secrets.toml ]] && return 0
    [[ "$base" == http-client.private.env.json ]] && return 0

    # --- SSH directory files ---
    [[ "$arg" == */.ssh/* && "$base" != known_hosts && "$base" != config && "$base" != authorized_keys ]] && return 0

    # --- password / key databases ---
    [[ "$arg" == *.kdbx  ]] && return 0   # KeePass
    [[ "$arg" == *.rdp   ]] && return 0   # Remote Desktop (can store creds)

    # --- vault / encrypted files ---
    [[ "$base" == vault.yml  || "$base" == vault.yaml  ]] && return 0
    [[ "$base" == *.gpg      || "$base" == *.pgp       ]] && return 0

    # --- sqlite / db files (may contain stored creds) ---
    [[ "$arg" == *.db   || "$arg" == *.sqlite || "$arg" == *.sqlite3 ]] && return 0

    # --- token files ---
    [[ "$arg" == *.token || "$base" == *token* ]] && return 0
  done
  return 1
}

# === Check whether any positional arg targets a "protected" file — profiles
# === or the guard script itself. Tampering with these can disable the guard.

_guard_has_protected_file_arg() {
  local arg base
  for arg in "$@"; do
    [[ "$arg" == -* ]] && continue
    base="${arg##*/}"
    # Shell profiles / rc files
    [[ "$base" == .bashrc       || "$base" == .zshrc       ]] && return 0
    [[ "$base" == .bash_profile || "$base" == .zprofile    ]] && return 0
    [[ "$base" == .profile      || "$base" == .zshenv      ]] && return 0
    [[ "$base" == .zlogin       || "$base" == .zlogout     ]] && return 0
    [[ "$base" == .bash_logout  || "$base" == .bash_aliases ]] && return 0
    # The guard script itself
    [[ "$base" == terminal-guard.sh ]] && return 0
  done
  return 1
}

# Check whether args represent a shell spawn that bypasses the guard.
_guard_is_shell_spawn_attempt() {
  local arg
  for arg in "$@"; do
    case "$arg" in
      --norc|--noprofile|-f) return 0 ;;
    esac
  done
  # No args or only flags = interactive shell (unguarded)
  [[ $# -eq 0 ]] && return 0
  local only_flags=true
  for arg in "$@"; do
    [[ "$arg" == -* ]] && continue
    only_flags=false
    break
  done
  $only_flags && return 0
  return 1
}

# ---- function wrappers for file-reading commands ---------------------------

_guard_wrap() {
  local cmd="$1"
  local mode="${2:-read}"
  local real
  if ! real="$(command -v "$cmd" 2>/dev/null)" || [[ -z "$real" ]]; then
    real="$cmd"
  fi
  local dispatch
  case "$cmd" in
    source|.) dispatch='builtin source "$@"' ;;
    *)         dispatch='command "'"$real"'" "$@"' ;;
  esac
  local extra_guard=""
  if [[ "$mode" == "write" ]]; then
    extra_guard='if _guard_is_on && _guard_has_protected_file_arg "$@"; then _guard_block "cannot modify protected file (profiles / guard script)"; return 1; fi; '
  fi
  # source / . are safe for .env files (loads into env, no stdout),
  # but must still block protected profile files.
  local secret_check="true"
  if [[ "$mode" == "source" ]]; then
    secret_check="false"
    extra_guard='if _guard_is_on && _guard_has_protected_file_arg "$@"; then _guard_block "cannot source protected file (profiles / guard script)"; return 1; fi; '
  fi
  eval "
    $cmd() {
      if $secret_check && _guard_is_on && _guard_has_secret_file_arg \"\$@\"; then
        _guard_block \"$cmd with secret-bearing file argument\"
        return 1
      fi
      $extra_guard
      $dispatch
    }
  "
}

_guard_wrap cat
_guard_wrap less
_guard_wrap head
_guard_wrap tail
_guard_wrap grep
_guard_wrap bat
_guard_wrap more
_guard_wrap nl
_guard_wrap od
_guard_wrap xxd
_guard_wrap open
_guard_wrap rg
_guard_wrap awk
_guard_wrap sed
_guard_wrap source source
_guard_wrap .      source

_guard_wrap cp    write
_guard_wrap mv    write
_guard_wrap ln    write
_guard_wrap tee   write
_guard_wrap dd    write
_guard_wrap rm    write
_guard_wrap touch write
_guard_wrap chmod write
_guard_wrap chown write
_guard_wrap chattr write
_guard_wrap rsync write
_guard_wrap scp   write
_guard_wrap install write
_guard_wrap tar   write
_guard_wrap gzip  write
_guard_wrap zip   write
_guard_wrap unzip write
_guard_wrap gpg   write
_guard_wrap sed   write
_guard_wrap truncate write

_guard_wrap view write
_guard_wrap vim  write
_guard_wrap nvim write
_guard_wrap nano write
_guard_wrap code write

# ---- command builtin guard (blocks 'command cat .env' bypass) ---------------

_guard_wrapped_cmds=(
  cat less head tail grep bat more nl od xxd view vim nvim nano code open rg awk sed
  cp mv ln tee dd rsync scp install tar gzip zip unzip gpg truncate
  rm touch chmod chown chattr
  source .
  python python2 python3 ruby node perl php
  cut paste pr find xargs
  env printenv
  gh
  bash sh zsh
)

command() {
  local args=("$@") i=0 target="" rest=()
  # Find the target command (skip -p/-v/-V flags and --)
  for ((i=0; i<${#args[@]}; i++)); do
    [[ "${args[i]}" == "-p" || "${args[i]}" == "-v" || "${args[i]}" == "-V" ]] && continue
    [[ "${args[i]}" == "--" ]] && { ((i++)); target="${args[i]}"; break; }
    target="${args[i]}"
    break
  done
  # If target is a wrapped command, inspect its args (args after target)
  if [[ -n "$target" ]]; then
    for wrapped in "${_guard_wrapped_cmds[@]}"; do
      if [[ "$target" == "$wrapped" ]]; then
        rest=("${args[@]:$((i+1))}")
        # Special: env/printenv with no args dumps everything
        if [[ "$wrapped" == "env" || "$wrapped" == "printenv" ]]; then
          if [[ ${#rest[@]} -eq 0 ]]; then
            _guard_block "command $wrapped would dump all environment variables"
            return 1
          fi
          break
        fi
        # Special: gh auth token prints GitHub token
        if [[ "$wrapped" == "gh" && "${rest[0]:-}" == "auth" && "${rest[1]:-}" == "token" ]]; then
          _guard_block "gh auth token would print your GitHub token"
          return 1
        fi
        # Special: shell spawns — block bare, --norc, -f, --noprofile
        if [[ "$wrapped" == "bash" || "$wrapped" == "sh" || "$wrapped" == "zsh" ]]; then
          if _guard_is_shell_spawn_attempt "${rest[@]}"; then
            _guard_block "command $wrapped would spawn an unguarded shell"
            return 1
          fi
          break
        fi
        if _guard_has_secret_file_arg "${rest[@]}"; then
          _guard_block "command $target with secret-bearing file argument"
          return 1
        fi
        if [[ "$wrapped" == "source" || "$wrapped" == "." ]] && _guard_has_protected_file_arg "${rest[@]}"; then
          _guard_block "cannot source protected file via command"
          return 1
        fi
        break
      fi
    done
  fi
  builtin command "$@"
}

# Interpreters — block reading secrets via inline code
_guard_wrap python
_guard_wrap python2
_guard_wrap python3
_guard_wrap ruby
_guard_wrap node
_guard_wrap perl
_guard_wrap php

# Misc file readers not in the common list
_guard_wrap cut
_guard_wrap paste
_guard_wrap pr
_guard_wrap find
_guard_wrap xargs

# Shell spawn guards — block 'bash --norc', 'zsh -f', 'bash -c "cat .env"',
# and 'bash .env' (which tries to run .env as a script).
bash() {
  _guard_shell_wrap bash "$@"
}
sh() {
  _guard_shell_wrap sh "$@"
}
zsh() {
  _guard_shell_wrap zsh "$@"
}

_guard_shell_wrap() {
  local shell="$1"; shift
  if ! _guard_is_on; then
    command "$shell" "$@"
    return
  fi
  # Block if any positional arg is a secret-bearing file (e.g. 'bash .env')
  if _guard_has_secret_file_arg "$@"; then
    _guard_block "$shell with secret-bearing file argument"
    return 1
  fi
  # Block spawns that bypass the guard
  if _guard_is_shell_spawn_attempt "$@"; then
    _guard_block "$shell would spawn an unguarded interactive shell"
    return 1
  fi
  command "$shell" "$@"
}

# ---- gh CLI guard (blocks 'gh auth token' only) ---------------------------

gh() {
  if _guard_is_on && [[ "$1" == "auth" && "$2" == "token" ]]; then
    _guard_block "gh auth token would print your GitHub token"
    return 1
  fi
  command gh "$@"
}

# ---- env / printenv guard (function wrappers) ------------------------------

env() {
  if _guard_is_on && [[ $# -eq 0 ]]; then
    _guard_block "bare 'env' would dump all environment variables"
    return 1
  fi
  command env "$@"
}

printenv() {
  if _guard_is_on && [[ $# -eq 0 ]]; then
    _guard_block "bare 'printenv' would dump all environment variables"
    return 1
  fi
  command printenv "$@"
}

# ---- declare / typeset / set / compgen guards -----------------------------

declare() {
  # Block declare -p (dumps vars with values), declare without args, typeset -p
  local arg has_p=false
  for arg in "$@"; do
    [[ "$arg" == "-p" ]] && has_p=true
  done
  if _guard_is_on; then
    if $has_p; then
      _guard_block "declare/typeset -p would dump variables with values"
      return 1
    fi
    if [[ $# -eq 0 ]]; then
      _guard_block "bare declare/typeset would dump all variables"
      return 1
    fi
  fi
  builtin declare "$@"
}

typeset() {
  declare "$@"
}

set() {
  if _guard_is_on; then
    # bare 'set' dumps all vars and functions
    # 'set | grep TOKEN' — the pipe is only detected when set alone
    if [[ $# -eq 0 ]]; then
      _guard_block "bare 'set' would dump all variables and functions"
      return 1
    fi
  fi
  builtin set "$@"
}

compgen() {
  if _guard_is_on; then
    # compgen -v lists all variable names — used to find secrets to extract
    _guard_block "compgen would list all variable names"
    return 1
  fi
  builtin compgen "$@"
}

# ---- pre-exec hook for echo/printf detection -------------------------------

# Bash: use extdebug + DEBUG trap to block BEFORE variable expansion.
if [[ -n "$BASH_VERSION" ]]; then
  shopt -s extdebug 2>/dev/null

  _guard_debug_trap() {
    local cmd="$1"
    local ret=$?

    # skip empty / guard internal / trap-driven commands
    [[ -z "$cmd" ]] && return 0
    [[ "$cmd" == _guard_* ]] && return 0
    [[ "$cmd" == guard_* ]] && return 0

    if _guard_is_on; then
      # Block echo/printf of environment variables (detect $VAR before expansion)
      if [[ "$cmd" =~ ^[[:space:]]*(echo|printf)[[:space:]]+.*\$[A-Za-z_] ]]; then
        _guard_block "echo/printf of environment variable detected: ${cmd:0:120}"
        return 1
      fi

      # Block full-path invocations of known wrapped commands with secret files
      # e.g. /bin/cat .env, /usr/bin/vim id_rsa
      if [[ "$cmd" =~ ^[[:space:]]*(/[^[:space:]]+/)(cat|less|head|tail|grep|bat|more|nl|od|xxd|view|vim|nvim|nano|rg|awk|sed|cp|mv|ln|tee|dd|rsync|scp|tar|gzip|zip|unzip|gpg|python|python2|python3|ruby|node|perl|php|cut|paste|pr|find|xargs|bash|sh|zsh)[[:space:]] ]]; then
        local _rest="${cmd#*${BASH_REMATCH[2]}}"
        _rest="${_rest#"${_rest%%[![:space:]]*}"}"  # trim leading space
        # Shell spawns: also block --norc/-f and bare invocation
        if [[ "${BASH_REMATCH[2]}" == "bash" || "${BASH_REMATCH[2]}" == "sh" || "${BASH_REMATCH[2]}" == "zsh" ]]; then
          if [[ -z "$_rest" || "$_rest" =~ ^-[^c] || "$_rest" =~ (--norc|--noprofile|-f) ]]; then
            _guard_block "full-path ${BASH_REMATCH[2]} would spawn unguarded shell"
            return 1
          fi
        fi
        if _guard_has_secret_file_arg $_rest; then
          _guard_block "full-path bypass of ${BASH_REMATCH[2]} with secret-bearing file"
          return 1
        fi
      fi

      # Block shell redirect reads from secret files
      # e.g. while read ... done < .env, exec 3< .env, cat < .env
      if [[ "$cmd" =~ [\<\"][[:space:]]*(\.env[^\ ]*|id_rsa|id_ed25519|id_ecdsa|id_dsa|.*\.pem|.*\.key|.*\.crt|.*\.jks|.*\.keystore|\.git-credentials|\.netrc|\.npmrc|\.pypirc|\.dockercfg|kubeconfig|.*\.tfvars|.*\.tfstate|secrets\.(yml|yaml|properties)|.*\.token|.*\.gpg|vault\.yml) ]]; then
        _guard_block "shell redirect from secret-bearing file"
        return 1
      fi
    fi

    return 0
  }

  trap '_guard_debug_trap "$BASH_COMMAND"' DEBUG

# Zsh: preexec hook (best-effort — can't block, but we warn).
elif [[ -n "$ZSH_VERSION" ]]; then
  _guard_preexec() {
    local cmd="$1"
    [[ -z "$cmd" ]] && return
    [[ "$cmd" == _guard_* ]] && return
    [[ "$cmd" == guard_* ]] && return

    if _guard_is_on; then
      if [[ "$cmd" =~ ^[[:space:]]*(echo|printf)[[:space:]]+.*\$[A-Za-z_] ]]; then
        printf '\033[1;33m⚠️  GUARD WARNING:\033[0m echo/printf of env var\n' >&2
      fi
      # Full-path bypass
      if [[ "$cmd" =~ ^[[:space:]]*(/[^[:space:]]+/)(cat|less|head|tail|grep|bat|more|nl|od|xxd|view|vim|nvim|nano|rg|awk|sed|cp|mv|ln|tee|dd|rsync|scp|tar|gzip|zip|unzip|gpg|python|python2|python3|ruby|node|perl|php|cut|paste|pr|find|xargs|bash|sh|zsh)[[:space:]] ]]; then
        if [[ "${BASH_REMATCH[2]}" == "bash" || "${BASH_REMATCH[2]}" == "sh" || "${BASH_REMATCH[2]}" == "zsh" ]]; then
          printf '\033[1;33m⚠️  GUARD WARNING:\033[0m full-path %s would spawn a shell\n' "${BASH_REMATCH[2]}" >&2
        else
          printf '\033[1;33m⚠️  GUARD WARNING:\033[0m full-path bypass of %s\n' "${BASH_REMATCH[2]:-command}" >&2
        fi
      fi
      # Redirect from secret file
      if [[ "$cmd" =~ [\<\"][[:space:]]*(\.env|id_rsa|id_ed25519|id_ecdsa|.*\.pem|.*\.key|.*\.crt|.*\.jks|\.git-credentials|\.netrc|.*\.tfvars|secrets\.(yml|yaml|properties)|.*\.token|.*\.gpg|vault\.yml) ]]; then
        printf '\033[1;33m⚠️  GUARD WARNING:\033[0m redirect from secret-bearing file\n' >&2
      fi
    fi
  }
  autoload -Uz add-zsh-hook && add-zsh-hook preexec _guard_preexec
fi

# ---- guard_check: safe env-var existence probe ----------------------------
# Reports whether a variable exists (in .env files or the current environment)
# and whether it has a non-empty value — WITHOUT ever printing the value.
#
# Looks up:
#   1. Standard .env files in $PWD (.env, .env.local, .env.development, etc.)
#   2. The current shell environment
#
# Exit codes:
#   0 = all vars found with non-empty values
#   1 = at least one var not found, or found but empty
#   2 = usage error (no args)
guard_check() {
  local var_name found has_value line val env_files f overall=0

  if [[ $# -eq 0 ]]; then
    printf '\033[1;33mUsage:\033[0m guard_check <VAR_NAME> [VAR_NAME ...]\n' >&2
    return 2
  fi

  for var_name in "$@"; do
    found=false
    has_value=false

    # 1) Check standard .env files in the current directory
    env_files=()
    for f in .env .env.local .env.development .env.prod .env.production; do
      [[ -f "$f" ]] && env_files+=("$f")
    done

    if [[ ${#env_files[@]} -gt 0 ]]; then
      for f in "${env_files[@]}"; do
        while IFS= read -r line || [[ -n "$line" ]]; do
          [[ "$line" =~ ^[[:space:]]*# ]] && continue        # skip comments
          [[ -z "${line// }" ]] && continue                   # skip blanks
          # Match: optional export, then VARNAME=
          if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?${var_name}= ]]; then
            found=true
            val="${line#*=}"
            val="${val#\"}"; val="${val%\"}"                  # strip double quotes
            val="${val#\'}"; val="${val%\'}"                  # strip single quotes
            [[ -n "${val// }" ]] && has_value=true
            break 2   # found — stop searching .env files
          fi
        done < "$f"
      done
    fi

    # 2) Check current environment (only if not already found in .env)
    if ! $found; then
      if [[ -n "${!var_name+x}" ]]; then
        found=true
        [[ -n "${!var_name}" ]] && has_value=true
      fi
    fi

    # 3) Report
    if $found && $has_value; then
      printf '✅ \033[1;32m%s\033[0m: set (has value)\n' "$var_name"
    elif $found; then
      printf '⚠️  \033[1;33m%s\033[0m: set but \033[1;33mempty\033[0m\n' "$var_name"
      overall=1
    else
      printf '❌ \033[1;31m%s\033[0m: not found in .env or environment\n' "$var_name"
      overall=1
    fi
  done

  return $overall
}

# ---- final message ---------------------------------------------------------

if [[ "${TERMINAL_GUARD_LOADED:-0}" != "1" ]]; then
  export TERMINAL_GUARD_LOADED=1
  printf '\033[1;32m🛡️  Terminal guard loaded.\033[0m\n'
  printf '   \033[1;36mBlocks:\033[0m  secret-bearing files  |  env/printenv dumps  |  echo of env vars\n'
  printf '   \033[1;36mFiles:\033[0m   .env .env.*  id_rsa id_ed25519 *.pem *.key *.crt *.jks\n'
  printf '           .git-credentials .netrc .npmrc .dockercfg .aws/* kubeconfig\n'
  printf '           terraform.tfvars *.tfstate secrets.yml *.token *.db *.gpg\n'
  printf '           appsettings.*.json *.kdbx vault.yml … and more\n'
  printf '   \033[1;36mSafe:\033[0m    guard_check <VAR>  |  source .env (loads, no stdout)\n'
fi
