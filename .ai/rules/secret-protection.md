# Secret protection

Never read, print, or send secrets, tokens, keys, or credentials to stdout,
a log, or a remote model endpoint. This applies everywhere — terminal commands,
inline scripts, file reads, debug output, and error messages.

## Files you cannot read

```
.env .env.local .env.development .env.prod .env.production .envrc
id_rsa id_ed25519 id_ecdsa id_dsa *.pem *.key *.crt *.cer *.p12 *.pfx
*.jks *.keystore *.truststore *private_key* *.private *.secret
.git-credentials .netrc .dockercfg .docker/config.json .npmrc .pypirc
.aws/credentials .aws/config kubeconfig .kube/config
terraform.tfvars *.auto.tfvars terraform.tfstate .terraform/*
serviceAccountKey.json
appsettings.*.json local.settings.json
secrets.yml secrets.yaml secrets.properties secret.properties
.streamlit/secrets.toml http-client.private.env.json
~/.ssh/* (except known_hosts, config, authorized_keys)
*.kdbx *.rdp vault.yml vault.yaml *.gpg *.pgp *.db *.sqlite *.sqlite3
*.token
terminal-guard.sh  .bashrc .zshrc .bash_profile .zprofile .profile
```

## Commands you cannot run

- `cat`, `less`, `head`, `tail`, `grep`, `bat`, `more`, `nl`, `od`, `xxd`,
  `vim`, `nvim`, `nano`, `code`, `open`, `view`, `rg`, `awk`, `sed` on any file above
- `cp`, `mv`, `ln`, `tee`, `dd`, `rsync`, `scp`, `install` with any file above
- `tar`, `gzip`, `zip`, `unzip`, `gpg` with any file above
- `rm`, `touch`, `chmod`, `chown`, `chattr`, `truncate` on protected files
  (profiles, guard script)
- `env` and `printenv` with no arguments
- `echo $SECRET`, `printf "$TOKEN"`, `declare -p`, `typeset -p`, bare `set`
- `python3 -c`, `ruby -e`, `node -e`, `perl -e`, `php -r` reading any file above
- `bash`, `sh`, `zsh` with `--norc`, `--noprofile`, `-f`, or no arguments
- `command cat .env`, `/bin/cat .env`, `\cat .env` (bypass attempts are blocked)
- `gh auth token`

## What to do instead

**If a command needs a secret** (API key, token, password):

1. Ask the user to set the environment variable in their shell
2. Ask the user to run `source .env` to load secrets without printing them
3. Use `guard_check VARNAME` to verify a variable exists without printing its value

**Never** attempt to read `.env` or any secret file yourself. Not with a
function wrapper, not with a full path, not with an interpreter, not with a
shell redirect. Ask the user.
