# Oops Catcher

A CLI scanner that catches common security footguns before they land in your git history.

```
$ npx oops-catcher scan

[CRITICAL] SEC001 · secrets.txt:3
  Private key block detected
  Why:  Private keys should not be committed to source control.
  Fix:  Remove the key from the repo and rotate it immediately.
  Seen: -----BE[REDACTED]Y-----

[CRITICAL] SEC003 · .env.local:12
  GitHub token detected
  Why:  Tokens provide API access and should be stored in a secret manager.
  Fix:  Remove the token and rotate it in GitHub immediately.
  Seen: ghp_[REDACTED]1234

[WARNING] CON004 · Dockerfile:1
  No USER instruction in Dockerfile (runs as root)
  Why:  Containers that run as root increase blast radius if compromised.
  Fix:  Add a USER instruction to run as a non-root user.

3 findings (2 critical, 1 warning)
```

Oops Catcher **never prints full secrets** — matched values are always redacted.

---

## What it catches

### Secrets
| Rule | What |
|---|---|
| SEC001 | Private key blocks (PEM, OpenSSH, PGP) |
| SEC002 | AWS access key IDs and secret keys |
| SEC003 | GitHub personal access tokens (ghp_*, github_pat_*) |
| SEC004 | Stripe live secret keys (sk_live_*) |
| SEC005 | Slack tokens (xoxb-, xapp-, xoxp-, …) |
| SEC006 | GCP service account key JSON files |
| SEC007 | Secrets files tracked (.env, *.pem, id_rsa, credentials.json, …) |
| SEC050 | High-entropy string heuristic |

### Containers
| Rule | What |
|---|---|
| CON001 | Docker socket mounted (/var/run/docker.sock) |
| CON002 | Privileged container (privileged: true / --privileged) |
| CON003 | Host networking (network_mode: host) |
| CON004 | Container runs as root (no USER in Dockerfile) |
| CON101 | Credential directories mounted (~/.ssh, ~/.aws, ~/.config/gcloud) |
| CON102 | Remote script execution piped to shell (curl\|bash, wget\|sh) |

### AI artifacts
| Rule | What |
|---|---|
| AI001 | AI transcript/prompt files tracked (*chat*, *prompt*, *transcript*, …) |
| AI002 | Secrets found inside AI artifact files |

See [docs/RULES.md](docs/RULES.md) for full descriptions, false positive guidance, and tuning options.

---

## Install

```bash
npm install -g oops-catcher
```

Or run without installing:

```bash
npx oops-catcher scan
```

---

## Usage

```bash
# Scan everything in the current repo
oops scan

# Scan only staged changes (fast, good for pre-commit)
oops scan --staged

# Write a starter oops.yml config to the current directory
oops init

# Install as a git pre-commit hook
oops install-hook
```

Exit codes: `0` = no findings at or above `failOn` severity, `1` = findings found, `2` = usage error.

---

## Configuration

`oops init` writes a starter `oops.yml`. The defaults:

```yaml
version: 1
include: ["**/*"]
exclude:
  - ".git/**"
  - "node_modules/**"
  - "dist/**"
  - "build/**"
rulesets: ["secrets_v1", "containers_v1", "ai_artifacts_v1"]
rules:
  disable: []
  severity_overrides: {}
output:
  format: text       # or: json
  failOn: critical   # or: warning, info
  redact:
    showPrefix: 4
    showSuffix: 4
allowlist:
  paths: []
  rules: {}
```

**Disable a rule:**
```yaml
rules:
  disable: ["SEC050"]  # turn off high-entropy heuristic
```

**Upgrade a severity:**
```yaml
rules:
  severity_overrides:
    SEC007: critical  # treat tracked secrets files as critical
```

**Exclude paths (e.g. test fixtures):**
```yaml
exclude:
  - "**/fixtures/**"
  - "**/test/**"
```

**JSON output** (for CI pipelines, `jq`, etc.):
```bash
oops scan --format json | jq '.[] | select(.severity == "critical")'
```
Or set `output.format: json` in `oops.yml`.

See [docs/configuration.md](docs/configuration.md) for the full reference.

---

## Pre-commit hook

```bash
oops install-hook
```

Installs a `.git/hooks/pre-commit` that runs `oops scan --staged` before every commit. Any critical finding blocks the commit.

Or add to an existing `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/auntiemoi-commits/oops-catcher
    rev: v0.1.0
    hooks:
      - id: oops-scan
```

---

## CI

```yaml
# GitHub Actions
- name: Oops Catcher
  run: npx oops-catcher scan
```

To fail only on critical findings (default) or tune the threshold:

```yaml
- run: npx oops-catcher scan
  env:
    OOPS_FAIL_ON: warning
```

---

## Contributing

Bug reports and rule suggestions welcome — open an issue. PRs welcome too.

Rules live in `packages/core/src/rules/`. Each rule set is a plain array of `Rule` objects with `appliesTo` (path filter) and `run` (content scanner) functions. Tests use `vitest` and fixture files in `packages/core/test/fixtures/`.

```bash
npm install
npm run build
npm test
```

---

## License

MIT — see [LICENSE](LICENSE).
