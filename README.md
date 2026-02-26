# oops-catcher

You're moving fast. AI is writing half your code. You're committing things without reading every line.

This isn't a replacement for a security review, but it helps catch the stuff that could ruin your weekend.

```bash
npx oops-catcher scan
```

```
[CRITICAL] SEC003 · .env.local:12
  GitHub token detected
  Seen: ghp_[REDACTED]1234
  Fix:  Remove and rotate it in GitHub now.

[CRITICAL] SEC004 · config/stripe.js:3
  Stripe live key detected
  Seen: sk_l[REDACTED]3AB
  Fix:  Remove and rotate it in the Stripe dashboard now.

[WARNING] CON004 · Dockerfile:1
  No USER instruction — container runs as root
  Fix:  Add a USER instruction.

3 findings  ·  2 critical  ·  1 warning
```

Secrets are never printed in full. Always redacted.

---

## Install the pre-commit hook and forget about it

```bash
npx oops-catcher install-hook
```

Now it runs automatically on every `git commit`. If it finds something critical, the commit is blocked. You can fix it before it ever touches your history.

---

## What it catches

**Secrets**
- Private keys (PEM, OpenSSH, PGP)
- AWS access keys and secrets
- GitHub tokens (`ghp_*`, `github_pat_*`)
- Stripe live keys (`sk_live_*`)
- Slack tokens (`xoxb-`, `xapp-`, …)
- GCP service account JSON files
- `.env` files, `id_rsa`, `credentials.json`, `*.pem` tracked in git
- High-entropy strings that look like secrets even if they don't match a known format

**Containers** (devcontainer.json, docker-compose, Dockerfile)
- Docker socket mounted (instant host escape)
- Privileged containers
- Host networking
- Running as root
- `~/.ssh`, `~/.aws`, `~/.config/gcloud` mounted into containers
- `curl | bash` / `wget | sh` in setup scripts

**AI artifacts**
- Chat transcripts, prompt logs, and LLM output files committed to the repo
- Secrets found *inside* those files (it happens more than you think)

---

## Usage

```bash
# Scan the whole repo
oops scan

# Scan only what you're about to commit
oops scan --staged

# Write a config file so you can tune it
oops init

# Install the pre-commit hook
oops install-hook
```

---

## Tune it for your repo

```bash
oops init
```

This writes an `oops.yml`. Common things to tweak:

**Turn off a noisy rule:**
```yaml
rules:
  disable: ["SEC050"]  # high-entropy heuristic fires too much on your codebase
```

**Exclude your test fixtures:**
```yaml
exclude:
  - "**/fixtures/**"
  - "**/test/**"
```

**Make tracked secrets files a hard block instead of a warning:**
```yaml
rules:
  severity_overrides:
    SEC007: critical
```

**JSON output for piping:**
```bash
oops scan --format json | jq '.[] | select(.severity == "critical")'
```

---

## CI

```yaml
- name: oops-catcher
  run: npx oops-catcher scan
```

Exits `1` if anything critical is found. Exits `0` if you're clean.

---

## The AI artifact rules

If you're using Cursor, Claude, Copilot, or any AI tool — you've probably saved chat logs, prompt files, or LLM output into your repo at some point. Sometimes those files have API keys in them because you pasted something into the chat to get help debugging.

`AI001` flags files that look like AI artifacts (by name).
`AI002` scans those files for secrets.

It's a niche rule set that exists because we needed it.

---

## Contributing

Rules live in `packages/core/src/rules/`. Each rule is a plain object with two functions: `appliesTo(path)` and `run(ctx)`. Tests use vitest with fixture files.

```bash
npm install && npm run build && npm test
```

PRs and rule suggestions welcome — open an issue.

---

MIT © Structured Enough LLC
