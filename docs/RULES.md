# Rules

Oops Catcher never prints full secrets; matched values are redacted.

## Secrets (secrets_v1)

- **SEC001** Private key block detected (critical)
  - Why: Private keys should never be committed.
  - What it catches: PEM/OpenSSH/PGP private key blocks.
  - Fix: Remove the key and rotate it.
  - False positives: Test fixtures or docs containing dummy keys.
  - Tuning: Disable rule or exclude fixtures.

- **SEC002** AWS credentials pattern detected (critical)
  - Why: Access keys grant account access.
  - What it catches: Common AWS key/secret patterns.
  - Fix: Remove and rotate the keys.
  - False positives: Sample keys in docs.
  - Tuning: Allowlist specific paths.

- **SEC003** GitHub token detected (critical) (ghp_*, github_pat_*)
  - Why: Tokens provide API access.
  - What it catches: GitHub personal access token formats.
  - Fix: Remove and rotate token.
  - False positives: Mock tokens in tests.
  - Tuning: Use fixtures exclusion.

- **SEC004** Stripe live secret key detected (critical) (sk_live_*)
  - Why: Live Stripe keys can charge real cards.
  - What it catches: Stripe live secret key format.
  - Fix: Remove and rotate the key.
  - False positives: None expected.
  - Tuning: Allowlist test data.

- **SEC005** Slack token detected (critical) (xoxb-, xapp-, etc.)
  - Why: Slack tokens grant API access.
  - What it catches: Slack token formats.
  - Fix: Remove and rotate the token.
  - False positives: Mock tokens in docs.
  - Tuning: Exclude docs.

- **SEC006** GCP service account key indicators (critical)
  - Why: Service account keys grant cloud access.
  - What it catches: JSON with `type=service_account` and `private_key`.
  - Fix: Remove and rotate the key.
  - False positives: Sample JSON with redacted keys.
  - Tuning: Allowlist paths.

- **SEC007** Secrets files tracked (warning default; optionally critical)
  - Why: Secrets files are often mistakenly committed.
  - What it catches: `.env`, `.env.*`, `credentials.json`, `*.pem`, `id_rsa`, `secrets.*`.
  - Fix: Remove file and add to `.gitignore`.
  - False positives: Non-secret configuration files.
  - Tuning: Override severity or exclude.

- **SEC050** High-entropy token heuristic (warning)
  - Why: Random tokens often indicate secrets.
  - What it catches: High-entropy strings.
  - Fix: Move to secret manager.
  - False positives: Random IDs in fixtures.
  - Tuning: Disable rule or exclude paths.

## Containers (containers_v1)

- **CON001** Docker socket mounted (critical)
  - Why: Grants host-level control in the container.
  - What it catches: `/var/run/docker.sock` mounts in devcontainer or compose.
  - Fix: Remove socket mount or isolate builds.
  - False positives: Local-only dev tools.
  - Tuning: Override severity.

- **CON002** Privileged container (critical)
  - Why: Privileged containers bypass isolation.
  - What it catches: `privileged: true` or `--privileged`.
  - Fix: Remove privileged flag.
  - False positives: Low-level tooling images.
  - Tuning: Allowlist specific services.

- **CON003** Host networking enabled (critical)
  - Why: Host networking reduces isolation.
  - What it catches: `network_mode: host`.
  - Fix: Use a bridge network.
  - False positives: Networking experiments.
  - Tuning: Exclude dev-only configs.

- **CON004** Container runs as root (warning)
  - Why: Root in containers is risky.
  - What it catches: `remoteUser=root` or missing `USER` in Dockerfile (heuristic).
  - Fix: Set a non-root user.
  - False positives: Base images that drop privileges.
  - Tuning: Override severity.

- **CON101** Credential directories mounted (warning)
  - Why: Exposes host credentials inside containers.
  - What it catches: `~/.ssh`, `~/.aws`, `~/.config/gcloud` mounts.
  - Fix: Remove mounts or use short-lived creds.
  - False positives: Local-only dev setups.
  - Tuning: Allowlist paths.

- **CON102** Remote script execution in dev setup (warning)
  - Why: Piping remote scripts to a shell is risky.
  - What it catches: `curl|bash`, `wget|sh` in devcontainer lifecycle or Dockerfile.
  - Fix: Pin scripts and validate checksums.
  - False positives: Internal scripts.
  - Tuning: Exclude dev scripts.

## AI artifacts (ai_artifacts_v1)

- **AI001** AI transcript/prompt artifacts tracked (info default; optionally warning)
  - Why: Transcripts may contain sensitive context.
  - What it catches: Filenames like `*chat*`, `*prompt*`, `*transcript*`, `.prompt_history`.
  - Fix: Remove artifacts or add to `.gitignore`.
  - False positives: Intentional training data.
  - Tuning: Override severity or allowlist.

- **AI002** Secrets detected in AI artifacts (inherits severity from underlying secret)
  - Why: Secrets in AI artifacts should be removed and rotated.
  - What it catches: Secrets in files already flagged by AI001.
  - Fix: Remove and rotate affected secrets.
  - False positives: Redacted examples.
  - Tuning: Exclude artifacts or disable AI001.

## Configuration examples

Disable rules:

```yaml
rules:
  disable: ["SEC001", "CON001"]
```

Override severity:

```yaml
rules:
  severity_overrides:
    SEC007: critical
```

Exclude paths:

```yaml
exclude:
  - "**/fixtures/**"
```
