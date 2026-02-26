# Configuration

Oops Catcher loads `oops.yml` from the repo root.

## Default config

```yaml
version: 1
include: ["**/*"]
exclude: [".git/**","node_modules/**","dist/**","build/**",".next/**","coverage/**"]
rulesets: ["secrets_v1","containers_v1","ai_artifacts_v1"]
rules:
  disable: []
  severity_overrides: {}
output:
  format: text
  failOn: critical
  redact: { showPrefix: 4, showSuffix: 4 }
baseline:
  mode: off
  file: ".oops-baseline.json"
allowlist:
  paths: []
  rules: {}
```

## Examples

Disable a rule:

```yaml
rules:
  disable: ["SEC001"]
```

Override severity:

```yaml
rules:
  severity_overrides:
    SEC007: warning
```

Exclude paths:

```yaml
exclude:
  - "**/fixtures/**"
```
