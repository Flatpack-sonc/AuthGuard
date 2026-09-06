# AuthGuard

Defensive OAuth 2.0 / OpenID Connect configuration auditor.

Inspects discovery metadata and JWKS against hardening guidance.  
Produces scored findings for local review and CI — not an exploit toolkit.

```text
discovery + jwks  →  policy rules  →  score / grade
                         ↓
              suppressions · baseline · drift
```

---

## Scope

| In scope | Out of scope |
|----------|--------------|
| Public OIDC discovery & JWKS | Token forgery, alg-confusion PoCs |
| Hardening misconfiguration signals | Live authorization-flow attacks |
| Suppressions, baseline, drift, SARIF | Replacement for a full pentest |

AuthGuard evaluates **advertised** policy. Runtime controls (redirect allowlists, refresh rotation, MFA) appear only as a manual checklist.

---

## Requirements

- .NET 8 SDK

---

## Install & build

```bash
git clone https://github.com/Flatpack-sonc/AuthGuard.git
cd AuthGuard

dotnet build AuthGuard.sln
dotnet test  AuthGuard.sln
```

```bash
dotnet publish src/AuthGuard.Cli -c Release -o ./publish
./publish/authguard version
```

---

## Usage

### Audit an issuer

```bash
authguard audit https://login.example.com --idp enterprise
```

```bash
# Offline / fixtures
authguard audit \
  --config discovery.json \
  --jwks jwks.json \
  --format html \
  --output report.html
```

### Policy file

```bash
authguard init
```

```yaml
# .authguard.yml
profile: standard
idp: enterprise          # generic | spa | mobile | enterprise
fail_on: high
baseline: .authguard-baseline.json

suppressions:
  - id: AG-FLOW-001
    reason: "Legacy hybrid retained until migration"
    until: 2027-06-01
    ticket: SEC-123
```

Every suppression requires a `reason`. Optional: `until`, `ticket`, `only_severity`.  
Issuer-specific blocks match by URL prefix.

### Baseline

```bash
authguard audit https://login.example.com --format json -o report.json
authguard baseline report.json -o .authguard-baseline.json

authguard audit https://login.example.com \
  --baseline .authguard-baseline.json \
  --fail-on high
```

Only **active** findings affect score and `--fail-on`. Suppressed items remain in the report for audit trail.

### Drift

```bash
authguard diff yesterday.json today.json --fail-on high
```

Reports added, resolved, and severity changes. Exit `1` on regressions at or above the threshold.

---

## CLI

| Command | Purpose |
|---------|---------|
| `authguard init` | Create `.authguard.yml` |
| `authguard audit <issuer>` | Run configuration audit |
| `authguard baseline <report.json>` | Freeze findings into a baseline |
| `authguard diff <a.json> <b.json>` | Compare two JSON reports |
| `authguard version` | Print version |

### `audit` options

| Option | Description |
|--------|-------------|
| `-p, --profile` | `relaxed` \| `standard` \| `strict` |
| `--idp` | `generic` \| `spa` \| `mobile` \| `enterprise` |
| `-f, --format` | `console` \| `json` \| `sarif` \| `html` |
| `-o, --output` | Report path |
| `--fail-on` | Fail if active findings ≥ severity |
| `--policy-file` | Path to policy YAML |
| `--no-policy-file` | Ignore auto-discovered policy |
| `--baseline` | Baseline JSON |
| `--write-baseline` | Write baseline after audit |
| `-c, --config` / `--jwks` | Offline discovery + JWKS |
| `--timeout` | HTTP timeout (seconds) |
| `--no-color` | Disable ANSI |

**Exit codes:** `0` clean · `1` findings / regressions · `2` tool error

---

## IdP presets

| Preset | Behaviour |
|--------|-----------|
| `generic` | No post-adjustment |
| `spa` | Escalate PKCE / implicit-hybrid |
| `mobile` | Escalate PKCE / flows |
| `enterprise` | Reduce legacy-flow noise; escalate token auth, revocation, issuer, algorithms |

---

## CI / GitHub Action

Composite action: `action.yml`. Example workflow: `.github/workflows/authguard-example.yml`.

```yaml
- uses: Flatpack-sonc/AuthGuard@main
  with:
    issuer: https://login.example.com
    idp: enterprise
    fail-on: high
    policy-file: .authguard.yml
    baseline: .authguard-baseline.json
    sarif-file: authguard.sarif
    json-file: authguard.json
```

Upload SARIF with `github/codeql-action/upload-sarif`. Keep JSON artifacts for drift.

---

## Finding catalogue

| Prefix | Area |
|--------|------|
| `AG-DISC-*` / `AG-TLS-*` | Discovery, TLS, HTTPS |
| `AG-PKCE-*` | PKCE |
| `AG-FLOW-*` / `AG-GRANT-*` | Implicit / hybrid / password grants |
| `AG-TEA-*` | Token endpoint authentication |
| `AG-ISS-*` | Issuer consistency / RFC 9207 |
| `AG-ALG-*` / `AG-JWKS-*` | Algorithms / JWKS hygiene |
| `AG-REV-*` / `AG-INT-*` / `AG-LOGOUT-*` | Revocation, introspection, logout |
| `AG-SCOPE-*` / `AG-CLAIM-*` / `AG-PAR-*` / `AG-EP-*` | Scopes, claims, PAR, required endpoints |
| `AG-MANUAL-*` | Manual verification checklist |

---

## Layout

```text
AuthGuard.sln
action.yml
.authguard.yml
src/AuthGuard.Cli/
src/AuthGuard.Core/
src/AuthGuard.Reporting/
tests/AuthGuard.Tests/
.github/workflows/
```

---

## Limitations

- Analysis is limited to public discovery and JWKS metadata.
- Refresh-token rotation, redirect allowlists, and live token behaviour are not verified automatically.
- Large enterprise IdPs often advertise legacy grants — use `--idp enterprise` with suppressions or a baseline.

---

## License

For defensive assessment of systems you own or are explicitly authorized to review.
