# InterfaceDelta Compatibility Check

This JavaScript Action runs the local InterfaceDelta passive scanner against a public HTTPS target, compares the canonical Passport with a committed baseline, and applies `ci-policy-v1`. It does not call InterfaceDelta production, need `GITHUB_TOKEN`, need secrets, write repository content, comment on pull requests, or update baselines.

The initial release is `v0.1.0`. After publication, prefer the full immutable release commit SHA; the convenient beta pin is the exact `@v0.1.0` tag. Do not consume `@main`.

```yaml
name: InterfaceDelta
on: pull_request

permissions:
  contents: read

jobs:
  compatibility:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
      - uses: arto-a/interfacedelta-action@140bc50b38e3005664a885f5c2e1e856fbe87bb9 # v0.1.0
        with:
          url: https://service.example
          baseline: .interfacedelta/passport.json
          fail-on: breaking
```

Inputs are `url` (required), `mcp-endpoint`, `baseline` (default `.interfacedelta/passport.json`), and `fail-on` (default `breaking`). Outputs are comparison state, highest classification, four classification counts, current fingerprint, and policy result.

The Action uses the bundled Node 24 runtime artifact and invokes the same packaged local inspection/check library directly. It downloads no package at runtime and interpolates no remote input into a shell. Logs, annotations, and the bounded 20-finding step summary sanitize untrusted remote metadata.

Breaking changes fail by default. Indeterminate findings warn/pass unless strict policy is selected. Execution/configuration failures are not reported as breaking changes. A passing result does not establish safety, security, trust, compliance, full behavioral compatibility, or certification.

Use ordinary `pull_request`, not `pull_request_target`. No secrets or write permissions are needed.

The repository's manual consumer-smoke workflow uses the committed `example.com` baseline and the local bundled Action with `contents: read` only. It neither receives a token nor writes repository content.
