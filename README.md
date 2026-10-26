# InterfaceDelta Compatibility Check

This JavaScript Action fails a pull request when an agent service your repository depends on makes a configured interface change. It runs the local InterfaceDelta passive scanner against each public HTTPS service, compares the canonical Passport with the baseline committed in your repository, and applies `ci-policy-v2`. It does not call the hosted InterfaceDelta service, need `GITHUB_TOKEN`, write repository content, comment on pull requests, or update baselines. It needs a secret only for a service you sign in to (see below).

Create the dependencies file and baselines with the CLI (`npx interfacedelta baseline`, see the `interfacedelta` package), commit them, then add:

```yaml
name: InterfaceDelta
on: pull_request

permissions:
  contents: read

jobs:
  compatibility:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: arto-a/interfacedelta-action@<release-commit-sha> # v0.2.0
        with:
          fail-on: breaking,metadata
          on-error: warn
```

Pin the full release commit SHA shown on the `v0.2.0` release; the exact `@v0.2.0` tag is the convenient alternative. Do not consume `@main`.

## Services that need sign-in

Bind each token to a server origin in the workflow, and set the variable from a repository secret:

```yaml
- uses: arto-a/interfacedelta-action@<release-commit-sha> # v0.2.0
  env:
    INTERFACEDELTA_TOKEN_GITHUB: ${{ secrets.INTERFACEDELTA_GITHUB_MCP_TOKEN }}
  with:
    tokens: |
      https://api.githubcopilot.com=INTERFACEDELTA_TOKEN_GITHUB
```

Bindings come only from the workflow, never from the checked-out files, and variables must start with `INTERFACEDELTA_TOKEN_`, so a pull request cannot redirect a secret or read runner credentials. The Action masks every bound token in the runner log before checking, sends it only to explicit MCP endpoints on its origin (never on a redirect), and keeps it out of annotations, the summary, outputs, and the JSON and SARIF files. Use a read-only token.

A binding line may name an exact MCP endpoint URL instead of an origin. A binding that matches no dependency's `mcpEndpoint` fails the run, so a typo never produces a quiet public check. A missing or refused token, or any answer other than a working MCP session, fails the run, even with `on-error: warn`. Pull requests from forks and from Dependabot receive no Actions secrets: their signed-in targets are skipped with a warning and counted in `dependencies-skipped`. They are not checked and never fail the run, so a run in which every target was skipped reports `passed` with `dependencies-skipped` above zero.

Never run this Action from `pull_request_target`, or from any workflow that has secrets and checks out untrusted pull request code: the checked-out dependencies file chooses the endpoints, so it could point a bound origin's token at any path on that origin.

## Inputs

- `dependencies`: dependencies file (default `.interfacedelta/dependencies.json`). Used when `url` is empty.
- `url`, `mcp-endpoint`, `baseline`: check one service instead (`baseline` defaults to `.interfacedelta/passport.json`).
- `tokens`: bearer token bindings, one `<https-origin>=INTERFACEDELTA_TOKEN_<NAME>` per line (see above).
- `fail-on`: comma-separated `breaking` (default), `non_breaking`, `indeterminate`, `informational`, `metadata`. `metadata` fails on changed tool names, titles, descriptions and other non-contract metadata.
- `on-error`: `fail` (default) or `warn`. With `warn`, a service that cannot be reached is annotated as a warning and does not fail the run; a missing or malformed baseline, or a missing or refused token, always fails.
- `json-output`: path for the `interfacedelta-check-set-v1` JSON result.
- `sarif-output`: path for a SARIF 2.1.0 file. To show findings in code scanning, add `github/codeql-action/upload-sarif` after this step; that step needs `security-events: write`.

## Outputs

`comparison-state` (`changed`, `unchanged` or `error`), `highest-classification`, four classification counts summed across dependencies, `current-fingerprint` (single `url` only), `policy-result` (`passed`, `failed` or `error`), `error-kind` (the most serious of `configuration`, `credentials`, `internal` and `inspection`, or `none`), and `dependencies-checked`, `dependencies-failed`, `dependencies-errored`, `dependencies-skipped`, and the decision counts `blocked-count`, `warned-count`, `accepted-count` with `owners`: the owners of blocked changes, comma-separated, ready for a review request. Pass it to a later step through `env:` rather than inline `${{ }}` in a `run:` script; owner labels are restricted to handle characters, but `env:` keeps any output out of shell syntax.

Decision rules, owners and acceptances live in the dependencies file (see the CLI README). Blocked changes are annotated as errors and warned ones as warnings, each with its owner, rule and next step; the summary lists blocked and warned counts and owners per dependency.

## Behavior

The Action uses the bundled Node 24 runtime artifact, built from this repository's source against the published `interfacedelta` package. It downloads no package at runtime and interpolates no remote input into a shell. Logs, annotations (at most 20), and the step summary sanitize untrusted remote metadata; each finding carries the same deterministic explanation as the CLI where the evidence supports one, and remote text in the summary is Markdown-escaped so it cannot inject links, emphasis, math or table cells.

Breaking changes fail by default. Indeterminate findings warn and pass unless selected. Execution and configuration failures are reported as errors, never as breaking changes. A baseline committed by an earlier version is refused; regenerate it with `interfacedelta baseline` and commit the new file. A passing result does not establish safety, security, trust, compliance, full behavioral compatibility, or certification.

Use ordinary `pull_request`, never `pull_request_target`: it would expose your secrets to code from forks. No write permissions are needed.
