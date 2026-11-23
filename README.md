# InterfaceDelta Compatibility Check

This JavaScript Action fails a pull request when an agent service your repository depends on makes a configured interface change. It runs the local InterfaceDelta passive scanner against each public HTTPS service, compares the canonical Passport with the baseline committed in your repository, and applies `ci-policy-v2`. The default `check` mode does not call the hosted InterfaceDelta service, need `GITHUB_TOKEN`, write repository content, comment on pull requests, or update baselines. It needs a secret only for a service you sign in to (see below).

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
      - uses: arto-a/interfacedelta-action@<release-commit-sha> # v0.8.0
        with:
          fail-on: breaking,metadata
          on-error: warn
```

Pin the full release commit SHA shown on the `v0.8.0` release; the exact `@v0.8.0` tag is the convenient alternative. Do not consume `@main`.

## Agent definitions and skills

`agent-check`, `skills` and `citations` are separate opt-in inputs, each `false`
by default. Enable any combination; each enabled mode runs even when another
mode reports a failure. Set `check: false` to skip the default compatibility
check. Their `*-fail-on` thresholds are independent and default to report only.

| Input         | What it checks                                                                 | SARIF category               | Upload                 |
| ------------- | ------------------------------------------------------------------------------ | ---------------------------- | ---------------------- |
| `agent-check` | MCP client definitions and recorded tools                                      | `interfacedelta-agent-check` | Automatic              |
| `skills`      | Exact tool/input mentions in instructions against baselines and signed records | `interfacedelta-skills`      | Automatic              |
| `citations`   | Source pins created with the CLI's `cite` command                              | `interfacedelta-citations`   | Separate workflow step |

Each report has its own SARIF automation ID, so code scanning keeps the results
separate. Agent-check and skills uploads need `github-token` and
`security-events: write`. Citations writes a local artifact without an upload
token; its upload step needs the same code-scanning permission.

### Check an agent configuration

Opt in with `agent-check: true` to read the repository's MCP client configs,
look up their recorded tools, and report the signed Record Check facts. This
mode calls only InterfaceDelta's record tools; it never contacts the configured
MCP servers. It also writes `.interfacedelta/agent-check.sarif` and uploads it
to GitHub code scanning using `github-token` (default `${{ github.token }}`).
The workflow needs code scanning enabled and `security-events: write`.

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  agent-tools:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: arto-a/interfacedelta-action@<release-commit-sha>
        with:
          check: false
          agent-check: true
          agent-check-fail-on: breaking,payment
```

No conditions fail by default. Keyless runs check the first five recorded tools;
set `INTERFACEDELTA_AGENT_KEY` in the step environment for REST batches of 50.
Config credentials never go into reports or requests. Signed responses echoing
one are refused. The SARIF upload still runs when a fail condition matches.
An upload failure fails the Action and retains the local SARIF file; GitHub's
accepted upload is processed asynchronously. No separate upload step is needed
for agent-check. Existing `check` SARIF files still use the explicit upload
step described below. Agent-check is off unless set.

### Find stale agent instructions

Opt in with `skills: 'true'`. This runs the CLI's stored-record skills check and
submits its SARIF to GitHub code scanning. It requires MCP baselines, the normal
GitHub token and `security-events: write`; code scanning must be available for the
repository. Upload errors fail the job. Skills mode is off by default.

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: arto-a/interfacedelta-action@<release-commit-sha> # v0.8.0
    with:
      check: 'false'
      skills: 'true'
      skills-fail-on: breaking_change,tool_removed,input_not_recorded
    env:
      INTERFACEDELTA_AGENT_KEY: ${{ secrets.INTERFACEDELTA_AGENT_KEY }}
```

Use the same Action reference as your existing workflow. Omit the agent key for a
keyless check of at most five tools sharing one start time. `skills-dir` defaults
to `GITHUB_WORKSPACE`; `skills-include` accepts additional globs, one per line.
`skills-mcp-config` reads URLs only and requires matching baseline inventories.
`skills-since` overrides the baseline times. `skills-fail-on` accepts the CLI's
six reason names and defaults to report only. These settings do not change the
compatibility check's `fail-on`. Set `check: 'false'` for skills only.

Outputs are `skills-mentions-count` and `skills-sarif-path`. The SARIF is also
written to `.interfacedelta/skills.sarif`. Instruction text is never included in
reports or annotations. See the CLI's “Agent definitions and skills” section
for exact matching limits and the distinction between mentions and proof of a
stale instruction.

### Check citations in instructions

Create pins with `interfacedelta cite` and commit the retained answers and public
keys with the instruction file. Opt in with `citations: true` to verify those
answers offline and compare tool fingerprints with the current stored record.
No baselines are needed. File sources check offline; URL and Git sources report
`not_checked`. The Action does not enable URL fetching.

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: arto-a/interfacedelta-action@<release-commit-sha>
    id: definitions
    with:
      check: false
      agent-check: true
      skills: true
      citations: true
      citations-fail-on: changed,removed,malformed,signature_invalid
  - uses: github/codeql-action/upload-sarif@v3
    if: ${{ always() && steps.definitions.outputs.citations-sarif-path != '' }}
    with:
      sarif_file: ${{ steps.definitions.outputs.citations-sarif-path }}
      category: interfacedelta-citations
```

`citations-dir` defaults to `GITHUB_WORKSPACE`; `citations-include` accepts one
glob per line. `citations-keys` supplies trusted published keys relative to that
directory. `citations-fail-on` accepts `changed`, `removed`, `malformed`,
`signature_invalid`, `missing`, `unreachable` and `not_checked`. Outputs are
`citations-count` and `citations-sarif-path` (`.interfacedelta/citations.sarif`).
SARIF locations include the selected subdirectory relative to the checkout.
The artifact is written before threshold failure. See the CLI's
[format and trust model](../interfacedelta-cli/docs/skill-citations.md).

## Services that need sign-in

Bind each token to a server origin in the workflow, and set the variable from a repository secret:

```yaml
- uses: arto-a/interfacedelta-action@<release-commit-sha> # v0.8.0
  env:
    INTERFACEDELTA_TOKEN_GITHUB: ${{ secrets.INTERFACEDELTA_GITHUB_MCP_TOKEN }}
  with:
    tokens: |
      https://api.githubcopilot.com=INTERFACEDELTA_TOKEN_GITHUB
```

Bindings come only from the workflow, never from the checked-out files, and variables must start with `INTERFACEDELTA_TOKEN_`, so a pull request cannot redirect a secret or read runner credentials. The Action masks every bound token in the runner log before checking, sends it only to explicit MCP endpoints on its origin (never on a redirect), and keeps it out of annotations, the summary, outputs, and the JSON and SARIF files. Use a read-only token.

A binding line may name an exact MCP endpoint URL instead of an origin. A binding that matches no dependency's `mcpEndpoint` fails the run, so a typo never produces a quiet public check. A missing or refused token, or any answer other than a working MCP session, fails the run, even with `on-error: warn`. Pull requests from forks and from Dependabot receive no Actions secrets: their signed-in targets are skipped with a warning and counted in `dependencies-skipped`. They are not checked and never fail the run, so a run in which every target was skipped reports `passed` with `dependencies-skipped` above zero.

Never run this Action from `pull_request_target`, or from any workflow that has secrets and checks out untrusted pull request code: the checked-out dependencies file chooses the endpoints, so it could point a bound origin's token at any path on that origin.

## Connected repositories and issues (Pro and Team)

With `watch: true`, the Action hands the dependencies file to InterfaceDelta. InterfaceDelta then checks every dependency continuously and delivers each decision to its owner by Slack, signed webhook, email or a GitHub issue. Run it on the default branch whenever the file changes. Use `actions/checkout` with `fetch-depth: 0` so the Action can prove the commit is newer than the watched one. In a shallow checkout it asks GitHub through `github-token`. A run on an older commit is skipped.

```yaml
on:
  push:
    branches: [main]
    paths: [.interfacedelta/**]
jobs:
  watch:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: arto-a/interfacedelta-action@<release-commit-sha> # v0.8.0
        with:
          watch: true
          api-token: ${{ secrets.INTERFACEDELTA_WATCH_TOKEN }}
```

With `issues: true`, the Action opens one GitHub issue for each decision InterfaceDelta has for this repository and branch, then acknowledges it. InterfaceDelta holds no GitHub credential: issues are opened with the workflow's own `GITHUB_TOKEN`.

Each issue carries the label `interfacedelta` and the decision's marker, `interfacedelta-decision:<id>`. Every labelled issue, open or closed, is read first, so a decision gets one issue even if a run is interrupted. Keep the label on these issues. Owners from the dependencies file are mentioned, and text that comes from the services is escaped. A run handles up to 100 decisions, and the rest wait for the next run. Decisions not picked up within seven days expire, and the account owner is emailed. From 0.3.1, each issue links to the decision's page on InterfaceDelta.

Decisions are queued for issues only while a GitHub destination exists for the repository; a decision made before the destination was added stays email, Slack and webhook only. From 0.3.1, when the repository has no GitHub destination and nothing is waiting, the run shows a warning that says so and links to Routing.

Before the first run:

1. In InterfaceDelta, open Routing → Destinations and add a GitHub destination for the repository, as `owner/name`.
2. In [Routing → Watch tokens](https://interfacedelta.com/routing#delivery-tokens), create a watch token for that repository and branch with the `decisions:read` and `decisions:ack` scopes, and store it as a repository secret.

```yaml
on:
  schedule:
    - cron: '*/30 * * * *'
  workflow_dispatch:
concurrency: interfacedelta-decisions
jobs:
  issues:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: arto-a/interfacedelta-action@<release-commit-sha> # v0.8.0
        with:
          check: false
          issues: true
          api-token: ${{ secrets.INTERFACEDELTA_DECISIONS_TOKEN }}
```

Create each watch token in [Routing → Watch tokens](https://interfacedelta.com/routing#delivery-tokens) for the repository and branch. For connected repositories, grant `lockfiles:write` and save it as `INTERFACEDELTA_WATCH_TOKEN`; for issues, grant `decisions:read` and `decisions:ack` and save that separate watch token as `INTERFACEDELTA_DECISIONS_TOKEN`. Account’s REST API tokens do not grant these scopes. The Action masks both tokens and sends each only to its own service.

## Inputs

- `dependencies`: dependencies file (default `.interfacedelta/dependencies.json`). Used when `url` is empty.
- `url`, `mcp-endpoint`, `baseline`: check one service instead (`baseline` defaults to `.interfacedelta/passport.json`).
- `tokens`: bearer token bindings, one `<https-origin>=INTERFACEDELTA_TOKEN_<NAME>` per line (see above).
- `fail-on`: comma-separated `breaking` (default), `non_breaking`, `indeterminate`, `informational`, `metadata`. `metadata` fails on changed tool names, titles, descriptions and other non-contract metadata.
- `on-error`: `fail` (default) or `warn`. With `warn`, a service that cannot be reached is annotated as a warning and does not fail the run; a missing or malformed baseline, or a missing or refused token, always fails.
- `find-uses`: `true` (default) or `false`. After decisions, search the checked-out repository (`GITHUB_WORKSPACE`) for likely uses of the names each blocked or warned change touched: tool, prompt and resource names, and the last segment of a changed field path, matched case-sensitively as whole identifiers (`create_pull_request` matches a call site, `create_pull_request_v2` does not). The results are hints only: a "Likely uses" summary section, `notice` annotations with file and line (at most 50), and the `likely-uses-count` output. The scan never follows symlinks or leaves the workspace, skips dependency, build and tool directories, binary and large files, and stops at 20,000 files or 64 MiB read. It reports file and line only, never line text, and never changes the check result, exit code or SARIF.
- `json-output`: path for the `interfacedelta-check-set-v1` JSON result.
- `sarif-output`: path for a SARIF 2.1.0 file. To show findings in code scanning, add `github/codeql-action/upload-sarif` after this step; that step needs `security-events: write`.
- `check`: run the compatibility check (default `true`). Set `false` for a job that only watches or opens issues.
- `agent-check`: also run `interfacedelta agent-check` on the MCP client configs in the checked-out repository (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.vscode/settings.json`), writing `.interfacedelta/agent-check.sarif` and uploading it to code scanning with `github-token` and `security-events: write` (default `false`). It reads the stored InterfaceDelta record only and never calls the configured servers; per tool it reports the recorded facts (changed, breaking since start, stale, not observed, asks for payment, moves money, deletes, sends messages), never a verdict. Keyless runs check the first five tools; set `INTERFACEDELTA_AGENT_KEY` in the step env for REST batches of 50 (get a free key: `POST https://interfacedelta.com/api/v1/agent-keys`).
- `agent-check-fail-on`: comma-separated conditions that fail the agent-check run: `breaking`, `changed`, `stale`, `payment`, `money`, `not_observed`. Unset by default: agent-check reports without failing the job.
- `skills`, `skills-dir`, `skills-include`, `skills-mcp-config`, `skills-since`, `skills-fail-on`: see “Agent definitions and skills” above.
- `citations`, `citations-dir`, `citations-include`, `citations-keys`, `citations-fail-on`: see “Agent definitions and skills” above.
- `watch`, `issues`: see above (both default `false`). They run after the check, whatever its result; the job then fails once, with every reason.
- `api-token`: the InterfaceDelta watch token for `watch` and `issues`, from a secret.
- `github-token`: for agent-check and skills SARIF uploads, `issues`, and proving commit order in a shallow checkout (default `github.token`).
- `api-url`: InterfaceDelta origin (default `https://interfacedelta.com`).
- `ref`: the branch to watch or pull decisions for, when it is not the branch the workflow runs on.

## Outputs

`comparison-state` (`changed`, `unchanged` or `error`), `highest-classification`, four classification counts summed across dependencies, `current-fingerprint` (single `url` only), `policy-result` (`passed`, `failed` or `error`), `error-kind` (the most serious of `configuration`, `credentials`, `internal` and `inspection`, or `none`), and `dependencies-checked`, `dependencies-failed`, `dependencies-errored`, `dependencies-skipped`, and the decision counts `blocked-count`, `warned-count`, `accepted-count` with `owners`: the owners of blocked changes, comma-separated, ready for a review request. With `find-uses` (the default), `likely-uses-count` is the number of likely-use locations found in the checked-out repository. With `watch`, `watch-status` is `synced` or `skipped`. With `issues`, `issues-opened` and `decisions-acknowledged` are set. Pass it to a later step through `env:` rather than inline `${{ }}` in a `run:` script; owner labels are restricted to handle characters, but `env:` keeps any output out of shell syntax.

Decision rules, owners and acceptances live in the dependencies file (see the CLI README). Blocked changes are annotated as errors and warned ones as warnings, each with its owner, rule and next step; the summary lists blocked and warned counts and owners per dependency. With `agent-check`, the outputs `agent-check-result` (`passed` or `failed`) and `agent-check-sarif-path` are set and a summary section lists each configured server and its record status.

## Behavior

The Action uses the bundled Node 24 runtime artifact, built from this repository's source against the published `interfacedelta` package. It downloads no package at runtime and interpolates no remote input into a shell. Logs, annotations (at most 20), and the step summary sanitize untrusted remote metadata; each finding carries the same deterministic explanation as the CLI where the evidence supports one, and remote text in the summary is Markdown-escaped so it cannot inject links, emphasis, math or table cells.

Breaking changes fail by default. Indeterminate findings warn and pass unless selected. Execution and configuration failures are reported as errors, never as breaking changes. A baseline committed by an earlier version is refused; regenerate it with `interfacedelta baseline` and commit the new file. A passing result does not establish safety, security, trust, compliance, full behavioral compatibility, or certification.

Use ordinary `pull_request`, never `pull_request_target`: it would expose your secrets to code from forks. Checking needs no write permissions; only `issues: true` needs `issues: write`.

## Export a policy artifact

Set `policy-export` to `github` or `generic` (unset by default). The Action writes
`.interfacedelta/policy-<format>.json` from the check it already ran and sets
`policy-export-path`. It requires `check: true` (the default). It also writes
review entries when checks fail, without changing the job's failure result.

```yaml
- uses: actions/checkout@v4
- uses: arto-a/interfacedelta-action@<release-commit-sha> # v0.8.0
  id: compatibility
  with:
    policy-export: github
- uses: actions/upload-artifact@v4
  if: ${{ always() && steps.compatibility.outputs.policy-export-path != '' }}
  with:
    name: dependency-policy
    path: ${{ steps.compatibility.outputs.policy-export-path }}
```

The GitHub file wraps `managedSettings` and an `excluded` review list. Only the
`managedSettings` object is GitHub configuration; copy it into
`copilot/managed-settings.json` after review. It permits passing explicit MCP
endpoints only, with no wildcard matchers. Generic output lists all dependencies
with `allow` or `review` decisions and reasons. An allowed entry means its
configured compatibility check passed. The Action does not install the policy.
