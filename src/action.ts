import { runSkillsMode } from './skills';
import { runCitationsMode } from './citations';
import { relative, resolve } from 'node:path';
import {
  baselinePathFor,
  changeExplanation,
  checkBaseline,
  checkDependencies,
  CI_POLICY_VERSION,
  assertBindingsUsed,
  credentialFor,
  downgradable,
  parseTokenBindings,
  redact,
  DEFAULT_DEPENDENCIES_PATH,
  errorKind,
  errorMessage,
  loadDependencies,
  machineJson,
  parseFailOn,
  parseOnError,
  readJsonFile,
  sanitizeGithub,
  summarizeOutcomes,
  scanLikelyUses,
  DEFAULT_API_URL,
  defaultGit,
  formatWatch,
  runWatch,
  type WatchEnvironment,
  toSarif,
  toGenericAllowlist,
  toGitHubAllowlist,
  writeAtomic,
  type CheckResult,
  type CheckSetResult,
  type Decision,
  type DependencyOutcome,
  type Inspector,
  type LikelyUsesReport,
  type SarifEntry,
  type TokenBinding,
  runAgentCheck,
  agentCheckSarif,
  registerSecret,
  type AgentCheckOutcome,
} from 'interfacedelta';
import { markdown, openDecisionIssues } from './issues';
import { uploadAgentCheckSarif } from './agent-check-upload';

type Change = CheckResult['comparison']['changes'][number];
const detailSuffix = (item: Change, result?: CheckResult) => {
  const detail = changeExplanation(item, result);
  return detail ? ` — ${detail}` : '';
};
const subjectOf = (item: Change, result?: CheckResult) => {
  const subject = result?.subjects[item.entityId];
  return subject
    ? `${subject.kind} ${subject.name}`
    : `${item.entityKind}: ${item.entityId}`;
};
/** Plain-text annotation for one finding; everything remote passes sanitizeGithub. */
export const annotationMessage = (
  item: Change,
  dependency?: string,
  result?: CheckResult,
  decision?: Decision,
) =>
  sanitizeGithub(
    `${dependency ? `${dependency}: ` : ''}${item.classification}: ${item.code} (${subjectOf(item, result)})${detailSuffix(item, result)}${decision?.owner ? `. Owner: ${decision.owner}` : ''}${decision?.rule ? ` (rule ${decision.rule})` : ''}${decision ? `. Next: ${decision.card.step}` : ''}`,
  );

export type ActionIo = {
  getInput(name: string): string;
  setOutput(name: string, value: string | number): void;
  warning(message: string): void;
  error(message: string): void;
  /** A neutral annotation; `file` and `startLine` anchor it in the diff. */
  notice(
    message: string,
    properties?: { file?: string; startLine?: number },
  ): void;
  setFailed(message: string): void;
  writeSummary(markdown: string): Promise<void>;
  /** Masks a value in every later log line (core.setSecret). */
  setSecret(value: string): void;
};

const DISPLAY_LIMIT = 20;
/** Notice annotations for likely uses: GitHub shows only the first ~50. */
export const LIKELY_USES_ANNOTATION_LIMIT = 50;
const ACTION_RANK = { block: 0, warn: 1, allow: 2 } as const;
/** Blocked, warned and accepted changes, most serious first. */
const notableDecisions = (result: CheckResult) =>
  result.comparison.changes
    .map((change, index) => ({ change, decision: result.decisions[index]! }))
    .filter(
      ({ decision }) =>
        decision.action !== 'allow' || decision.source === 'acceptance',
    )
    .sort(
      (a, b) => ACTION_RANK[a.decision.action] - ACTION_RANK[b.decision.action],
    );
const findingLine = (
  result: CheckResult,
  item: Change,
  decision: Decision,
  dependency?: string,
) => {
  const detail = changeExplanation(item, result);
  const label =
    decision.source === 'acceptance'
      ? `ACCEPTED until ${decision.accepted!.expires}`
      : decision.action.toUpperCase();
  const who = [
    decision.owner && `owner ${markdown(decision.owner, 100)}`,
    decision.rule && `rule ${markdown(decision.rule, 64)}`,
  ].filter(Boolean);
  return `- ${dependency ? `${markdown(dependency, 64)} — ` : ''}**${label}** ${markdown(item.classification, 40)} — ${markdown(item.code, 100)} (${markdown(subjectOf(item, result), 260)})${detail ? ` — ${markdown(detail, 240)}` : ''}${who.length ? ` — ${who.join(', ')}` : ''}${decision.source === 'acceptance' ? '' : `. Next: ${markdown(decision.card.step, 200)}`}`;
};
const DISCLAIMER =
  '_This is a deterministic compatibility result, not a security, safety, trust, or certification assessment._';
const LIKELY_USES_HINT =
  '_Where the checked-out repository may use a changed name. Hints, not proof of use._';

/**
 * The "Likely uses" summary section: one block per blocked or warned change
 * with locations, and a note when the scan stopped early. Paths and terms
 * only; never line text.
 */
function likelyUsesSummary(results: readonly CheckResult[]): string[] {
  const reports = results.filter((result) => result.likelyUses);
  if (!reports.length) return [];
  const lines: string[] = [];
  let truncated = false;
  for (const result of reports) {
    const report = result.likelyUses as LikelyUsesReport;
    truncated = truncated || report.truncated;
    for (const { change: id, uses } of report.changes) {
      if (!uses.length) continue;
      const index = result.comparison.changes.findIndex(
        (item) => item.semanticId === id,
      );
      const change = result.comparison.changes[index];
      const decision = result.decisions[index];
      lines.push(
        `- **${markdown(decision ? decision.action.toUpperCase() : 'CHANGED', 10)} ${markdown(change?.code ?? id, 100)}** (${markdown(change ? subjectOf(change, result) : id, 260)})`,
      );
      for (const use of uses)
        lines.push(
          `  - \`${markdown(use.path, 300)}:${use.line}\` — \`${markdown(use.term, 200)}\``,
        );
    }
  }
  return [
    '',
    '### Likely uses',
    '',
    LIKELY_USES_HINT,
    ...(lines.length ? lines : ['- None found in the checked-out repository.']),
    ...(truncated
      ? ['', '_The scan stopped early at its size cap; more uses may exist._']
      : []),
  ];
}

export function actionSummary(result: CheckResult): string {
  const notable = notableDecisions(result);
  const lines = notable
    .slice(0, DISPLAY_LIMIT)
    .map(({ change, decision }) => findingLine(result, change, decision));
  if (notable.length > DISPLAY_LIMIT)
    lines.push(
      `- ${notable.length - DISPLAY_LIMIT} additional findings omitted from display.`,
    );
  return [
    '## InterfaceDelta compatibility check',
    '',
    `**Target:** ${markdown(result.inspectionUrl, 300)}`,
    '',
    `**Baseline:** \`sha256:${result.previousFingerprint}\``,
    '',
    `**Current:** \`sha256:${result.currentFingerprint}\``,
    '',
    `**Comparison:** ${markdown(result.comparison.state, 60)}`,
    '',
    `| Classification | Count |`,
    `| --- | ---: |`,
    `| Breaking | ${result.comparison.counts.breaking} |`,
    `| Non-breaking | ${result.comparison.counts.nonBreaking} |`,
    `| Needs review | ${result.comparison.counts.indeterminate} |`,
    `| Informational | ${result.comparison.counts.informational} |`,
    '',
    `**Result:** ${result.policy.result === 'failed' ? 'FAILED — configured compatibility classification detected' : 'PASSED — configured compatibility gate not violated'}`,
    ...(lines.length ? ['', '### Findings', '', ...lines] : []),
    ...likelyUsesSummary([result]),
    '',
    DISCLAIMER,
  ].join('\n');
}

const RESULT_TEXT = {
  passed: 'PASSED — configured compatibility gate not violated',
  failed: 'FAILED — configured compatibility classification detected',
  error: 'ERROR — at least one dependency could not be checked',
} as const;

export function actionSetSummary(set: CheckSetResult): string {
  const rows = set.dependencies.map((item) => {
    if (item.status === 'error')
      return `| ${markdown(item.name, 64)} | error (${item.error.kind}) | – | – | ${markdown(item.owner ?? '', 100)} | ${markdown(item.error.message, 200)} |`;
    const { decisions } = item.result;
    const count = (action: string) =>
      decisions.filter(
        (decision) =>
          decision.action === action && decision.source !== 'acceptance',
      ).length;
    return `| ${markdown(item.name, 64)} | ${item.result.policy.result} | ${count('block')} | ${count('warn')} | ${markdown(ownersOf([item.result]) || (item.owner ?? ''), 200)} | ${markdown(item.result.comparison.state, 40)} |`;
  });
  const findings = set.dependencies.flatMap((item) =>
    item.status === 'checked'
      ? notableDecisions(item.result).map(({ change, decision }) =>
          findingLine(item.result, change, decision, item.name),
        )
      : [],
  );
  const shown = findings.slice(0, DISPLAY_LIMIT);
  if (findings.length > shown.length)
    shown.push(
      `- ${findings.length - shown.length} additional findings omitted from display.`,
    );
  return [
    '## InterfaceDelta compatibility check',
    '',
    `**Policy:** ${set.policy.version} (${markdown(set.policy.failOn.join(', '))}); on-error: ${set.policy.onError}`,
    '',
    '| Dependency | Result | Blocked | Warned | Owner | Comparison |',
    '| --- | --- | ---: | ---: | --- | --- |',
    ...rows,
    '',
    `**Result:** ${RESULT_TEXT[set.result]}`,
    ...(set.counts.skipped
      ? [
          '',
          `**Skipped:** ${set.counts.skipped} signed-in dependencies (a pull request from a fork has no secrets); they were not checked.`,
        ]
      : []),
    ...(shown.length ? ['', '### Findings', '', ...shown] : []),
    ...likelyUsesSummary(
      set.dependencies.flatMap((item) =>
        item.status === 'checked' ? [item.result] : [],
      ),
    ),
    '',
    DISCLAIMER,
  ].join('\n');
}

const RANK = {
  none: 0,
  informational: 1,
  non_breaking: 2,
  indeterminate: 3,
  breaking: 4,
} as const;

/** Owners of blocked changes, in first-seen order, for review requests. */
const ownersOf = (results: readonly CheckResult[]) =>
  [
    ...new Set(
      results.flatMap((result) =>
        result.decisions.flatMap((decision) =>
          decision.action === 'block' && decision.owner ? [decision.owner] : [],
        ),
      ),
    ),
  ].join(', ');

function outputsFor(set: CheckSetResult, single?: CheckResult) {
  const checked = set.dependencies.flatMap((item) =>
    item.status === 'checked' ? [item.result] : [],
  );
  const highest = checked.reduce<keyof typeof RANK>(
    (top, result) =>
      RANK[result.comparison.highestClassification] > RANK[top]
        ? result.comparison.highestClassification
        : top,
    'none',
  );
  const kinds = set.dependencies.flatMap((item) =>
    item.status === 'error' ? [item.error.kind] : [],
  );
  return {
    'comparison-state': !checked.length
      ? 'error'
      : checked.some((result) => result.comparison.state === 'changed')
        ? 'changed'
        : 'unchanged',
    'highest-classification': highest,
    'breaking-count': set.counts.breaking,
    'non-breaking-count': set.counts.nonBreaking,
    'indeterminate-count': set.counts.indeterminate,
    'informational-count': set.counts.informational,
    'current-fingerprint': single?.currentFingerprint ?? '',
    'policy-result': set.result,
    'error-kind':
      (
        ['configuration', 'credentials', 'internal', 'inspection'] as const
      ).find((kind) => kinds.includes(kind)) ?? 'none',
    'dependencies-checked': checked.length,
    'dependencies-failed': set.counts.failed,
    'dependencies-errored': set.counts.errored,
    'dependencies-skipped': set.counts.skipped,
    'blocked-count': set.counts.blocked,
    'warned-count': set.counts.warned,
    'accepted-count': set.counts.accepted,
    owners: ownersOf(checked),
  };
}

const repositoryUri = (path: string) =>
  relative(process.cwd(), resolve(path)).split('\\').join('/');

/** Every message, output and summary passes redact(): no credential value leaves. */
const redacting = (io: ActionIo): ActionIo => ({
  getInput: (name) => io.getInput(name),
  setOutput: (name, value) =>
    io.setOutput(name, typeof value === 'string' ? redact(value) : value),
  warning: (message) => io.warning(redact(message)),
  error: (message) => io.error(redact(message)),
  notice: (message, properties) => io.notice(redact(message), properties),
  setFailed: (message) => io.setFailed(redact(message)),
  writeSummary: (markdown) => io.writeSummary(redact(markdown)),
  setSecret: (value) => io.setSecret(value),
});

/** Masks bound credentials in runner logs before anything can print them. */
function maskCredentials(io: ActionIo, bindings: readonly TokenBinding[]) {
  for (const { variable } of bindings) {
    const value = process.env[variable];
    if (value) io.setSecret(value);
  }
}

export type ActionDependencies = {
  inspector?: Inspector;
  readBaseline?: (path: string) => Promise<unknown>;
  /** watch and issues: network, Git and environment, for tests. */
  fetch?: typeof fetch;
  git?: WatchEnvironment['git'];
  env?: Record<string, string | undefined>;
};

/** The compatibility check; returns why the run fails, if it does. */
async function runCheck(
  io: ActionIo,
  dependencies: ActionDependencies,
  findUses: boolean,
): Promise<string | undefined> {
  try {
    const policyFormat = io.getInput('policy-export').trim();
    if (policyFormat && policyFormat !== 'github' && policyFormat !== 'generic')
      throw new Error('Input "policy-export" must be github or generic.');
    const url = io.getInput('url').trim();
    const dependenciesPath = io.getInput('dependencies').trim();
    if (url && dependenciesPath)
      throw new Error('Set either "url" or "dependencies", not both.');
    // Token bindings come from the workflow, never from the checked-out files.
    const tokens = parseTokenBindings(
      io
        .getInput('tokens')
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean),
    );
    maskCredentials(io, tokens);
    const failOnInput = io.getInput('fail-on').trim() || undefined;
    const onErrorInput = io.getInput('on-error').trim() || undefined;
    let set: CheckSetResult,
      single: CheckResult | undefined,
      sarif: SarifEntry[];
    if (url) {
      const failOn = parseFailOn(failOnInput);
      const onError = parseOnError(onErrorInput);
      const mcpEndpoint = io.getInput('mcp-endpoint').trim() || undefined;
      assertBindingsUsed(tokens, [mcpEndpoint]);
      const baselinePath =
        io.getInput('baseline').trim() || '.interfacedelta/passport.json';
      const entry = {
        name: 'target',
        url,
        mcpEndpoint: mcpEndpoint ?? null,
        baseline: baselinePath,
      };
      let outcome: DependencyOutcome;
      try {
        const bearerToken = credentialFor(tokens, mcpEndpoint);
        const baseline = await (dependencies.readBaseline ?? readJsonFile)(
          baselinePath,
        );
        single = await checkBaseline(url, baseline, {
          mcpEndpoint,
          failOn: failOn.join(','),
          inspector: dependencies.inspector,
          bearerToken,
        });
        outcome = { ...entry, status: 'checked', result: single };
      } catch (error) {
        outcome = {
          ...entry,
          status: 'error',
          error: { kind: errorKind(error), message: errorMessage(error) },
        };
      }
      set = summarizeOutcomes([outcome], failOn, onError);
      sarif = [
        {
          baselineUri: repositoryUri(baselinePath),
          ...(single ? { result: single } : {}),
          ...(outcome.status === 'error'
            ? { error: outcome.error.message }
            : {}),
        },
      ];
    } else {
      const file = await loadDependencies(
        dependenciesPath || DEFAULT_DEPENDENCIES_PATH,
      );
      set = await checkDependencies(file, {
        failOn: failOnInput,
        onError: onErrorInput,
        inspector: dependencies.inspector,
        tokens,
      });
      sarif = set.dependencies.map((item) => ({
        name: item.name,
        baselineUri: repositoryUri(baselinePathFor(file, item)),
        ...(item.status === 'checked'
          ? { result: item.result }
          : { error: item.error.message }),
      }));
    }
    // Hints after the decisions: where the checked-out code may use a changed
    // name. Informational only, and a scan problem never fails the check.
    let likelyUsesCount: number | undefined;
    if (findUses) {
      const workspace = (
        dependencies.env ?? process.env
      ).GITHUB_WORKSPACE?.trim();
      if (workspace) {
        const checked = set.dependencies.flatMap((item) =>
          item.status === 'checked' ? [item.result] : [],
        );
        try {
          const reports = await scanLikelyUses(workspace, checked);
          likelyUsesCount = 0;
          checked.forEach((result, index) => {
            const report = reports[index];
            if (!report) return;
            result.likelyUses = report;
            likelyUsesCount! += report.changes.reduce(
              (total, change) => total + change.uses.length,
              0,
            );
          });
        } catch (error) {
          likelyUsesCount = 0;
          io.warning(
            sanitizeGithub(
              `Likely-uses scan skipped: ${error instanceof Error ? error.message : 'unknown failure'}`,
            ),
          );
        }
      }
    }
    const outputs: Record<string, string | number> = {
      ...outputsFor(set, single),
      ...(likelyUsesCount !== undefined
        ? { 'likely-uses-count': likelyUsesCount }
        : {}),
    };
    for (const [name, value] of Object.entries(outputs))
      io.setOutput(name, value);
    let annotations = 0;
    for (const item of set.dependencies) {
      const label = url ? undefined : item.name;
      if (item.status === 'error') {
        const message = sanitizeGithub(
          `${label ? `${label}: ` : ''}${item.error.message}`,
        );
        if (
          item.error.kind === 'skipped' ||
          (downgradable(item.error.kind) && set.policy.onError === 'warn')
        )
          io.warning(message);
        else io.error(message);
        continue;
      }
      for (const { change, decision } of notableDecisions(item.result)) {
        if (decision.action === 'allow') continue;
        if (annotations++ >= DISPLAY_LIMIT) break;
        const message = annotationMessage(change, label, item.result, decision);
        if (decision.action === 'block') io.error(message);
        else io.warning(message);
      }
    }
    if (likelyUsesCount !== undefined) {
      let notices = 0;
      for (const item of set.dependencies) {
        if (item.status !== 'checked' || !item.result.likelyUses) continue;
        const label = url ? item.result.inspectionUrl : item.name;
        for (const { uses } of item.result.likelyUses.changes) {
          for (const use of uses) {
            if (notices >= LIKELY_USES_ANNOTATION_LIMIT) break;
            io.notice(
              sanitizeGithub(`Likely use of ${use.term} (changed in ${label})`),
              { file: use.path, startLine: use.line },
            );
            notices++;
          }
        }
      }
    }
    if (policyFormat) {
      const path = `.interfacedelta/policy-${policyFormat}.json`;
      const exportPolicy =
        policyFormat === 'github' ? toGitHubAllowlist : toGenericAllowlist;
      await writeAtomic(
        path,
        machineJson(
          exportPolicy(
            set.dependencies.map((outcome) => ({ ...outcome, outcome })),
            {
              generatedFrom:
                url || dependenciesPath || DEFAULT_DEPENDENCIES_PATH,
            },
          ),
        ),
        true,
      );
      io.setOutput('policy-export-path', path);
    }
    const jsonOutput = io.getInput('json-output').trim();
    // Atomic rename replaces a planted symlink instead of writing through it.
    if (jsonOutput) await writeAtomic(jsonOutput, machineJson(set), true);
    const sarifOutput = io.getInput('sarif-output').trim();
    if (sarifOutput)
      await writeAtomic(sarifOutput, machineJson(toSarif(sarif)), true);
    await io.writeSummary(
      single ? actionSummary(single) : actionSetSummary(set),
    );
    if (set.exitCode === 1)
      return `InterfaceDelta ${CI_POLICY_VERSION} compatibility gate failed.`;
    if (set.exitCode !== 0) {
      const failed = set.dependencies.flatMap((item) =>
        item.status === 'error' ? [item] : [],
      );
      return sanitizeGithub(
        url
          ? (failed[0]?.error.message ?? 'InterfaceDelta Action failed.')
          : `InterfaceDelta could not check ${failed.map((item) => item.name).join(', ')}: ${failed[0]?.error.message ?? ''}`,
      );
    }
    return undefined;
  } catch (error) {
    return sanitizeGithub(
      error instanceof Error ? error.message : 'InterfaceDelta Action failed.',
    );
  }
}

const AGENT_CHECK_SARIF_PATH = '.interfacedelta/agent-check.sarif';

function agentCheckSummary(outcome: AgentCheckOutcome): string {
  const report = outcome.report;
  const rows = report.servers.map(
    (server) =>
      `| ${markdown(server.name, 64)} | ${markdown(server.target, 300)} | ${server.status} | ${server.tools?.length ?? 0} |`,
  );
  return [
    '### InterfaceDelta agent-check',
    '',
    `**Result:** ${outcome.exitCode === 1 ? 'FAILED — a --fail-on condition matched' : 'PASSED — no --fail-on condition matched'}`,
    '',
    `**Configs:** ${report.configs.map((path) => markdown(path, 300)).join(', ')}`,
    '',
    '| Server | Target | Record | Tools |',
    '| --- | --- | --- | ---: |',
    ...rows,
    ...(report.keylessLimit
      ? [
          '',
          `**Keyless limit:** checked the first ${report.keylessLimit.checked} of ${report.keylessLimit.checked + report.keylessLimit.unchecked} tools; set INTERFACEDELTA_AGENT_KEY to check the rest.`,
        ]
      : []),
    '',
    '_No recorded change is not proof of no change._',
  ].join('\n');
}

/**
 * agent-check: runs `interfacedelta agent-check` on the checked-out MCP
 * client configs and writes SARIF for code scanning. Off unless requested.
 */
async function runAgentCheckMode(
  io: ActionIo,
  dependencies: ActionDependencies,
): Promise<string | undefined> {
  try {
    const workspace =
      (dependencies.env ?? process.env).GITHUB_WORKSPACE?.trim() ||
      process.cwd();
    const githubToken = io.getInput('github-token').trim();
    if (githubToken) {
      registerSecret(githubToken);
      io.setSecret(githubToken);
    }
    const failOn = io.getInput('agent-check-fail-on').trim() || undefined;
    // The CLI validates the origin itself (HTTPS; localhost HTTP for tests).
    const apiUrl = io.getInput('api-url').trim() || DEFAULT_API_URL;
    const outcome = await runAgentCheck(
      { path: workspace, ...(failOn ? { failOn } : {}), apiUrl },
      {
        env: dependencies.env ?? process.env,
        fetch: dependencies.fetch ?? fetch,
      },
    );
    const sarif = machineJson(agentCheckSarif(outcome.report, 1000, workspace));
    await writeAtomic(AGENT_CHECK_SARIF_PATH, sarif, true);
    io.setOutput('agent-check-sarif-path', AGENT_CHECK_SARIF_PATH);
    await uploadAgentCheckSarif(
      sarif,
      workspace,
      dependencies.env ?? process.env,
      githubToken,
      dependencies.fetch ?? fetch,
    );
    await io.writeSummary(`\n${agentCheckSummary(outcome)}\n`);
    io.setOutput(
      'agent-check-result',
      outcome.exitCode === 1 ? 'failed' : 'passed',
    );
    return outcome.exitCode === 1
      ? 'InterfaceDelta agent-check gate failed.'
      : undefined;
  } catch (error) {
    io.setOutput('agent-check-result', 'failed');
    return sanitizeGithub(
      error instanceof Error
        ? error.message
        : 'InterfaceDelta agent-check failed.',
    );
  }
}

const flag = (io: ActionIo, name: string, fallback: boolean) => {
  const value = io.getInput(name).trim().toLowerCase();
  if (!value) return fallback;
  if (value === 'true' || value === 'false') return value === 'true';
  throw new Error(`Input "${name}" must be true or false.`);
};

/** An https:// base: the origin plus any path, as GitHub Enterprise's /api/v3. */
function httpsOrigin(name: string, value: string, keepPath = false) {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Input "${name}" is not a URL.`);
  }
  if (url.protocol !== 'https:' || url.username || url.password)
    throw new Error(`Input "${name}" must be an https:// origin.`);
  return keepPath
    ? `${url.origin}${url.pathname.replace(/\/$/, '')}`
    : url.origin;
}

/**
 * watch (Pro and Team): syncs the dependencies file so InterfaceDelta checks
 * it continuously. issues: opens a GitHub issue for each decision waiting
 * for this repository and branch. Both run after the check, whatever its
 * result; the job then fails once with every reason.
 */
async function runDelivery(
  io: ActionIo,
  dependencies: ActionDependencies,
  modes: { watch: boolean; issues: boolean },
) {
  const env = dependencies.env ?? process.env;
  if (modes.watch && io.getInput('url').trim())
    throw new Error(
      '"watch" syncs a dependencies file; it cannot be used with "url".',
    );
  const apiToken = io.getInput('api-token').trim();
  if (!apiToken)
    throw new Error(
      'Set "api-token" from a secret: an InterfaceDelta watch token from Routing → Watch tokens, bound to this repository and branch.',
    );
  io.setSecret(apiToken);
  const githubToken = io.getInput('github-token').trim();
  if (githubToken) io.setSecret(githubToken);
  const apiUrl = httpsOrigin(
    'api-url',
    io.getInput('api-url').trim() || DEFAULT_API_URL,
  );
  const githubApiUrl = httpsOrigin(
    'GITHUB_API_URL',
    env.GITHUB_API_URL?.trim() || 'https://api.github.com',
    true,
  );
  const refInput = io.getInput('ref').trim();
  if (modes.watch) {
    const outcome = await runWatch(
      {
        dependencies:
          io.getInput('dependencies').trim() || DEFAULT_DEPENDENCIES_PATH,
        ...(refInput ? { ref: refInput } : {}),
        force: false,
        off: false,
      },
      {
        env: {
          ...env,
          INTERFACEDELTA_API_TOKEN: apiToken,
          INTERFACEDELTA_API_URL: apiUrl,
          GITHUB_API_URL: githubApiUrl,
          ...(githubToken ? { GITHUB_TOKEN: githubToken } : {}),
        },
        fetch: dependencies.fetch ?? fetch,
        git: dependencies.git ?? defaultGit,
      },
    );
    io.setOutput('watch-status', outcome.status);
    await io.writeSummary(
      `\n### InterfaceDelta watch\n\n${markdown(formatWatch(outcome), 500)}\n`,
    );
  }
  if (modes.issues) {
    const repository = env.GITHUB_REPOSITORY?.trim();
    const ref =
      refInput ||
      (env.GITHUB_REF_TYPE === 'branch' ? env.GITHUB_REF_NAME?.trim() : '');
    if (!repository || !ref)
      throw new Error(
        '"issues" needs GITHUB_REPOSITORY and a branch: run it on a branch, or set "ref".',
      );
    if (!githubToken)
      throw new Error('"issues" needs "github-token" (default github.token).');
    const outcome = await openDecisionIssues(
      { repository, ref, apiUrl, apiToken, githubApiUrl, githubToken },
      dependencies.fetch ?? fetch,
    );
    io.setOutput('issues-opened', outcome.opened);
    io.setOutput('decisions-acknowledged', outcome.acknowledged);
    // A run that cannot open issues must not look like a quiet one.
    const missing = outcome.noDestination
      ? `InterfaceDelta has no GitHub destination for ${repository}, so its decisions do not become issues. Add one in Routing → Destinations: ${new URL('/routing', apiUrl).href}. Decisions made before it was added stay email, Slack and webhook only.`
      : '';
    if (missing) io.warning(missing);
    await io.writeSummary(
      `\n### InterfaceDelta decisions\n\nOpened ${outcome.opened} issues; ${outcome.existing} decisions already had one; acknowledged ${outcome.acknowledged}.${outcome.remaining ? ' More decisions are waiting for the next run.' : ''}${missing ? `\n\n${markdown(missing, 500)}` : ''}\n`,
    );
  }
}

export async function runAction(
  rawIo: ActionIo,
  dependencies: ActionDependencies = {},
): Promise<void> {
  const io = redacting(rawIo);
  const failures: string[] = [];
  let modes: {
    check: boolean;
    watch: boolean;
    issues: boolean;
    findUses: boolean;
    agentCheck: boolean;
    skills: boolean;
    citations: boolean;
  };
  try {
    modes = {
      skills: flag(io, 'skills', false),
      citations: flag(io, 'citations', false),
      check: flag(io, 'check', true),
      watch: flag(io, 'watch', false),
      issues: flag(io, 'issues', false),
      findUses: flag(io, 'find-uses', true),
      agentCheck: flag(io, 'agent-check', false),
    };
  } catch (error) {
    io.setFailed(error instanceof Error ? error.message : 'Invalid input.');
    return;
  }
  if (!modes.check && io.getInput('policy-export').trim()) {
    io.setFailed('Input "policy-export" requires check: true.');
    return;
  }
  if (
    !modes.check &&
    !modes.watch &&
    !modes.issues &&
    !modes.agentCheck &&
    !modes.skills &&
    !modes.citations
  ) {
    io.setFailed(
      'Nothing to do: "check", "watch", "issues", "agent-check", "skills" and "citations" are all false.',
    );
    return;
  }
  if (modes.check) {
    const failure = await runCheck(io, dependencies, modes.findUses);
    if (failure) failures.push(failure);
  }
  if (modes.agentCheck) {
    const failure = await runAgentCheckMode(io, dependencies);
    if (failure) failures.push(failure);
  }
  if (modes.skills) {
    try {
      const failure = await runSkillsMode(io, dependencies);
      if (failure) failures.push(failure);
    } catch (error) {
      failures.push(
        sanitizeGithub(
          error instanceof Error ? error.message : 'Skills check failed.',
        ),
      );
    }
  }
  if (modes.citations) {
    try {
      const failure = await runCitationsMode(io, dependencies);
      if (failure) failures.push(failure);
    } catch (error) {
      failures.push(
        sanitizeGithub(
          error instanceof Error ? error.message : 'Citations check failed.',
        ),
      );
    }
  }
  if (modes.watch || modes.issues)
    try {
      await runDelivery(io, dependencies, modes);
    } catch (error) {
      failures.push(
        sanitizeGithub(
          error instanceof Error
            ? error.message
            : 'InterfaceDelta Action failed.',
        ),
      );
    }
  if (failures.length) io.setFailed(failures.join(' '));
}
