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
  sanitizeTerminal,
  summarizeOutcomes,
  toSarif,
  writeAtomic,
  type CheckResult,
  type CheckSetResult,
  type Decision,
  type DependencyOutcome,
  type Inspector,
  type SarifEntry,
  type TokenBinding,
} from 'interfacedelta';

// Remote-derived text in the summary must not create links, emphasis, math or
// tables. Escaping ':' and '@' also breaks GFM autolinks (bare URLs, emails,
// mentions). Angle brackets become entities last, so they are not re-escaped.
const markdown = (value: unknown, maxLength?: number) =>
  sanitizeTerminal(value, maxLength)
    .replace(/[\\`*_[\]()#|~!:@&$]/g, '\\$&')
    .replace(/\b(www)\./gi, '$1\\.')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
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
  setFailed(message: string): void;
  writeSummary(markdown: string): Promise<void>;
  /** Masks a value in every later log line (core.setSecret). */
  setSecret(value: string): void;
};

const DISPLAY_LIMIT = 20;
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

export async function runAction(
  rawIo: ActionIo,
  dependencies: {
    inspector?: Inspector;
    readBaseline?: (path: string) => Promise<unknown>;
  } = {},
): Promise<void> {
  const io = redacting(rawIo);
  try {
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
    for (const [name, value] of Object.entries(outputsFor(set, single)))
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
      io.setFailed(
        `InterfaceDelta ${CI_POLICY_VERSION} compatibility gate failed.`,
      );
    else if (set.exitCode !== 0) {
      const failed = set.dependencies.flatMap((item) =>
        item.status === 'error' ? [item] : [],
      );
      io.setFailed(
        sanitizeGithub(
          url
            ? (failed[0]?.error.message ?? 'InterfaceDelta Action failed.')
            : `InterfaceDelta could not check ${failed.map((item) => item.name).join(', ')}: ${failed[0]?.error.message ?? ''}`,
        ),
      );
    }
  } catch (error) {
    io.setFailed(
      sanitizeGithub(
        error instanceof Error
          ? error.message
          : 'InterfaceDelta Action failed.',
      ),
    );
  }
}
