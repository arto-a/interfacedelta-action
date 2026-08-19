import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  checkBaseline,
  sanitizeGithub,
  type CheckResult,
  type Inspector,
} from 'interfacedelta';

export type ActionIo = {
  getInput(name: string): string;
  setOutput(name: string, value: string | number): void;
  warning(message: string): void;
  error(message: string): void;
  setFailed(message: string): void;
  writeSummary(markdown: string): Promise<void>;
};

const boundedFindings = (result: CheckResult) => {
  const notable = result.comparison.changes.filter((item) =>
    ['breaking', 'indeterminate'].includes(item.classification),
  );
  const shown = notable.slice(0, 20);
  const lines = shown.map(
    (item) =>
      `- **${sanitizeGithub(item.classification, 40)}** — ${sanitizeGithub(item.code, 100)} (${sanitizeGithub(item.entityKind, 80)}: ${sanitizeGithub(item.entityId, 160)})`,
  );
  if (notable.length > shown.length)
    lines.push(`- ${notable.length - shown.length} additional findings omitted from display.`);
  return { notable, lines };
};

export function actionSummary(result: CheckResult): string {
  const { lines } = boundedFindings(result);
  return [
    '## InterfaceDelta compatibility check',
    '',
    `**Target:** ${sanitizeGithub(result.targetScope.origin, 300)}`,
    '',
    `**Baseline:** \`sha256:${result.previousFingerprint}\``,
    '',
    `**Current:** \`sha256:${result.currentFingerprint}\``,
    '',
    `**Comparison:** ${sanitizeGithub(result.comparison.state, 60)}`,
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
    '_This is a deterministic compatibility result, not a security, safety, trust, or certification assessment._',
  ].join('\n');
}

export async function runAction(
  io: ActionIo,
  dependencies: { inspector?: Inspector; readBaseline?: (path: string) => Promise<unknown> } = {},
): Promise<void> {
  try {
    const url = io.getInput('url').trim();
    if (!url) throw new Error('Input "url" is required.');
    const mcpEndpoint = io.getInput('mcp-endpoint').trim() || undefined;
    const baselinePath = io.getInput('baseline').trim() || '.interfacedelta/passport.json';
    const failOn = io.getInput('fail-on').trim() || 'breaking';
    const baseline = dependencies.readBaseline
      ? await dependencies.readBaseline(baselinePath)
      : (JSON.parse(await readFile(resolve(baselinePath), 'utf8')) as unknown);
    const result = await checkBaseline(url, baseline, {
      mcpEndpoint,
      failOn,
      inspector: dependencies.inspector,
    });
    const outputs: Record<string, string | number> = {
      'comparison-state': result.comparison.state,
      'highest-classification': result.comparison.highestClassification,
      'breaking-count': result.comparison.counts.breaking,
      'non-breaking-count': result.comparison.counts.nonBreaking,
      'indeterminate-count': result.comparison.counts.indeterminate,
      'informational-count': result.comparison.counts.informational,
      'current-fingerprint': result.currentFingerprint,
      'policy-result': result.policy.result,
    };
    for (const [name, value] of Object.entries(outputs)) io.setOutput(name, value);
    const notable = result.comparison.changes
      .filter((item) => ['breaking', 'indeterminate'].includes(item.classification))
      .slice(0, 20);
    for (const item of notable) {
      const message = `${item.classification}: ${item.code} (${item.entityKind}: ${item.entityId})`;
      if (item.classification === 'breaking') io.error(sanitizeGithub(message));
      else io.warning(sanitizeGithub(message));
    }
    await io.writeSummary(actionSummary(result));
    if (result.policy.result === 'failed')
      io.setFailed('InterfaceDelta ci-policy-v1 compatibility gate failed.');
  } catch (error) {
    io.setFailed(
      sanitizeGithub(error instanceof Error ? error.message : 'InterfaceDelta Action failed.'),
    );
  }
}
