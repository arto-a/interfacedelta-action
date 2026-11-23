import { isAbsolute, relative, resolve, sep } from 'node:path';
import {
  runCitations,
  citationsToSarif,
  writeAtomic,
  sanitizeGithub,
} from 'interfacedelta';
import type { ActionDependencies, ActionIo } from './action';

/** Opt-in citations check, with a local SARIF artifact ready for upload. */
export async function runCitationsMode(
  io: ActionIo,
  dependencies: ActionDependencies,
): Promise<string | undefined> {
  const env = dependencies.env ?? process.env;
  if (env.INTERFACEDELTA_AGENT_KEY?.trim())
    io.setSecret(env.INTERFACEDELTA_AGENT_KEY.trim());
  const workspace = resolve(env.GITHUB_WORKSPACE || '.');
  const dir = resolve(workspace, io.getInput('citations-dir').trim() || '.');
  const prefix = relative(workspace, dir);
  if (prefix === '..' || prefix.startsWith(`..${sep}`) || isAbsolute(prefix))
    throw new Error('citations-dir must be inside GITHUB_WORKSPACE.');
  const outcome = await runCitations(
    {
      dir,
      include: io
        .getInput('citations-include')
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean),
      keys: io.getInput('citations-keys').trim() || undefined,
      failOn: io.getInput('citations-fail-on').trim() || undefined,
      apiUrl: io.getInput('api-url').trim() || undefined,
    },
    { env, fetch: dependencies.fetch ?? fetch },
  );
  const located = {
    ...outcome.report,
    citations: outcome.report.citations.map((item) => ({
      ...item,
      path: [prefix.split(sep).join('/'), item.path].filter(Boolean).join('/'),
    })),
  };
  const path = resolve(workspace, '.interfacedelta/citations.sarif');
  await writeAtomic(
    path,
    JSON.stringify(citationsToSarif(located), null, 2) + '\n',
    true,
  );
  io.setOutput('citations-sarif-path', path);
  io.setOutput('citations-count', outcome.report.citations.length);
  await io.writeSummary(
    `\n### InterfaceDelta citations\n\n${outcome.report.citations.length} citations across ${outcome.report.filesRead} instruction files; ${outcome.report.citations.filter((item) => item.status !== 'current').length} need review.${outcome.report.truncated ? ' Scan truncated; some citations may be missing.' : ''}\n`,
  );
  for (const item of located.citations
    .filter((item) => item.status !== 'current')
    .slice(0, 20))
    io.notice(sanitizeGithub(`Tool citation: ${item.status}`), {
      file: item.path,
      startLine: item.line,
    });
  return outcome.exitCode === 1
    ? 'InterfaceDelta citations threshold matched.'
    : undefined;
}
