import { gzipSync } from 'node:zlib';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import {
  runSkills,
  sanitizeGithub,
  skillsToSarif,
  writeAtomic,
} from 'interfacedelta';
import type { ActionDependencies, ActionIo } from './action';

/** Opt-in stored-record/local-file mode; upload the same SARIF the CLI emits. */
export async function runSkillsMode(
  io: ActionIo,
  dependencies: ActionDependencies,
): Promise<string | undefined> {
  const env = dependencies.env ?? process.env;
  const key = env.INTERFACEDELTA_AGENT_KEY?.trim();
  if (key) io.setSecret(key);
  const token = io.getInput('github-token').trim();
  if (token) io.setSecret(token);
  const repository = env.GITHUB_REPOSITORY ?? '';
  const commit = env.GITHUB_SHA ?? '';
  const ref = env.GITHUB_REF ?? '';
  if (
    !token ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) ||
    !/^[a-f0-9]{40,64}$/.test(commit) ||
    !ref.startsWith('refs/')
  )
    throw new Error(
      'Skills SARIF upload needs github-token, GITHUB_REPOSITORY, GITHUB_SHA and GITHUB_REF; grant security-events: write.',
    );
  let api: URL;
  try {
    api = new URL(env.GITHUB_API_URL || 'https://api.github.com');
    if (
      api.protocol !== 'https:' ||
      api.username ||
      api.password ||
      api.search ||
      api.hash
    )
      throw new Error();
  } catch {
    throw new Error(
      'GITHUB_API_URL must be HTTPS without credentials, query or fragment.',
    );
  }
  const workspace = resolve(env.GITHUB_WORKSPACE || '.');
  const directory = resolve(workspace, io.getInput('skills-dir').trim() || '.');
  const prefix = relative(workspace, directory);
  if (prefix === '..' || prefix.startsWith(`..${sep}`) || isAbsolute(prefix))
    throw new Error('skills-dir must be inside GITHUB_WORKSPACE.');
  const outcome = await runSkills(
    {
      dependencies: io.getInput('dependencies').trim() || undefined,
      skillsDir: directory,
      skillIncludes: io
        .getInput('skills-include')
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean),
      mcpConfig: io.getInput('skills-mcp-config').trim() || undefined,
      since: io.getInput('skills-since').trim() || undefined,
      failOn: io.getInput('skills-fail-on').trim() || undefined,
      apiUrl: io.getInput('api-url').trim() || undefined,
    },
    { env, fetch: dependencies.fetch ?? fetch },
  );
  // The CLI reports paths relative to its scan root. GitHub needs paths
  // relative to the checkout, including a selected subdirectory.
  const located = {
    ...outcome.report,
    mentions: outcome.report.mentions.map((item) => ({
      ...item,
      path: [prefix.split(sep).join('/'), item.path].filter(Boolean).join('/'),
    })),
  };
  const sarif = JSON.stringify(skillsToSarif(located));
  const path = resolve(
    env.GITHUB_WORKSPACE || '.',
    '.interfacedelta/skills.sarif',
  );
  await writeAtomic(path, sarif + '\n', true);
  io.setOutput('skills-sarif-path', path);
  io.setOutput('skills-mentions-count', outcome.report.mentions.length);
  await io.writeSummary(
    `\n### InterfaceDelta skills\n\n${outcome.report.mentions.length} stale mentions across ${outcome.report.filesRead} instruction files.${outcome.report.truncated ? ' Scan truncated; some locations may be missing.' : ''}\n`,
  );
  // Do not put file contents or signed remote text in workflow annotations.
  for (const item of located.mentions.slice(0, 20))
    io.notice(
      sanitizeGithub(
        `${item.term}: ${item.why.join(', ')} (${item.tool} at ${item.endpoint})`,
      ),
      { file: item.path, startLine: item.line },
    );
  const response = await (dependencies.fetch ?? fetch)(
    `${api.href.replace(/\/$/, '')}/repos/${repository}/code-scanning/sarifs`,
    {
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/vnd.github+json',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        commit_sha: commit,
        ref,
        sarif: gzipSync(sarif).toString('base64'),
      }),
    },
  );
  await response.body?.cancel();
  if (!response.ok)
    throw new Error(
      `Skills SARIF upload failed (HTTP ${response.status}); check security-events: write and code scanning availability.`,
    );
  return outcome.exitCode === 1
    ? 'InterfaceDelta skills threshold matched.'
    : undefined;
}
