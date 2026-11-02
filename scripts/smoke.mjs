/* global process, console, URL */
// Runs the ncc bundle the way the runner does, offline, with a missing dependencies file.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const bundle = new URL('../dist/index.js', import.meta.url).pathname;
const dir = mkdtempSync(join(tmpdir(), 'interfacedelta-action-smoke-'));
try {
  const output = join(dir, 'output'),
    summary = join(dir, 'summary.md');
  writeFileSync(output, '');
  writeFileSync(summary, '');
  const result = spawnSync(process.execPath, [bundle], {
    cwd: dir,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      GITHUB_OUTPUT: output,
      GITHUB_STEP_SUMMARY: summary,
    },
  });
  const text = `${result.stdout}${result.stderr}`;
  if (
    result.status !== 1 ||
    !text.includes('::error::Dependencies file could not be read')
  )
    throw new Error(
      `Action smoke failed (status ${result.status}):\n${text}`.slice(0, 2000),
    );
  const dependencies = join(dir, 'dependencies.json');
  writeFileSync(
    dependencies,
    JSON.stringify({
      formatVersion: 'interfacedelta-dependencies-v1',
      dependencies: [
        {
          name: 'fixture',
          url: 'https://example.com',
          baseline: 'missing.json',
        },
      ],
    }),
  );
  for (const format of ['github', 'generic']) {
    const exported = spawnSync(process.execPath, [bundle], {
      cwd: dir,
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH,
        GITHUB_OUTPUT: output,
        GITHUB_STEP_SUMMARY: summary,
        INPUT_DEPENDENCIES: dependencies,
        'INPUT_POLICY-EXPORT': format,
      },
    });
    const path = `.interfacedelta/policy-${format}.json`;
    const policy = JSON.parse(readFileSync(join(dir, path), 'utf8'));
    // Unchecked entries are never allowlisted.
    const entries = policy.excluded;
    if (format === 'generic' && policy.servers.length !== 0)
      throw new Error('Unchecked entry was allowlisted.');
    if (
      exported.status !== 1 ||
      entries[0].decision !== 'review' ||
      !readFileSync(output, 'utf8').includes(path)
    )
      throw new Error(
        'Action did not export the failed check and its output path.',
      );
  }
  console.log(
    'interfacedelta action bundle smoke passed; 2 policy fixtures passed',
  );
} finally {
  rmSync(dir, { recursive: true, force: true });
}
