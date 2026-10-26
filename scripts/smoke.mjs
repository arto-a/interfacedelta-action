/* global process, console, URL */
// Runs the ncc bundle the way the runner does, offline, with a missing dependencies file.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
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
  console.log('interfacedelta action bundle smoke passed');
} finally {
  rmSync(dir, { recursive: true, force: true });
}
