import { resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';
import { redact, registerSecret } from 'interfacedelta';

/** Upload only the generated SARIF to this workflow's GitHub repository. */
export async function uploadAgentCheckSarif(
  sarif: string,
  workspace: string,
  env: Record<string, string | undefined>,
  token: string,
  fetcher: typeof fetch,
): Promise<void> {
  if (!token)
    throw new Error(
      'agent-check SARIF upload needs github-token and permissions: security-events: write.',
    );
  registerSecret(token);
  if (redact(sarif) !== sarif)
    throw new Error(
      'The agent-check SARIF upload would contain the credential; nothing was uploaded.',
    );
  const repository = env.GITHUB_REPOSITORY ?? '';
  const commit = env.GITHUB_SHA ?? '';
  const ref = env.GITHUB_REF ?? '';
  if (
    !/^[A-Za-z0-9][A-Za-z0-9-]*\/(?!\.{1,2}$)[A-Za-z0-9_.-]+$/.test(
      repository,
    ) ||
    !/^[a-f0-9]{40,64}$/i.test(commit) ||
    !/^refs\/(heads|pull|tags)\/[^\s]+$/.test(ref)
  )
    throw new Error(
      'agent-check SARIF upload needs GITHUB_REPOSITORY, GITHUB_SHA and GITHUB_REF from the workflow.',
    );
  let base: URL;
  try {
    base = new URL(env.GITHUB_API_URL || 'https://api.github.com');
    if (
      base.protocol !== 'https:' ||
      base.username ||
      base.password ||
      base.search ||
      base.hash
    )
      throw new Error();
  } catch {
    throw new Error(
      'GITHUB_API_URL must be an HTTPS API URL without credentials, query or fragment.',
    );
  }
  const url = `${base.href.replace(/\/$/, '')}/repos/${repository}/code-scanning/sarifs`;
  let response: Response;
  try {
    response = await fetcher(url, {
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
      headers: {
        accept: 'application/vnd.github+json',
        'content-type': 'application/json',
        authorization: `Bearer ${token}`,
        'x-github-api-version': '2022-11-28',
      },
      body: JSON.stringify({
        commit_sha: commit,
        ref,
        sarif: gzipSync(sarif).toString('base64'),
        checkout_uri: pathToFileURL(`${resolve(workspace)}${sep}`).href,
      }),
    });
  } catch {
    throw new Error(
      'GitHub SARIF upload was unavailable; the local SARIF file is retained.',
    );
  }
  // Provider bodies and URLs can echo credentials; never print them.
  await response.body?.cancel().catch(() => undefined);
  if (response.status !== 202)
    throw new Error(
      `GitHub SARIF upload answered HTTP ${response.status}. Give the workflow permissions: security-events: write and access to code scanning.`,
    );
}
