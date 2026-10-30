import { redact, registerSecret, sanitizeTerminal } from 'interfacedelta';

/**
 * Issue mode: pulls the hosted decisions for this repository and branch and
 * opens one GitHub issue per decision, with the workflow's own GITHUB_TOKEN.
 * InterfaceDelta holds no GitHub credential (delivery-contracts-v1.md §6).
 * Delivery is at least once: an issue carries the decision's marker, and
 * every labelled issue in any state is read first, so a decision whose
 * acknowledgement was lost is acknowledged again rather than reopened.
 */
export const ISSUE_LABEL = 'interfacedelta';
const TIMEOUT_MS = 15_000;
const DEFAULT_MAX_DECISIONS = 100;
const MAX_ISSUE_PAGES = 30;
const MAX_RESULT_ROWS = 50;
const MARKER =
  /interfacedelta-decision:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/g;
const OWNER = /^@?[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$/;

export type IssuesOptions = {
  repository: string;
  ref: string;
  apiUrl: string;
  apiToken: string;
  githubApiUrl: string;
  githubToken: string;
  /** Decisions handled in one run; the rest wait for the next run. */
  maxDecisions?: number;
};
export type IssuesOutcome = {
  opened: number;
  /** Decisions that already had an issue: only acknowledged. */
  existing: number;
  acknowledged: number;
  /** More decisions are waiting than this run handled. */
  remaining: boolean;
  /**
   * Nothing waited and InterfaceDelta has no GitHub destination for this
   * repository, so no decision can become an issue yet.
   */
  noDestination?: boolean;
};

type Card = {
  id: string;
  marker: string;
  decision: string;
  headline?: unknown;
  repository?: unknown;
  ref?: unknown;
  commitSha?: unknown;
  dependency?: unknown;
  results?: unknown;
  changes?: unknown;
  totalResults?: unknown;
  truncated?: unknown;
  evidence?: unknown;
};

// Remote-derived text in an issue must not create links, mentions, emphasis
// or tables (the same escaping as the job summary).
export const markdown = (value: unknown, maxLength?: number) =>
  sanitizeTerminal(value, maxLength)
    .replace(/[\\`*_[\]()#|~!:@&$]/g, '\\$&')
    .replace(/\b(www)\./gi, '$1\\.')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

/** Owners come from the repository's own dependencies file: mention them. */
const owner = (value: unknown) =>
  typeof value === 'string' && OWNER.test(value) && redact(value) === value
    ? value.replace(/_/g, '\\_')
    : markdown(value, 100);

async function call(
  fetcher: typeof fetch,
  service: string,
  url: string,
  init: RequestInit,
) {
  try {
    return await fetcher(url, {
      ...init,
      redirect: 'error',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch {
    throw new Error(`Could not reach ${service}. Try again in the next run.`);
  }
}

async function json(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function failure(response: Response, what: string): Promise<never> {
  const body = (await json(response)) as {
    error?: { message?: unknown };
    message?: unknown;
  } | null;
  const reason = body?.error?.message ?? body?.message;
  throw new Error(
    `${what} answered ${response.status}.${typeof reason === 'string' ? ` ${sanitizeTerminal(reason, 300)}` : ''}`,
  );
}

const validCard = (value: unknown): value is Card => {
  const card = value as Card | null;
  return (
    !!card &&
    typeof card.id === 'string' &&
    /^[0-9a-f-]{36}$/.test(card.id) &&
    card.marker === `interfacedelta-decision:${card.id}` &&
    typeof card.decision === 'string'
  );
};

/**
 * A change in words, as InterfaceDelta's emails and decision page say it
 * (the hosted service words it the same way): "operation cancelOrder
 * removed". Cards before 0.3.1 carry no subject: "operation removed".
 */
export function changePhrase(change: { code?: unknown; subject?: unknown }) {
  const code = String(change.code ?? '');
  const text = (
    /^[A-Z][A-Z0-9_]*$/.test(code)
      ? code
          .replace(/^(OPENAPI|MCP|A2A|ARD|WEBMCP)_(?=[A-Z])/, '')
          .toLowerCase()
          .replaceAll('_', ' ')
      : code
  ).trim();
  const subject = change.subject as { kind?: unknown; name?: unknown } | null;
  if (
    !subject ||
    typeof subject.kind !== 'string' ||
    typeof subject.name !== 'string'
  )
    return text;
  const kind = (subject.kind.split('.').at(-1) ?? '').replaceAll('_', ' ');
  const [first, ...rest] = text.split(' ');
  return rest.length && (first === kind || first === 'capability')
    ? `${kind} ${subject.name} ${rest.join(' ')}`
    : `${text} on ${kind} ${subject.name}`;
}

/** The headline without the dependency name older cards already carry. */
const headlineOf = (card: Card) => {
  const headline = typeof card.headline === 'string' ? card.headline : '';
  const dependency = typeof card.dependency === 'string' ? card.dependency : '';
  return dependency && headline.startsWith(`${dependency}: `)
    ? headline.slice(dependency.length + 2)
    : headline || 'interface change';
};

export function issueTitle(card: Card) {
  return sanitizeTerminal(
    `InterfaceDelta: ${card.decision.toUpperCase()} — ${typeof card.dependency === 'string' ? `${card.dependency}: ` : ''}${headlineOf(card)}`,
    200,
  );
}

/** What the decision means for checks, in the decision page's words. */
const consequence = (card: Card) => {
  const where = `${markdown(card.repository, 201)} on ${markdown(card.ref, 255)}`;
  return card.decision === 'block'
    ? `Checks for ${where} fail until the change is accepted in the lockfile or the baseline is updated.`
    : card.decision === 'warn'
      ? `Checks for ${where} still pass with a warning.`
      : `Recorded for ${where}. Nothing to do.`;
};

/**
 * The issue reads as a short list, not a table, so GitHub's notification
 * email stays readable as plain text too. `decisionUrl` is built from the
 * configured api-url, never from the card.
 */
export function issueBody(card: Card, decisionUrl?: string) {
  const changes = new Map(
    (Array.isArray(card.changes) ? card.changes : []).map((change) => [
      (change as { id?: unknown }).id,
      change as { code?: unknown; classification?: unknown; subject?: unknown },
    ]),
  );
  const results = (Array.isArray(card.results) ? card.results : []).slice(
    0,
    MAX_RESULT_ROWS,
  ) as {
    dependency?: unknown;
    change?: unknown;
    action?: unknown;
    owner?: unknown;
    note?: unknown;
    card?: { step?: unknown };
  }[];
  const items = results.flatMap((result) => {
    const change = changes.get(result.change);
    const what = change ? changePhrase(change) : String(result.change ?? '');
    const step = result.note ?? result.card?.step;
    return [
      `- **${markdown(String(result.action ?? '').toUpperCase(), 10)}** ${markdown(result.dependency, 64)}: ${markdown(what, 300)}${change?.classification ? ` (${markdown(change.classification === 'indeterminate' ? 'needs review' : String(change.classification).replaceAll('_', '-'), 40)})` : ''}`,
      ...(result.owner ? [`  Owner: ${owner(result.owner)}`] : []),
      ...(step ? [`  Next step: ${markdown(step, 200)}`] : []),
    ];
  });
  const total = Number(card.totalResults ?? results.length);
  const evidence = (Array.isArray(card.evidence) ? card.evidence : [])
    .map((item) => (item as { observationId?: unknown }).observationId)
    .filter((id): id is string => typeof id === 'string')
    .map((id) => `\`${markdown(id, 36)}\``);
  const lines = [
    `**${markdown(card.decision.toUpperCase(), 10)}** — ${markdown(typeof card.dependency === 'string' ? `${card.dependency}: ${headlineOf(card)}` : headlineOf(card), 300)}`,
    '',
    consequence(card),
    ...(decisionUrl
      ? ['', `**[View the decision on InterfaceDelta](${decisionUrl})**`]
      : []),
    '',
    '### What changed',
    '',
    ...items,
    ...(card.truncated === true || total > results.length
      ? [
          '',
          `${total - results.length} more results are in the decision record.`,
        ]
      : []),
    '',
    `Repository ${markdown(card.repository, 201)} · branch ${markdown(card.ref, 255)} · commit ${markdown(String(card.commitSha ?? '').slice(0, 12), 12)}`,
    ...(evidence.length
      ? [`Evidence: observation ${evidence.join(', ')}`]
      : []),
    '',
    '_A deterministic compatibility decision from your dependencies file, not a security, safety, trust or certification assessment._',
    '',
    `<!-- ${card.marker} -->`,
    `<sub>${card.marker}</sub>`,
  ];
  // No registered credential leaves in an issue, whatever a card holds.
  return redact(lines.join('\n'));
}

/** Markers of every labelled issue, open or closed. */
async function existingMarkers(options: IssuesOptions, fetcher: typeof fetch) {
  const markers = new Set<string>();
  for (let page = 1; page <= MAX_ISSUE_PAGES; page++) {
    const response = await call(
      fetcher,
      'GitHub',
      `${options.githubApiUrl}/repos/${options.repository}/issues?labels=${ISSUE_LABEL}&state=all&per_page=100&page=${page}`,
      { headers: githubHeaders(options) },
    );
    if (!response.ok) await failure(response, 'GitHub, listing issues,');
    const issues = (await json(response)) as
      { body?: unknown; pull_request?: unknown }[] | null;
    if (!Array.isArray(issues)) break;
    // The issues endpoint lists pull requests too; only issues count.
    for (const issue of issues)
      if (!issue.pull_request && typeof issue.body === 'string')
        for (const match of issue.body.matchAll(MARKER))
          markers.add(`interfacedelta-decision:${match[1]}`);
    if (issues.length < 100) return markers;
  }
  throw new Error(
    `More than ${MAX_ISSUE_PAGES * 100} issues carry the ${ISSUE_LABEL} label; close and unlabel old ones so new decisions can be checked against them.`,
  );
}

const githubHeaders = (options: IssuesOptions) => ({
  authorization: `Bearer ${options.githubToken}`,
  accept: 'application/vnd.github+json',
  'x-github-api-version': '2022-11-28',
});

export async function openDecisionIssues(
  options: IssuesOptions,
  fetcher: typeof fetch = fetch,
): Promise<IssuesOutcome> {
  registerSecret(options.apiToken);
  registerSecret(options.githubToken);
  const max = options.maxDecisions ?? DEFAULT_MAX_DECISIONS;
  const base = `${options.apiUrl}/api/v1/lockfiles/${encodeURIComponent(options.repository)}/decisions`;
  const ref = encodeURIComponent(options.ref);
  const auth = { authorization: `Bearer ${options.apiToken}` };
  let markers: Set<string> | undefined;
  const outcome: IssuesOutcome = {
    opened: 0,
    existing: 0,
    acknowledged: 0,
    remaining: false,
  };
  let cursor: string | null = null;
  let handled = 0;
  do {
    const response = await call(
      fetcher,
      'InterfaceDelta',
      `${base}?ref=${ref}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
      { headers: auth },
    );
    if (response.status === 401)
      throw new Error(
        'InterfaceDelta refused the API token. It needs the decisions:read and decisions:ack scopes for this repository and branch.',
      );
    if (!response.ok) await failure(response, 'InterfaceDelta');
    const page = (await json(response)) as {
      decisions?: unknown;
      nextCursor?: unknown;
      githubDestination?: unknown;
    } | null;
    const cards = Array.isArray(page?.decisions) ? page.decisions : [];
    if (!cursor && !cards.length && page?.githubDestination === false)
      outcome.noDestination = true;
    for (const card of cards) {
      if (handled >= max) {
        outcome.remaining = true;
        return outcome;
      }
      if (!validCard(card)) continue;
      handled += 1;
      markers ??= await existingMarkers(options, fetcher);
      if (markers.has(card.marker)) outcome.existing += 1;
      else {
        const created = await call(
          fetcher,
          'GitHub',
          `${options.githubApiUrl}/repos/${options.repository}/issues`,
          {
            method: 'POST',
            headers: {
              ...githubHeaders(options),
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              title: redact(issueTitle(card)),
              body: issueBody(
                card,
                new URL(
                  `/decisions/${encodeURIComponent(card.id)}`,
                  options.apiUrl,
                ).href,
              ),
              labels: [ISSUE_LABEL],
            }),
          },
        );
        if (created.status === 403 || created.status === 404)
          throw new Error(
            'GitHub refused to create an issue. Give the workflow `permissions: issues: write` and make sure issues are enabled.',
          );
        if (!created.ok) await failure(created, 'GitHub, creating an issue,');
        markers.add(card.marker);
        outcome.opened += 1;
      }
      const acked = await call(
        fetcher,
        'InterfaceDelta',
        `${base}/${card.id}/ack?ref=${ref}`,
        { method: 'POST', headers: auth },
      );
      // 404: expired or acknowledged elsewhere; the issue exists either way.
      if (acked.ok) outcome.acknowledged += 1;
      else if (acked.status !== 404)
        await failure(acked, 'InterfaceDelta, acknowledging a decision,');
    }
    cursor = typeof page?.nextCursor === 'string' ? page.nextCursor : null;
  } while (cursor);
  return outcome;
}
