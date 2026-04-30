import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const workspaceRoot = resolve(import.meta.dirname, '..');
const currentTag = process.argv[2] ?? process.env['GITHUB_REF_NAME'];

if (!currentTag) {
  console.error('Expected a release tag argument or GITHUB_REF_NAME.');
  process.exit(1);
}

function git(args) {
  return execFileSync('git', args, {
    cwd: workspaceRoot,
    encoding: 'utf8',
  }).trim();
}

function tryGit(args) {
  try {
    return git(args);
  } catch {
    return null;
  }
}

function parseGithubRepository(remoteUrl) {
  if (!remoteUrl) {
    return null;
  }

  const httpsMatch = remoteUrl.match(/github\.com[:/]([^/]+\/[^/.]+)(?:\.git)?$/);

  if (httpsMatch?.[1]) {
    return httpsMatch[1];
  }

  return null;
}

function parseConventionalCommit(subject, body) {
  const match = subject.match(
    /^(?<type>[a-z]+)(?:\((?<scope>[^)]+)\))?(?<breaking>!)?: (?<summary>.+)$/,
  );

  const breakingNote = body.match(/^BREAKING CHANGE:\s+(.+)$/m)?.[1]?.trim();

  if (!match?.groups) {
    return {
      type: 'other',
      scope: null,
      summary: subject,
      isBreaking: Boolean(breakingNote),
      breakingNote,
    };
  }

  return {
    type: match.groups.type,
    scope: match.groups.scope ?? null,
    summary: match.groups.summary,
    isBreaking: match.groups.breaking === '!' || Boolean(breakingNote),
    breakingNote,
  };
}

const previousTag = tryGit(['describe', '--tags', '--abbrev=0', `${currentTag}^`]);
const remoteUrl = tryGit(['remote', 'get-url', 'origin']);
const repository = parseGithubRepository(remoteUrl);
const range = previousTag ? `${previousTag}..${currentTag}` : currentTag;
const rawCommits = git(['log', '--format=%H%x1f%s%x1f%b%x1e', range]);
const commits = rawCommits
  .split('\x1e')
  .map((entry) => entry.trim())
  .filter(Boolean)
  .map((entry) => {
    const [hash, subject, body = ''] = entry.split('\x1f');
    const conventional = parseConventionalCommit(subject, body);

    return {
      hash,
      subject,
      body,
      ...conventional,
    };
  })
  .filter((commit) => !commit.subject.startsWith('Merge '));

const orderedSections = [
  ['feat', 'Features'],
  ['fix', 'Fixes'],
  ['perf', 'Performance'],
  ['refactor', 'Refactors'],
  ['docs', 'Documentation'],
  ['test', 'Tests'],
  ['build', 'Build'],
  ['ci', 'CI'],
  ['chore', 'Chores'],
  ['revert', 'Reverts'],
  ['other', 'Other'],
];

const sectionEntries = new Map(orderedSections.map(([key]) => [key, []]));
const breakingChanges = [];

for (const commit of commits) {
  const scopePrefix = commit.scope ? `**${commit.scope}:** ` : '';
  const commitLink =
    repository === null
      ? commit.hash.slice(0, 7)
      : `[${commit.hash.slice(0, 7)}](https://github.com/${repository}/commit/${commit.hash})`;
  const line = `- ${scopePrefix}${commit.summary} (${commitLink})`;

  if (commit.isBreaking) {
    breakingChanges.push(
      commit.breakingNote ? `${line} - ${commit.breakingNote}` : line,
    );
  }

  const section = sectionEntries.get(commit.type) ?? sectionEntries.get('other');
  section?.push(line);
}

const lines = ['# Release Notes', '', `Release: \`${currentTag}\``];

if (previousTag) {
  lines.push(`Previous tag: \`${previousTag}\``);
}

if (repository && previousTag) {
  lines.push(
    `[Compare changes](https://github.com/${repository}/compare/${previousTag}...${currentTag})`,
  );
}

lines.push('');

if (commits.length === 0) {
  lines.push('- No user-facing changes.');
} else {
  if (breakingChanges.length > 0) {
    lines.push('## Breaking Changes', '', ...breakingChanges, '');
  }

  for (const [key, title] of orderedSections) {
    const entries = sectionEntries.get(key) ?? [];

    if (entries.length === 0) {
      continue;
    }

    lines.push(`## ${title}`, '', ...entries, '');
  }
}

process.stdout.write(`${lines.join('\n').replace(/\n{3,}/g, '\n\n')}\n`);
