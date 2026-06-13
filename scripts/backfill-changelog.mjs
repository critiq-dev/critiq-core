import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse } from 'yaml';

const workspaceRoot = resolve(import.meta.dirname, '..');
const packageName = '@critiq/cli';
const changelogPath = resolve(workspaceRoot, 'apps/cli/CHANGELOG.md');

const releases = [
  { version: '0.1.0', commit: '93073f76518b7d403fa8cbcd08db1b06b0c17010' },
  { version: '0.2.0', commit: '2daa17e38683c0f54bf4f957c33f05238e0b7257' },
  {
    version: '0.3.0',
    commit: '16ddbdc018c02168ab506c784d22ee52bc453244',
    extraFiles: ['.changeset/2026-06-06-cli-oss-0-3-0-release.md'],
  },
];

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

function listConsumedChangesets(releaseCommit) {
  const files = git([
    'diff-tree',
    '--no-commit-id',
    '--name-only',
    '-r',
    releaseCommit,
  ])
    .split('\n')
    .map((value) => value.trim())
    .filter(
      (path) =>
        path.startsWith('.changeset/') &&
        path.endsWith('.md') &&
        path !== '.changeset/README.md' &&
        !path.endsWith('/agent.md') &&
        path !== '.changeset/agent.md',
    );

  return files;
}

function extractFrontmatter(text) {
  if (!text.startsWith('---')) {
    return { frontmatter: '', body: text.trim() };
  }

  const closingIndex = text.indexOf('\n---', 3);
  if (closingIndex === -1) {
    return { frontmatter: '', body: text.trim() };
  }

  return {
    frontmatter: text.slice(3, closingIndex).trim(),
    body: text.slice(closingIndex + 4).trim(),
  };
}

function parseChangeset(raw, sourcePath) {
  const { frontmatter, body } = extractFrontmatter(raw);
  let bumpType = 'patch';

  if (frontmatter) {
    try {
      const parsed = parse(frontmatter);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const bumps = Object.values(parsed).filter(
          (value) => typeof value === 'string',
        );
        if (bumps.includes('major')) {
          bumpType = 'major';
        } else if (bumps.includes('minor')) {
          bumpType = 'minor';
        }
      }
    } catch {
      // keep default patch
    }
  }

  const summary = body
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .join(' ')
    .replace(/\s+/g, ' ')
    .trim();

  if (!summary) {
    return null;
  }

  return {
    bumpType,
    summary,
    sourcePath,
  };
}

function readChangesetAtCommit(releaseCommit, filePath) {
  const raw = tryGit(['show', `${releaseCommit}^:${filePath}`]);
  if (!raw) {
    return null;
  }

  return parseChangeset(raw, filePath);
}

function readWorkingTreeChangeset(filePath) {
  const absolutePath = resolve(workspaceRoot, filePath);
  const raw = readFileSync(absolutePath, 'utf8');
  return parseChangeset(raw, filePath);
}

function sectionTitle(bumpType) {
  if (bumpType === 'major') {
    return 'Major Changes';
  }

  if (bumpType === 'minor') {
    return 'Minor Changes';
  }

  return 'Patch Changes';
}

const lines = [`# ${packageName}`, ''];

for (const release of releases.slice().reverse()) {
  const entries = [];

  for (const filePath of listConsumedChangesets(release.commit)) {
    const entry = readChangesetAtCommit(release.commit, filePath);
    if (entry) {
      entries.push(entry);
    }
  }

  for (const filePath of release.extraFiles ?? []) {
    const entry = readWorkingTreeChangeset(filePath);
    if (entry) {
      entries.push(entry);
    }
  }

  if (entries.length === 0) {
    continue;
  }

  lines.push(`## ${release.version}`, '');

  const grouped = new Map([
    ['major', []],
    ['minor', []],
    ['patch', []],
  ]);

  for (const entry of entries) {
    grouped.get(entry.bumpType)?.push(entry);
  }

  for (const bumpType of ['major', 'minor', 'patch']) {
    const sectionEntries = grouped.get(bumpType) ?? [];
    if (sectionEntries.length === 0) {
      continue;
    }

    lines.push(`### ${sectionTitle(bumpType)}`, '');
    for (const entry of sectionEntries) {
      lines.push(`- ${entry.summary}`);
    }

    lines.push('');
  }
}

writeFileSync(changelogPath, `${lines.join('\n').trimEnd()}\n`);
console.log(`Wrote ${changelogPath} (${releases.length} releases).`);
