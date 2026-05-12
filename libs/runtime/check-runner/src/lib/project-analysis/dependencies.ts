import type {
  AnalyzedFile,
  ObservedFact,
  ObservedRange,
} from '@critiq/core-rules-engine';
import { basename } from 'node:path/posix';

export type DependencyEcosystem =
  | 'cargo'
  | 'composer'
  | 'gem'
  | 'go'
  | 'maven'
  | 'npm'
  | 'python';

export interface DependencyManifestInput {
  path: string;
  text: string;
}

export interface ProjectDependencyFact {
  ecosystem: DependencyEcosystem;
  packageName: string;
  versionRange: string;
  manifestPath: string;
  policyId?: 'dompurify-unsafe-version' | 'marked-unsafe-version';
}

const npmDependencySections = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
] as const;

function fileStartRange(text: string): ObservedRange {
  const firstLine = text.split(/\r?\n/u, 1)[0] ?? '';

  return {
    startLine: 1,
    startColumn: 1,
    endLine: 1,
    endColumn: Math.max(1, firstLine.length + 1),
  };
}

function normalizeVersionRange(versionRange: string): string {
  return versionRange.trim().replace(/^[~^<>=\s]+/u, '');
}

function parseMajorMinorPatch(versionRange: string): [number, number, number] | undefined {
  const normalized = normalizeVersionRange(versionRange);
  const match = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?/u.exec(normalized);

  if (!match) {
    return undefined;
  }

  return [
    Number.parseInt(match[1], 10),
    Number.parseInt(match[2] ?? '0', 10),
    Number.parseInt(match[3] ?? '0', 10),
  ];
}

function isBelow(versionRange: string, minimum: [number, number, number]): boolean {
  const current = parseMajorMinorPatch(versionRange);

  if (!current) {
    return false;
  }

  for (let index = 0; index < minimum.length; index += 1) {
    if (current[index] !== minimum[index]) {
      return current[index] < minimum[index];
    }
  }

  return false;
}

function packagePolicyId(
  packageName: string,
  versionRange: string,
): ProjectDependencyFact['policyId'] {
  const normalized = packageName.toLowerCase();

  if (normalized === 'dompurify' && isBelow(versionRange, [2, 4, 0])) {
    return 'dompurify-unsafe-version';
  }

  if (normalized === 'marked' && isBelow(versionRange, [4, 0, 10])) {
    return 'marked-unsafe-version';
  }

  return undefined;
}

function collectNpmDependencies(input: DependencyManifestInput): ProjectDependencyFact[] {
  if (basename(input.path) !== 'package.json') {
    return [];
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(input.text);
  } catch {
    return [];
  }

  if (!parsed || typeof parsed !== 'object') {
    return [];
  }

  const root = parsed as Record<string, unknown>;
  const facts: ProjectDependencyFact[] = [];

  for (const sectionName of npmDependencySections) {
    const section = root[sectionName];

    if (!section || typeof section !== 'object') {
      continue;
    }

    for (const [packageName, rawVersion] of Object.entries(
      section as Record<string, unknown>,
    )) {
      if (typeof rawVersion !== 'string') {
        continue;
      }

      facts.push({
        ecosystem: 'npm',
        packageName,
        versionRange: rawVersion,
        manifestPath: input.path,
        policyId: packagePolicyId(packageName, rawVersion),
      });
    }
  }

  return facts;
}

function collectLineBasedDependencies(
  input: DependencyManifestInput,
): ProjectDependencyFact[] {
  const name = basename(input.path);
  const facts: ProjectDependencyFact[] = [];

  for (const line of input.text.split(/\r?\n/u)) {
    const trimmed = line.trim();
    let match: RegExpExecArray | null = null;
    let ecosystem: DependencyEcosystem | undefined;

    if (name === 'requirements.txt' || name === 'requirements.lock') {
      match = /^([A-Za-z0-9_.-]+)\s*(?:==|~=|>=|<=|>|<)\s*([A-Za-z0-9_.-]+)/u.exec(
        trimmed,
      );
      ecosystem = 'python';
    } else if (name === 'Gemfile' || name === 'Gemfile.lock') {
      match = /^gem\s+["']([^"']+)["']\s*,\s*["']([^"']+)["']/u.exec(trimmed);
      ecosystem = 'gem';
    } else if (name === 'go.mod') {
      match = /^(?:require\s+)?([A-Za-z0-9_./-]+)\s+v?([A-Za-z0-9_.-]+)/u.exec(
        trimmed,
      );
      ecosystem = 'go';
    }

    if (!match || !ecosystem) {
      continue;
    }

    facts.push({
      ecosystem,
      packageName: match[1],
      versionRange: match[2],
      manifestPath: input.path,
    });
  }

  return facts;
}

function collectRegexDependencies(input: DependencyManifestInput): ProjectDependencyFact[] {
  const name = basename(input.path);
  const facts: ProjectDependencyFact[] = [];
  let ecosystem: DependencyEcosystem | undefined;
  let pattern: RegExp | undefined;

  if (name === 'composer.json' || name === 'composer.lock') {
    ecosystem = 'composer';
    pattern = /"([a-z0-9_.-]+\/[a-z0-9_.-]+)"\s*:\s*"([^"]+)"/giu;
  } else if (name === 'Cargo.toml' || name === 'Cargo.lock') {
    ecosystem = 'cargo';
    pattern = /(?:name\s*=\s*"([^"]+)"[\s\S]{0,160}?version\s*=\s*"([^"]+)"|^([A-Za-z0-9_-]+)\s*=\s*"([^"]+)")/gmu;
  } else if (name === 'pom.xml' || name.endsWith('.gradle')) {
    ecosystem = 'maven';
    pattern = /(?:<artifactId>([^<]+)<\/artifactId>[\s\S]{0,160}?<version>([^<]+)<\/version>|['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^'"]+)['"])/gu;
  }

  if (!ecosystem || !pattern) {
    return facts;
  }

  for (const match of input.text.matchAll(pattern)) {
    const packageName = match[1] ?? match[3];
    const versionRange = match[2] ?? match[4] ?? match[5];

    if (!packageName || !versionRange) {
      continue;
    }

    facts.push({
      ecosystem,
      packageName,
      versionRange,
      manifestPath: input.path,
    });
  }

  return facts;
}

export function isDependencyManifestPath(path: string): boolean {
  const name = basename(path);

  return (
    name === 'package.json' ||
    name === 'package-lock.json' ||
    name === 'yarn.lock' ||
    name === 'pnpm-lock.yaml' ||
    name === 'go.mod' ||
    name === 'pom.xml' ||
    name.endsWith('.gradle') ||
    name === 'composer.json' ||
    name === 'composer.lock' ||
    name === 'requirements.txt' ||
    name === 'requirements.lock' ||
    name === 'Gemfile' ||
    name === 'Gemfile.lock' ||
    name === 'Cargo.toml' ||
    name === 'Cargo.lock'
  );
}

export function collectProjectDependencyFacts(
  manifests: readonly DependencyManifestInput[],
): ProjectDependencyFact[] {
  return manifests.flatMap((input) => [
    ...collectNpmDependencies(input),
    ...collectLineBasedDependencies(input),
    ...collectRegexDependencies(input),
  ]);
}

export function appendDependencyFacts(
  analyzedFiles: readonly AnalyzedFile[],
  dependencyFacts: readonly ProjectDependencyFact[],
): void {
  const targetFile = analyzedFiles.find(
    (file) => file.language === 'typescript' || file.language === 'javascript',
  );

  if (!targetFile) {
    return;
  }

  const facts = (targetFile.semantics ??= {}).controlFlow ??= {
    functions: [],
    blocks: [],
    edges: [],
    facts: [],
  };

  for (const dependency of dependencyFacts) {
    if (!dependency.policyId) {
      continue;
    }

    const factKind = `security.dependency.${dependency.policyId}`;
    const observedFact: ObservedFact = {
      id: [
        'project',
        factKind,
        dependency.policyId,
        dependency.packageName,
        dependency.manifestPath,
      ].join(':'),
      kind: factKind,
      appliesTo: 'project',
      range: fileStartRange(targetFile.text),
      text: `${dependency.packageName}@${dependency.versionRange}`,
      props: {
        ecosystem: dependency.ecosystem,
        packageName: dependency.packageName,
        versionRange: dependency.versionRange,
        manifestPath: dependency.manifestPath,
        policyId: dependency.policyId,
      },
    };

    if (!facts.facts.some((candidate) => candidate.id === observedFact.id)) {
      facts.facts.push(observedFact);
    }
  }
}
