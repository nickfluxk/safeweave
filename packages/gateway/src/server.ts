import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { readFileSync, existsSync } from 'node:fs';
import { basename, join, relative, resolve, sep } from 'node:path';
import type { Finding, ScanResult } from '@safeweave/common';
import { calculateScore, deriveRepoSlug, normalizeRepoSlug } from '@safeweave/common';
import { loadConfig } from './config.js';
import { Router } from './router/index.js';
import { ProfileManager } from './profiles/index.js';
import { LicenseClient } from './license.js';
import { collectLocalFiles, materializeFiles } from './collect-files.js';

interface ClientFile { path: string; content: string }
interface ResolvedInput {
  rootDir: string;
  files: Array<{ path: string; content?: string }>;
  cleanup: () => void;
}

/** Resolve scan input: collect local files or materialize remote files */
function resolveInput(
  directory: string | undefined,
  clientFiles: ClientFile[] | undefined,
  fallbackDir: string,
  allowLocalFiles = true,
  confineToRoot = false,
): ResolvedInput {
  const dir = directory || fallbackDir;

  if (allowLocalFiles && existsSync(dir)) {
    // Local mode — collect files from disk.
    //
    // Containment belongs HERE, not at the top of the function: it must gate
    // the disk read only. A remote caller legitimately sends its own absolute
    // `directory` as metadata next to `files` content, and checking before
    // that branch would refuse them. Over the HTTP bridge a token-holding
    // caller could otherwise pass directory:"/root" and have the secrets
    // scanner walk it and hand back the credentials it matched — the wider of
    // the two holes, since scan_project walks a whole tree.
    if (confineToRoot) {
      const root = resolve(fallbackDir);
      const target = resolve(root, dir);
      if (target !== root && !target.startsWith(root + sep)) {
        throw new Error(`Refusing to read outside the project root: ${dir}`);
      }
    }
    const files = collectLocalFiles(dir);
    return { rootDir: dir, files, cleanup: () => {} };
  }

  // Remote mode — need client-provided files
  if (!clientFiles || clientFiles.length === 0) {
    throw new Error(
      `Directory "${dir}" is not accessible on this server. ` +
      `When using SafeWeave remotely, pass file contents in the "files" parameter. ` +
      `Example: { "directory": "myproject", "files": [{ "path": "src/index.ts", "content": "..." }] }`
    );
  }

  const materialized = materializeFiles(clientFiles);
  return {
    rootDir: materialized.rootDir,
    files: clientFiles,
    cleanup: materialized.cleanup,
  };
}

const GATED_SCANNERS = new Set(['iac', 'container', 'dast', 'license', 'posture']);

/** Tool name -> scanner for the licensed tools that share one handler body. */
const GATED_TOOL_SCANNERS: Record<string, string> = {
  scan_iac: 'iac',
  check_container: 'container',
  check_license: 'license',
  check_posture: 'posture',
};
const GATED_PROFILES = new Set(['hardened', 'owasp', 'soc2', 'pci-dss', 'hipaa']);
const LICENSE_SERVER_URL = process.env.SAFEWEAVE_LICENSE_URL || 'https://license.safeweave.dev';

const SCANNER_LABELS: Record<string, string> = {
  iac: 'IaC scanning',
  container: 'container scanning',
  dast: 'DAST scanning',
  license: 'license compliance',
  posture: 'security posture',
};

function upgradeFindings(blockedScanners: string[]): Finding[] {
  return blockedScanners.map((s) => ({
    id: `LICENSE-UPGRADE-${s.toUpperCase()}`,
    severity: 'info' as const,
    title: `Upgrade to Self-Hosted Pro to unlock ${SCANNER_LABELS[s] || s}`,
    description: `${SCANNER_LABELS[s] || s} requires a SafeWeave Self-Hosted Pro license.`,
    file: '',
    remediation: 'Visit https://safeweave.dev/pricing to upgrade',
  }));
}

/**
 * @param allowLocalFiles      May this server read files from its own disk at all?
 * @param servedOverHttp Whether this instance answers remote callers via the
 *   HTTP bridge rather than local stdio. Two things follow from it:
 *   file reads are confined to projectDir, so a trusted (token-holding) but
 *   remote caller cannot turn one into arbitrary file access on the host; and
 *   repo attribution is NOT derived from projectDir, which over HTTP is our own
 *   container rather than the caller's checkout. The local stdio server is the
 *   developer's own process on their own machine, so neither applies there.
 */
export function createServer(
  projectDir: string,
  overrideLicenseKey?: string,
  allowLocalFiles = true,
  servedOverHttp = false,
): Server {
  const config = loadConfig(projectDir);
  const router = new Router(config);
  const profileManager = new ProfileManager();
  // Load an optional custom profile from .safeweave/profile.yaml (extends a
  // built-in via deepMerge). No-op when the file is absent — behavior unchanged.
  try {
    profileManager.loadCustomProfile(projectDir);
  } catch (err) {
    // Never use stdout: it is the MCP stdio transport channel.
    console.error(`Failed to load custom profile: ${(err as Error).message}`);
  }
  // Over HTTP, projectDir is this container — deriving a slug from it would file
  // every tenant's every repo under the same name, and because the dashboard
  // reads scans back with DISTINCT ON (repo) each one would overwrite the last.
  // Remote callers attribute per request instead; see reportUsage(repo).
  const licenseClient = new LicenseClient(
    LICENSE_SERVER_URL,
    servedOverHttp ? undefined : deriveRepoSlug(projectDir),
  );
  const licenseKey = overrideLicenseKey || config.licenseKey;

  // A remote caller's repo can only come from what THEY told us; locally the
  // client's constructor default already holds the right slug. Without this,
  // every repo scanned over HTTP shares one bucket and overwrites the last.
  const repoFor = (directory?: unknown): string | undefined =>
    servedOverHttp ? normalizeRepoSlug(basename(String(directory || ''))) : undefined;

  let lastFindings: Finding[] = [];

  const server = new Server(
    { name: 'safeweave', version: '0.1.0' },
    { capabilities: { tools: {}, resources: {}, prompts: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'scan_file',
        description: 'Scan a single file for security vulnerabilities',
        inputSchema: {
          type: 'object' as const,
          properties: {
            file_path: { type: 'string', description: 'Path to the file to scan' },
            content: { type: 'string', description: 'File content (required when running remotely)' },
          },
          required: ['file_path'],
        },
      },
      {
        name: 'scan_project',
        description: 'Run a full security scan on the project. Collects files automatically when directory is accessible, or accepts files array for remote scanning.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            directory: { type: 'string', description: 'Project root directory' },
            files: {
              type: 'array', description: 'Files with content for remote scanning',
              items: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] },
            },
          },
        },
      },
      {
        name: 'scan_dependencies',
        description: 'Audit project dependencies for known CVEs',
        inputSchema: {
          type: 'object' as const,
          properties: {
            directory: { type: 'string', description: 'Project root directory' },
            files: {
              type: 'array', description: 'Files with content for remote scanning',
              items: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] },
            },
          },
        },
      },
      {
        name: 'get_findings',
        description: 'Get current scan findings, optionally filtered by severity',
        inputSchema: {
          type: 'object' as const,
          properties: {
            severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
            file: { type: 'string', description: 'Filter by file path' },
          },
        },
      },
      {
        name: 'set_profile',
        description: 'Switch the active compliance profile',
        inputSchema: {
          type: 'object' as const,
          properties: {
            profile: { type: 'string', description: 'Profile name (standard, hardened, owasp, soc2, pci-dss, hipaa, or custom when a .safeweave/profile.yaml is present)', enum: ['standard', 'hardened', 'owasp', 'soc2', 'pci-dss', 'hipaa', 'custom'] },
          },
          required: ['profile'],
        },
      },
      {
        name: 'get_security_score',
        description: 'Get overall security posture score for the project',
        inputSchema: {
          type: 'object' as const,
          properties: {},
        },
      },
      {
        name: 'suggest_fix',
        description: 'Get remediation suggestions for a specific finding',
        inputSchema: {
          type: 'object' as const,
          properties: {
            finding_id: { type: 'string', description: 'The finding ID to get fix suggestions for' },
          },
          required: ['finding_id'],
        },
      },
      {
        name: 'scan_iac',
        description: 'Scan infrastructure-as-code files (Terraform, Dockerfile, Kubernetes) for misconfigurations (Self-Hosted Pro)',
        inputSchema: {
          type: 'object' as const,
          properties: {
            directory: { type: 'string', description: 'Project root directory' },
            files: {
              type: 'array', description: 'Files with content for remote scanning',
              items: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] },
            },
          },
        },
      },
      {
        name: 'check_container',
        description: 'Scan container images for known vulnerabilities (Self-Hosted Pro)',
        inputSchema: {
          type: 'object' as const,
          properties: {
            directory: { type: 'string', description: 'Project root directory containing Dockerfile' },
            files: {
              type: 'array', description: 'Files with content for remote scanning',
              items: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] },
            },
          },
        },
      },
      {
        name: 'check_license',
        description: 'Check dependency license compliance — detect problematic licenses like AGPL, GPL (Self-Hosted Pro)',
        inputSchema: {
          type: 'object' as const,
          properties: {
            directory: { type: 'string', description: 'Project root directory' },
            files: {
              type: 'array', description: 'Files with content for remote scanning',
              items: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] },
            },
          },
        },
      },
      {
        name: 'dast_check',
        description: 'Run lightweight dynamic security testing on API endpoints (Self-Hosted Pro)',
        inputSchema: {
          type: 'object' as const,
          properties: {
            directory: { type: 'string', description: 'Project root directory' },
            target_url: { type: 'string', description: 'Base URL of the running application to test' },
          },
        },
      },
      {
        name: 'check_posture',
        description: 'Check API security posture — detect missing auth, rate limiting, security headers, CORS misconfig, missing input validation, and other security control gaps (Self-Hosted Pro)',
        inputSchema: {
          type: 'object' as const,
          properties: {
            directory: { type: 'string', description: 'Project root directory' },
            files: {
              type: 'array', description: 'Files with content for remote scanning',
              items: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] },
            },
          },
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const params = (args || {}) as Record<string, unknown>;
    const profile = profileManager.getActive();

    switch (name) {
      case 'scan_file': {
        const filePath = params.file_path as string;
        let content = params.content as string | undefined;
        if (!content) {
          if (!allowLocalFiles) {
            return { content: [{ type: 'text', text: JSON.stringify({ error: `This instance does not read files from disk. Pass the file body in the "content" parameter.` }) }], isError: true };
          }
          const root = resolve(projectDir);
          const target = resolve(root, filePath);
          // Over the HTTP bridge an unrestricted absolute path would be an
          // arbitrary-file-read primitive against the host. Locally it is just
          // the developer reading their own files, so leave that alone.
          if (servedOverHttp && target !== root && !target.startsWith(root + sep)) {
            return { content: [{ type: 'text', text: JSON.stringify({ error: `Refusing to read outside the project root: ${filePath}` }) }], isError: true };
          }
          try {
            content = readFileSync(target, 'utf-8');
          } catch {
            return { content: [{ type: 'text', text: JSON.stringify({ error: `Cannot read file: ${filePath}. If running remotely, pass file content via the "content" parameter.` }) }], isError: true };
          }
        }
        // Send a path RELATIVE to the project root. materializeFiles() writes
        // request files into a temp dir via safeJoin, which rejects absolute
        // paths as traversal and drops them — so an MCP client passing the
        // absolute path it normally uses got a confident "no issues" on a file
        // that was never written, and therefore never scanned.
        const rel = relative(resolve(projectDir), resolve(projectDir, filePath)) || basename(filePath);
        const scanPath = rel.startsWith('..') ? basename(filePath) : rel;

        const result = await router.scanWith('sast', {
          files: [{ path: scanPath, content }],
          profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
          context: { rootDir: projectDir },
        });

        // Report findings against the path the caller actually asked about.
        for (const f of result.findings) {
          if (f.file === scanPath) f.file = filePath;
        }

        lastFindings = [...lastFindings, ...result.findings];
        licenseClient.reportUsage(licenseKey, 'sast', result.findings, typeof result.metadata.duration_ms === 'number' ? result.metadata.duration_ms : 0);
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      case 'scan_project': {
        let resolved: ResolvedInput;
        try {
          resolved = resolveInput(params.directory as string | undefined, params.files as ClientFile[] | undefined, projectDir, allowLocalFiles, servedOverHttp);
        } catch (err) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: (err as Error).message }) }], isError: true };
        }
        try {
          const blocked: string[] = [];
          for (const s of GATED_SCANNERS) {
            if (!(await licenseClient.isFeatureAllowed(licenseKey, s))) {
              blocked.push(s);
            }
          }
          const result = await router.scanAll(
            {
              files: resolved.files,
              profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
              context: { rootDir: resolved.rootDir },
            },
            new Set(blocked),
          );
          if (blocked.length > 0) {
            result.findings.push(...upgradeFindings(blocked));
          }
          lastFindings = result.findings;
          licenseClient.reportUsage(licenseKey, 'all', result.findings, typeof result.metadata.duration_ms === 'number' ? result.metadata.duration_ms : 0, repoFor(params.directory));
          return { content: [{ type: 'text', text: JSON.stringify(result) }] };
        } finally {
          resolved.cleanup();
        }
      }

      case 'scan_dependencies': {
        let resolved: ResolvedInput;
        try {
          resolved = resolveInput(params.directory as string | undefined, params.files as ClientFile[] | undefined, projectDir, allowLocalFiles, servedOverHttp);
        } catch (err) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: (err as Error).message }) }], isError: true };
        }
        try {
          const result = await router.scanWith('deps', {
            files: resolved.files,
            profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
            context: { rootDir: resolved.rootDir },
          });
          lastFindings = [...lastFindings, ...result.findings];
          licenseClient.reportUsage(licenseKey, 'deps', result.findings, typeof result.metadata.duration_ms === 'number' ? result.metadata.duration_ms : 0, repoFor(params.directory));
          return { content: [{ type: 'text', text: JSON.stringify(result) }] };
        } finally {
          resolved.cleanup();
        }
      }

      case 'get_findings': {
        let filtered = lastFindings;
        if (params.severity) {
          filtered = filtered.filter(f => f.severity === (params.severity as string));
        }
        if (params.file) {
          filtered = filtered.filter(f => f.file.includes(params.file as string));
        }
        return { content: [{ type: 'text', text: JSON.stringify({ findings: filtered, total: filtered.length }) }] };
      }

      case 'set_profile': {
        try {
          const profileName = params.profile as string;
          if (GATED_PROFILES.has(profileName)) {
            const feature = profileName === 'hardened' ? 'hardened_profile' : 'compliance_profiles';
            const allowed = await licenseClient.isFeatureAllowed(licenseKey, feature);
            if (!allowed) {
              return {
                content: [{ type: 'text', text: JSON.stringify({ error: `The '${profileName}' profile requires a SafeWeave Self-Hosted Pro license. Visit https://safeweave.dev/pricing` }) }],
                isError: true,
              };
            }
          }
          profileManager.setActive(profileName);
          const active = profileManager.getActive();
          return { content: [{ type: 'text', text: JSON.stringify({ profile: active.name, description: active.description }) }] };
        } catch (err) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: (err as Error).message }) }], isError: true };
        }
      }

      case 'get_security_score': {
        const score = calculateScore(lastFindings);
        return { content: [{ type: 'text', text: JSON.stringify(score) }] };
      }

      case 'suggest_fix': {
        const finding = lastFindings.find(f => f.id === (params.finding_id as string));
        if (!finding) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: `Finding not found: ${params.finding_id}` }) }], isError: true };
        }
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              finding_id: finding.id,
              title: finding.title,
              remediation: finding.remediation,
              code_snippet: finding.code_snippet,
              fix_snippet: finding.fix_snippet,
            }),
          }],
        };
      }

      // iac / container / license / posture are all the same flow: check the
      // licensed feature, resolve input, run one scanner, record usage.
      case 'scan_iac':
      case 'check_container':
      case 'check_license':
      case 'check_posture': {
        const scanner = GATED_TOOL_SCANNERS[name];
        const allowed = await licenseClient.isFeatureAllowed(licenseKey, scanner);
        if (!allowed) {
          return { content: [{ type: 'text', text: JSON.stringify({ findings: upgradeFindings([scanner]), metadata: { scanner, version: '0.1.0', duration_ms: 0, files_scanned: 0, timestamp: new Date().toISOString() } }) }] };
        }
        let resolved: ResolvedInput;
        try {
          resolved = resolveInput(params.directory as string | undefined, params.files as ClientFile[] | undefined, projectDir, allowLocalFiles, servedOverHttp);
        } catch (err) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: (err as Error).message }) }], isError: true };
        }
        try {
          const result = await router.scanWith(scanner, {
            files: resolved.files,
            profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
            context: { rootDir: resolved.rootDir },
          });
          lastFindings = [...lastFindings, ...result.findings];
          licenseClient.reportUsage(licenseKey, scanner, result.findings, typeof result.metadata.duration_ms === 'number' ? result.metadata.duration_ms : 0, repoFor(params.directory));
          return { content: [{ type: 'text', text: JSON.stringify(result) }] };
        } finally {
          resolved.cleanup();
        }
      }

      case 'dast_check': {
        const dir = (params.directory as string) || projectDir;
        const allowed = await licenseClient.isFeatureAllowed(licenseKey, 'dast');
        if (!allowed) {
          return { content: [{ type: 'text', text: JSON.stringify({ findings: upgradeFindings(['dast']), metadata: { scanner: 'dast', version: '0.1.0', duration_ms: 0, files_scanned: 0, timestamp: new Date().toISOString() } }) }] };
        }
        const result = await router.scanWith('dast', {
          files: [{ path: dir }],
          profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
          context: { rootDir: dir, target_url: params.target_url as string },
        });
        lastFindings = [...lastFindings, ...result.findings];
        licenseClient.reportUsage(licenseKey, 'dast', result.findings, typeof result.metadata.duration_ms === 'number' ? result.metadata.duration_ms : 0, repoFor(params.directory));
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      default:
        return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
    }
  });

  // --- MCP Resources ---

  server.setRequestHandler(ListResourcesRequestSchema, async () => ({
    resources: [
      { uri: 'safeweave://profiles', name: 'Available Profiles', mimeType: 'application/json' },
      { uri: 'safeweave://findings/summary', name: 'Findings Summary', mimeType: 'application/json' },
      { uri: 'safeweave://config', name: 'Current Configuration', mimeType: 'application/json' },
      ...profileManager.listProfiles().map((p) => ({
        uri: `safeweave://compliance/${p}`,
        name: `Compliance Profile: ${p}`,
        mimeType: 'application/json',
      })),
    ],
  }));

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;

    switch (uri) {
      case 'safeweave://profiles':
        return {
          contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(profileManager.listProfiles()) }],
        };
      case 'safeweave://findings/summary': {
        const summary = summarizeFindings(lastFindings);
        return {
          contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(summary) }],
        };
      }
      case 'safeweave://config':
        return {
          contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(config) }],
        };
      default: {
        // Handle safeweave://compliance/{profile} URIs
        const complianceMatch = uri.match(/^safeweave:\/\/compliance\/(.+)$/);
        if (complianceMatch) {
          const profileData = profileManager.getProfile(complianceMatch[1]);
          if (profileData) {
            return {
              contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(profileData) }],
            };
          }
        }
        throw new Error(`Unknown resource: ${uri}`);
      }
    }
  });

  // --- MCP Prompts ---

  server.setRequestHandler(ListPromptsRequestSchema, async () => ({
    prompts: [
      {
        name: 'security_review',
        description: 'Conduct a security review of specific code. Analyzes code for vulnerabilities, suggests fixes, and rates risk.',
        arguments: [
          { name: 'code', description: 'The code to review for security issues', required: true },
          { name: 'language', description: 'Programming language of the code', required: false },
          { name: 'context', description: 'Additional context about where this code runs', required: false },
        ],
      },
      {
        name: 'threat_model',
        description: 'Generate a threat model for a system or feature. Identifies threats, attack surfaces, and mitigations using STRIDE.',
        arguments: [
          { name: 'system', description: 'Description of the system or feature to threat model', required: true },
          { name: 'data_flows', description: 'Description of data flows (who sends what to whom)', required: false },
          { name: 'trust_boundaries', description: 'Description of trust boundaries in the system', required: false },
        ],
      },
      {
        name: 'secure_code_guide',
        description: 'Get secure coding guidelines for a specific language, framework, or vulnerability class.',
        arguments: [
          { name: 'topic', description: 'The topic to get guidance on (e.g., "SQL injection in Node.js", "React XSS prevention")', required: true },
          { name: 'profile', description: 'Compliance profile to align guidance with (standard, owasp, soc2, pci-dss, hipaa)', required: false },
        ],
      },
    ],
  }));

  server.setRequestHandler(GetPromptRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const promptArgs = (args || {}) as Record<string, string>;

    switch (name) {
      case 'security_review': {
        const lang = promptArgs.language ? ` (${promptArgs.language})` : '';
        const ctx = promptArgs.context ? `\n\nContext: ${promptArgs.context}` : '';
        return {
          messages: [
            {
              role: 'user',
              content: {
                type: 'text',
                text: `You are a senior application security engineer conducting a code review. Analyze the following code${lang} for security vulnerabilities.${ctx}

For each issue found:
1. **Severity**: Rate as critical/high/medium/low/info
2. **Vulnerability**: Name the vulnerability type (e.g., SQL Injection, XSS, SSRF)
3. **CWE**: Provide the CWE identifier if applicable
4. **Location**: Point to the exact line(s)
5. **Impact**: Explain what an attacker could do
6. **Fix**: Provide a corrected code snippet

After individual findings, provide:
- **Overall Risk Rating**: critical/high/medium/low
- **Summary**: 1-2 sentence risk summary
- **Top Priority Fix**: The single most important change to make

Code to review:
\`\`\`
${promptArgs.code}
\`\`\``,
              },
            },
          ],
        };
      }

      case 'threat_model': {
        const dataFlows = promptArgs.data_flows ? `\n\nData Flows:\n${promptArgs.data_flows}` : '';
        const trustBoundaries = promptArgs.trust_boundaries ? `\n\nTrust Boundaries:\n${promptArgs.trust_boundaries}` : '';
        return {
          messages: [
            {
              role: 'user',
              content: {
                type: 'text',
                text: `You are a security architect conducting a threat modeling exercise using the STRIDE methodology. Analyze the following system.

System Description:
${promptArgs.system}${dataFlows}${trustBoundaries}

Produce a threat model with the following sections:

## 1. Attack Surface
List all entry points, interfaces, and exposed components.

## 2. STRIDE Analysis
For each threat category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege):
- **Threat**: Specific threat scenario
- **Component**: Which part of the system is affected
- **Likelihood**: High/Medium/Low
- **Impact**: High/Medium/Low
- **Risk**: Overall risk rating

## 3. Data Flow Risks
Identify where sensitive data crosses trust boundaries and what protections are needed.

## 4. Recommended Mitigations
Prioritized list of security controls to implement, ordered by risk reduction.

## 5. Security Requirements
Concrete security requirements that should be added to the backlog.`,
              },
            },
          ],
        };
      }

      case 'secure_code_guide': {
        const profileName = promptArgs.profile || 'standard';
        const profileData = profileManager.getProfile(profileName);
        const profileContext = profileData
          ? `\n\nAlign guidance with the "${profileData.name}" compliance profile: ${profileData.description}. Severity thresholds: error=${profileData.severity_thresholds.error}, warn=${profileData.severity_thresholds.warn}.`
          : '';
        return {
          messages: [
            {
              role: 'user',
              content: {
                type: 'text',
                text: `You are a secure coding expert. Provide comprehensive, practical secure coding guidance on the following topic:

Topic: ${promptArgs.topic}${profileContext}

Structure your response as:

## Overview
Brief explanation of the vulnerability class or security concern.

## Common Mistakes
Code examples showing vulnerable patterns (with comments explaining why they're dangerous).

## Secure Patterns
Code examples showing the correct, secure approach (with comments explaining the security benefit).

## Checklist
A developer checklist for preventing this class of vulnerability.

## Testing
How to verify the code is secure (specific test cases, tools, or manual checks).

## References
Relevant CWEs, OWASP entries, and documentation links.`,
              },
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown prompt: ${name}`);
    }
  });

  return server;
}

function summarizeFindings(findings: Finding[]): { total: number; by_severity: Record<string, number> } {
  const by_severity: Record<string, number> = {};
  for (const f of findings) {
    by_severity[f.severity] = (by_severity[f.severity] || 0) + 1;
  }
  return { total: findings.length, by_severity };
}

export async function startServer(projectDir: string): Promise<void> {
  const server = createServer(projectDir);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
