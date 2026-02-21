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
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import type { Finding, ScanResult, Severity } from '@safeweave/common';
import { loadConfig } from './config.js';
import { Router } from './router/index.js';
import { ProfileManager } from './profiles/index.js';

// Map host filesystem paths to container mount paths.
// Docker volume: ${SCAN_DIR:-/Users}:/scan:ro
// So /Users/foo/bar → /scan/foo/bar
const SCAN_MOUNT = process.env.SCAN_MOUNT || '/scan';
const SCAN_DIR = process.env.SCAN_DIR || '/Users';

function toContainerPath(hostPath: string): string {
  // If the path already starts with the mount point, return as-is
  if (hostPath.startsWith(SCAN_MOUNT + '/') || hostPath === SCAN_MOUNT) return hostPath;
  // If the path starts with the host scan dir, translate it
  if (hostPath.startsWith(SCAN_DIR + '/')) {
    return SCAN_MOUNT + hostPath.slice(SCAN_DIR.length);
  }
  // If it starts with / and the translated version exists, use it
  const translated = SCAN_MOUNT + hostPath;
  if (existsSync(translated)) return translated;
  // Fall back to original path
  return hostPath;
}

// Recursively collect source files from a directory for scanning
const SOURCE_EXTS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.java', '.go', '.rb', '.php', '.rs',
  '.c', '.cpp', '.h', '.hpp', '.cs', '.swift',
  '.yaml', '.yml', '.json', '.toml', '.xml',
  '.tf', '.hcl', '.dockerfile',
  '.sh', '.bash', '.zsh',
]);

function collectFiles(dir: string, maxFiles = 5000): Array<{ path: string; content: string }> {
  const files: Array<{ path: string; content: string }> = [];
  const walk = (d: string) => {
    if (files.length >= maxFiles) return;
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (files.length >= maxFiles) break;
      const fullPath = join(d, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist' || entry.name === '__pycache__' || entry.name === 'vendor') continue;
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        const basename = entry.name.toLowerCase();
        if (SOURCE_EXTS.has(ext) || basename === 'dockerfile' || basename === 'makefile') {
          try {
            const stat = statSync(fullPath);
            if (stat.size > 1024 * 1024) continue; // Skip files > 1MB
            const content = readFileSync(fullPath, 'utf-8');
            files.push({ path: fullPath, content });
          } catch { /* skip unreadable files */ }
        }
      }
    }
  };
  walk(dir);
  return files;
}

export function createServer(projectDir: string): Server {
  const config = loadConfig(projectDir);
  const router = new Router(config);
  const profileManager = new ProfileManager();
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
          },
          required: ['file_path'],
        },
      },
      {
        name: 'scan_project',
        description: 'Run a full security scan on the project',
        inputSchema: {
          type: 'object' as const,
          properties: {
            directory: { type: 'string', description: 'Project root directory' },
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
            profile: { type: 'string', description: 'Profile name (standard, hardened, owasp, soc2, pci-dss, hipaa)', enum: ['standard', 'hardened', 'owasp', 'soc2', 'pci-dss', 'hipaa'] },
          },
          required: ['profile'],
        },
      },
      {
        name: 'get_security_score',
        description: 'Get overall security posture score for the project',
        inputSchema: {
          type: 'object' as const,
          properties: {
            directory: { type: 'string', description: 'Project root directory' },
          },
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
        description: 'Scan infrastructure-as-code files (Terraform, Dockerfile, Kubernetes) for misconfigurations',
        inputSchema: {
          type: 'object' as const,
          properties: {
            directory: { type: 'string', description: 'Project root directory' },
          },
        },
      },
      {
        name: 'check_container',
        description: 'Scan container images for known vulnerabilities',
        inputSchema: {
          type: 'object' as const,
          properties: {
            directory: { type: 'string', description: 'Project root directory containing Dockerfile' },
          },
        },
      },
      {
        name: 'check_license',
        description: 'Check dependency license compliance — detect problematic licenses like AGPL, GPL',
        inputSchema: {
          type: 'object' as const,
          properties: {
            directory: { type: 'string', description: 'Project root directory' },
          },
        },
      },
      {
        name: 'dast_check',
        description: 'Run lightweight dynamic security testing on API endpoints',
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
        description: 'Check API security posture — detect missing auth, rate limiting, security headers, CORS misconfig, missing input validation, and other security control gaps',
        inputSchema: {
          type: 'object' as const,
          properties: {
            directory: { type: 'string', description: 'Project root directory' },
          },
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const params = (args || {}) as Record<string, string>;
    const profile = profileManager.getActive();

    switch (name) {
      case 'scan_file': {
        const filePath = params.file_path;
        const containerPath = toContainerPath(filePath);
        let content: string | undefined;
        try {
          content = readFileSync(containerPath, 'utf-8');
        } catch {
          return { content: [{ type: 'text', text: JSON.stringify({ error: `Cannot read file: ${filePath} (resolved to ${containerPath})` }) }], isError: true };
        }
        const result = await router.scanWith('sast', {
          files: [{ path: filePath, content }],
          profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
          context: { rootDir: projectDir },
        });
        lastFindings = [...lastFindings, ...result.findings];
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      case 'scan_project': {
        const dir = params.directory || projectDir;
        const containerDir = toContainerPath(dir);
        const files = collectFiles(containerDir);
        const result = await router.scanAll({
          files: files.length > 0 ? files : [{ path: containerDir }],
          profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
          context: { rootDir: containerDir },
        });
        lastFindings = result.findings;
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      case 'scan_dependencies': {
        const dir = params.directory || projectDir;
        const containerDir = toContainerPath(dir);
        const result = await router.scanWith('deps', {
          files: [{ path: 'package.json' }],
          profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
          context: { rootDir: containerDir },
        });
        lastFindings = [...lastFindings, ...result.findings];
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      case 'get_findings': {
        let filtered = lastFindings;
        if (params.severity) {
          filtered = filtered.filter(f => f.severity === params.severity);
        }
        if (params.file) {
          filtered = filtered.filter(f => f.file.includes(params.file));
        }
        return { content: [{ type: 'text', text: JSON.stringify({ findings: filtered, total: filtered.length }) }] };
      }

      case 'set_profile': {
        try {
          profileManager.setActive(params.profile);
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
        const finding = lastFindings.find(f => f.id === params.finding_id);
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

      case 'scan_iac': {
        const dir = params.directory || projectDir;
        const containerDir = toContainerPath(dir);
        const result = await router.scanWith('iac', {
          files: [{ path: containerDir }],
          profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
          context: { rootDir: containerDir },
        });
        lastFindings = [...lastFindings, ...result.findings];
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      case 'check_container': {
        const dir = params.directory || projectDir;
        const containerDir = toContainerPath(dir);
        const result = await router.scanWith('container', {
          files: [{ path: containerDir }],
          profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
          context: { rootDir: containerDir },
        });
        lastFindings = [...lastFindings, ...result.findings];
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      case 'check_license': {
        const dir = params.directory || projectDir;
        const containerDir = toContainerPath(dir);
        const result = await router.scanWith('license', {
          files: [{ path: containerDir }],
          profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
          context: { rootDir: containerDir },
        });
        lastFindings = [...lastFindings, ...result.findings];
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      case 'dast_check': {
        const dir = params.directory || projectDir;
        const containerDir = toContainerPath(dir);
        const result = await router.scanWith('dast', {
          files: [{ path: containerDir }],
          profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
          context: { rootDir: containerDir, target_url: params.target_url },
        });
        lastFindings = [...lastFindings, ...result.findings];
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      case 'check_posture': {
        const dir = params.directory || projectDir;
        const containerDir = toContainerPath(dir);
        const result = await router.scanWith('posture', {
          files: [{ path: containerDir }],
          profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
          context: { rootDir: containerDir },
        });
        lastFindings = [...lastFindings, ...result.findings];
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
        description: 'Conduct a security review of specific code.',
        arguments: [
          { name: 'code', description: 'The code to review', required: true },
          { name: 'language', description: 'Programming language', required: false },
          { name: 'context', description: 'Additional context', required: false },
        ],
      },
      {
        name: 'threat_model',
        description: 'Generate a threat model using STRIDE.',
        arguments: [
          { name: 'system', description: 'System description', required: true },
          { name: 'data_flows', description: 'Data flow description', required: false },
          { name: 'trust_boundaries', description: 'Trust boundary description', required: false },
        ],
      },
      {
        name: 'secure_code_guide',
        description: 'Get secure coding guidelines.',
        arguments: [
          { name: 'topic', description: 'Topic to get guidance on', required: true },
          { name: 'profile', description: 'Compliance profile', required: false },
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
          messages: [{
            role: 'user',
            content: {
              type: 'text',
              text: `You are a senior application security engineer. Analyze the following code${lang} for security vulnerabilities.${ctx}\n\nCode:\n\`\`\`\n${promptArgs.code}\n\`\`\``,
            },
          }],
        };
      }
      case 'threat_model': {
        const dataFlows = promptArgs.data_flows ? `\n\nData Flows:\n${promptArgs.data_flows}` : '';
        const trustBoundaries = promptArgs.trust_boundaries ? `\n\nTrust Boundaries:\n${promptArgs.trust_boundaries}` : '';
        return {
          messages: [{
            role: 'user',
            content: {
              type: 'text',
              text: `Conduct a STRIDE threat model for:\n\n${promptArgs.system}${dataFlows}${trustBoundaries}`,
            },
          }],
        };
      }
      case 'secure_code_guide': {
        const profileName = promptArgs.profile || 'standard';
        const profileData = profileManager.getProfile(profileName);
        const profileContext = profileData ? `\n\nAlign with "${profileData.name}" profile: ${profileData.description}` : '';
        return {
          messages: [{
            role: 'user',
            content: {
              type: 'text',
              text: `Provide secure coding guidance on: ${promptArgs.topic}${profileContext}`,
            },
          }],
        };
      }
      default:
        throw new Error(`Unknown prompt: ${name}`);
    }
  });

  return server;
}

function calculateScore(findings: Finding[]): { score: number; status: string; breakdown: Record<string, number> } {
  if (findings.length === 0) {
    return { score: 100, status: 'no_findings', breakdown: {} };
  }

  const weights: Record<Severity, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
  let deductions = 0;
  const breakdown: Record<string, number> = {};

  for (const f of findings) {
    deductions += weights[f.severity] || 0;
    breakdown[f.severity] = (breakdown[f.severity] || 0) + 1;
  }

  const score = Math.max(0, 100 - deductions);
  const status = score >= 80 ? 'good' : score >= 50 ? 'needs_attention' : 'critical';

  return { score, status, breakdown };
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
