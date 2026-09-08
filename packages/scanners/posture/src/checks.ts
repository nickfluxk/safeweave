import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, extname, resolve as resolvePath, sep } from 'node:path';
import type { ScanRequest, Finding, Severity, ScanOutcome } from '@safeweave/common';

interface PostureCheck {
  id: string;
  title: string;
  severity: Severity;
  cwe: string;
  description: string;
  remediation: string;
  /** Returns true if this issue is detected in the file */
  check: (content: string, filePath: string) => boolean;
}

const POSTURE_CHECKS: PostureCheck[] = [
  {
    id: 'POSTURE-001',
    title: 'HTTP server without authentication middleware',
    severity: 'high',
    cwe: 'CWE-306',
    description:
      'HTTP server created without authentication middleware. All endpoints are publicly accessible.',
    remediation:
      'Add authentication middleware before route handlers. Use libraries like passport, express-jwt, or implement API key / Bearer token validation.',
    check: (content) => {
      if (!isServerFile(content)) return false;
      const authPatterns = [
        /auth(?:enticate|orize|Middleware|Guard|Check)/i,
        /passport\./,
        /express-jwt/,
        /jsonwebtoken/,
        /bearer/i,
        /api[_-]?key/i,
        /session\(/,
        /requireAuth/,
        /isAuthenticated/,
        /verifyToken/,
        /checkAuth/,
      ];
      return !authPatterns.some((p) => p.test(content));
    },
  },
  {
    id: 'POSTURE-002',
    title: 'No rate limiting detected',
    severity: 'medium',
    cwe: 'CWE-770',
    description:
      'HTTP server without rate limiting. Vulnerable to brute force attacks, credential stuffing, and denial of service.',
    remediation:
      'Add rate limiting middleware: express-rate-limit, @fastify/rate-limit, or implement token bucket / sliding window rate limiting.',
    check: (content) => {
      if (!isServerFile(content)) return false;
      const rateLimitPatterns = [
        /rate[_-]?limit/i,
        /rateLimit/,
        /throttle/i,
        /express-rate-limit/,
        /express-slow-down/,
        /@fastify\/rate-limit/,
        /token[_-]?bucket/i,
        /sliding[_-]?window/i,
      ];
      return !rateLimitPatterns.some((p) => p.test(content));
    },
  },
  {
    id: 'POSTURE-003',
    title: 'Missing security headers',
    severity: 'medium',
    cwe: 'CWE-693',
    description:
      'HTTP server without security headers (CSP, X-Content-Type-Options, X-Frame-Options, HSTS).',
    remediation:
      'Add security headers using helmet middleware or set them manually: Content-Security-Policy, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Strict-Transport-Security.',
    check: (content) => {
      if (!isServerFile(content)) return false;
      const headerPatterns = [
        /helmet/i,
        /Content-Security-Policy/,
        /X-Content-Type-Options/,
        /X-Frame-Options/,
        /Strict-Transport-Security/,
      ];
      return !headerPatterns.some((p) => p.test(content));
    },
  },
  {
    id: 'POSTURE-004',
    title: 'No request body size limit',
    severity: 'medium',
    cwe: 'CWE-770',
    description:
      'HTTP server reads request body without size constraints. An attacker can send extremely large payloads to exhaust server memory.',
    remediation:
      'Add body size limits: express.json({ limit: "1mb" }), or check Content-Length header and abort connections exceeding the threshold.',
    check: (content) => {
      if (!isServerFile(content)) return false;
      const hasBodyReading =
        /req\.on\s*\(\s*['"]data['"]/.test(content) ||
        /body[_-]?parser/i.test(content) ||
        /express\.json/i.test(content);
      if (!hasBodyReading) return false;

      const sizeLimitPatterns = [
        /limit\s*[:=]/i,
        /MAX_BODY_SIZE/i,
        /maxBodySize/i,
        /content-length/i,
        /totalSize\s*>/,
        /bodyLimit/i,
      ];
      return !sizeLimitPatterns.some((p) => p.test(content));
    },
  },
  {
    id: 'POSTURE-005',
    title: 'CORS allows all origins (wildcard)',
    severity: 'medium',
    cwe: 'CWE-346',
    description:
      'Access-Control-Allow-Origin set to * allows any website to make cross-origin requests to this API.',
    remediation:
      'Restrict CORS to specific trusted origins. Use an allowlist of domains instead of the wildcard.',
    check: (content) => {
      return /Access-Control-Allow-Origin['"]*\s*[,:=]\s*['"]?\*/.test(content) ||
        /cors\(\s*\{[^}]*origin\s*:\s*['"]\*/.test(content) ||
        /cors\(\s*\{[^}]*origin\s*:\s*true/.test(content);
    },
  },
  {
    id: 'POSTURE-006',
    title: 'No CSRF protection detected',
    severity: 'medium',
    cwe: 'CWE-352',
    description:
      'Server handles state-changing requests without CSRF token validation. If cookies are used for authentication, this enables cross-site request forgery.',
    remediation:
      'Add CSRF protection using csurf middleware, double-submit cookie pattern, or SameSite cookie attribute.',
    check: (content) => {
      if (!isServerFile(content)) return false;
      const usesCookies =
        /cookie/i.test(content) || /session/i.test(content);
      if (!usesCookies) return false;

      const csrfPatterns = [
        /csrf/i,
        /xsrf/i,
        /csurf/,
        /SameSite/i,
        /anti[_-]?forgery/i,
      ];
      return !csrfPatterns.some((p) => p.test(content));
    },
  },
  {
    id: 'POSTURE-007',
    title: 'HTTP server without TLS encryption',
    severity: 'medium',
    cwe: 'CWE-319',
    description:
      'Server uses createServer() from http module instead of https. All traffic including credentials transmitted in cleartext.',
    remediation:
      'Use https.createServer() with TLS certificates, or terminate TLS at a reverse proxy (nginx, Caddy, cloud load balancer).',
    check: (content) => {
      const hasHttpServer =
        /createServer\s*\(/.test(content) &&
        /from\s+['"]node:?http['"]/.test(content);
      if (!hasHttpServer) return false;
      const hasHttps =
        /from\s+['"]node:?https['"]/.test(content) ||
        /https\.createServer/.test(content);
      return !hasHttps;
    },
  },
  {
    id: 'POSTURE-008',
    title: 'Detailed error messages exposed to clients',
    severity: 'low',
    cwe: 'CWE-209',
    description:
      'Stack traces or internal error messages sent in HTTP responses. This leaks implementation details useful for attackers.',
    remediation:
      'Return generic error messages to clients. Log detailed errors server-side only. Use error handling middleware.',
    check: (content) => {
      return /\.stack/.test(content) &&
        /(res\.send|res\.json|res\.write|JSON\.stringify)/.test(content) &&
        /err(or)?\.stack/.test(content);
    },
  },
  {
    id: 'POSTURE-009',
    title: 'No request logging or audit trail',
    severity: 'low',
    cwe: 'CWE-778',
    description:
      'HTTP server without request logging. Security events like failed auth attempts go unrecorded.',
    remediation:
      'Add request logging middleware (morgan, pino-http, winston). Log method, URL, status code, IP, and user agent at minimum.',
    check: (content) => {
      if (!isServerFile(content)) return false;
      const loggingPatterns = [
        /morgan\(/,
        /pino[_-]?http/i,
        /winston/,
        /logger\.info/,
        /logger\.log/,
        /console\.log\(\s*['"`].*request/i,
        /createLogger/,
        /accessLog/i,
      ];
      return !loggingPatterns.some((p) => p.test(content));
    },
  },
  {
    id: 'POSTURE-010',
    title: 'Unsafe JSON.parse without try-catch',
    severity: 'medium',
    cwe: 'CWE-502',
    description:
      'JSON.parse called on external input without try-catch. Malformed input will crash the request handler or the entire process.',
    remediation:
      'Always wrap JSON.parse in try-catch when parsing external input. Return a 400 status code for malformed JSON.',
    check: (content) => {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (/JSON\.parse/.test(lines[i])) {
          let inTry = false;
          for (let j = Math.max(0, i - 5); j < i; j++) {
            if (/try\s*\{/.test(lines[j])) inTry = true;
          }
          if (!inTry) return true;
        }
      }
      return false;
    },
  },
  {
    id: 'POSTURE-011',
    title: 'Server binds to all interfaces (0.0.0.0)',
    severity: 'low',
    cwe: 'CWE-668',
    description:
      'Server listens on 0.0.0.0, making it accessible from all network interfaces including public networks.',
    remediation:
      'Bind to 127.0.0.1 for local-only access, or ensure proper firewall rules are in place for production.',
    check: (content) => {
      return /['"]0\.0\.0\.0['"]/.test(content) &&
        /listen/.test(content);
    },
  },
  {
    id: 'POSTURE-012',
    title: 'No input validation library or schema validation detected',
    severity: 'medium',
    cwe: 'CWE-20',
    description:
      'No runtime input validation found. TypeScript type assertions are erased at runtime and provide no protection against malformed data.',
    remediation:
      'Use a validation library like zod, joi, yup, or ajv to validate all external input at API boundaries.',
    check: (content) => {
      if (!isServerFile(content)) return false;
      const validationPatterns = [
        /zod/,
        /joi\./,
        /yup\./,
        /ajv/i,
        /class-validator/,
        /validate\(/,
        /validateScanRequest/,
        /\.parse\s*\(/,
        /\.safeParse\s*\(/,
      ];
      return !validationPatterns.some((p) => p.test(content));
    },
  },
];

function isServerFile(content: string): boolean {
  return (
    /createServer/.test(content) ||
    /express\(\)/.test(content) ||
    /fastify\(\)/.test(content) ||
    /new Koa\(\)/.test(content) ||
    /new Hono\(\)/.test(content) ||
    /app\.(get|post|put|delete|use)\(/.test(content)
  );
}

const SCAN_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java', '.rb',
]);

const MAX_POSTURE_FILES = 5000;
const MAX_POSTURE_DEPTH = 20;
const MAX_FILE_SIZE = 1024 * 1024; // 1MB

function collectSourceFiles(dir: string): { path: string; content: string }[] {
  const results: { path: string; content: string }[] = [];

  function walk(currentDir: string, depth: number) {
    if (results.length >= MAX_POSTURE_FILES || depth > MAX_POSTURE_DEPTH) return;
    let entries;
    try {
      entries = readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (results.length >= MAX_POSTURE_FILES) break;
      const fullPath = join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist' || entry.name === '__pycache__' || entry.name === 'vendor' || entry.name === '.next') continue;
        walk(fullPath, depth + 1);
      } else if (entry.isFile() && SCAN_EXTENSIONS.has(extname(entry.name))) {
        try {
          const stat = statSync(fullPath);
          if (stat.size > MAX_FILE_SIZE) continue;
          const content = readFileSync(fullPath, 'utf-8');
          const relativePath = fullPath.replace(dir + '/', '');
          results.push({ path: relativePath, content });
        } catch {
          // skip unreadable files
        }
      }
    }
  }

  walk(dir, 0);
  return results;
}

export async function runPostureChecks(request: ScanRequest): Promise<ScanOutcome> {
  const findings: Finding[] = [];
  const warnings: string[] = [];

  let sourceFiles: { path: string; content: string }[];

  if (request.files.length === 1 && !request.files[0].content) {
    // A bare path means "walk this directory yourself", which the gateway does
    // for local scans. The walk root is THIS service's own working directory,
    // never the client-supplied context.rootDir: this scanner has no auth, so a
    // direct caller could otherwise set rootDir:"/" and read the host
    // filesystem. Real scans arrive as file content (the else branch) and are
    // unaffected; sibling scanners avoid this by materializing content instead.
    const root = resolvePath(process.cwd());
    const requested = resolvePath(root, request.files[0].path || '.');
    if (requested !== root && !requested.startsWith(root + sep)) {
      return {
        findings: [],
        warnings: [`Refused to scan "${request.files[0].path}": it resolves outside the scan root. No posture checks ran.`],
      };
    }
    sourceFiles = collectSourceFiles(requested);
    if (sourceFiles.length === 0) {
      warnings.push('No readable source files were found, so posture results are INCOMPLETE.');
    }
  } else {
    sourceFiles = request.files
      .filter((f) => f.content)
      .map((f) => ({ path: f.path, content: f.content! }));
  }

  for (const file of sourceFiles) {
    for (const check of POSTURE_CHECKS) {
      try {
        if (check.check(file.content, file.path)) {
          findings.push({
            id: check.id,
            severity: check.severity,
            title: check.title,
            description: check.description,
            file: file.path,
            cwe: check.cwe,
            remediation: check.remediation,
          });
        }
      } catch {
        // Individual check failure shouldn't stop other checks
      }
    }
  }

  const seen = new Set<string>();
  const deduped = findings.filter((f) => {
    const key = `${f.id}:${f.file}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return { findings: deduped, warnings };
}
