import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import type { ScanRequest, Finding, Severity } from '@safeweave/common';

interface PostureCheck {
  id: string;
  title: string;
  severity: Severity;
  cwe: string;
  description: string;
  remediation: string;
  /** Returns files where this issue is detected */
  check: (content: string, filePath: string) => boolean;
}

// ── Posture Checks ──────────────────────────────────────────────────

const POSTURE_CHECKS: PostureCheck[] = [
  // ── Missing Authentication ──────────────────────────────────────
  {
    id: 'POSTURE-001',
    title: 'HTTP server without authentication middleware',
    severity: 'high',
    cwe: 'CWE-306',
    description:
      'HTTP server created without authentication middleware. All endpoints are publicly accessible. ' +
      'Look for createServer/express/fastify/koa without auth middleware like passport, express-jwt, ' +
      'or custom auth checks.',
    remediation:
      'Add authentication middleware before route handlers. Use libraries like passport, ' +
      'express-jwt, or implement API key / Bearer token validation.',
    check: (content, filePath) => {
      if (!isServerFile(content)) return false;
      // Check if any auth pattern exists
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

  // ── Missing Rate Limiting ───────────────────────────────────────
  {
    id: 'POSTURE-002',
    title: 'No rate limiting detected',
    severity: 'medium',
    cwe: 'CWE-770',
    description:
      'HTTP server without rate limiting. Vulnerable to brute force attacks, ' +
      'credential stuffing, and denial of service.',
    remediation:
      'Add rate limiting middleware: express-rate-limit, @fastify/rate-limit, ' +
      'or implement token bucket / sliding window rate limiting.',
    check: (content, filePath) => {
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

  // ── Missing Security Headers ────────────────────────────────────
  {
    id: 'POSTURE-003',
    title: 'Missing security headers',
    severity: 'medium',
    cwe: 'CWE-693',
    description:
      'HTTP server without security headers (CSP, X-Content-Type-Options, ' +
      'X-Frame-Options, HSTS). Vulnerable to clickjacking, MIME sniffing, ' +
      'and content injection attacks.',
    remediation:
      'Add security headers using helmet middleware or set them manually: ' +
      'Content-Security-Policy, X-Content-Type-Options: nosniff, ' +
      'X-Frame-Options: DENY, Strict-Transport-Security.',
    check: (content, filePath) => {
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

  // ── Missing Request Body Size Limit ─────────────────────────────
  {
    id: 'POSTURE-004',
    title: 'No request body size limit',
    severity: 'medium',
    cwe: 'CWE-770',
    description:
      'HTTP server reads request body without size constraints. An attacker ' +
      'can send extremely large payloads to exhaust server memory.',
    remediation:
      'Add body size limits: express.json({ limit: "1mb" }), or check ' +
      'Content-Length header and abort connections exceeding the threshold.',
    check: (content, filePath) => {
      if (!isServerFile(content)) return false;
      // Check if body reading has size limits
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

  // ── CORS Wildcard ───────────────────────────────────────────────
  {
    id: 'POSTURE-005',
    title: 'CORS allows all origins (wildcard)',
    severity: 'medium',
    cwe: 'CWE-346',
    description:
      'Access-Control-Allow-Origin set to * allows any website to make ' +
      'cross-origin requests to this API, potentially enabling CSRF-like attacks.',
    remediation:
      'Restrict CORS to specific trusted origins. Use an allowlist ' +
      'of domains instead of the wildcard.',
    check: (content) => {
      return /Access-Control-Allow-Origin['"]*\s*[,:=]\s*['"]?\*/.test(content) ||
        /cors\(\s*\{[^}]*origin\s*:\s*['"]\*/.test(content) ||
        /cors\(\s*\{[^}]*origin\s*:\s*true/.test(content);
    },
  },

  // ── Missing CSRF Protection ─────────────────────────────────────
  {
    id: 'POSTURE-006',
    title: 'No CSRF protection detected',
    severity: 'medium',
    cwe: 'CWE-352',
    description:
      'Server handles state-changing requests (POST/PUT/DELETE) without ' +
      'CSRF token validation. If cookies are used for authentication, ' +
      'this enables cross-site request forgery.',
    remediation:
      'Add CSRF protection using csurf middleware, double-submit cookie ' +
      'pattern, or SameSite cookie attribute.',
    check: (content, filePath) => {
      if (!isServerFile(content)) return false;
      // Only flag if using cookies/sessions AND missing CSRF
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

  // ── Plain HTTP (No TLS) ────────────────────────────────────────
  {
    id: 'POSTURE-007',
    title: 'HTTP server without TLS encryption',
    severity: 'medium',
    cwe: 'CWE-319',
    description:
      'Server uses createServer() from http module instead of https. ' +
      'All traffic including credentials transmitted in cleartext.',
    remediation:
      'Use https.createServer() with TLS certificates, or terminate ' +
      'TLS at a reverse proxy (nginx, Caddy, cloud load balancer).',
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

  // ── Error Details Exposed ───────────────────────────────────────
  {
    id: 'POSTURE-008',
    title: 'Detailed error messages exposed to clients',
    severity: 'low',
    cwe: 'CWE-209',
    description:
      'Stack traces or internal error messages sent in HTTP responses. ' +
      'This leaks implementation details useful for attackers.',
    remediation:
      'Return generic error messages to clients. Log detailed errors ' +
      'server-side only. Use error handling middleware.',
    check: (content) => {
      return /\.stack/.test(content) &&
        /(res\.send|res\.json|res\.write|JSON\.stringify)/.test(content) &&
        /err(or)?\.stack/.test(content);
    },
  },

  // ── Missing Logging / Audit Trail ───────────────────────────────
  {
    id: 'POSTURE-009',
    title: 'No request logging or audit trail',
    severity: 'low',
    cwe: 'CWE-778',
    description:
      'HTTP server without request logging. Security events like failed ' +
      'auth attempts, suspicious requests, and errors go unrecorded.',
    remediation:
      'Add request logging middleware (morgan, pino-http, winston). ' +
      'Log method, URL, status code, IP, and user agent at minimum.',
    check: (content, filePath) => {
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

  // ── Unsafe Deserialization ──────────────────────────────────────
  {
    id: 'POSTURE-010',
    title: 'Unsafe JSON.parse without try-catch',
    severity: 'medium',
    cwe: 'CWE-502',
    description:
      'JSON.parse called on external input without try-catch. Malformed ' +
      'input will crash the request handler or the entire process.',
    remediation:
      'Always wrap JSON.parse in try-catch when parsing external input. ' +
      'Return a 400 status code for malformed JSON.',
    check: (content) => {
      // Look for JSON.parse not inside try block
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (/JSON\.parse/.test(lines[i])) {
          // Check if within a try block (rough heuristic)
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

  // ── Insecure Default Binding ────────────────────────────────────
  {
    id: 'POSTURE-011',
    title: 'Server binds to all interfaces (0.0.0.0)',
    severity: 'low',
    cwe: 'CWE-668',
    description:
      'Server listens on 0.0.0.0, making it accessible from all network ' +
      'interfaces including public networks.',
    remediation:
      'Bind to 127.0.0.1 for local-only access, or ensure proper ' +
      'firewall rules are in place for production.',
    check: (content) => {
      return /['"]0\.0\.0\.0['"]/.test(content) &&
        /listen/.test(content);
    },
  },

  // ── Missing Input Validation ────────────────────────────────────
  {
    id: 'POSTURE-012',
    title: 'No input validation library or schema validation detected',
    severity: 'medium',
    cwe: 'CWE-20',
    description:
      'No runtime input validation found. TypeScript type assertions are ' +
      'erased at runtime and provide no protection against malformed data.',
    remediation:
      'Use a validation library like zod, joi, yup, or ajv to validate ' +
      'all external input at API boundaries.',
    check: (content, filePath) => {
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

// ── Helpers ──────────────────────────────────────────────────────────

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

function collectSourceFiles(dir: string): { path: string; content: string }[] {
  const results: { path: string; content: string }[] = [];

  function walk(currentDir: string) {
    let entries;
    try {
      entries = readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist') continue;
        walk(fullPath);
      } else if (entry.isFile() && SCAN_EXTENSIONS.has(extname(entry.name))) {
        try {
          const content = readFileSync(fullPath, 'utf-8');
          const relativePath = fullPath.replace(dir + '/', '');
          results.push({ path: relativePath, content });
        } catch {
          // skip unreadable files
        }
      }
    }
  }

  walk(dir);
  return results;
}

// ── Main ─────────────────────────────────────────────────────────────

export async function runPostureChecks(request: ScanRequest): Promise<Finding[]> {
  const rootDir = request.context.rootDir || '.';
  const findings: Finding[] = [];

  // Collect files to analyze
  let sourceFiles: { path: string; content: string }[];

  if (request.files.length === 1 && !request.files[0].content) {
    // Directory mode — scan all source files recursively
    sourceFiles = collectSourceFiles(request.files[0].path || rootDir);
  } else {
    // File mode — use provided files
    sourceFiles = request.files
      .filter((f) => f.content)
      .map((f) => ({ path: f.path, content: f.content! }));
  }

  // Run each posture check against each file
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

  // Deduplicate — same check ID on same file only reported once
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.id}:${f.file}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
