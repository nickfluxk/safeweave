# SafeWeave

AI-native security scanning with 7 scanners, MCP integration, and compliance profiles. No Docker required — scanner binaries are downloaded automatically.

## Quick Start

Add SafeWeave to your AI editor's MCP config and start scanning immediately:

```json
{
  "mcpServers": {
    "safeweave": {
      "command": "npx",
      "args": ["safeweave-mcp"],
      "env": {
        "SAFEWEAVE_LICENSE_KEY": "your-license-key-here"
      }
    }
  }
}
```

That's it. No `brew install`, no `pip install`, no `docker compose up`. Scanner binaries are downloaded automatically on first use.

> **Get your license key** at [safeweave.dev/signup](https://safeweave.dev/signup).

### Alternative: Docker

If you prefer running via Docker:

```bash
git clone https://github.com/nickfluxk/safeweave.git
cd safeweave
cp .env.example .env   # Edit with your license key and SCAN_DIR
docker compose up
```

## How Scanner Binaries Work

SafeWeave automatically downloads and manages the scanner binaries it needs on first use.

| Tool | Version | Purpose |
|------|---------|---------|
| [gitleaks](https://github.com/gitleaks/gitleaks) | 8.21.2 | Secret and credential detection |
| [trivy](https://github.com/aquasecurity/trivy) | 0.58.0 | Container vulnerability and IaC misconfiguration scanning |
| [opengrep](https://github.com/opengrep/opengrep) | 1.16.3 | SAST analysis (Semgrep-compatible, standalone binary) |

- Binaries are resolved in order: **system PATH** → **`~/.safeweave/bin/` cache** → **auto-download**
- If you already have `gitleaks` or `trivy` installed via Homebrew/apt, those are used (never shadowed)
- For SAST, system `semgrep` is preferred; if not found, `opengrep` (a standalone Semgrep-compatible fork) is downloaded — no Python required
- Downloads happen in the background at startup — the server is ready immediately
- Versions are pinned and updated with each SafeWeave release
- If a download fails (no internet), that scanner is skipped gracefully

**Supported platforms:** macOS (arm64, x64), Linux (arm64, x64), Windows (x64)

**Cache location:**

```
~/.safeweave/
  bin/       # Downloaded binaries
  meta/      # Version metadata (JSON)
```

To force a re-download: `rm -rf ~/.safeweave/bin ~/.safeweave/meta`

## What's Included

| Scanner | Description |
|---------|-------------|
| **SAST** | Static code analysis for vulnerabilities |
| **Dependencies** | CVE scanning for package dependencies |
| **Secrets** | Detect leaked credentials and API keys |
| **IaC** | Infrastructure-as-Code misconfiguration detection |
| **Container** | Docker image vulnerability scanning |
| **DAST** | Dynamic API security testing |
| **License** | Dependency license compliance checking |

## MCP Integration

Works with any MCP-compatible editor — Cursor, Claude Code, VS Code, Windsurf, and more.

Once configured (see Quick Start above), ask your AI:

- *"Scan this project for security vulnerabilities"*
- *"Check my dependencies for CVEs"*
- *"Scan for hardcoded secrets"*
- *"Run an IaC misconfiguration scan"*

If running via Docker, use the SSE transport instead:

```json
{
  "mcpServers": {
    "safeweave": {
      "url": "http://localhost:9000/sse"
    }
  }
}
```

## HTTP API

### Health Check
```bash
curl http://localhost:9000/api/health
```

### Run a Scan
```bash
curl -X POST http://localhost:9000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"directory": "/path/to/project"}'
```

### Scan Specific Scanners
```bash
curl -X POST http://localhost:9000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"directory": "/path/to/project", "scanners": ["sast", "secrets"]}'
```

## Compliance Profiles

Built-in profiles: `standard`, `hardened`, `owasp`, `soc2`, `pci-dss`, `hipaa`

Set via MCP `set_profile` tool or create a custom `.safeweave/profile.yaml` in your project.

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SAFEWEAVE_LICENSE_KEY` | Yes | Your license key from [safeweave.dev](https://safeweave.dev) |
| `SCAN_DIR` | Docker only | Host directory to mount for scanning |
| `SAFEWEAVE_LICENSE_URL` | No | License server URL (defaults to `https://license.safeweave.dev`) |

## License

MIT
