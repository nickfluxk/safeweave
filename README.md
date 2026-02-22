# SafeWeave — Self-Hosted

AI-native security scanning with 7 scanners, MCP integration, and compliance profiles. Run entirely on your own infrastructure.

## Quick Start

```bash
git clone https://github.com/nickfluxk/safeweave.git
cd safeweave
cp .env.example .env
```

Edit `.env` with your license key and scan directory:

```bash
# .env
SAFEWEAVE_LICENSE_KEY=your-license-key-here
SCAN_DIR=/Users/yourname/projects          # macOS
# SCAN_DIR=/home/yourname/projects         # Linux
# SCAN_DIR=/mnt/c/Users/yourname/projects  # Windows (WSL/Docker Desktop)
```

Then start the services:

```bash
docker compose up
```

All 7 scanners will be available at `http://localhost:9000`.

> **Get your license key** at [safeweave.dev/signup](https://safeweave.dev/signup). The gateway will not start without a valid key.

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

Add SafeWeave to your AI editor (Cursor, Claude Code, VS Code, Windsurf):

```json
{
  "mcpServers": {
    "safeweave": {
      "url": "http://localhost:9000/sse"
    }
  }
}
```

Then ask your AI: *"Scan this project for security vulnerabilities"*

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
| `SCAN_DIR` | Yes | Host directory to mount for scanning (e.g. your projects folder) |
| `SAFEWEAVE_LICENSE_URL` | No | License server URL (defaults to `https://license.safeweave.dev`) |

### Scanner Addresses

Override scanner addresses if running scanners separately:

```bash
SCANNER_SAST_HOST=my-sast-host
SCANNER_SAST_PORT=9001
SCANNER_SAST_ENABLED=true
```

## License

MIT
