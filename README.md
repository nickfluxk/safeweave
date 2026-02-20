# SafeWeave — Self-Hosted

AI-native security scanning with 7 scanners, MCP integration, and compliance profiles. Run entirely on your own infrastructure.

## Quick Start

```bash
git clone https://github.com/safeweave/safeweave.git
cd safeweave
docker compose up
```

That's it. All 7 scanners will be available at `http://localhost:9000`.

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
      "url": "http://localhost:9000/mcp"
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

Override scanner addresses with environment variables:

```bash
SCANNER_SAST_HOST=my-sast-host
SCANNER_SAST_PORT=9001
SCANNER_SAST_ENABLED=true
```

## License

MIT
