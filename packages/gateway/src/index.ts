import { startServer } from './server.js';
import { startHttpBridge } from './http-bridge.js';

const projectDir = process.argv[2] || process.cwd();

// Start HTTP bridge + MCP SSE server
startHttpBridge(projectDir);

// Start MCP stdio server for IDE integration (only when stdin is not a TTY,
// i.e. when an MCP client is piping to us)
if (!process.stdin.isTTY) {
  startServer(projectDir);
}
