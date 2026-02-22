import { startServer } from './server.js';
import { startHttpBridge } from './http-bridge.js';
import { LicenseClient } from './license.js';

const LICENSE_SERVER_URL = process.env.SAFEWEAVE_LICENSE_URL || 'https://license.safeweave.dev';
const LICENSE_KEY = process.env.SAFEWEAVE_LICENSE_KEY || '';

async function main() {
  // Require a valid license key
  if (!LICENSE_KEY) {
    console.error('ERROR: SAFEWEAVE_LICENSE_KEY environment variable is required.');
    console.error('Get your license key at https://safeweave.dev/signup');
    process.exit(1);
  }

  // Validate the license key against the cloud server
  const licenseClient = new LicenseClient(LICENSE_SERVER_URL);
  console.log('Validating license key...');
  const validation = await licenseClient.validate(LICENSE_KEY);

  if (!validation.valid) {
    console.error('ERROR: Invalid license key. Please check your SAFEWEAVE_LICENSE_KEY.');
    console.error('Get a valid key at https://safeweave.dev/signup');
    process.exit(1);
  }

  console.log(`License validated: plan=${validation.plan}`);

  const projectDir = process.argv[2] || process.cwd();

  // Start HTTP bridge + MCP SSE server
  startHttpBridge(projectDir);

  // Start MCP stdio server for IDE integration (only when stdin is not a TTY)
  if (!process.stdin.isTTY) {
    startServer(projectDir);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
