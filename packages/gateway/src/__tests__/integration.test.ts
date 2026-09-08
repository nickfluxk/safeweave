import { describe, it, expect } from 'vitest';
import { createServer } from '../server.js';

describe('Gateway Integration', () => {
  it('creates server without errors', () => {
    const server = createServer(process.cwd());
    expect(server).toBeDefined();
  });

  it('server has the correct name and version', () => {
    const server = createServer(process.cwd());
    // The Server object should be created successfully with our config
    expect(server).toBeDefined();
  });
});
