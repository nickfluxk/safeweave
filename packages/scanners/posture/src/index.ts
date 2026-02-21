import { createServer } from './server.js';

const port = parseInt(process.env.PORT || '9008', 10);
const server = createServer();

server.listen(port, '0.0.0.0', () => {
  console.log(`SafeWeave API Posture scanner listening on port ${port}`);
});
