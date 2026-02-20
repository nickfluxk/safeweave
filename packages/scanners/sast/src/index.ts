import { createServer } from './server.js';

const PORT = parseInt(process.env.PORT || '9001', 10);
const server = createServer();
server.listen(PORT, () => {
  console.log(`SAST scanner listening on port ${PORT}`);
});
