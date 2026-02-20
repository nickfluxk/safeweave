import { createServer } from './server.js';

const PORT = parseInt(process.env.PORT || '9002', 10);
const server = createServer();
server.listen(PORT, () => {
  console.log(`Dependency auditor listening on port ${PORT}`);
});
