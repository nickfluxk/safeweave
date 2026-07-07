import { createServer } from './server.js';

const PORT = parseInt(process.env.PORT || '9006', 10);
const server = createServer();
server.listen(PORT, () => {
  console.log(`dast scanner listening on port ${PORT}`);
});
