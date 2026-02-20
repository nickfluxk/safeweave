import { createServer } from './server.js';

const PORT = parseInt(process.env.PORT || '9007', 10);
const server = createServer();
server.listen(PORT, () => {
  console.log(`license scanner listening on port ${PORT}`);
});
