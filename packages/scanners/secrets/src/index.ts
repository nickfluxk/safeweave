import { createServer } from './server.js';

const PORT = parseInt(process.env.PORT || '9003', 10);
const server = createServer();
server.listen(PORT, () => {
  console.log(`Secret detector listening on port ${PORT}`);
});
