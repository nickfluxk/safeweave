import { createServer } from './server.js';

const PORT = parseInt(process.env.PORT || '9005', 10);
const server = createServer();
server.listen(PORT, () => {
  console.log(`container scanner listening on port ${PORT}`);
});
