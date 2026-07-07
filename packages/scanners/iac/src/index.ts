import { createServer } from './server.js';

const PORT = parseInt(process.env.PORT || '9004', 10);
const server = createServer();
server.listen(PORT, () => {
  console.log(`iac scanner listening on port ${PORT}`);
});
