FROM node:20-slim
RUN apt-get update && apt-get install -y python3 python3-pip && pip3 install --break-system-packages semgrep && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json ./
RUN node -e "const p=require('./package.json'); delete p.dependencies['@safeweave/common']; require('fs').writeFileSync('package.json', JSON.stringify(p,null,2))"
RUN npm install --omit=dev
COPY dist/ ./dist/
ENV PORT=9001
EXPOSE 9001
CMD ["node", "dist/index.js"]
