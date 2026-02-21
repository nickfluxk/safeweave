FROM node:20-slim
RUN apt-get update && apt-get install -y python3 python3-pip && \
    pip3 install --break-system-packages pip-licenses && \
    npm install -g license-checker && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json ./
RUN node -e "const p=require('./package.json'); delete p.dependencies['@safeweave/common']; require('fs').writeFileSync('package.json', JSON.stringify(p,null,2))"
RUN npm install --omit=dev
COPY dist/ ./dist/
COPY common-dist/ ./node_modules/@safeweave/common/
ENV PORT=9007
EXPOSE 9007
CMD ["node", "dist/index.js"]
