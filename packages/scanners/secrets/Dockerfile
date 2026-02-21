FROM node:20-slim
RUN apt-get update && apt-get install -y wget && \
    wget -qO /tmp/gitleaks.tar.gz https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz && \
    tar xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json ./
RUN node -e "const p=require('./package.json'); delete p.dependencies['@safeweave/common']; require('fs').writeFileSync('package.json', JSON.stringify(p,null,2))"
RUN npm install --omit=dev
COPY dist/ ./dist/
COPY common-dist/ ./node_modules/@safeweave/common/
ENV PORT=9003
EXPOSE 9003
CMD ["node", "dist/index.js"]
