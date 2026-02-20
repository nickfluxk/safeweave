FROM node:20-slim
RUN apt-get update && apt-get install -y wget && \
    wget -qO- https://github.com/aquasecurity/trivy/releases/download/v0.58.0/trivy_0.58.0_Linux-64bit.tar.gz | tar xz -C /usr/local/bin && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json ./
RUN node -e "const p=require('./package.json'); delete p.dependencies['@safeweave/common']; require('fs').writeFileSync('package.json', JSON.stringify(p,null,2))"
RUN npm install --omit=dev
COPY dist/ ./dist/
ENV PORT=9004
EXPOSE 9004
CMD ["node", "dist/index.js"]
