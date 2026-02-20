FROM node:20-slim
RUN apt-get update && apt-get install -y wget unzip && \
    wget -qO /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin && rm /tmp/nuclei.zip && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json ./
RUN node -e "const p=require('./package.json'); delete p.dependencies['@safeweave/common']; require('fs').writeFileSync('package.json', JSON.stringify(p,null,2))"
RUN npm install --omit=dev
COPY dist/ ./dist/
ENV PORT=9006
EXPOSE 9006
CMD ["node", "dist/index.js"]
