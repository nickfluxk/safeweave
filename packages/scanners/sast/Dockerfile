FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip git && pip3 install --break-system-packages semgrep && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json ./
RUN node -e "const p=require('./package.json'); delete p.dependencies['@safeweave/common']; require('fs').writeFileSync('package.json', JSON.stringify(p,null,2))"
RUN npm install --omit=dev
COPY dist/ ./dist/
COPY common-dist/ ./node_modules/@safeweave/common/
COPY rules/ ./rules/
RUN addgroup --system safeweave && adduser --system --home /home/safeweave --ingroup safeweave safeweave
USER safeweave
ENV PORT=9001
EXPOSE 9001
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD node -e "fetch('http://localhost:9001/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "dist/index.js"]
