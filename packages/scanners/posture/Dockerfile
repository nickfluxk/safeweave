FROM node:20-slim
WORKDIR /app
COPY package.json ./
RUN node -e "const p=require('./package.json'); delete p.dependencies['@safeweave/common']; require('fs').writeFileSync('package.json', JSON.stringify(p,null,2))"
RUN npm install --omit=dev
COPY dist/ ./dist/
COPY common-dist/ ./node_modules/@safeweave/common/
RUN addgroup --system safeweave && adduser --system --ingroup safeweave safeweave
USER safeweave
ENV PORT=9008
EXPOSE 9008
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD node -e "fetch('http://localhost:9008/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "dist/index.js"]
