FROM node:20-slim AS builder
WORKDIR /build

# Copy posture scanner package
COPY packages/scanners/posture/package.json ./

# Remove @safeweave/common from dependencies and install
RUN node -e "const p=require('./package.json'); delete p.dependencies['@safeweave/common']; require('fs').writeFileSync('package.json', JSON.stringify(p,null,2))"
RUN npm install
RUN npm install --save-dev typescript @types/node

# Build @safeweave/common types
COPY packages/common/src/ ./_common_src/
COPY packages/common/package.json ./node_modules/@safeweave/common/
RUN rm -rf _common_src/__tests__
RUN node -e " \
  const ts = { \
    compilerOptions: { \
      target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext', \
      declaration: true, sourceMap: true, strict: true, \
      esModuleInterop: true, skipLibCheck: true, forceConsistentCasingInFileNames: true, \
      types: ['node'], \
      outDir: 'node_modules/@safeweave/common/dist', rootDir: '_common_src' \
    }, \
    include: ['_common_src/**/*'] \
  }; \
  require('fs').writeFileSync('tsconfig.common.json', JSON.stringify(ts, null, 2)); \
"
RUN npx tsc -p tsconfig.common.json

# Build posture scanner
COPY packages/scanners/posture/src/ ./src/
RUN node -e " \
  const ts = { \
    compilerOptions: { \
      target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext', \
      declaration: true, sourceMap: true, strict: true, \
      esModuleInterop: true, skipLibCheck: true, forceConsistentCasingInFileNames: true, \
      types: ['node'], \
      outDir: 'dist', rootDir: 'src' \
    }, \
    include: ['src/**/*'], \
    exclude: ['src/__tests__/**'] \
  }; \
  require('fs').writeFileSync('tsconfig.json', JSON.stringify(ts, null, 2)); \
"
RUN npx tsc

# --- Production stage ---
FROM node:20-slim
WORKDIR /app

COPY --from=builder /build/package.json ./
RUN npm install --omit=dev

COPY --from=builder /build/node_modules/@safeweave/common/ ./node_modules/@safeweave/common/
COPY --from=builder /build/dist/ ./dist/

USER node
ENV PORT=9008
EXPOSE 9008
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:9008/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
ENV NODE_ENV=production
CMD ["node", "dist/index.js"]
