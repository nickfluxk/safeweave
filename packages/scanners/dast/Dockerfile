FROM node:20-slim AS builder
WORKDIR /build

# Copy dast scanner package manifest (repo root is the build context)
COPY packages/scanners/dast/package.json ./

# Drop the workspace dep so npm doesn't try to resolve it from the registry
RUN node -e "const p=require('./package.json'); delete p.dependencies['@safeweave/common']; require('fs').writeFileSync('package.json', JSON.stringify(p,null,2))"
RUN npm install
RUN npm install --save-dev typescript @types/node

# Build @safeweave/common from source into node_modules/@safeweave/common
COPY packages/common/src/ ./_common_src/
RUN rm -rf _common_src/__tests__
COPY packages/common/package.json ./node_modules/@safeweave/common/
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

# Build the dast scanner
COPY packages/scanners/dast/src/ ./src/
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

# Install nuclei (DAST engine)
RUN apt-get update && apt-get install -y --no-install-recommends wget unzip ca-certificates && \
    wget -qO /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin && rm /tmp/nuclei.zip && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/package.json ./
RUN npm install --omit=dev

COPY --from=builder /build/node_modules/@safeweave/common/ ./node_modules/@safeweave/common/
COPY --from=builder /build/dist/ ./dist/

ENV PORT=9006
EXPOSE 9006
CMD ["node", "dist/index.js"]
