FROM node:20-slim AS builder
WORKDIR /build

# Copy gateway package
COPY packages/gateway/package.json ./

# Remove @safeweave/common from dependencies and install
RUN node -e "const p=require('./package.json'); delete p.dependencies['@safeweave/common']; require('fs').writeFileSync('package.json', JSON.stringify(p,null,2))"
RUN npm install
RUN npm install --save-dev typescript @types/node

# Build @safeweave/common types
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

# Build gateway
COPY packages/gateway/src/ ./src/
RUN node -e " \
  const ts = { \
    compilerOptions: { \
      target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext', \
      declaration: true, sourceMap: true, strict: true, \
      esModuleInterop: true, skipLibCheck: true, forceConsistentCasingInFileNames: true, \
      types: ['node'], \
      outDir: 'dist', rootDir: 'src' \
    }, \
    include: ['src/**/*'] \
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

EXPOSE 9000
CMD ["node", "dist/index.js"]
