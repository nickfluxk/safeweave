FROM node:20-slim AS builder
WORKDIR /build

# Copy deps scanner package manifest (repo root is the build context)
COPY packages/scanners/deps/package.json ./

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

# Build the deps scanner
COPY packages/scanners/deps/src/ ./src/
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

# Install dependency-audit toolchain (npm/pip/go/cargo/bundler)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    ruby ruby-dev \
    curl wget git build-essential \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --break-system-packages pip-audit
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then GOARCH="arm64"; else GOARCH="amd64"; fi && \
    wget -qO- "https://go.dev/dl/go1.23.6.linux-${GOARCH}.tar.gz" | tar xz -C /usr/local
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
RUN CGO_ENABLED=0 go install golang.org/x/vuln/cmd/govulncheck@latest
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install cargo-audit
RUN gem install bundler-audit
COPY --from=builder /build/package.json ./
RUN npm install --omit=dev

COPY --from=builder /build/node_modules/@safeweave/common/ ./node_modules/@safeweave/common/
COPY --from=builder /build/dist/ ./dist/

ENV PORT=9002
EXPOSE 9002
CMD ["node", "dist/index.js"]
