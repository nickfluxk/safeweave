FROM node:20-slim AS builder

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    ruby ruby-dev \
    curl wget git build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install pip-audit
RUN pip3 install --break-system-packages pip-audit

# Install Go 1.23
RUN wget -qO- https://go.dev/dl/go1.23.6.linux-amd64.tar.gz | tar xz -C /usr/local
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

# Install Rust + cargo-audit
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install cargo-audit

# Install bundle-audit
RUN gem install bundler-audit

WORKDIR /app

# Copy package files from monorepo context (Railway uses repo root as build context)
COPY packages/scanners/deps/package.json ./

# Install all deps (including dev for TypeScript compilation)
RUN node -e "const p=require('./package.json'); delete p.dependencies['@safeweave/common']; require('fs').writeFileSync('package.json', JSON.stringify(p,null,2))"
RUN npm install && npm install typescript @types/node

# Create a self-contained tsconfig (can't use extends since base is outside context)
RUN echo '{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","declaration":true,"sourceMap":true,"strict":true,"esModuleInterop":true,"skipLibCheck":true,"forceConsistentCasingInFileNames":true,"outDir":"dist","rootDir":"src"},"include":["src/**/*"],"exclude":["src/__tests__/**"]}' > tsconfig.json

# Create a stub for @safeweave/common types (only needed at compile time)
RUN mkdir -p node_modules/@safeweave/common/dist && \
    echo '{"name":"@safeweave/common","version":"0.1.0","type":"module","main":"dist/index.js","types":"dist/index.d.ts"}' > node_modules/@safeweave/common/package.json && \
    printf 'export interface ScanRequest { files: string[]; context: { rootDir?: string } }\nexport interface ScanResult { findings: Finding[]; metadata: Record<string, unknown> }\nexport interface Finding { id: string; severity: string; title: string; description: string; file: string; line?: number; column?: number; remediation?: string; cwe?: string; metadata?: Record<string, unknown> }\n' > node_modules/@safeweave/common/dist/index.d.ts && \
    printf 'export {};\n' > node_modules/@safeweave/common/dist/index.js

# Copy source and compile
COPY packages/scanners/deps/src/ ./src/
RUN npx tsc

# Clean up dev deps, reinstall prod only
RUN rm -rf node_modules && \
    npm install --omit=dev 2>/dev/null || true

ENV PORT=9002
EXPOSE 9002
CMD ["node", "dist/index.js"]
