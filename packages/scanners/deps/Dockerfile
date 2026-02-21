FROM node:20-slim AS builder

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    ruby ruby-dev \
    curl wget git build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install pip-audit
RUN pip3 install --break-system-packages pip-audit

# Install Go 1.23 (detect architecture)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then GOARCH="arm64"; else GOARCH="amd64"; fi && \
    wget -qO- "https://go.dev/dl/go1.23.6.linux-${GOARCH}.tar.gz" | tar xz -C /usr/local
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
RUN CGO_ENABLED=0 go install golang.org/x/vuln/cmd/govulncheck@latest

# Install Rust + cargo-audit
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install cargo-audit

# Install bundle-audit
RUN gem install bundler-audit

WORKDIR /app

# Copy package files
COPY package.json ./

# Install all deps (including dev for TypeScript compilation)
RUN node -e "const p=require('./package.json'); delete p.dependencies['@safeweave/common']; require('fs').writeFileSync('package.json', JSON.stringify(p,null,2))"
RUN npm install && npm install typescript @types/node

# Create a self-contained tsconfig (can't use extends since base is outside context)
RUN echo '{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","declaration":true,"sourceMap":true,"strict":true,"esModuleInterop":true,"skipLibCheck":true,"forceConsistentCasingInFileNames":true,"outDir":"dist","rootDir":"src"},"include":["src/**/*"],"exclude":["src/__tests__/**"]}' > tsconfig.json

# Install @safeweave/common (real package with types + runtime code)
COPY common-dist/ ./node_modules/@safeweave/common/

# Copy source and compile
COPY src/ ./src/
RUN npx tsc

# Clean up dev deps, reinstall prod only
RUN rm -rf node_modules && \
    npm install --omit=dev 2>/dev/null || true

# Install @safeweave/common runtime (validateScanRequest)
COPY common-dist/ ./node_modules/@safeweave/common/

ENV PORT=9002
EXPOSE 9002
CMD ["node", "dist/index.js"]
