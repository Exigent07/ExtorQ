# syntax=docker/dockerfile:1
#
# ExtorQ Security Console image.
# - Multi-stage: dependencies and build stages are discarded; the runtime stage holds only the
#   Next.js standalone server, its traced node_modules and the static assets.
# - Runs as uid/gid 1001 (no shell login); application files are owned by root and read-only.
# - No secrets at build time or in the image: the API token, account passwords and the session
#   signing secret are mounted at runtime and passed by file path (EXTORQ_*_FILE).
# - Base image pinned by version and digest (Node 22 LTS; the local toolchain is Node 20.11).

ARG NODE_IMAGE=node:22.23.5-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a

FROM ${NODE_IMAGE} AS deps
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1 COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
RUN pnpm install --frozen-lockfile

FROM ${NODE_IMAGE} AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1 NODE_ENV=production COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN pnpm build

FROM ${NODE_IMAGE} AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
RUN addgroup -S -g 1001 nextjs \
 && adduser -S -D -H -u 1001 -G nextjs -s /sbin/nologin nextjs \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn* /usr/local/bin/yarn /usr/local/bin/yarnpkg
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
USER 1001:1001
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "server.js"]
