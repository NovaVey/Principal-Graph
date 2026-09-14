# Multi-stage: this project's own scripts are TypeScript run through
# `tsx` in dev (no build step needed locally — see package.json's own
# scripts), but a container image ships compiled JS rather than carrying
# the whole TypeScript toolchain (`tsx`, `typescript`, ...) into a
# runtime image just to run it.
#
# One image, many uses: this repo is eleven+ separate scripts (an
# adapter each, the report, the server, policy-check, verify-chain,
# sync — see README's own Usage sections), not one long-running
# process — so this image does NOT hardcode a single ENTRYPOINT script.
# CMD defaults to the report server (the one process actually meant to
# run continuously); `docker run <image> node dist/scripts/<other>.js`
# overrides it for a one-off adapter/migration/sync run — exactly what
# docker-compose.yml (this directory) already does for its own
# `migrate`/`sync` services.

FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json tsconfig.scripts.json ./
COPY src ./src
COPY scripts ./scripts
RUN npm run build

FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
# Only the nested dist/src + dist/scripts output tsconfig.scripts.json
# produces — everything this image's CMD and docker-compose.yml's own
# `command:`s import (`../src/...` relative to dist/scripts/) lives there.
# The flat dist/index.js etc. tsconfig.build.json also produces (so
# package.json's own "main" resolves for an external npm consumer of this
# package) is a different, non-overlapping part of dist/ that a runtime
# image never imports — not copied here, nothing in it is reachable.
COPY --from=build /app/dist/src ./dist/src
COPY --from=build /app/dist/scripts ./dist/scripts
# schema/*.sql is read directly at runtime by src/migrate.ts (via
# scripts/run-migrations.ts) — not compiled, so it has to ship as-is.
COPY schema ./schema

EXPOSE 8080
CMD ["node", "dist/scripts/run-server.js"]
