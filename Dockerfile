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

FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
RUN npm run build

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
# Only src/ and scripts/ own compiled output — `tsc` also compiles
# test/*.ts (tsconfig.json's own `include`), which a runtime image has
# no use for.
COPY --from=build /app/dist/src ./dist/src
COPY --from=build /app/dist/scripts ./dist/scripts
# schema/*.sql is read directly at runtime by src/migrate.ts (via
# scripts/run-migrations.ts) — not compiled, so it has to ship as-is.
COPY schema ./schema

EXPOSE 8080
CMD ["node", "dist/scripts/run-server.js"]
