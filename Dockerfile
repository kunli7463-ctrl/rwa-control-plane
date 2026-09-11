FROM node:22.23.2-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS dependencies

WORKDIR /opt/rwa-control-plane
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
    && npm cache clean --force

FROM node:22.23.2-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS runtime

ENV NODE_ENV=production
WORKDIR /opt/rwa-control-plane

# Fixed security update; fail rather than silently use an older package.
RUN apt-get update \
    && apt-get install --no-install-recommends -y libpcre2-8-0=10.42-1+deb12u1

# npm is required only in the dependency build stage. Runtime commands use
# node directly; removing its global CLI tree does not remove app packages.
RUN rm -rf /usr/local/lib/node_modules/npm \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx

RUN groupadd --system --gid 10001 rwa \
    && useradd --system --uid 10001 --gid rwa --home-dir /nonexistent --shell /usr/sbin/nologin rwa \
    && install -d -m 0700 -o 10001 -g 10001 /var/lib/rwa-control-plane

COPY --from=dependencies --chown=rwa:rwa /opt/rwa-control-plane/node_modules ./node_modules
COPY --chown=rwa:rwa package.json package-lock.json ./
COPY --chown=rwa:rwa src ./src
COPY --chown=rwa:rwa public ./public
COPY --chown=rwa:rwa db ./db
COPY --chown=rwa:rwa scripts/migrate.js scripts/validate-production-env.js scripts/verify-groth16-artifacts.js scripts/verify-institution-callback.js ./scripts/

USER 10001:10001

EXPOSE 8765 8770
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||8765)+'/health/ready').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

CMD ["node", "src/server.js"]
