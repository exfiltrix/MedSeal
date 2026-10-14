# MedSeal website (Next.js standalone server). NEXT_PUBLIC_API_URL is baked into the browser bundle
# at build time: the public URL of the backend API as the browser sees it (behind the proxy).
FROM node:22-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL NEXT_PUBLIC_USE_MOCK=0 NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN addgroup -S medseal && adduser -S -G medseal medseal
COPY --from=build --chown=medseal:medseal /src/.next/standalone ./
COPY --from=build --chown=medseal:medseal /src/.next/static ./.next/static
USER medseal
EXPOSE 3000
CMD ["node", "server.js"]
