ARG API_TOKEN=example-token
FROM node:22-alpine
ENV NODE_ENV=production API_KEY=example-key
ENV PASSWORD example-password
ARG BUILD_MODE=release
