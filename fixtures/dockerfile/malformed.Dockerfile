FROM alpine:3.20
BOGUS value
123-not-an-instruction
RUN apk add --no-cache \
    ca-certificates \
    curl
