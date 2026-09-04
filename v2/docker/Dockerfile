#################
# Build Step
#################

FROM golang:1.25-alpine AS build

RUN apk add --no-cache git busybox-static dumb-init

WORKDIR /src

# Download modules first for layer caching
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/glauth .

#################
# Run Step
#################

FROM gcr.io/distroless/base-debian13 AS run

LABEL maintainers="Ben Yanke <ben@benyanke.com>, Jörn Friedrich Dreyer <jfd@butonic.de>, Chris F Ravenscroft <chris@voilaweb.com>" \
      org.opencontainers.image.title="GLauth" \
      org.opencontainers.image.description="A simple LDAP server for development, home use, or CI pipelines" \
      org.opencontainers.image.authors="Ben Yanke, Jörn Friedrich Dreyer, Chris F Ravenscroft" \
      org.opencontainers.image.source="https://github.com/glauth/glauth" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="latest" \
      org.opencontainers.image.url="https://github.com/glauth/glauth"

# Copy docker specific scripts
COPY docker/assets/start-standalone.sh /app/docker/start-standalone.sh
COPY docker/assets/default-config-standalone.cfg /app/docker/default-config-standalone.cfg
COPY --from=build /out/glauth /app/glauth

# Just what we need
COPY --from=build /usr/bin/dumb-init /usr/bin/dumb-init
COPY --from=build /bin/busybox.static /bin/sh
COPY --from=build /bin/busybox.static /bin/ln
COPY --from=build /bin/busybox.static /bin/rm
RUN ln /bin/sh /usr/bin/cp && ln /bin/sh /usr/bin/mkdir && rm /bin/ln /bin/rm

# Expose web and LDAP ports
EXPOSE 3893 3894 5555

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/bin/sh", "/app/docker/start-standalone.sh"]
