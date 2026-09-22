FROM golang:1.23-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod ./
RUN go mod download
COPY . .
ARG ODO_VERSION=dev
ARG ODO_COMMIT=unknown
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X example.org/odo/internal/api.Version=${ODO_VERSION} -X example.org/odo/internal/api.Commit=${ODO_COMMIT}" -o /out/odo ./cmd/odo

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && addgroup -S odo && adduser -S -G odo odo
WORKDIR /app
COPY --from=build /out/odo /usr/local/bin/odo
COPY config /etc/odo
RUN mkdir -p /var/lib/odo /etc/odo && chown -R odo:odo /var/lib/odo /etc/odo
USER odo
ENV APP_ADDR=:8080
ENV APP_ENV=development
ENV APP_DATA_DIR=/var/lib/odo
ENV APP_DB_PATH=/var/lib/odo/odo.db
ENV APP_CONFIG_DIR=/etc/odo
ENV APP_ADMIN_API_KEY=
ENV APP_PUBLIC_URL=
ENV APP_TRUST_PROXY_HEADERS=false
ENV APP_ACCESS_LOG_FORMAT=privacy
ENV APP_ACCESS_LOG_PATH=
VOLUME ["/var/lib/odo", "/etc/odo"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1:8080/api/v1/health >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/odo"]
