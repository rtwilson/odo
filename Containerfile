FROM golang:1.23-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/odo ./cmd/odo

FROM alpine:3.21
RUN addgroup -S odo && adduser -S -G odo odo
WORKDIR /app
COPY --from=build /out/odo /usr/local/bin/odo
COPY config /config
RUN mkdir -p /data && chown -R odo:odo /data /config
USER odo
ENV APP_ADDR=:8080
ENV APP_DB_PATH=/data/app.db
ENV APP_CONFIG_DIR=/config
ENV APP_ADMIN_API_KEY=
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/odo"]
