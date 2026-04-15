FROM golang:1.26-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /fcgi-proxy .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=builder /fcgi-proxy /usr/local/bin/fcgi-proxy

USER nobody

EXPOSE 8080

ENTRYPOINT ["fcgi-proxy"]
CMD ["-config", "/etc/fcgi-proxy/config.json"]
