# syntax=docker/dockerfile:1
FROM golang:1.22 as builder
WORKDIR /app
COPY go.mod .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o vpnpannel ./cmd/server

FROM gcr.io/distroless/base-debian12
WORKDIR /srv
COPY --from=builder /app/vpnpannel /srv/vpnpannel
COPY --from=builder /app/web /srv/web
ENV APP_PORT=8080
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/srv/vpnpannel"]



