# syntax=docker/dockerfile:1
FROM golang:1.22 as builder
WORKDIR /app
COPY go.mod .
RUN go mod download
COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates && rm -rf /var/lib/apt/lists/*
# Install xray binary (v1.8.4)
RUN curl -L -o /root/xray.zip https://github.com/XTLS/Xray-core/releases/download/v1.8.4/Xray-linux-64.zip \
    && unzip -o /root/xray.zip -d /root/xray-v184 \
    && chmod +x /root/xray-v184/xray
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o vpnpannel ./cmd/server

FROM gcr.io/distroless/base-debian12
WORKDIR /srv
COPY --from=builder /app/vpnpannel /srv/vpnpannel
COPY --from=builder /app/web /srv/web
# Provide xray in runtime image for link testing
COPY --from=builder /root/xray-v184/xray /usr/local/bin/xray
ENV APP_PORT=8080
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/srv/vpnpannel"]



