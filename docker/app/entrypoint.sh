#!/bin/sh
set -e

cd /app
go mod download
exec go run ./cmd/server
#!/bin/sh
set -e

# Ensure we are in project root inside container
cd /app

# Download modules (cached in go-modules volume)
go mod download

# Run the server (main at cmd/server/main.go)
exec go run ./cmd/server

#!/bin/bash

chown -R www-data:www-data /app

go mod download

go run cmd/app/server/main.go
