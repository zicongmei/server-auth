# Stage 1: Build the Go binary
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -o /reverse-proxy main.go

# Stage 2: Create the final lightweight image
FROM alpine:latest

# Install ca-certificates for Let's Encrypt
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /reverse-proxy /app/reverse-proxy

# Create data and certs directory
RUN mkdir /app/data /app/certs

# Expose ports
EXPOSE 80
EXPOSE 443

# Run the application
# Default to listening on 443, proxying to 3000, and storing data in /app/data
ENTRYPOINT ["/app/reverse-proxy", "-data-dir", "/app/data"]
