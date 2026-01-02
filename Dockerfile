# Stage 1: Build the Go binary
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -o /server-auth main.go

# Stage 2: Create the final lightweight image
FROM alpine:latest

WORKDIR /app

# Create a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy the binary from the builder stage
COPY --from=builder /server-auth /app/server-auth

# Copy static assets
COPY --chown=appuser:appgroup static /app/static

# Create and set permissions for the data directory
RUN mkdir /data && chown -R appuser:appgroup /data

# Switch to the non-root user
USER appuser

# Expose the server port
EXPOSE 8080

# Run the application
CMD ["/app/server-auth", "-data-dir", "/data"]
