# Build stage
FROM golang:1.24-alpine AS builder

# Install necessary build tools
RUN apk add --no-cache git

# Set working directory for the build
WORKDIR /app

# Copy go module files to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy all source files including client directory
COPY . .

# Build the Go app with static linking, stripping debug info
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o main .

# Final stage
FROM scratch

# Copy CA certificates for HTTPS connections
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Set working directory
WORKDIR /app

# Copy the compiled binary from builder
COPY --from=builder /app/main /app/main

# Copy client directory and set permissions
COPY --from=builder /app/client /app/client/
RUN chmod -R 755 /app/client

# Create config directory with strict permissions
RUN mkdir /app/config && chmod 700 /app/config

# Create non-root user and set ownership
RUN adduser -D -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose the application port
EXPOSE 3347

# Health check to verify the application is running
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3347/api/v1/settings || exit 1

# Metadata labels
LABEL maintainer="Your Name <your.email@example.com>"
LABEL version="1.0"
LABEL description="Secure Go torrent client for self-hosted environments"

# Environment variable for encryption key (must be set at runtime)
# Example: docker run -e TORRENT_CLIENT_KEY="your-secure-key" ...
ENV TORRENT_CLIENT_KEY=""

# Command to run the application
CMD ["/app/main"]
