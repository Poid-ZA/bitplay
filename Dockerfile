# Stage 1: Build Go backend
FROM golang:1.24 AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o torrent-stream

# Stage 2: Build frontend
FROM node:20 AS node-builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --production
COPY src/input.css ./
RUN npm run build

# Stage 3: Final image
FROM scratch
WORKDIR /app
COPY --from=go-builder /app/torrent-stream .
COPY --from=node-builder /app/dist/output.css ./dist/output.css
COPY static ./static
ENV TORRENT_CLIENT_KEY=""
EXPOSE 3347
ENTRYPOINT ["/app/torrent-stream"]
