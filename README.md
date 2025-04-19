# BitPlay: Torrent Streaming Web App

BitPlay is a secure, lightweight web application built with Go and Tailwind CSS that allows you to stream video content directly from torrents in your browser. It features a clean, accessible web UI, SOCKS5 proxy support, and integration with Prowlarr and Jackett for seamless torrent searching. Designed for self-hosting, BitPlay prioritizes security, minimalism, and auditability.

![BitPlay Home](screenshots/bitplay_home.png)

## Features

- **Direct Torrent Streaming**: Stream video files from magnet links or torrent files without downloading them completely.
- **Web-Based UI**: Access and control BitPlay through a user-friendly, accessible web interface built with Tailwind CSS and Video.js.
- **Proxy Support**: Configure a SOCKS5 proxy for all torrent-related traffic (metadata fetching, peer connections). HTTP proxies are not supported.
- **Prowlarr Integration**: Search across configured indexers via your Prowlarr instance directly within BitPlay.
- **Jackett Integration**: Use Jackett as an alternative search provider.
- **On-the-Fly Subtitle Conversion**: Converts SRT subtitles to VTT for browser compatibility.
- **Session Management**: Handles multiple torrent sessions and cleans up inactive ones.
- **Security Features**: Encrypted settings storage, Content Security Policy (CSP), and minimal dependencies to reduce attack surface.
- **Accessibility**: ARIA attributes, keyboard navigation, and clear UI labels for inclusive access.

## Security

BitPlay has been designed with security in mind to address concerns about insecure code, plaintext secrets, and malicious code:

- **Encrypted Settings**: Proxy credentials, Prowlarr/Jackett API keys, and other sensitive data are encrypted in `settings.json` using `golang.org/x/crypto`.
- **Secure Frontend**: The web UI uses a strict CSP, local Video.js assets (no CDNs), and masks API keys in input fields.
- **Minimized Dependencies**: Go and Node.js dependencies are kept to a minimum, with regular audits using `govulncheck` and `npm audit`.
- **Docker Security**: The Docker image uses a `scratch` base for minimalism and can be scanned for vulnerabilities.
- **Input Validation**: User inputs (magnet links, torrent files, search queries) are sanitized to prevent XSS and malicious uploads.

To verify security:
- Run `govulncheck` for Go dependencies:
  ```bash
  go install golang.org/x/vuln/cmd/govulncheck@latest
  govulncheck ./...
  ```
- Run `npm audit` for frontend dependencies:
  ```bash
  npm audit
  ```
- Scan the Docker image:
  ```bash
  docker scan ghcr.io/aculix/bitplay:main
  ```

## Getting Started

You can run BitPlay locally with Go or via Docker (recommended for self-hosting).

### Prerequisites

- **Go**: Go 1.24 or later (for local runs).
- **Docker & Docker Compose**: Required for Docker deployments.
- **Node.js**: Node 20 or later (for building frontend assets locally).
- **Host Configuration**: Ensure port 3347 is open and the `./config` directory has secure permissions (`chmod 700 ./config`).

### Running Locally with Go

1. **Clone the repository**:
   ```bash
   git clone https://github.com/aculix/bitplay.git
   cd bitplay
   ```
2. **Download Go dependencies**:
   ```bash
   go mod download
   ```
3. **Install frontend dependencies**:
   ```bash
   npm ci --production
   ```
4. **Build frontend assets**:
   ```bash
   npm run build
   ```
5. **Run the application**:
   ```bash
   go run main.go
   ```
   The server starts on `http://localhost:3347`.

### Running with Docker Compose (Recommended)

1. **Create a `docker-compose.yml` file**:
   ```yaml
   services:
     bitplay:
       image: ghcr.io/aculix/bitplay:main
       container_name: bitplay
       ports:
         - 3347:3347
       volumes:
         - ./config:/app/config
       environment:
         - TORRENT_CLIENT_KEY=your-secure-key
       restart: unless-stopped
   ```
   - **Persistence**: The `./config` volume mounts `settings.json` for persistent settings. Create the directory first:
     ```bash
     mkdir -p ./config
     chmod 700 ./config
     ```
   - **Security**: Set `TORRENT_CLIENT_KEY` to a secure value for API authentication.
   - **Ephemeral Data**: Torrent data is not persisted and is cleared on container restart.

2. **Start the container**:
   ```bash
   docker-compose up -d
   ```
3. **Access the application**: Open `http://<your-server-ip>:3347`.

### Running with Docker Run

1. **Create the config directory** (optional, for persistent settings):
   ```bash
   mkdir -p ./config
   chmod 700 ./config
   ```
2. **Run the container**:
   ```bash
   docker run -d \
     --name bitplay \
     -p 3347:3347 \
     -v $(pwd)/config:/app/config \
     -e TORRENT_CLIENT_KEY=your-secure-key \
     --restart unless-stopped \
     ghcr.io/aculix/bitplay:main
   ```
3. **Access the application**: Open `http://<your-server-ip>:3347`.

## Configuration

Configure BitPlay via the web UI:

1. **Access the Web UI**: Go to `http://<your-server-ip>:3347`.
2. **Open Settings**: Click the "Settings" button.
3. **Configure**:
   - **Proxy**:
     - Enable/disable SOCKS5 proxy.
     - Enter the proxy URL (e.g., `socks5://user:pass@host:port`).
     - Click "Test Proxy" to verify connectivity.
   - **Prowlarr**:
     - Enable/disable Prowlarr.
     - Enter the host URL (e.g., `http://prowlarr:9696`).
     - Enter your API key (masked for security).
     - Click "Test Connection".
   - **Jackett**:
     - Enable/disable Jackett.
     - Enter the host URL (e.g., `http://jackett:9117`).
     - Enter your API key (masked for security).
     - Click "Test Connection".
4. **Save Settings**: Settings are encrypted and saved to `/app/config/settings.json` (mapped to `./config/settings.json` if using the volume mount).

### API Endpoints

For advanced users, BitPlay exposes RESTful API endpoints (requires `TORRENT_CLIENT_KEY` for authentication):
- **Add Torrent**: `POST /api/v1/torrent/add` (body: `{ "magnet": "magnet:..." }`)
- **Get Settings**: `GET /api/v1/settings`
- **Update Settings**: `POST /api/v1/settings` (body: `{ "proxy": {...}, "prowlarr": {...}, "jackett": {...} }`)

## Usage

1. **Configure Settings**: Set up proxy and search providers in the web UI.
2. **Search Torrents**: Use the search bar to query Prowlarr or Jackett.
3. **Add Torrent**:
   - Paste a magnet link and click "Play Now".
   - Upload a `.torrent` file via drag-and-drop.
   - Select a search result to add the torrent.
   - Try the demo with Sintel (CC-licensed movie).
4. **Stream**: Select a video file from the torrent to stream in the Video.js player.

## Troubleshooting

- **Prowlarr/Jackett Connection Issues**:
  - Verify host URLs and API keys.
  - Ensure Prowlarr (`:9696`) or Jackett (`:9117`) is running and accessible.
  - Check Docker network settings if using containers.
- **Proxy Errors**:
  - Confirm the SOCKS5 URL format (`socks5://user:pass@host:port`).
  - Test the proxy in the UI before saving.
- **Streaming Issues**:
  - Ensure sufficient seeders for the torrent.
  - Check browser console for errors (`index.js` logs).
- **Docker Issues**:
  - Verify port 3347 is not in use: `lsof -i :3347`.
  - Check container logs: `docker logs bitplay`.

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-name`.
3. Commit changes: `git commit -m "Add feature"`.
4. Push to the branch: `git push origin feature-name`.
5. Open a pull request.

Please include tests and update documentation. Run security checks before submitting:
```bash
govulncheck ./...
npm audit
```

## Customizing the Frontend

The frontend uses Tailwind CSS, Video.js, and Butterup for styling, video playback, and toast notifications. To customize:
1. Edit `src/input.css` and rebuild:
   ```bash
   npm run build
   ```
2. Modify `static/index.html` or `static/assets/index.js` for UI changes.
3. Minimize dependencies (e.g., remove Butterup or Video.js hotkeys) by updating `package.json` and `index.html`.

For a lighter frontend, replace Tailwind CSS with PicoCSS or native CSS.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [anacrolix/torrent](https://github.com/anacrolix/torrent) for torrent handling.
- Styled with [Tailwind CSS](https://tailwindcss.com).
- Video playback powered by [Video.js](https://videojs.com).
- Toast notifications by [Butterup](https://github.com/butterup).
