package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"net/url"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/net/proxy"
	"golang.org/x/crypto/sha256"
)

const (
	maxUploadSize         = 10 << 20 // 10MB
	sessionTimeout        = 15 * time.Minute
	cleanupInterval       = 5 * time.Minute
	defaultPort           = 3347
	defaultStoragePath    = "./torrent-data"
	configDir             = "config"
	settingsFilePath      = "config/settings.json"
	clientDir             = "./client"
	faviconPath           = "./client/favicon.ico"
	encryptionKeyEnv      = "TORRENT_CLIENT_KEY"
)

var (
	currentSettings Settings
	settingsMutex   sync.RWMutex
	sessions        sync.Map
	usedPorts       sync.Map
	portMutex       sync.Mutex
	encryptionKey   []byte
	secureTransport = &http.Transport{
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConnsPerHost:   10,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
		},
	}
	secureClient = &http.Client{
		Transport:     secureTransport,
		Timeout:       30 * time.Second,
		CheckRedirect: redirectPolicy,
	}
	urlValidator = regexp.MustCompile(`^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$`)
)

type Settings struct {
	EnableProxy    bool   `json:"enableProxy"`
	ProxyURL       string `json:"proxyUrl"` // Encrypted in storage
	EnableProwlarr bool   `json:"enableProwlarr"`
	ProwlarrHost   string `json:"prowlarrHost"` // Encrypted in storage
	ProwlarrApiKey string `json:"prowlarrApiKey"` // Encrypted in storage
	EnableJackett  bool   `json:"enableJackett"`
	JackettHost    string `json:"jackettHost"` // Encrypted in storage
	JackettApiKey  string `json:"jackettApiKey"` // Encrypted in storage
}

type ProxySettings struct {
	EnableProxy bool   `json:"enableProxy"`
	ProxyURL    string `json:"proxyUrl"`
}

type ProwlarrSettings struct {
	EnableProwlarr bool   `json:"enableProwlarr"`
	ProwlarrHost   string `json:"prowlarrHost"`
	ProwlarrApiKey string `json:"prowlarrApiKey"`
}

type JackettSettings struct {
	EnableJackett bool   `json:"enableJackett"`
	JackettHost   string `json:"jackettHost"`
	JackettApiKey string `json:"jackettApiKey"`
}

type TorrentSession struct {
	Client   *torrent.Client
	Torrent  *torrent.Torrent
	Port     int
	LastUsed time.Time
}

func init() {
	rand.Seed(time.Now().UnixNano())
	if err := initializeEncryptionKey(); err != nil {
		log.Fatalf("Failed to initialize encryption key: %v", err)
	}
	if err := initializeSettings(); err != nil {
		log.Fatalf("Failed to initialize settings: %v", err)
	}
}

func initializeEncryptionKey() error {
	keyStr := os.Getenv(encryptionKeyEnv)
	if keyStr == "" {
		return errors.New("encryption key not set in environment variable " + encryptionKeyEnv)
	}
	// Derive a 32-byte key using PBKDF2 for secure key stretching
	encryptionKey = pbkdf2.Key([]byte(keyStr), []byte("torrent-client-salt"), 100000, 32, sha256.New)
	return nil
}

func encrypt(data string) (string, error) {
	if data == "" {
		return "", nil
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}
	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}
	return string(plaintext), nil
}

func initializeSettings() error {
	if _, err := os.Stat(settingsFilePath); os.IsNotExist(err) {
		defaultSettings := Settings{}
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return fmt.Errorf("failed to create config directory: %v", err)
		}
		if err := saveSettingsToFile(defaultSettings); err != nil {
			return fmt.Errorf("failed to create default settings: %v", err)
		}
		log.Println("Created default settings file")
	}

	file, err := os.Open(settingsFilePath)
	if err != nil {
		return fmt.Errorf("failed to open settings file: %v", err)
	}
	defer file.Close()

	var settings Settings
	if err := json.NewDecoder(file).Decode(&settings); err != nil {
		return fmt.Errorf("failed to decode settings: %v", err)
	}

	// Decrypt sensitive fields
	settings.ProxyURL, err = decrypt(settings.ProxyURL)
	if err != nil {
		return fmt.Errorf("failed to decrypt proxy URL: %v", err)
	}
	settings.ProwlarrHost, err = decrypt(settings.ProwlarrHost)
	if err != nil {
		return fmt.Errorf("failed to decrypt Prowlarr host: %v", err)
	}
	settings.ProwlarrApiKey, err = decrypt(settings.ProwlarrApiKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt Prowlarr API key: %v", err)
	}
	settings.JackettHost, err = decrypt(settings.JackettHost)
	if err != nil {
		return fmt.Errorf("failed to decrypt Jackett host: %v", err)
	}
	settings.JackettApiKey, err = decrypt(settings.JackettApiKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt Jackett API key: %v", err)
	}

	settingsMutex.Lock()
	currentSettings = settings
	settingsMutex.Unlock()
	return nil
}

func saveSettingsToFile(settings Settings) error {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Encrypt sensitive fields
	encryptedSettings := settings
	var err error
	encryptedSettings.ProxyURL, err = encrypt(settings.ProxyURL)
	if err != nil {
		return fmt.Errorf("failed to encrypt proxy URL: %v", err)
	}
	encryptedSettings.ProwlarrHost, err = encrypt(settings.ProwlarrHost)
	if err != nil {
		return fmt.Errorf("failed to encrypt Prowlarr host: %v", err)
	}
	encryptedSettings.ProwlarrApiKey, err = encrypt(settings.ProwlarrApiKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt Prowlarr API key: %v", err)
	}
	encryptedSettings.JackettHost, err = encrypt(settings.JackettHost)
	if err != nil {
		return fmt.Errorf("failed to encrypt Jackett host: %v", err)
	}
	encryptedSettings.JackettApiKey, err = encrypt(settings.JackettApiKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt Jackett API key: %v", err)
	}

	file, err := os.OpenFile(settingsFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create settings file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(encryptedSettings); err != nil {
		return fmt.Errorf("failed to encode settings: %v", err)
	}
	return nil
}

func redirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("too many redirects")
	}
	for k, vv := range via[0].Header {
		if _, ok := req.Header[k]; !ok {
			req.Header[k] = vv
		}
	}
	return nil
}

func formatSize(sizeInBytes float64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case sizeInBytes < kb:
		return fmt.Sprintf("%.0f B", sizeInBytes)
	case sizeInBytes < mb:
		return fmt.Sprintf("%.2f KB", sizeInBytes/kb)
	case sizeInBytes < gb:
		return fmt.Sprintf("%.2f MB", sizeInBytes/mb)
	default:
		return fmt.Sprintf("%.2f GB", sizeInBytes/gb)
	}
}

func getAvailablePort() int {
	portMutex.Lock()
	defer portMutex.Unlock()

	for i := 0; i < 50; i++ {
		port := 10000 + rand.Intn(50000)
		if _, exists := usedPorts.Load(port); !exists {
			usedPorts.Store(port, true)
			return port
		}
	}
	return 60000 + rand.Intn(5000)
}

func releasePort(port int) {
	portMutex.Lock()
	defer portMutex.Unlock()
	usedPorts.Delete(port)
}

func createProxyDialer(proxyURL string) (proxy.Dialer, error) {
	if !urlValidator.MatchString(proxyURL) {
		return nil, errors.New("invalid proxy URL format")
	}
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy URL: %v", err)
	}
	if parsedURL.Scheme != "socks5" {
		return nil, errors.New("only SOCKS5 proxies are supported")
	}

	auth := &proxy.Auth{}
	if parsedURL.User != nil {
		auth.User = parsedURL.User.Username()
		if password, ok := parsedURL.User.Password(); ok {
			auth.Password = password
		}
	}

	dialer, err := proxy.SOCKS5("tcp", parsedURL.Host, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
	}
	return dialer, nil
}

func createSecureClient() *http.Client {
	return secureClient
}

func createProxyClient(proxyURL string) (*http.Client, error) {
	dialer, err := createProxyDialer(proxyURL)
	if err != nil {
		return nil, err
	}
	transport := secureTransport.Clone()
	transport.DialContext = dialer.DialContext
	return &http.Client{
		Transport:     transport,
		Timeout:       30 * time.Second,
		CheckRedirect: redirectPolicy,
	}, nil
}

func initTorrentWithProxy() (*torrent.Client, int, error) {
	settingsMutex.RLock()
	enableProxy := currentSettings.EnableProxy
	proxyURL := currentSettings.ProxyURL
	settingsMutex.RUnlock()

	config := torrent.NewDefaultClientConfig()
	config.DefaultStorage = storage.NewFile(defaultStoragePath)
	port := getAvailablePort()
	config.ListenPort = port

	if enableProxy {
		if proxyURL == "" {
			releasePort(port)
			return nil, port, errors.New("proxy enabled but no URL provided")
		}
		proxyDialer, err := createProxyDialer(proxyURL)
		if err != nil {
			releasePort(port)
			return nil, port, fmt.Errorf("failed to create proxy dialer: %v", err)
		}

		config.DialContext = proxyDialer.DialContext
		config.HTTPProxy = func(*http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		}

		client, err := torrent.NewClient(config)
		if err != nil {
			releasePort(port)
			return nil, port, fmt.Errorf("failed to create torrent client: %v", err)
		}
		return client, port, nil
	}

	client, err := torrent.NewClient(config)
	if err != nil {
		releasePort(port)
		return nil, port, fmt.Errorf("failed to create torrent client: %v", err)
	}
	return client, port, nil
}

func setGlobalProxy() {
	settingsMutex.RLock()
	defer settingsMutex.RUnlock()

	transport := secureTransport.Clone()
	if !currentSettings.EnableProxy || currentSettings.ProxyURL == "" {
		transport.DialContext = nil
		http.DefaultTransport = transport
		return
	}

	dialer, err := createProxyDialer(currentSettings.ProxyURL)
	if err != nil {
		log.Printf("Warning: Failed to create proxy dialer: %v", err)
		return
	}

	transport.DialContext = dialer.DialContext
	http.DefaultTransport = transport
	log.Println("Configured global SOCKS5 proxy")
}

func main() {
	setGlobalProxy()

	http.HandleFunc("/api/v1/torrent/add", addTorrentHandler)
	http.HandleFunc("/api/v1/torrent/", torrentHandler)
	http.HandleFunc("/api/v1/settings", settingsHandler)
	http.HandleFunc("/api/v1/settings/proxy", saveProxySettingsHandler)
	http.HandleFunc("/api/v1/settings/prowlarr", saveProwlarrSettingsHandler)
	http.HandleFunc("/api/v1/settings/jackett", saveJackettSettingsHandler)
	http.HandleFunc("/api/v1/prowlarr/search", searchFromProwlarr)
	http.HandleFunc("/api/v1/jackett/search", searchFromJackett)
	http.HandleFunc("/api/v1/prowlarr/test", testProwlarrConnection)
	http.HandleFunc("/api/v1/jackett/test", testJackettConnection)
	http.HandleFunc("/api/v1/proxy/test", testProxyConnection)
	http.HandleFunc("/api/v1/torrent/convert", convertTorrentToMagnetHandler)

	http.Handle("/", http.FileServer(http.Dir(clientDir)))
	http.HandleFunc("/client/", func(w http.ResponseWriter, r *http.Request) {
		http.StripPrefix("/client/", http.FileServer(http.Dir(clientDir))).ServeHTTP(w, r)
	})
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, faviconPath)
	})

	go cleanupSessions()

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", defaultPort),
		Handler: nil,
		TLSConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
		},
	}

	log.Printf("Starting server on :%d", defaultPort)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}

func settingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	settingsMutex.RLock()
	defer settingsMutex.RUnlock()
	// Return settings without sensitive data
	safeSettings := Settings{
		EnableProxy:    currentSettings.EnableProxy,
		EnableProwlarr: currentSettings.EnableProwlarr,
		EnableJackett:  currentSettings.EnableJackett,
	}
	respondWithJSON(w, http.StatusOK, safeSettings)
}

func addTorrentHandler(w http.ResponseWriter, r *http.Request) {
	var request struct{ Magnet string }
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	magnet := strings.TrimSpace(request.Magnet)
	if magnet == "" {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "No magnet link provided"})
		return
	}

	if strings.HasPrefix(magnet, "http") {
		if !urlValidator.MatchString(magnet) {
			respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid URL format"})
			return
		}
		var err error
		magnet, err = resolveHTTPMagnet(magnet)
		if err != nil {
			respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}

	if !strings.HasPrefix(magnet, "magnet:") || len(magnet) > 2048 {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid magnet link"})
		return
	}

	client, port, err := initTorrentWithProxy()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create client"})
		return
	}

	torrent, err := client.AddMagnet(magnet)
	if err != nil {
		releasePort(port)
		client.Close()
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid magnet URL"})
		return
	}

	select {
	case <-torrent.GotInfo():
	case <-time.After(3 * time.Minute):
		releasePort(port)
		client.Close()
		respondWithJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "Timeout getting torrent info"})
		return
	}

	sessionID := torrent.InfoHash().HexString()
	sessions.Store(sessionID, &TorrentSession{
		Client:   client,
		Torrent:  torrent,
		Port:     port,
		LastUsed: time.Now(),
	})

	respondWithJSON(w, http.StatusOK, map[string]string{"sessionId": sessionID})
}

func resolveHTTPMagnet(urlStr string) (string, error) {
	client := createSecureClient()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if strings.HasPrefix(location, "magnet:") {
			return location, nil
		}
		return "", errors.New("URL redirects to non-magnet content")
	}
	return "", errors.New("invalid response status")
}

func torrentHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid path"})
		return
	}

	sessionID := parts[4]
	if !isValidHex(sessionID) {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid session ID"})
		return
	}

	sessionValue, ok := sessions.Load(sessionID)
	if !ok {
		respondWithJSON(w, http.StatusNotFound, map[string]string{"error": "Session not found"})
		return
	}

	session := sessionValue.(*TorrentSession)
	session.LastUsed = time.Now()

	if len(parts) > 5 && parts[5] == "stream" {
		if len(parts) < 7 {
			http.Error(w, "Invalid stream path", http.StatusBadRequest)
			return
		}

		fileIndexStr := strings.TrimSuffix(parts[6], ".vtt")
		fileIndex, err := strconv.Atoi(fileIndexStr)
		if err != nil || fileIndex < 0 || fileIndex >= len(session.Torrent.Files()) {
			http.Error(w, "Invalid file index", http.StatusBadRequest)
			return
		}

		file := session.Torrent.Files()[fileIndex]
		serveFile(w, r, file, r.URL.Query().Get("format") == "vtt")
		return
	}

	files := make([]map[string]interface{}, 0, len(session.Torrent.Files()))
	for i, file := range session.Torrent.Files() {
		filePath := file.DisplayPath()
		if !isSafePath(filePath) {
			continue
		}
		files = append(files, map[string]interface{}{
			"index": i,
			"name":  filePath,
			"size":  file.Length(),
		})
	}
	respondWithJSON(w, http.StatusOK, files)
}

func isValidHex(s string) bool {
	return regexp.MustCompile(`^[0-9a-fA-F]+$`).MatchString(s)
}

func isSafePath(path string) bool {
	cleanPath := filepath.Clean(path)
	return !strings.Contains(cleanPath, "..") && !filepath.IsAbs(cleanPath)
}

func serveFile(w http.ResponseWriter, r *http.Request, file *torrent.File, asVTT bool) {
	fileName := file.DisplayPath()
	if !isSafePath(fileName) {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}
	extension := strings.ToLower(filepath.Ext(fileName))
	w.Header().Set("Access-Control-Allow-Origin", "*")

	contentType := "application/octet-stream"
	switch extension {
	case ".mp4":
		contentType = "video/mp4"
	case ".webm":
		contentType = "video/webm"
	case ".mkv":
		contentType = "video/x-matroska"
	case ".avi":
		contentType = "video/x-msvideo"
	case ".srt":
		contentType = "text/plain"
		if asVTT {
			contentType = "text/vtt"
		}
	case ".vtt":
		contentType = "text/vtt"
	case ".sub":
		contentType = "text/plain"
	}
	w.Header().Set("Content-Type", contentType)

	reader := file.NewReader()
	defer reader.Close()

	if extension == ".srt" && asVTT {
		srtBytes, err := io.ReadAll(io.LimitReader(reader, maxUploadSize))
		if err != nil {
			http.Error(w, "Failed to read subtitle file", http.StatusInternalServerError)
			return
		}
		w.Write(convertSRTtoVTT(srtBytes))
		return
	}

	http.ServeContent(w, r, fileName, time.Time{}, reader)
}

func convertSRTtoVTT(srtBytes []byte) []byte {
	vttContent := "WEBVTT\n\n"
	lines := strings.Split(string(srtBytes), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if _, err := strconv.Atoi(line); err == nil {
			continue
		}
		if strings.Contains(line, " --> ") {
			line = strings.Replace(line, ",", ".", -1)
			vttContent += line + "\n"
		} else if line != "" {
			vttContent += line + "\n"
		}
	}
	return []byte(vttContent)
}

func cleanupSessions() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		sessions.Range(func(key, value interface{}) bool {
			session := value.(*TorrentSession)
			if time.Since(session.LastUsed) > sessionTimeout {
				releasePort(session.Port)
				session.Torrent.Drop()
				session.Client.Close()
				sessions.Delete(key)
				log.Printf("Removed unused session: %s", key)
			}
			return true
		})
		runtime.GC()
	}
}

func testProwlarrConnection(w http.ResponseWriter, r *http.Request) {
	handleCORSPreflight(w, r)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var settings ProwlarrSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if settings.ProwlarrHost == "" || settings.ProwlarrApiKey == "" {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Prowlarr host or API key missing"})
		return
	}

	if !strings.HasPrefix(settings.ProwlarrHost, "https://") {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Prowlarr host must use HTTPS"})
		return
	}

	client := createSecureClient()
	resp, err := testServiceConnection(client, fmt.Sprintf("%s/api/v1/system/status", settings.ProwlarrHost), settings.ProwlarrApiKey)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	handleServiceResponse(w, resp)
}

func testJackettConnection(w http.ResponseWriter, r *http.Request) {
	handleCORSPreflight(w, r)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var settings JackettSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if settings.JackettHost == "" || settings.JackettApiKey == "" {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Jackett host or API key missing"})
		return
	}

	if !strings.HasPrefix(settings.JackettHost, "https://") {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Jackett host must use HTTPS"})
		return
	}

	client := createSecureClient()
	resp, err := testServiceConnection(client, fmt.Sprintf("%s/api/v2.0/indexers/all/results?apikey=%s", settings.JackettHost, settings.JackettApiKey), "")
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	handleServiceResponse(w, resp)
}

func testServiceConnection(client *http.Client, url, apiKey string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	if apiKey != "" {
		req.Header.Set("X-Api-Key", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}
	return resp, nil
}

func handleServiceResponse(w http.ResponseWriter, resp *http.Response) {
	if resp.StatusCode != http.StatusOK {
		respondWithJSON(w, resp.StatusCode, map[string]string{"error": fmt.Sprintf("Service returned status %d", resp.StatusCode)})
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read response"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func searchFromProwlarr(w http.ResponseWriter, r *http.Request) {
	if !handleSearchRequest(w, r) {
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" || len(query) > 256 {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid or missing search query"})
		return
	}

	settingsMutex.RLock()
	host := currentSettings.ProwlarrHost
	apiKey := currentSettings.ProwlarrApiKey
	settingsMutex.RUnlock()

	if host == "" || apiKey == "" {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Prowlarr configuration missing"})
		return
	}

	if !strings.HasPrefix(host, "https://") {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Prowlarr host must use HTTPS"})
		return
	}

	results, err := searchService(fmt.Sprintf("%s/api/v1/search?query=%s&limit=10", host, url.QueryEscape(query)), apiKey, createSecureClient())
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	respondWithJSON(w, http.StatusOK, results)
}

func searchFromJackett(w http.ResponseWriter, r *http.Request) {
	if !handleSearchRequest(w, r) {
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" || len(query) > 256 {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid or missing search query"})
		return
	}

	settingsMutex.RLock()
	host := currentSettings.JackettHost
	apiKey := currentSettings.JackettApiKey
	settingsMutex.RUnlock()

	if host == "" || apiKey == "" {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Jackett configuration missing"})
		return
	}

	if !strings.HasPrefix(host, "https://") {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Jackett host must use HTTPS"})
		return
	}

	results, err := searchService(fmt.Sprintf("%s/api/v2.0/indexers/all/results?Query=%s&apikey=%s", host, url.QueryEscape(query), apiKey), "", createSecureClient())
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	respondWithJSON(w, http.StatusOK, results)
}

func handleSearchRequest(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Prowlarr-Host, X-Api-Key")
	if r.Method == "OPTIONS" {
		return false
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func searchService(url, apiKey string, client *http.Client) ([]map[string]interface{}, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	if apiKey != "" {
		req.Header.Set("X-Api-Key", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("service returned status %d", resp.StatusCode)
	}

	var results []map[string]interface{}
	var jacketResponse struct {
		Results []map[string]interface{} `json:"Results"`
	}

	if strings.Contains(url, "jackett") {
		if err := json.Unmarshal(body, &jacketResponse); err != nil {
			return nil, fmt.Errorf("failed to parse response: %v", err)
		}
		results = jacketResponse.Results
	} else {
		if err := json.Unmarshal(body, &results); err != nil {
			return nil, fmt.Errorf("failed to parse response: %v", err)
		}
	}

	return processSearchResults(results, strings.Contains(url, "jackett")), nil
}

func processSearchResults(results []map[string]interface{}, isJackett bool) []map[string]interface{} {
	processed := make([]map[string]interface{}, 0, len(results))
	for _, result := range results {
		var title, downloadURL, magnetURL string
		var hasTitle, hasDownloadURL, hasMagnet bool

		if isJackett {
			title, hasTitle = result["Title"].(string)
			downloadURL, hasDownloadURL = result["Link"].(string)
			magnetURL, hasMagnet = result["MagnetUri"].(string)
		} else {
			title, hasTitle = result["title"].(string)
			downloadURL, hasDownloadURL = result["downloadUrl"].(string)
			magnetURL, hasMagnet = result["magnetUrl"].(string)
		}

		if !hasTitle || title == "" || (!hasDownloadURL && !hasMagnet) {
			continue
		}

		processedResult := map[string]interface{}{"title": title}
		if hasMagnet && magnetURL != "" && strings.HasPrefix(magnetURL, "magnet:") {
			processedResult["magnetUrl"] = magnetURL
			processedResult["directMagnet"] = true
		} else if hasDownloadURL && downloadURL != "" && urlValidator.MatchString(downloadURL) {
			processedResult["downloadUrl"] = downloadURL
			processedResult["directMagnet"] = false
		} else {
			continue
		}

		if size, ok := result["size"].(float64); ok {
			processedResult["size"] = formatSize(size)
		}
		if seeders, ok := result["seeders"].(float64); ok {
			processedResult["seeders"] = seeders
		}
		if leechers, ok := result[isJackettKey("Peers", "leechers", isJackett)].(float64); ok {
			processedResult["leechers"] = leechers
		}
		if indexer, ok := result[isJackettKey("Tracker", "indexer", isJackett)].(string); ok {
			processedResult["indexer"] = indexer
		}
		if publishDate, ok := result["publishDate"].(string); ok {
			processedResult["publishDate"] = publishDate
		}
		if category, ok := result["category"].(string); ok {
			processedResult["category"] = category
		}

		processed = append(processed, processedResult)
	}
	return processed
}

func isJackettKey(jackettKey, prowlarrKey string, isJackett bool) string {
	if isJackett {
		return jackettKey
	}
	return prowlarrKey
}

func testProxyConnection(w http.ResponseWriter, r *http.Request) {
	handleCORSPreflight(w, r)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var settings ProxySettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if settings.ProxyURL == "" {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Proxy URL missing"})
		return
	}

	client, err := createProxyClient(settings.ProxyURL)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid proxy configuration"})
		return
	}

	resp, err := client.Get("https://httpbin.org/ip")
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Proxy connection failed"})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read response"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func handleCORSPreflight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
	}
}

func saveProxySettingsHandler(w http.ResponseWriter, r *http.Request) {
	if !handleSaveSettingsRequest(w, r) {
		return
	}

	var newSettings ProxySettings
	if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if newSettings.EnableProxy && !urlValidator.MatchString(newSettings.ProxyURL) {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid proxy URL"})
		return
	}

	settingsMutex.Lock()
	defer settingsMutex.Unlock()
	currentSettings.EnableProxy = newSettings.EnableProxy
	currentSettings.ProxyURL = newSettings.ProxyURL

	if err := saveSettingsToFile(currentSettings); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save settings"})
		return
	}

	setGlobalProxy()
	respondWithJSON(w, http.StatusOK, map[string]string{"message": "Proxy settings saved"})
}

func saveProwlarrSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if !handleSaveSettingsRequest(w, r) {
		return
	}

	var newSettings ProwlarrSettings
	if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if newSettings.EnableProwlarr {
		if newSettings.ProwlarrHost == "" || newSettings.ProwlarrApiKey == "" {
			respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Prowlarr host or API key missing"})
			return
		}
		if !strings.HasPrefix(newSettings.ProwlarrHost, "https://") || !urlValidator.MatchString(newSettings.ProwlarrHost) {
			respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Prowlarr host; must use HTTPS"})
			return
		}
	}

	settingsMutex.Lock()
	defer settingsMutex.Unlock()
	currentSettings.EnableProwlarr = newSettings.EnableProwlarr
	currentSettings.ProwlarrHost = newSettings.ProwlarrHost
	currentSettings.ProwlarrApiKey = newSettings.ProwlarrApiKey

	if err := saveSettingsToFile(currentSettings); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save settings"})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "Prowlarr settings saved"})
}

func saveJackettSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if !handleSaveSettingsRequest(w, r) {
		return
	}

	var newSettings JackettSettings
	if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if newSettings.EnableJackett {
		if newSettings.JackettHost == "" || newSettings.JackettApiKey == "" {
			respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Jackett host or API key missing"})
			return
		}
		if !strings.HasPrefix(newSettings.JackettHost, "https://") || !urlValidator.MatchString(newSettings.JackettHost) {
			respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Jackett host; must use HTTPS"})
			return
		}
	}

	settingsMutex.Lock()
	defer settingsMutex.Unlock()
	currentSettings.EnableJackett = newSettings.EnableJackett
	currentSettings.JackettHost = newSettings.JackettHost
	currentSettings.JackettApiKey = newSettings.JackettApiKey

	if err := saveSettingsToFile(currentSettings); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save settings"})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "Jackett settings saved"})
}

func handleSaveSettingsRequest(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == "OPTIONS" {
		return false
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func convertTorrentToMagnetHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == "OPTIONS" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Failed to parse form"})
		return
	}

	file, header, err := r.FormFile("torrent")
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing torrent file"})
		return
	}
	defer file.Close()

	if header.Size > maxUploadSize {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "File too large"})
		return
	}

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read file"})
		return
	}

	mi, err := metainfo.Load(bytes.NewReader(fileBytes))
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid torrent file"})
		return
	}

	infoHash := mi.HashInfoBytes().String()
	magnet := fmt.Sprintf("magnet:?xt=urn:btih:%s", infoHash)

	info, err := mi.UnmarshalInfo()
	if err == nil && isSafePath(info.Name) {
		magnet += fmt.Sprintf("&dn=%s", url.QueryEscape(info.Name))
	}

	for _, tier := range mi.AnnounceList {
		for _, tracker := range tier {
			if urlValidator.MatchString(tracker) {
				magnet += fmt.Sprintf("&tr=%s", url.QueryEscape(tracker))
			}
		}
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"magnet": magnet})
}

func respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Failed to encode JSON response: %v", err)
	}
}
