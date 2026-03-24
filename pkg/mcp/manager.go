package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sipeed/picoclaw/pkg/config"
	"github.com/sipeed/picoclaw/pkg/logger"
)

// headerTransport is an http.RoundTripper that adds custom headers to requests
type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	req = req.Clone(req.Context())

	// Add custom headers
	for key, value := range t.headers {
		req.Header.Set(key, value)
	}

	// Use the base transport
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// loadEnvFile loads environment variables from a file in .env format
// Each line should be in the format: KEY=value
// Lines starting with # are comments
// Empty lines are ignored
func loadEnvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open env file: %w", err)
	}
	defer file.Close()

	envVars := make(map[string]string)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format at line %d: %s", lineNum, line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if key == "" {
			return nil, fmt.Errorf("invalid format at line %d: empty key", lineNum)
		}

		// Remove surrounding quotes if present
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		envVars[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading env file: %w", err)
	}

	return envVars, nil
}

// ServerConnection represents a connection to an MCP server
type ServerConnection struct {
	Name    string
	Client  *mcp.Client
	Session *mcp.ClientSession
	Tools   []*mcp.Tool
}

// Manager manages multiple MCP server connections
type Manager struct {
	servers     map[string]*ServerConnection
	mu          sync.RWMutex
	closed      atomic.Bool    // changed from bool to atomic.Bool to avoid TOCTOU race
	wg          sync.WaitGroup // tracks in-flight CallTool calls
	onAuthEvent AuthEventHandler
}

// NewManager creates a new MCP manager
func NewManager() *Manager {
	return &Manager{
		servers: make(map[string]*ServerConnection),
	}
}

// extractURL finds the first http/https URL in a string.
func extractURL(s string) string {
	for _, prefix := range []string{"https://", "http://"} {
		idx := strings.Index(s, prefix)
		if idx == -1 {
			continue
		}
		// Find end of URL (space, quote, or end of string)
		end := idx
		for end < len(s) && s[end] != ' ' && s[end] != '"' && s[end] != '\'' && s[end] != '>' && s[end] != ')' {
			end++
		}
		return s[idx:end]
	}
	return ""
}

// SetAuthEventHandler sets a callback that is invoked when an MCP server
// requires user authentication (e.g., OAuth URL, QR code).
func (m *Manager) SetAuthEventHandler(handler AuthEventHandler) {
	m.onAuthEvent = handler
}

// emitAuthEvent fires the auth event handler if one is set.
func (m *Manager) emitAuthEvent(event AuthEvent) {
	if m.onAuthEvent != nil {
		m.onAuthEvent(event)
	}
}

// LoadFromConfig loads MCP servers from configuration
func (m *Manager) LoadFromConfig(ctx context.Context, cfg *config.Config) error {
	return m.LoadFromMCPConfig(ctx, cfg.Tools.MCP, cfg.WorkspacePath())
}

// LoadFromMCPConfig loads MCP servers from MCP configuration and workspace path.
// This is the minimal dependency version that doesn't require the full Config object.
func (m *Manager) LoadFromMCPConfig(
	ctx context.Context,
	mcpCfg config.MCPConfig,
	workspacePath string,
) error {
	if !mcpCfg.Enabled {
		logger.InfoCF("mcp", "MCP integration is disabled", nil)
		return nil
	}

	if len(mcpCfg.Servers) == 0 {
		logger.InfoCF("mcp", "No MCP servers configured", nil)
		return nil
	}

	logger.InfoCF("mcp", "Initializing MCP servers",
		map[string]any{
			"count": len(mcpCfg.Servers),
		})

	var wg sync.WaitGroup
	errs := make(chan error, len(mcpCfg.Servers))
	enabledCount := 0

	for name, serverCfg := range mcpCfg.Servers {
		if !serverCfg.Enabled {
			logger.DebugCF("mcp", "Skipping disabled server",
				map[string]any{
					"server": name,
				})
			continue
		}

		enabledCount++
		wg.Add(1)
		go func(name string, serverCfg config.MCPServerConfig, workspace string) {
			defer wg.Done()

			// Resolve relative envFile paths relative to workspace
			if serverCfg.EnvFile != "" && !filepath.IsAbs(serverCfg.EnvFile) {
				if workspace == "" {
					err := fmt.Errorf(
						"workspace path is empty while resolving relative envFile %q for server %s",
						serverCfg.EnvFile,
						name,
					)
					logger.ErrorCF("mcp", "Invalid MCP server configuration",
						map[string]any{
							"server":   name,
							"env_file": serverCfg.EnvFile,
							"error":    err.Error(),
						})
					errs <- err
					return
				}
				serverCfg.EnvFile = filepath.Join(workspace, serverCfg.EnvFile)
			}

			if err := m.ConnectServer(ctx, name, serverCfg); err != nil {
				logger.ErrorCF("mcp", "Failed to connect to MCP server",
					map[string]any{
						"server": name,
						"error":  err.Error(),
					})
				errs <- fmt.Errorf("failed to connect to server %s: %w", name, err)
			}
		}(name, serverCfg, workspacePath)
	}

	wg.Wait()
	close(errs)

	// Collect errors
	var allErrors []error
	for err := range errs {
		allErrors = append(allErrors, err)
	}

	connectedCount := len(m.GetServers())

	// If all enabled servers failed to connect, return aggregated error
	if enabledCount > 0 && connectedCount == 0 {
		logger.ErrorCF("mcp", "All MCP servers failed to connect",
			map[string]any{
				"failed": len(allErrors),
				"total":  enabledCount,
			})
		return errors.Join(allErrors...)
	}

	if len(allErrors) > 0 {
		logger.WarnCF("mcp", "Some MCP servers failed to connect",
			map[string]any{
				"failed":    len(allErrors),
				"connected": connectedCount,
				"total":     enabledCount,
			})
		// Don't fail completely if some servers successfully connected
	}

	logger.InfoCF("mcp", "MCP server initialization complete",
		map[string]any{
			"connected": connectedCount,
			"total":     enabledCount,
		})

	return nil
}

// ConnectServer connects to a single MCP server
func (m *Manager) ConnectServer(
	ctx context.Context,
	name string,
	cfg config.MCPServerConfig,
) error {
	logger.InfoCF("mcp", "Connecting to MCP server",
		map[string]any{
			"server":     name,
			"command":    cfg.Command,
			"args_count": len(cfg.Args),
		})

	// Create client
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "picoclaw",
		Version: "1.0.0",
	}, nil)

	// Create transport based on configuration
	// Auto-detect transport type if not explicitly specified
	var transport mcp.Transport
	transportType := cfg.Type

	// Auto-detect: if URL is provided, use SSE; if command is provided, use stdio
	if transportType == "" {
		if cfg.URL != "" {
			transportType = "sse"
		} else if cfg.Command != "" {
			transportType = "stdio"
		} else {
			return fmt.Errorf("either URL or command must be provided")
		}
	}

	switch transportType {
	case "sse", "http":
		if cfg.URL == "" {
			return fmt.Errorf("URL is required for SSE/HTTP transport")
		}
		logger.DebugCF("mcp", "Using SSE/HTTP transport",
			map[string]any{
				"server": name,
				"url":    cfg.URL,
			})

		sseTransport := &mcp.StreamableClientTransport{
			Endpoint: cfg.URL,
		}

		// Add custom headers if provided
		if len(cfg.Headers) > 0 {
			// Create a custom HTTP client with header-injecting transport
			sseTransport.HTTPClient = &http.Client{
				Transport: &headerTransport{
					base:    http.DefaultTransport,
					headers: cfg.Headers,
				},
			}
			logger.DebugCF("mcp", "Added custom HTTP headers",
				map[string]any{
					"server":       name,
					"header_count": len(cfg.Headers),
				})
		}

		transport = sseTransport
	case "stdio":
		if cfg.Command == "" {
			return fmt.Errorf("command is required for stdio transport")
		}
		logger.DebugCF("mcp", "Using stdio transport",
			map[string]any{
				"server":  name,
				"command": cfg.Command,
			})
		// Create command with context
		cmd := exec.CommandContext(ctx, cfg.Command, cfg.Args...)

		// Build environment variables with proper override semantics
		// Use a map to ensure config variables override file variables
		envMap := make(map[string]string)

		// Start with parent process environment
		for _, e := range cmd.Environ() {
			if idx := strings.Index(e, "="); idx > 0 {
				envMap[e[:idx]] = e[idx+1:]
			}
		}

		// Load environment variables from file if specified
		if cfg.EnvFile != "" {
			envVars, err := loadEnvFile(cfg.EnvFile)
			if err != nil {
				return fmt.Errorf("failed to load env file %s: %w", cfg.EnvFile, err)
			}
			for k, v := range envVars {
				envMap[k] = v
			}
			logger.DebugCF("mcp", "Loaded environment variables from file",
				map[string]any{
					"server":    name,
					"envFile":   cfg.EnvFile,
					"var_count": len(envVars),
				})
		}

		// Environment variables from config override those from file
		for k, v := range cfg.Env {
			envMap[k] = v
		}

		// Convert map to slice
		env := make([]string, 0, len(envMap))
		for k, v := range envMap {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = env

		// Capture stderr to detect auth URLs from tools like mcp-remote.
		// The MCP SDK only uses stdin/stdout for the protocol; stderr is
		// where tools print auth prompts, errors, and debug info.
		stderrPipe, pipeErr := cmd.StderrPipe()
		if pipeErr != nil {
			logger.WarnCF("mcp", "Could not create stderr pipe, auth detection disabled",
				map[string]any{"server": name, "error": pipeErr.Error()})
		}

		transport = &mcp.CommandTransport{Command: cmd}

		// If we got a stderr pipe, start a goroutine to scan it for auth URLs.
		// Only emits a single event for the real OAuth URL (with PKCE rewriting).
		if pipeErr == nil && stderrPipe != nil {
			go func(serverName string, serverCfg config.MCPServerConfig) {
				authEmitted := false // Only emit one auth event per server
				lineCount := 0
				scanner := bufio.NewScanner(stderrPipe)
				logger.InfoCF("mcp", "Started stderr scanner for server",
					map[string]any{"server": serverName})
				for scanner.Scan() {
					line := scanner.Text()
					lineCount++
					// Log all stderr lines at INFO for debugging auth URL detection
					logger.InfoCF("mcp", "Server stderr line",
						map[string]any{"server": serverName, "line_num": lineCount, "line": line})

					if authEmitted {
						continue // Already found the OAuth URL for this server
					}

					// Extract any URL from the line
					rawURL := extractURL(line)
					if rawURL == "" {
						continue
					}

					logger.InfoCF("mcp", "Extracted URL from stderr",
						map[string]any{"server": serverName, "url": rawURL, "is_oauth": IsOAuthURL(rawURL)})

					// Only process real OAuth URLs (skip localhost, base domains, etc.)
					if !IsOAuthURL(rawURL) {
						logger.InfoCF("mcp", "Skipping non-OAuth URL from stderr",
							map[string]any{"server": serverName, "url": rawURL})
						continue
					}

					logger.InfoCF("mcp", "OAuth URL detected from server stderr",
						map[string]any{"server": serverName, "url": rawURL})

					// Determine the callback URL
					callbackURL := serverCfg.CallbackURL
					if callbackURL == "" {
						callbackURL = os.Getenv("PICOCLAW_OAUTH_CALLBACK_URL")
					}
					if callbackURL == "" {
						callbackURL = "https://makersfuel.com/api/auth/tool-callback"
					}

					// Generate a flow ID for the state parameter
					flowID := fmt.Sprintf("mcp-%s-%d", serverName, time.Now().UnixMilli())

					// Rewrite the OAuth URL with our callback and new PKCE
					rewrittenURL, codeVerifier, oauthMeta, rewriteErr := RewriteOAuthURL(rawURL, callbackURL, flowID)
					if rewriteErr != nil {
						logger.WarnCF("mcp", "Failed to rewrite OAuth URL, using original",
							map[string]any{"server": serverName, "error": rewriteErr.Error()})
						// Fall back to emitting the original URL
						m.emitAuthEvent(AuthEvent{
							ServerName: serverName,
							EventType:  AuthEventURL,
							URL:        rawURL,
							Message:    fmt.Sprintf("MCP server %q requires authorization", serverName),
							Timestamp:  time.Now(),
						})
					} else {
						logger.InfoCF("mcp", "OAuth URL rewritten with our callback",
							map[string]any{
								"server":       serverName,
								"callback_url": callbackURL,
								"has_verifier": codeVerifier != "",
							})
						m.emitAuthEvent(AuthEvent{
							ServerName:   serverName,
							EventType:    AuthEventURL,
							URL:          rewrittenURL,
							CodeVerifier: codeVerifier,
							OAuthMeta:    oauthMeta,
							Message:      fmt.Sprintf("MCP server %q requires authorization", serverName),
							Timestamp:    time.Now(),
						})
					}
					authEmitted = true
				}
			}(name, cfg)
		}
	default:
		return fmt.Errorf(
			"unsupported transport type: %s (supported: stdio, sse, http)",
			transportType,
		)
	}

	// Connect to server
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		// Check if the error indicates an authentication requirement
		errStr := err.Error()
		if strings.Contains(errStr, "401") || strings.Contains(errStr, "403") ||
			strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "Unauthorized") ||
			strings.Contains(errStr, "authentication required") {
			m.emitAuthEvent(AuthEvent{
				ServerName: name,
				EventType:  AuthEventError,
				Message:    fmt.Sprintf("MCP server %q requires authentication: %s", name, errStr),
				Timestamp:  time.Now(),
			})
		}
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Get server info
	initResult := session.InitializeResult()
	logger.InfoCF("mcp", "Connected to MCP server",
		map[string]any{
			"server":        name,
			"serverName":    initResult.ServerInfo.Name,
			"serverVersion": initResult.ServerInfo.Version,
			"protocol":      initResult.ProtocolVersion,
		})

	// List available tools if supported
	var tools []*mcp.Tool
	if initResult.Capabilities.Tools != nil {
		for tool, err := range session.Tools(ctx, nil) {
			if err != nil {
				logger.WarnCF("mcp", "Error listing tool",
					map[string]any{
						"server": name,
						"error":  err.Error(),
					})
				continue
			}
			tools = append(tools, tool)
		}

		logger.InfoCF("mcp", "Listed tools from MCP server",
			map[string]any{
				"server":    name,
				"toolCount": len(tools),
			})
	}

	// Store connection
	m.mu.Lock()
	m.servers[name] = &ServerConnection{
		Name:    name,
		Client:  client,
		Session: session,
		Tools:   tools,
	}
	m.mu.Unlock()

	return nil
}

// GetServers returns all connected servers
func (m *Manager) GetServers() map[string]*ServerConnection {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*ServerConnection, len(m.servers))
	for k, v := range m.servers {
		result[k] = v
	}
	return result
}

// GetServer returns a specific server connection
func (m *Manager) GetServer(name string) (*ServerConnection, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	conn, ok := m.servers[name]
	return conn, ok
}

// CallTool calls a tool on a specific server
func (m *Manager) CallTool(
	ctx context.Context,
	serverName, toolName string,
	arguments map[string]any,
) (*mcp.CallToolResult, error) {
	// Check if closed before acquiring lock (fast path)
	if m.closed.Load() {
		return nil, fmt.Errorf("manager is closed")
	}

	m.mu.RLock()
	// Double-check after acquiring lock to prevent TOCTOU race
	if m.closed.Load() {
		m.mu.RUnlock()
		return nil, fmt.Errorf("manager is closed")
	}
	conn, ok := m.servers[serverName]
	if ok {
		m.wg.Add(1) // Add to WaitGroup while holding the lock
	}
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("server %s not found", serverName)
	}
	defer m.wg.Done()

	params := &mcp.CallToolParams{
		Name:      toolName,
		Arguments: arguments,
	}

	result, err := conn.Session.CallTool(ctx, params)
	if err != nil {
		// Check if the tool call failed due to authentication
		errStr := err.Error()
		if strings.Contains(errStr, "401") || strings.Contains(errStr, "403") ||
			strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "Unauthorized") ||
			strings.Contains(errStr, "authentication required") || strings.Contains(errStr, "token expired") {
			m.emitAuthEvent(AuthEvent{
				ServerName: serverName,
				EventType:  AuthEventError,
				Message:    fmt.Sprintf("Tool %q on server %q requires authentication: %s", toolName, serverName, errStr),
				Timestamp:  time.Now(),
			})
		}
		return nil, fmt.Errorf("failed to call tool: %w", err)
	}

	return result, nil
}

// Close closes all server connections
func (m *Manager) Close() error {
	// Use Swap to atomically set closed=true and get the previous value
	// This prevents TOCTOU race with CallTool's closed check
	if m.closed.Swap(true) {
		return nil // already closed
	}

	// Wait for all in-flight CallTool calls to finish before closing sessions
	// After closed=true is set, no new CallTool can start (they check closed first)
	m.wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()

	logger.InfoCF("mcp", "Closing all MCP server connections",
		map[string]any{
			"count": len(m.servers),
		})

	var errs []error
	for name, conn := range m.servers {
		if err := conn.Session.Close(); err != nil {
			logger.ErrorCF("mcp", "Failed to close server connection",
				map[string]any{
					"server": name,
					"error":  err.Error(),
				})
			errs = append(errs, fmt.Errorf("server %s: %w", name, err))
		}
	}

	m.servers = make(map[string]*ServerConnection)

	if len(errs) > 0 {
		return fmt.Errorf("failed to close %d server(s): %w", len(errs), errors.Join(errs...))
	}

	return nil
}

// ConnectWithToken connects to an MCP server via SSE transport using
// a Bearer token for authentication. This bypasses mcp-remote entirely
// and connects directly to the MCP server's SSE/HTTP endpoint.
func (m *Manager) ConnectWithToken(
	ctx context.Context,
	name string,
	serverURL string,
	token string,
) error {
	logger.InfoCF("mcp", "Connecting to MCP server with token (SSE direct)",
		map[string]any{"server": name, "url": serverURL})

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "picoclaw",
		Version: "1.0.0",
	}, nil)

	sseTransport := &mcp.StreamableClientTransport{
		Endpoint: serverURL,
		HTTPClient: &http.Client{
			Transport: &headerTransport{
				base: http.DefaultTransport,
				headers: map[string]string{
					"Authorization": "Bearer " + token,
				},
			},
		},
	}

	session, err := client.Connect(ctx, sseTransport, nil)
	if err != nil {
		return fmt.Errorf("failed to connect with token: %w", err)
	}

	initResult := session.InitializeResult()
	logger.InfoCF("mcp", "Connected to MCP server with token",
		map[string]any{
			"server":        name,
			"serverName":    initResult.ServerInfo.Name,
			"serverVersion": initResult.ServerInfo.Version,
		})

	// List tools
	var tools []*mcp.Tool
	if initResult.Capabilities.Tools != nil {
		for tool, err := range session.Tools(ctx, nil) {
			if err != nil {
				logger.WarnCF("mcp", "Error listing tool",
					map[string]any{"server": name, "error": err.Error()})
				continue
			}
			tools = append(tools, tool)
		}
		logger.InfoCF("mcp", "Listed tools from authenticated MCP server",
			map[string]any{"server": name, "toolCount": len(tools)})
	}

	// Store connection (replace any existing one)
	m.mu.Lock()
	if existing, ok := m.servers[name]; ok {
		_ = existing.Session.Close()
	}
	m.servers[name] = &ServerConnection{
		Name:    name,
		Client:  client,
		Session: session,
		Tools:   tools,
	}
	m.mu.Unlock()

	return nil
}

// PollForTokenAndReconnect starts a background goroutine that polls
// the makersclaw-api for completed auth tokens. When a token is received,
// it connects to the MCP server directly via SSE with the token.
//
// apiBaseURL is the makersclaw-api URL (e.g., "http://localhost:8000")
// instanceID is the employee instance UUID
// serverURL is the MCP server's SSE endpoint URL
func (m *Manager) PollForTokenAndReconnect(
	ctx context.Context,
	serverName string,
	serverURL string,
	apiBaseURL string,
	instanceID string,
) {
	go func() {
		pollInterval := 5 * time.Second
		timeout := 5 * time.Minute
		deadline := time.Now().Add(timeout)

		logger.InfoCF("mcp", "Starting token poll for MCP server",
			map[string]any{
				"server":      serverName,
				"api_base":    apiBaseURL,
				"instance_id": instanceID,
				"timeout":     timeout.String(),
			})

		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				logger.InfoCF("mcp", "Token poll cancelled", map[string]any{"server": serverName})
				return
			case <-time.After(pollInterval):
			}

			// Poll the API for tokens
			url := fmt.Sprintf("%s/v1/auth-flows/%s/tokens?service_name=%s",
				apiBaseURL, instanceID, serverName)

			resp, err := http.Get(url)
			if err != nil {
				logger.DebugCF("mcp", "Token poll request failed",
					map[string]any{"server": serverName, "error": err.Error()})
				continue
			}

			if resp.StatusCode == 404 {
				resp.Body.Close()
				continue // No flow yet
			}

			if resp.StatusCode != 200 {
				resp.Body.Close()
				continue
			}

			// Parse response
			var tokenResp struct {
				Status      string `json:"status"`
				AccessToken string `json:"access_token"`
			}

			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				continue
			}

			if err := json.Unmarshal(body, &tokenResp); err != nil {
				logger.DebugCF("mcp", "Token poll parse error",
					map[string]any{"server": serverName, "error": err.Error()})
				continue
			}

			if tokenResp.Status != "completed" || tokenResp.AccessToken == "" {
				continue
			}

			accessToken := tokenResp.AccessToken

			logger.InfoCF("mcp", "Received auth token, reconnecting MCP server",
				map[string]any{"server": serverName})

			if err := m.ConnectWithToken(ctx, serverName, serverURL, accessToken); err != nil {
				logger.ErrorCF("mcp", "Failed to reconnect with token",
					map[string]any{"server": serverName, "error": err.Error()})
			} else {
				logger.InfoCF("mcp", "Successfully reconnected MCP server with auth token",
					map[string]any{"server": serverName})
			}
			return
		}

		logger.WarnCF("mcp", "Token poll timed out",
			map[string]any{"server": serverName, "timeout": timeout.String()})
	}()
}

// GetAllTools returns all tools from all connected servers
func (m *Manager) GetAllTools() map[string][]*mcp.Tool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string][]*mcp.Tool)
	for name, conn := range m.servers {
		if len(conn.Tools) > 0 {
			result[name] = conn.Tools
		}
	}
	return result
}
