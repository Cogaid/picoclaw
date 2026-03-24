package mcp

import "time"

// AuthEvent represents an authentication requirement detected during
// MCP server connection or tool execution. When emitted, the handler
// should forward this to the user (e.g., via Supabase tool_auth_flows).
type AuthEvent struct {
	// ServerName is the MCP server that needs authentication
	ServerName string `json:"server_name"`
	// EventType describes what happened
	EventType AuthEventType `json:"event_type"`
	// URL is the OAuth or verification URL the user needs to visit
	URL string `json:"url,omitempty"`
	// QRData is the QR code payload (base64 image or raw text)
	QRData string `json:"qr_data,omitempty"`
	// DeviceCode is the device code for device_code flows
	DeviceCode string `json:"device_code,omitempty"`
	// Message is a human-readable description of what's needed
	Message string `json:"message,omitempty"`
	// CodeVerifier is the PKCE code_verifier for OAuth URL rewriting.
	// Stored in the auth flow metadata so the callback can exchange the code.
	CodeVerifier string `json:"code_verifier,omitempty"`
	// OAuthMeta contains OAuth parameters extracted from the original URL
	// (client_id, token_url, scopes, resource, etc.)
	OAuthMeta map[string]string `json:"oauth_meta,omitempty"`
	// Timestamp is when the event was detected
	Timestamp time.Time `json:"timestamp"`
}

// AuthEventType describes the kind of auth event
type AuthEventType string

const (
	AuthEventURL        AuthEventType = "auth_url"
	AuthEventQRCode     AuthEventType = "qr_code"
	AuthEventDeviceCode AuthEventType = "device_code"
	AuthEventError      AuthEventType = "auth_error"
	AuthEventSuccess    AuthEventType = "auth_success"
)

// AuthEventHandler is a callback invoked when an MCP server
// or channel requires user authentication.
type AuthEventHandler func(event AuthEvent)
