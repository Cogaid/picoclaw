package mcp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// GeneratePKCE generates a PKCE code_verifier and code_challenge pair.
// The code_verifier is a random 64-character base64url string.
// The code_challenge is the SHA256 hash of the verifier, base64url-encoded.
func GeneratePKCE() (codeVerifier, codeChallenge string, err error) {
	// Generate 48 random bytes → 64 base64url characters
	buf := make([]byte, 48)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	codeVerifier = base64.RawURLEncoding.EncodeToString(buf)

	// SHA256 hash of the verifier, base64url-encoded (no padding)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return codeVerifier, codeChallenge, nil
}

// RewriteOAuthURL takes an OAuth authorization URL (from mcp-remote stderr),
// rewrites the redirect_uri to our callback, generates new PKCE parameters,
// and extracts OAuth metadata needed for the token exchange.
//
// Returns the rewritten URL, the code_verifier for PKCE, and metadata.
func RewriteOAuthURL(originalURL, callbackURL, flowID string) (rewrittenURL, codeVerifier string, metadata map[string]string, err error) {
	parsed, err := url.Parse(originalURL)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to parse OAuth URL: %w", err)
	}

	params := parsed.Query()

	// Extract metadata before rewriting
	metadata = map[string]string{
		"client_id":              params.Get("client_id"),
		"scope":                  params.Get("scope"),
		"resource":               params.Get("resource"),
		"original_redirect_uri":  params.Get("redirect_uri"),
		"original_state":         params.Get("state"),
		"authorization_endpoint": parsed.Scheme + "://" + parsed.Host + parsed.Path,
	}

	// Infer the token endpoint from the authorization endpoint
	// Common patterns:
	//   /oauth/v2/auth → /oauth/v2/token
	//   /oauth → /oauth/token
	//   /authorize → /token
	tokenURL := inferTokenURL(parsed)
	if tokenURL != "" {
		metadata["token_url"] = tokenURL
	}

	// Generate new PKCE pair
	codeVerifier, codeChallenge, err := GeneratePKCE()
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	// Rewrite parameters
	params.Set("redirect_uri", callbackURL)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", flowID)

	parsed.RawQuery = params.Encode()

	return parsed.String(), codeVerifier, metadata, nil
}

// IsOAuthURL checks if a URL looks like an OAuth authorization URL.
// Returns true for URLs containing response_type=code or /oauth paths.
func IsOAuthURL(rawURL string) bool {
	lower := strings.ToLower(rawURL)

	// Must be a full URL
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return false
	}

	// Parse the URL to check the HOST (not query params which may contain localhost in redirect_uri)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Skip localhost/127.0.0.1 as the HOST (mcp-remote's local callback server)
	// Don't check the full URL because redirect_uri param may contain "localhost"
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || host == "127.0.0.1" {
		return false
	}

	// Check for OAuth indicators
	if strings.Contains(lower, "response_type=code") {
		return true
	}
	if strings.Contains(parsed.Path, "/oauth") && strings.Contains(lower, "client_id=") {
		return true
	}

	return false
}

// inferTokenURL attempts to derive the token endpoint from the authorization endpoint.
func inferTokenURL(authURL *url.URL) string {
	path := authURL.Path
	base := authURL.Scheme + "://" + authURL.Host

	// Zoho: /mcp-client/.../oauth → token endpoint is on accounts.zoho.com
	if strings.Contains(authURL.Host, "zoho") {
		// Zoho uses accounts.zoho.com for token exchange
		// Detect region from host: zoho.com, zoho.in, zoho.eu, etc.
		parts := strings.Split(authURL.Host, ".")
		if len(parts) >= 2 {
			tld := strings.Join(parts[len(parts)-2:], ".")
			return "https://accounts." + tld + "/oauth/v2/token"
		}
		return "https://accounts.zoho.com/oauth/v2/token"
	}

	// Google: /o/oauth2/v2/auth → /token (or /oauth2/v4/token)
	if strings.Contains(authURL.Host, "google") || strings.Contains(authURL.Host, "googleapis") {
		return "https://oauth2.googleapis.com/token"
	}

	// Microsoft: .../oauth2/v2.0/authorize → .../oauth2/v2.0/token
	if strings.Contains(path, "/oauth2/v2.0/authorize") {
		return base + strings.Replace(path, "/authorize", "/token", 1)
	}

	// Generic: /oauth/authorize → /oauth/token, /auth → /token
	if strings.HasSuffix(path, "/authorize") || strings.HasSuffix(path, "/auth") {
		dir := path[:strings.LastIndex(path, "/")]
		return base + dir + "/token"
	}

	// Generic: /oauth/v2/auth → /oauth/v2/token
	if strings.HasSuffix(path, "/auth") {
		return base + path[:len(path)-4] + "token"
	}

	return ""
}
