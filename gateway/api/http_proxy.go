package api

// HTTPProxyRequest is the type of request expected to be received for creating
// a new http proxy
type HTTPProxyRequest struct {
	ServiceHostPort string `json:"serviceHostPort"`
}
