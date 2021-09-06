package api

// Handshake -
type Handshake struct {
	Success        string `json:"success"`
	LoggerListener string `json:"log_listener"`
}

// HandshakeRequest -
type HandshakeRequest struct {
	LoggerAddr string `json:"logger"`
}
