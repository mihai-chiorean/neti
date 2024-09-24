package client

import "github.com/mihai-chiorean/neti/cli/config"

// Client -
type Client struct {
	config *config.Config
}

func NewClient(config *config.Config) *Client {
	return &Client{
		config: config,
	}
}
