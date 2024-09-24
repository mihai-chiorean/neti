/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/mihai-chiorean/neti/cli/config"
	netissh "github.com/mihai-chiorean/neti/cli/ssh"
	"github.com/mihai-chiorean/neti/internal/proxy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

var ProxyPort string
var GatewayHost string

type netiClient interface {
	DialBastion(hostport string) error
	StartGateway() (string, error)
	DialGateway(gwHostport string) (*ssh.Client, error)
	Handshake() error
	CreateHTTPProxy(string) (string, error)
}

func NewRootCmd(logger *zap.SugaredLogger) *cobra.Command {
	// rootCmd represents the base command when called without any subcommands
	return &cobra.Command{
		Use:   "neti",
		Short: "Neti is the client to connect the the neti gateway and route local traffic to remote services",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			config := getConfig()
			// Load the private key
			logger.Debugf("Loading private key from: %s", config.PrivateKeyPath)
			signer, err := loadPrivateKey(config.PrivateKeyPath, logger)
			if err != nil {
				logger.Error("Failed to load private key:", err)
			}

			sshConfig := &ssh.ClientConfig{
				User: "testuser",
				Auth: []ssh.AuthMethod{
					ssh.PublicKeys(signer),
				},
				// TODO what's up with this?
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), //hostKeyCallback, //ssh.FixedHostKey(hostKey),
			}

			c := netissh.NewSSHClient(sshConfig, logger)
			start(c, logger, config)
		},
	}
}

func getConfig() *config.Config {
	conf := config.Config{}
	err := viper.Unmarshal(&conf)
	if err != nil {
		fmt.Printf("Unable to decode into config struct, %v", err)
	}

	return &conf
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(cmd *cobra.Command) {
	cobra.CheckErr(cmd.Execute())
}

func start(c netiClient, logger *zap.SugaredLogger, cliConfig *config.Config) error {

	// Dial your ssh server.
	if err := c.DialBastion(cliConfig.Gateway); err != nil {
		logger.Error(err)
		return err
	}

	serverPort, err := c.StartGateway()
	if err != nil {
		logger.Fatalf("Could not start gateway", err)
	}

	// Create a connection from server A to server B
	gwHostport := fmt.Sprintf("127.0.0.1:%s", serverPort)
	conn, err := c.DialGateway(gwHostport)
	if err != nil {
		return err
	}

	logger.Debug("Sending handshake to gateway")
	if err := c.Handshake(); err != nil {
		return err
	}

	proxyHost, err := c.CreateHTTPProxy("dummy:8080")
	if err != nil {
		return err
	}

	// Serve HTTP with your SSH server acting as a reverse proxy.
	// payload has the hostport
	p, err := proxy.NewHTTPProxy(fmt.Sprintf(":%s", cliConfig.Port), proxyHost, proxy.Dialer(func(ctx context.Context, n string, addr string) (net.Conn, error) {
		logger.Infow("Dialing...", "addr", addr)
		newChannel, err := conn.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		logger.Infow("Have tcp connection", "remote", newChannel.RemoteAddr().String())

		return newChannel, nil
	}), logger)
	if err != nil {
		return err
	}
	l, err := p.ListenAndServe()
	if err != nil {
		return err
	}
	defer l.Close()
	k := make(chan os.Signal, 1)
	signal.Notify(k, os.Interrupt)
	<-k
	return nil
}

func loadPrivateKey(privateKeyPath string, logger *zap.SugaredLogger) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	logger.Debug("Read private key")
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, err
	}

	logger.Debug("Decoded private key")
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	logger.Debug("Parsed private key")
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}

	return signer, nil
}
