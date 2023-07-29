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
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/mihai-chiorean/neti/cli/config"
	"github.com/mihai-chiorean/neti/cli/logging"
	"github.com/mihai-chiorean/neti/gateway/api"
	"github.com/mihai-chiorean/neti/internal/proxy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
)

var ProxyPort string
var GatewayHost string

func NewRootCmd(logger *zap.SugaredLogger) *cobra.Command {
	// rootCmd represents the base command when called without any subcommands
	return &cobra.Command{
		Use:   "cli",
		Short: "A brief description of your application",
		Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		// Uncomment the following line if your bare application
		// has an action associated with it:
		Run: func(cmd *cobra.Command, args []string) {
			config := getConfig()
			sshclient(logger, config)
		},
	}
}

func getConfig() *config.Config {
	conf := config.Config{}
	err := viper.Unmarshal(&conf)
	if err != nil {
		fmt.Printf("Unable to decode into config struct, %v", err)
	}

	fmt.Println(viper.GetString("port"))
	fmt.Println(viper.GetString("gateway"))
	fmt.Println(viper.GetString("private_key_path"))
	fmt.Println(conf)
	return &conf
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(cmd *cobra.Command) {
	cobra.CheckErr(cmd.Execute())
}

func sshclient(logger *zap.SugaredLogger, cliConfig *config.Config) {

	// Load the private key
	// privateKeyPath := "private_unencrypted.pem"
	logger.Infof("Loading private key from: %s", cliConfig.PrivateKeyPath)
	signer, err := loadPrivateKey(cliConfig.PrivateKeyPath, logger)
	if err != nil {
		// TODO - log.Fatal is not the best way to handle this - return an error and do "fatals" in main
		logger.Fatal("Failed to load private key:", err)
	}

	sshConfig := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			// ssh.Password("tiger"),
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //hostKeyCallback, //ssh.FixedHostKey(hostKey),
	}

	// Dial your ssh server.
	logger.Infof("Connecting to gateway: %s", cliConfig.Gateway)
	connAuth, err := ssh.Dial("tcp", cliConfig.Gateway, sshConfig)
	if err != nil {
		logger.Fatal(err, "unable to connect: ")
	}
	defer connAuth.Close()

	logger.Info("Starting SSH session")
	// Perform the SSH handshake
	sshSession, err := connAuth.NewSession()
	if err != nil {
		// TODO - log.Fatal is not the best way to handle this - return an error and do "fatals" in main
		log.Fatalf("Failed to create SSH session: %s", err)
	}
	defer sshSession.Close()

	outputPipe, err := sshSession.StdoutPipe()
	if err != nil {
		// TODO - log.Fatal is not the best way to handle this - return an error and do "fatals" in main
		log.Fatalf("Failed to get server output pipe: %s", err)
	}
	outputScanner := bufio.NewScanner(outputPipe)

	// Redirect the session's output to the local stdout
	sshSession.Stdout = os.Stdout
	sshSession.Stderr = os.Stderr

	logger.Info("Echo to session")

	// TODO - is this needed if the force command is set up in the server ssh config?
	// Start the session and wait for the force command to be executed
	// Need this to be in a goroutine because it will block until the command is done
	go func() {
		if err = sshSession.Run("/bin/gateway "); err != nil {
			log.Fatalf("Failed to execute command: %s", err)
		}
	}()

	logger.Info("Waiting for the gw to start listening... (2 sec timer)")

	time.Sleep(2 * time.Second)

	serverPort := ""
	for outputScanner.Scan() {
		line := outputScanner.Text()

		if strings.HasPrefix(line, "gateway listening hostport ") {
			postStr := strings.TrimPrefix(line, "gateway listening hostport ")
			_, serverPort, err = net.SplitHostPort(postStr)
			if err != nil {
				log.Fatalf("Failed to parse server port: %s", err)
			}
			break
		}
	}
	if serverPort == "" {
		log.Fatal("Failed to find server port in the output")
	}

	// Create a connection from server A to server B
	gwHostport := fmt.Sprintf("127.0.0.1:%s", serverPort)
	connAB, err := connAuth.Dial("tcp", gwHostport)
	if err != nil {
		log.Fatalf("Failed to connect to server B through server A: %s", err)
	}

	// Establish an SSH connection with server B using the connection from server A
	connB, chans, reqs, err := ssh.NewClientConn(connAB, gwHostport, sshConfig)
	if err != nil {
		log.Fatalf("Failed to establish SSH connection with server B: %s", err)
	}
	defer connB.Close()

	// Create an SSH client from the connection with server B
	clientB := ssh.NewClient(connB, chans, reqs)
	defer clientB.Close()

	// TODO this is a hack to wait for the command to be executed
	// TODO if each user is connected to a different gw process, we need to figure out the listener port for each client to connect to
	logger.Infof("Dialing %s", serverPort)

	// Dial your ssh server.
	conn := ssh.NewClient(connB, chans, reqs)
	// if err != nil {
	// 	logger.Fatal(err, "unable to connect: ")
	// }
	defer conn.Close()

	logger.Info("Sending handshake to gateway")
	handshake := api.HandshakeRequest{
		LoggerAddr: ":0",
	}
	// TODO handle error
	body, _ := json.Marshal(&handshake)

	// this is an "ssh request"; the body will likely expand with other things
	// TODO we need these api names - like Handshake - in some static form
	_, payload, err := conn.SendRequest("Handshake", true, body)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Info("Handshake?")

	// this is the handshake response; it will expose the port logs come on
	var handshakeRes api.Handshake
	if err := json.Unmarshal(payload, &handshakeRes); err != nil {
		logger.Fatal(err)
	}
	logger.Info("Handshake received", "payload", handshakeRes)

	gwLogger := logging.NewGatewayLogger(zapcore.DebugLevel, handshakeRes.LoggerListener, logger.Named("GATEWAY").Desugar())
	gwLogger.Start(conn)

	httpProxyReq := api.HTTPProxyRequest{
		ServiceHostPort: "dummy:8080",
	}

	// TODO handle error
	body, _ = json.Marshal(&httpProxyReq)

	// this is another api that the gateway provides. At the moment there is no payload schema for it
	_, payload, err = conn.SendRequest("NewHTTPProxy", true, body)
	if err != nil {
		logger.Fatal(err)
	}

	logger.Info("addr", payload, "Received http proxy payload")

	// Serve HTTP with your SSH server acting as a reverse proxy.
	// payload has the hostport
	p, _ := proxy.NewHTTPProxy(fmt.Sprintf(":%s", cliConfig.Port), string(payload), proxy.Dialer(func(ctx context.Context, n string, addr string) (net.Conn, error) {
		logger.Infow("Dialing...", "addr", addr)
		newChannel, err := conn.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		logger.Infow("Have tcp connection", "remote", newChannel.RemoteAddr().String())

		return newChannel, nil
	}), logger)
	l, err := p.ListenAndServe()
	if err != nil {
		logger.Fatal(err)
	}
	logger.Debug(l.Addr().String())
	defer l.Close()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}

func loadPrivateKey(privateKeyPath string, logger *zap.SugaredLogger) (ssh.Signer, error) {
	keyBytes, err := ioutil.ReadFile(privateKeyPath)
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
