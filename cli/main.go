/*
   Copyright © 2021 NAME HERE mihai.v.chiorean@gmail.com

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

// package proxy
package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/mihai-chiorean/neti/cli/cmd"
	"github.com/mihai-chiorean/neti/cli/logging"
	"github.com/mihai-chiorean/neti/gateway/api"
	"github.com/mihai-chiorean/neti/internal/proxy"
	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
)

// Config -
type Config struct {
	host string
	port string
}

type logDecoder interface {
	Decode(in io.Reader)
	Log([]byte)
}

func sshclient(logger *zap.SugaredLogger) {

	// Load the private key
	privateKeyPath := "private_unencrypted.pem"
	signer, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		log.Fatal("Failed to load private key:", err)
	}

	config := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			// ssh.Password("tiger"),
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //hostKeyCallback, //ssh.FixedHostKey(hostKey),
	}

	// Dial your ssh server.
	connAuth, err := ssh.Dial("tcp", "a7be28a34b40e4b9b8da39f451765819-44965618e660adb0.elb.us-west-2.amazonaws.com:10023", config)
	// connAuth, err := ssh.Dial("tcp", "127.0.0.1:8023", config)
	if err != nil {
		logger.Fatal(err, "unable to connect: ")
	}
	defer connAuth.Close()

	logger.Info("Starting SSH session")
	// Perform the SSH handshake
	sshSession, err := connAuth.NewSession()
	if err != nil {
		log.Fatalf("Failed to create SSH session: %s", err)
	}
	defer sshSession.Close()

	outputPipe, err := sshSession.StdoutPipe()
	if err != nil {
		log.Fatalf("Failed to get server output pipe: %s", err)
	}
	outputScanner := bufio.NewScanner(outputPipe)

	// Redirect the session's output to the local stdout
	sshSession.Stdout = os.Stdout
	sshSession.Stderr = os.Stderr

	logger.Info("Echo to session")

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
	connB, chans, reqs, err := ssh.NewClientConn(connAB, gwHostport, config)
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
	p, _ := proxy.NewHTTPProxy(fmt.Sprintf(":%s", cmd.ProxyPort), string(payload), proxy.Dialer(func(ctx context.Context, n string, addr string) (net.Conn, error) {
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

func loadPrivateKey(privateKeyPath string) (ssh.Signer, error) {
	keyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

func madTCPProxyThing() {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	out, err := d.DialContext(ctx, "tcp", ":8888")
	if err != nil {
		// handle error
		log.Fatal(err)
	}

	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Listening on 8080")

	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go func(c net.Conn) {
			logger := zerolog.New(out).With().Timestamp().Logger()
			logger.Info().Msg("infoo!!")
			// Echo all incoming data.
			io.Copy(out, c)
			c.Write([]byte(`message sent`))
			// set SetReadDeadline
			err := out.SetReadDeadline(time.Now().Add(5 * time.Second))
			if err != nil {
				fmt.Println("SetReadDeadline failed:", err)
				// do something else, for example create new conn
				return
			}

			recvBuf := make([]byte, 1024)
			n, err := out.Read(recvBuf[:])
			if err != nil {
				fmt.Println(err.Error())
			}
			fmt.Println(n)
			c.Write(recvBuf)
			// Shut down the connection.
			c.Close()
		}(conn)
	}
}

func main() {

	lp, _ := zap.NewDevelopment()
	logger := lp.Sugar()
	defer logger.Sync()

	// logger.Info("Starting DNS server on port 8889")
	// dns := dns.NewDNSServer(53)
	// TODO dns.AddZoneData(zone string, records map[string]string, lookupFunc func(string) (string, error), lookupZone dns.ZoneType)
	// if err := dns.StartAndServe(); err != nil {
	// logger.Fatal(err)
	// }

	cmd.Execute()
	sshclient(logger)
}
