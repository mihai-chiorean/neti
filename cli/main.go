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

//package proxy
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/mihai-chiorean/neti/cli/cmd"
	"github.com/mihai-chiorean/neti/cli/logging"
	"github.com/mihai-chiorean/neti/gateway/api"
	"github.com/mihai-chiorean/neti/internal/proxy"
	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
	knownhosts "golang.org/x/crypto/ssh/knownhosts"
)

// Config -
type Config struct{}

type logDecoder interface {
	Decode(in io.Reader)
	Log([]byte)
}

func sshclient(logger *zap.SugaredLogger) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		logger.Fatal(err)
	}

	hostKeyCallback, err := knownhosts.New(fmt.Sprintf("%s/.ssh/known_hosts", homedir))
	if err != nil {
		logger.Fatal(err)
	}

	// TODO we need to make this work with a public key, not a password
	//var hostKey ssh.PublicKey
	config := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.Password("tiger"),
		},
		HostKeyCallback: hostKeyCallback, //ssh.FixedHostKey(hostKey),
	}

	// Dial your ssh server.
	conn, err := ssh.Dial("tcp", "localhost:8022", config)
	if err != nil {
		logger.Fatal(err, "unable to connect: ")
	}
	defer conn.Close()

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
	// this is the handshake response; it will expose the port logs come on
	var handshakeRes api.Handshake
	if err := json.Unmarshal(payload, &handshakeRes); err != nil {
		logger.Fatal(err)
	}
	logger.Info("Handshake received", "payload", handshakeRes)

	gwLogger := logging.NewGatewayLogger(zapcore.DebugLevel, handshakeRes.LoggerListener, logger.Named("GATEWAY").Desugar())
	gwLogger.Start(conn)

	httpProxyReq := api.HTTPProxyRequest{
		ServiceHostPort: "dummy:80",
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
	p := proxy.NewHTTPProxy(":8085", string(payload), proxy.Dialer(func(n string, addr string) (net.Conn, error) {
		logger.Infow("Dialing...", "addr", addr)
		newChannel, err := conn.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		logger.Infow("Have tcp connection", "remote", newChannel.RemoteAddr().String())

		return newChannel, nil
	}), logger)
	p.ListenAndServe()
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
	sshclient(logger)

	cmd.Execute()
}
