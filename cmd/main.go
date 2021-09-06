//package proxy
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/mihai-chiorean/cerberus/cmd/logging"
	"github.com/mihai-chiorean/cerberus/gateway/api"
	"github.com/mihai-chiorean/cerberus/internal/proxy"
	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
	knownhosts "golang.org/x/crypto/ssh/knownhosts"
)

// Config -
type Config struct{}

// Proxy -
type Proxy struct{}

// NewProxy -
func NewProxy() *Proxy {
	return nil
}

type logDecoder interface {
	Decode(in io.Reader)
	Log([]byte)
}

func sshclient(logger *zap.SugaredLogger) {
	// the ssh client config needs a way to lookup known hosts{
	hostKeyCallback, err := knownhosts.New("/Users/mihaichiorean/.ssh/known_hosts")
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

	gwLogger := logging.NewGatewayLogger(zapcore.DebugLevel, handshakeRes.LoggerListener, logger.Desugar())
	gwLogger.Start(conn)

	// this is another api that the gateway provides. At the moment there is no payload schema for it
	_, payload, err = conn.SendRequest("NewHTTPProxy", true, []byte(`duude!`))
	if err != nil {
		logger.Fatal(err)
	}

	logger.Info("addr", payload, "Received http proxy payload")

	//httpconn, err := conn.Dial("tcp", string(payload))
	//if err != nil {
	//	logger.Fatal(err)
	//}
	//var hs map[string]interface{}
	//if err := json.Unmarshal(payload, &hs); err != nil {
	//	logger.Fatal(err)
	//}

	logger.Info(string(payload))

	// Request the remote side to open port 8080 on all interfaces.
	//l, err := conn.Listen("tcp", ":8085")
	//if err != nil {
	//	logger.Fatal(err, "unable to register tcp forward: ")
	//}
	//defer l.Close()
	//logger.Info("Listening tcp on ", l.Addr().String())

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
	p.Start()
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
}
