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

func newGatewayLogListener(logger *zap.SugaredLogger) (string, error) {
	//log := logger.Named("GATEWAY")
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", err
	}

	// TODO add don channel
	go func() {
		defer l.Close()
		for {
			// Wait for a connection.
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Handle the connection in a new goroutine.
			// The loop then returns to accepting, so that
			// multiple connections may be served concurrently.
			go func(c net.Conn) {
				// Echo all incoming data.
				io.Copy(c, c)
				// Shut down the connection.
				c.Close()
			}(conn)
		}
	}()
	return l.Addr().String(), nil
}

func sshclient(logger *zap.SugaredLogger) {
	hostKeyCallback, err := knownhosts.New("/Users/mihaichiorean/.ssh/known_hosts")
	if err != nil {
		logger.Fatal(err)
	}

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

	//	conn.SendRequest
	//	t := http.Transport{
	//		Dial: conn.Dial,
	//	}

	//	cli := http.Client{
	//		Transport: t,
	//	}
	//addr, _ := newGatewayLogListener(logger)
	handshake := api.HandshakeRequest{
		LoggerAddr: ":0",
	}
	// TODO handle error
	body, _ := json.Marshal(&handshake)
	_, payload, err := conn.SendRequest("Handshake", true, body)
	if err != nil {
		logger.Fatal(err)
	}
	var handshakeRes api.Handshake
	if err := json.Unmarshal(payload, &handshakeRes); err != nil {
		logger.Fatal(err)
	}
	logger.Info("Handshake received", "payload", handshakeRes)

	newChannel, err := conn.Dial("tcp", handshakeRes.LoggerListener)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Infow("Have tcp connection for logger", "remote", newChannel.RemoteAddr().String())
	go func(l logDecoder) {
		//rawEntry := json.NewDecoder(newChannel)
		//io.Copy(os.Stderr, newChannel)
		//for {
		//var entry zapcore.Entry
		//	var entry map[string]interface{}
		//	if err := rawEntry.Decode(&entry); err == io.EOF {
		//		logger.Error(err)
		//		break
		//	} else if err != nil {
		//		logger.Error(err)
		//	}
		//	data, _ := json.Marshal(entry)
		//	fmt.Println(string(data))
		//var cEntry zapcore.CheckedEntry
		//fmt.Printf("%v\n", cEntry.Entry)
		//core.Check(entry, &cEntry).Write()
		//cEntry.Write()
		//core.Write(entry, []zapcore.Field{})
		//}
		l.Decode(newChannel)
	}(logging.NewLogReceiver(logger.Desugar().Named("GATEWAY")))

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
