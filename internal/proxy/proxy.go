package proxy

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// Config -
type Config struct{}

// Proxy -
type Proxy struct {
	srv  *http.Server
	done chan os.Signal
	log  *zap.SugaredLogger
}

// NewProxy -
func NewProxy() *Proxy {
	return nil
}

// NewHTTPProxy starts a new proxy
func NewHTTPProxy(hostport string, remote string, conn *ssh.Client, logger *zap.SugaredLogger) *Proxy {
	// downstream connection
	cli := http.Client{
		Transport: http.RoundTripper(&http.Transport{
			Dial: func(n string, addr string) (net.Conn, error) {
				logger.Infow("Dialing...", "addr", addr)
				newChannel, err := conn.Dial("tcp", addr)
				if err != nil {
					return nil, err
				}
				logger.Infow("Have tcp connection", "remote", newChannel.RemoteAddr().String())

				return newChannel, nil
			},
		}),
	}

	srv := http.Server{
		Addr: hostport,
		Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			logger.Info("Request received")
			res, err := cli.Get("http://" + remote)
			if err != nil {
				logger.Error(err)
				fmt.Fprintf(resp, "Fail!\n")
				return
			}
			logger.Info("Request proxied")
			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				logger.Error(err)
				fmt.Fprintf(resp, "Fail!\n")
				return
			}
			logger.Info("money!")
			logger.Info(string(body))
			fmt.Fprintf(resp, "Hello world!\n")
		}),
	}
	p := Proxy{
		srv:  &srv,
		done: make(chan os.Signal, 1),
		log:  logger,
	}

	return &p
}

// Start starts the http listener
func (p *Proxy) Start() {

	go func() {
		// listener
		if err := p.srv.ListenAndServe(); err != nil {
			p.log.Fatal(err)
		}
	}()
	<-p.done

	p.log.Info("Shutting down proxy")
	if err := p.srv.Shutdown(context.Background()); err != nil {
		p.log.Error(err)
	}
}

// Stop stops the http proxy
func (p *Proxy) Stop() {
	p.done <- syscall.SIGSTOP
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
