package proxy

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"syscall"

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

// Start starts the http listener. This is blocking
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
