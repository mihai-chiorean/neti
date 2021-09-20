package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"

	"go.uber.org/zap"
)

// Config -
type Config struct{}

// Proxy -
type Proxy struct {
	srv            *http.Server
	done           chan os.Signal
	log            *zap.SugaredLogger
	transport      *http.Transport
	listener       net.Listener
	downstreamHost string
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.log.Debugw("Received request", "method", req.Method, "host", req.Host, "remote", req.RemoteAddr, "url", req.RequestURI, "requrl", req.URL)
	// step 1
	outReq := new(http.Request)
	*outReq = *req // this only does shallow copies of maps
	outReq.URL = &url.URL{
		Scheme: "http",
		Path:   req.URL.Path,
		Host:   p.downstreamHost,
	}
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if prior, ok := outReq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outReq.Header.Set("X-Forwarded-For", clientIP)
	}
	p.log.Debug("calling transport")

	p.log.Debugw("outreq:", "uri", outReq.RequestURI, "url", outReq.URL, "requri", req.RequestURI, "requrl", req.URL)
	// step 2
	res, err := p.transport.RoundTrip(outReq)
	if err != nil {
		p.log.Error(err.Error())
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	p.log.Debug("copying headers")
	// step 3
	for key, value := range res.Header {
		for _, v := range value {
			rw.Header().Add(key, v)
		}
	}
	p.log.Debug("Proxy streams")
	rw.WriteHeader(res.StatusCode)
	io.Copy(rw, res.Body)
	res.Body.Close()
}

// TODO this kind of interface is used in the cli too. move this to some common package
// Dialer is the downstream dialer function
type Dialer func(n string, addr string) (net.Conn, error)

// NewHTTPProxy starts a new proxy
func NewHTTPProxy(hostport string, remote string, dialer Dialer, log *zap.SugaredLogger) *Proxy {
	logger := log.Named("HTTPProxy")
	if dialer == nil {
		logger.Fatal("Dialer  not passed")
	}
	// downstream connection
	t := &http.Transport{}
	t.Dial = dialer

	// TODO probably move this listener in the Start() or merge Start() with this.
	l, err := net.Listen("tcp", hostport)
	if err != nil {
		log.Error("Failed to open tcp listener", "error", err)
		return nil
	}
	p := Proxy{
		done:           make(chan os.Signal, 1),
		log:            logger,
		transport:      t,
		listener:       l,
		downstreamHost: remote,
	}

	return &p
}

// Start starts the http listener. This is blocking
func (p *Proxy) Start() {
	srv := &http.Server{}
	mux := http.NewServeMux()
	mux.Handle("/", p)
	srv.Handler = mux
	go func() {
		// listener
		if err := srv.Serve(p.listener); err != nil {
			p.log.Fatal(err)
		}
		//if err := srv.ListenAndServe(); err != nil {
		//	p.log.Fatal(err)
		//}
	}()
	p.srv = srv
	<-p.done

	p.log.Info("Shutting down proxy")
	if err := srv.Shutdown(context.Background()); err != nil {
		p.log.Error(err)
	}
}

// Stop stops the http proxy
func (p *Proxy) Stop() {
	p.done <- syscall.SIGSTOP
}

// ListenerHost gets the server addr
func (p *Proxy) ListenerHost() string {
	return p.listener.Addr().String()
}
