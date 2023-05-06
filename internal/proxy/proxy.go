package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"go.uber.org/zap"
)

// Config -
type Config struct {
	//Heartbeat
	// Timeout
}

// HTTPProxy -
type HTTPProxy struct {
	srv       *http.Server
	done      chan os.Signal
	log       *zap.SugaredLogger
	transport *http.Transport
	listener  net.Listener

	// downstreamHost is the host to which the proxy will forward requests
	downstreamHost string

	// hostport is the hostport on which the proxy will listen
	hostport string
}

// ServeHTTP is the handler that proxies the request through. This is where requests are received
// and this would be where we'd expect to add logic fo allow/denylist, rate limiting, record/replay.
func (p *HTTPProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	log := p.log.With("method", req.Method, "host", req.Host, "remote", req.RemoteAddr, "url", req.RequestURI, "requrl", req.URL)
	log.Debugw("Received request")

	// step 1: create outgoing request
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
		log.With("clientIP", clientIP).Debug("Setting X-Forwarded-For")
	}
	log.Debug("Calling transport")

	log.Debugw("Outreq:",
		"target_uri", outReq.RequestURI,
		"target_url", outReq.URL,
		"requri", req.RequestURI,
		"requrl", req.URL,
	)

	// step 2: call transport with the outgoing request
	res, err := p.transport.RoundTrip(outReq)
	if err != nil {
		p.log.Error(err.Error())
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	log.Debug("Copying headers")

	// step 3
	for key, value := range res.Header {
		for _, v := range value {
			rw.Header().Add(key, v)
		}
	}
	log.Debug("HTTPProxy streams")
	rw.WriteHeader(res.StatusCode)

	// step 4 copy the response body
	io.Copy(rw, res.Body)
	res.Body.Close() // close the body
}

// Dialer is the downstream dialer function
type Dialer func(ctx context.Context, n string, addr string) (net.Conn, error)

// NewHTTPProxy starts a new proxy
func NewHTTPProxy(hostport string, remote string, dialer Dialer, log *zap.SugaredLogger) (*HTTPProxy, error) {
	logger := log.Named("HTTPProxy")
	if dialer == nil {
		ErrNilDialer := fmt.Errorf("must pass a dialer")
		return nil, ErrNilDialer
	}

	// Setting up the transport that diales the downstream connection
	t := &http.Transport{}
	t.DialContext = dialer

	logger.Debug("Setting downstream host", "host", remote)
	p := HTTPProxy{
		done:           make(chan os.Signal, 1),
		log:            logger,
		transport:      t,
		downstreamHost: remote,
		hostport:       hostport,
	}

	srv := &http.Server{}
	mux := http.NewServeMux()
	mux.Handle("/", &p)
	srv.Handler = mux
	p.srv = srv

	return &p, nil
}

// Start starts the http listener.
func (p *HTTPProxy) ListenAndServe() (net.Listener, error) {
	l, err := net.Listen("tcp", p.hostport)
	if err != nil {
		p.log.With("error", err).Error("Failed to open tcp listener")
		return nil, err
	}
	p.listener = l
	p.log.With("hostport", p.hostport).Debug("Starting listener")
	// go func(l net.Listener) {
	p.log.Debug("Starting http proxy")
	// listener
	if err := p.srv.Serve(l); err != nil {
		p.log.With("error", err).Error("Unable to serve proxy")
	}
	// }(l)

	return l, nil
}

// Stop stops the http proxy
func (p *HTTPProxy) Stop() {
	p.log.Info("Shutting down proxy")
	if err := p.srv.Shutdown(context.Background()); err != nil {
		p.log.Error(err)
	}

}

// ListenerHost gets the server addr
func (p *HTTPProxy) ListenerHost() string {
	// TODO make this error
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}
