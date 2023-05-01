package proxy

import (
	"context"
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
	srv            *http.Server
	done           chan os.Signal
	log            *zap.SugaredLogger
	transport      *http.Transport
	listener       net.Listener
	downstreamHost string
}

// ServeHTTP is the handler that proxies the request through
func (p *HTTPProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
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
	p.log.Debug("HTTPProxy streams")
	rw.WriteHeader(res.StatusCode)
	io.Copy(rw, res.Body)
	res.Body.Close()
}

// Dialer is the downstream dialer function
type Dialer func(n string, addr string) (net.Conn, error)

// NewHTTPProxy starts a new proxy
func NewHTTPProxy(hostport string, remote string, dialer Dialer, log *zap.SugaredLogger) *HTTPProxy {
	logger := log.Named("HTTPProxy")
	if dialer == nil {
		logger.Fatal("Dialer  not passed")
	}

	// TODO use context dialer
	// downstream connection
	t := &http.Transport{}
	t.Dial = dialer

	p := HTTPProxy{
		done:           make(chan os.Signal, 1),
		log:            logger,
		transport:      t,
		downstreamHost: remote,
	}
	logger.Debug("setting downstream host", "host", remote)
	srv := &http.Server{}
	mux := http.NewServeMux()
	mux.Handle("/", &p)
	srv.Handler = mux
	p.srv = srv

	return &p
}

// Start starts the http listener. This is blocking
func (p *HTTPProxy) ListenAndServe() (net.Listener, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		p.log.With("error", err).Error("Failed to open tcp listener")
		return nil, err
	}
	p.listener = l
	p.log.Debug("Starting listener")
	go func(l net.Listener) {
		p.log.Debug("Starting http proxy")
		// listener
		if err := p.srv.Serve(l); err != nil {
			p.log.With("error", err).Error("Unable to serve proxy")
		}
	}(l)

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
