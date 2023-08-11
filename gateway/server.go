package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/mihai-chiorean/neti/gateway/api"
	"github.com/mihai-chiorean/neti/internal/proxy"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
)

// Server is the gateway ssh server
type Server struct {
	log     *zap.SugaredLogger
	config  *ssh.ServerConfig
	proxies map[string]interface{}
}

// NewServer creates a gateway server
func NewServer(log *zap.SugaredLogger) (*Server, error) {
	config := &ssh.ServerConfig{
		// Remove to disable password auth.
		// PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		// 	// Should use constant-time compare (or better, salt+hash) in
		// 	// a production setting.
		// 	log.Infow("Checking handshake")
		// 	if c.User() == "testuser" && string(pass) == "tiger" {
		// 		return nil, nil
		// 	}
		// 	return nil, fmt.Errorf("password rejected for %q", c.User())
		// },

		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{
				// Record the public key used for authentication.
				Extensions: map[string]string{
					"pubkey-fp": ssh.FingerprintSHA256(pubKey),
				},
			}, nil
		},
	}

	privateBytes, err := os.ReadFile("/etc/ssh/probe/probe.key")
	if err != nil {
		return nil, err
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}

	config.AddHostKey(private)

	server := Server{
		log:     log,
		config:  config,
		proxies: map[string]interface{}{},
	}

	return &server, nil
}

// routeRequests is a "dumb" router for ssh.Requests
func (s *Server) routeRequests(in <-chan *ssh.Request) {
	logger := s.log
	for req := range in {
		logger.Infow("Request received", "type", req.Type)
		switch req.Type {
		case "Handshake":
			s.handshake(req)
		case "NewHTTPProxy":
			// TODO change this to an ctual service, not a hardcoded one
			s.newHTTPProxy(req)
		default:
			{
				if req.WantReply {
					req.Reply(true, nil)
				}
			}
		}
	}
}

// handshake is the initial call the client makes to the gateway
// ideally we'd do some authorization here.
//
// currently it opens a tcp connection used for the gateway to send
// logs to the client
func (s *Server) handshake(req *ssh.Request) {
	h := api.Handshake{
		Success: "pong",
	}
	var hr api.HandshakeRequest
	if err := json.Unmarshal(req.Payload, &hr); err != nil {
		s.log.Error(err)
		h.Success = "json unmarshal error"
	}

	s.log.Debugw("Handshake req unpacked", string(req.Payload))

	ll, err := net.Listen("tcp", hr.LoggerAddr)
	if err != nil {
		s.log.Error(err)
		req.Reply(false, nil)
	}
	h.LoggerListener = ll.Addr().String()
	s.log.Debugw("Listening for log connections", "addr", ll.Addr().String())
	s.proxies[ll.Addr().String()] = ll
	go func() {
		conn, err := ll.Accept()
		if err != nil {
			s.log.Error(err)
			return
		}

		s.log.Debug("Rerouting logs to client")
		s.log = s.log.Desugar().WithOptions(newToClientLogger(conn)).Sugar()
		s.log.Debug("Logs rerouted to client")
	}()
	payload, err := json.Marshal(&h)
	if err != nil {
		s.log.Error(err)
		req.Reply(false, nil)
	}
	req.Reply(true, payload)
}

func (s *Server) newHTTPProxy(req *ssh.Request) {

	var httpProxyReq api.HTTPProxyRequest
	if err := json.Unmarshal(req.Payload, &httpProxyReq); err != nil {
		s.log.Error(err)
		return
	}

	target := httpProxyReq.ServiceHostPort
	log := s.log.Named("gateway_proxy").With("target", target)
	log.Debugw("Opening new HTTP handler")

	// TODO Replace with new http proxy; the request should have some
	//		the request should have some destination service name or port
	dialer := func(ctx context.Context, n string, addr string) (net.Conn, error) {
		log.Debugw("Dialing..", "remote", target, "addr", addr)
		return net.Dial("tcp", target)
	}

	// Start new http listener on an ephemeral port
	p, _ := proxy.NewHTTPProxy(":0", target, dialer, s.log)

	_, err := p.ListenAndServe()
	if err != nil {
		log.Error(err)
		req.Reply(false, nil)
		return
	}

	log.Infow("HTTP Proxy started", "hostport", p.ListenerHost())
	s.proxies[p.ListenerHost()] = p
	req.Reply(true, []byte(p.ListenerHost()))
}

func (s *Server) proxyTCP(dest string, ch io.ReadWriteCloser) error {
	s.log.Info("Starting direct tcp proxy")
	var dialer net.Dialer
	dconn, err := dialer.Dial("tcp", dest)
	if err != nil {
		return err
	}

	// to
	go func() {
		s.log.Debug("Streaming data TO")
		defer ch.Close()
		defer dconn.Close()
		io.Copy(ch, dconn)
		s.log.Debug("Closing tcp proxy ->")
	}()

	// from
	go func() {
		s.log.Debug("Streaming data FROM")
		defer ch.Close()
		defer dconn.Close()
		io.Copy(dconn, ch)
		s.log.Debug("Closing tcp proxy <-")
	}()

	return nil
}

func (s *Server) handleDirectTCP(newChannel ssh.NewChannel) {
	logger := s.log
	logger.Debug("Direct channel")
	var fwdData localForwardChannelData
	if err := ssh.Unmarshal(newChannel.ExtraData(), &fwdData); err != nil {
		logger.Error(err)
		return
	}

	logger.Debugw("Got forwarding data",
		"dest", fwdData.DestAddr,
		"destPort", fwdData.DestPort,
	)

	dest := net.JoinHostPort(fwdData.DestAddr, strconv.FormatInt(int64(fwdData.DestPort), 10))

	if _, ok := s.proxies[dest]; !ok {
		logger.Error("Destination not open for tcp listening", "dest", dest)
		return
	}

	ch, reqs, err := newChannel.Accept()
	if err != nil {
		logger.Error(err)
		return
	}
	go ssh.DiscardRequests(reqs)

	err = s.proxyTCP(dest, ch)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		logger.Errorw("Failed to open TCP proxy", "error", err)
		return
	}
	logger.Debug("Dialer started")
}

func newToClientLogger(w io.Writer) zap.Option {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	consoleEncoder := zapcore.NewJSONEncoder(encoderConfig)
	return zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return zapcore.NewCore(consoleEncoder, zapcore.AddSync(w), zapcore.InfoLevel)
	})
}

// Listen starts the gateway server
func (s *Server) Listen(hostport string) (func(), error) {

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", hostport)
	if err != nil {
		return nil, err
	}
	s.log.Infow("Gateway listening", "hostport", listener.Addr())

	// prints hostport to STDOUT so CLI can extract it and connect to the dynamic port
	fmt.Printf("gateway listening hostport %s\n", listener.Addr())

	// basically expecting 1 connection, given the 1cli-1gw process pairing
	s.log.Infow("Accepting connections", "where", hostport)
	nConn, err := listener.Accept()
	if err != nil {
		return nil, err
	}

	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	conn, chans, reqs, err := ssh.NewServerConn(nConn, s.config)
	if err != nil {
		return nil, err
	}
	s.log.Infow("Connection established", "user", conn.User())

	go s.routeRequests(reqs)

	logger := s.log
	// Service the incoming Channel channel.
	for newChannel := range chans {
		logger.Infow("New channel opened") // "type", newChannel.ChannelType(),
		// "data", string(newChannel.ExtraData()),

		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		switch newChannel.ChannelType() {
		case "session":
			{
				channel, requests, err := newChannel.Accept()
				if err != nil {
					log.Fatalf("Could not accept channel: %v", err)
				}

				// Sessions have out-of-band requests such as "shell",
				// "pty-req" and "env".  Here we handle only the
				// "shell" request.
				go func(in <-chan *ssh.Request) {
					for req := range in {
						req.Reply(req.Type == "shell", nil)
					}
				}(requests)
				gwLogger := logger.Desugar().Named("GW").WithOptions(newToClientLogger(channel)).Sugar()
				gwLogger.Debug("Gateway logger ok")
			}
		case "direct-tcpip":
			{
				s.handleDirectTCP(newChannel)
				continue
			}
		// (mihai) NOT USED AS OF 9/16
		case "tcpip-forward":
			{
				// TODO start tcp listener on random port
				_, _, err := newChannel.Accept()
				if err != nil {
					logger.Error("Could not accept channel", err)
					continue
				}

				listener, err := net.Listen("tcp", "0.0.0.0:0")
				if err != nil {
					logger.Error(err, "Failed to open tcp listener for proxy")
					continue
				}

				go func(l net.Listener) {
					http.Serve(l, http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
						resp.WriteHeader(500)
						resp.Write([]byte(`Not the plmbing  you are looking for`))
					}))
				}(listener)
			}
		default:
			{
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
		}

	}
	return nil, nil
}
