package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/mihai-chiorean/cerberus/gateway/api"
	"github.com/mihai-chiorean/cerberus/internal/proxy"
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
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			log.Infow("Checking handshake")
			if c.User() == "testuser" && string(pass) == "tiger" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},

		// Remove to disable public key auth.
		//	PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
		//		if authorizedKeysMap[string(pubKey.Marshal())] {
		//			return &ssh.Permissions{
		//				// Record the public key used for authentication.
		//				Extensions: map[string]string{
		//					"pubkey-fp": ssh.FingerprintSHA256(pubKey),
		//				},
		//			}, nil
		//		}
		//		return nil, fmt.Errorf("unknown public key for %q", c.User())
		//	},
	}

	privateBytes, err := ioutil.ReadFile("/run/secrets/id_rsa")
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
			s.newHTTPProxy(req, "dummy:80")
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
		Success: "yeahhh",
	}
	var hr api.HandshakeRequest
	if err := json.Unmarshal(req.Payload, &hr); err != nil {
		s.log.Error(err)
		h.Success = "nooo, json, noo"
	}

	s.log.Infow(string(req.Payload))
	s.log.Infow("Handshake req unpacked")

	ll, err := net.Listen("tcp", hr.LoggerAddr)
	if err != nil {
		s.log.Error(err)
		req.Reply(false, nil)
	}
	h.LoggerListener = ll.Addr().String()
	s.log.Infow("Listening for log connections", "addr", ll.Addr().String())
	s.proxies[ll.Addr().String()] = ll
	go func() {
		conn, err := ll.Accept()
		if err != nil {
			s.log.Error(err)
			return
		}

		s.log.Info("Rerouting logs to client")
		s.log = s.log.Desugar().WithOptions(newToClientLogger(conn)).Sugar()

		s.log.Info("Logs rerouted to client")
	}()
	payload, err := json.Marshal(&h)
	if err != nil {
		s.log.Error(err)
		req.Reply(false, nil)
	}
	req.Reply(true, payload)
}

func (s *Server) newHTTPProxy(req *ssh.Request, target string) {
	s.log.Infow("Opening new HTTP handler")
	// TODO make a struct for the payload that includes some service name/port

	// TODO Replace with new http proxy; the request should have some
	//		the request should have some destination service name or port

	// Start new http listener on an ephemeral port
	p := proxy.NewHTTPProxy(":0", target, nil, s.log)
	go func() {
		p.Start()
	}()

	s.log.Infow("HTTP Proxy started", "hostport", p.ListenerHost())
	t, err := net.Listen("tcp", ":0")
	if err != nil {
		s.log.Error("Failed to open tcp listener", "error", err)
		return
	}
	s.log.Infow("Starting http listener")
	go func(t net.Listener) {
		http.Serve(t, http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			fmt.Fprintf(resp, "Hello proxy!")
		}))
	}(t)
	s.log.Infow("Http proxy listening", "addr", t.Addr().String())
	s.proxies[t.Addr().String()] = t
	req.Reply(true, []byte(t.Addr().String()))
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
		s.log.Info("Streaming data TO")
		defer ch.Close()
		defer dconn.Close()
		io.Copy(ch, dconn)
		s.log.Info("Closing tcp proxy ->")
	}()

	// from
	go func() {
		s.log.Infow("Streaming data FROM", "field", "value")
		defer ch.Close()
		defer dconn.Close()
		io.Copy(dconn, ch)
		s.log.Info("Closing tcp proxy <-")
	}()

	return nil
}

func (s *Server) handleDirectTCP(newChannel ssh.NewChannel) {
	logger := s.log
	logger.Info("Direct channel")
	var fwdData localForwardChannelData
	if err := ssh.Unmarshal(newChannel.ExtraData(), &fwdData); err != nil {
		logger.Error(err)
		return
	}

	logger.Infow("Got forwarding data",
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
	logger.Info("Dialer started")
}

func newToClientLogger(w io.Writer) zap.Option {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	consoleEncoder := zapcore.NewJSONEncoder(encoderConfig)
	return zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return zapcore.NewCore(consoleEncoder, zapcore.AddSync(w), zapcore.DebugLevel)
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
	s.log.Infow("Accepting connections", "where", hostport)
	nConn, err := listener.Accept()
	if err != nil {
		return nil, err
	}

	s.log.Infow("SSH listening", "port", "8022")
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
		logger.Infow("New channel opened",
			"type", newChannel.ChannelType(),
			"data", string(newChannel.ExtraData()),
		)
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
				gwLogger := logger.Desugar().WithOptions(newToClientLogger(channel)).Sugar()
				gwLogger.Info("We have a new gateway logger!!")
			}
		case "direct-tcpip":
			{
				s.handleDirectTCP(newChannel)
				// TODO start tcp listener on random port
				//ch, directReq, err := newChannel.Accept()
				//if err != nil {
				//	logger.Error("Could not accept channel", err)
				//	continue
				//}
				//go func(in <-chan *ssh.Request) {
				//	for req := range in {
				//		logger.Infow("Request on direct ip channel",
				//			"type", req.Type,
				//			"payload", string(req.Payload),
				//		)
				//		req.Reply(true, nil)
				//	}
				//}(directReq)
				//go func() {
				//	defer ch.Close()
				//	scanner := bufio.NewScanner(ch)
				//	scanner.Split(bufio.ScanLines)
				//	count := 0
				//	for scanner.Scan() {
				//		count++
				//		logger.Info(scanner.Text())
				//	}
				//	if err := scanner.Err(); err != nil {
				//		fmt.Println(err)
				//	}
				//	logger.Info(count)
				//	ch.Write([]byte(`done`))
				//}()
				continue
			}
		default:
			{
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
		}

		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if newChannel.ChannelType() == "tcpip-forward" {
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
					fmt.Fprintf(resp, "Hello world!\n")

				}))
			}(listener)
		}
	}
	return nil, nil
}
