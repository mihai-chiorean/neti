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
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// Server is the gateway ssh server
type Server struct {
	log    *zap.SugaredLogger
	config *ssh.ServerConfig
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
		log,
		config,
	}

	return &server, nil
}

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

func (s *Server) handshake(req *ssh.Request) {
	s.log.Infow(string(req.Payload))
	h := api.Handshake{
		Success: "yeahhh",
	}
	payload, err := json.Marshal(&h)
	if err != nil {
		s.log.Error(err)
		req.Reply(false, nil)
	}
	req.Reply(true, payload)
}

func (s *Server) newHTTPProxy(req *ssh.Request, target string) {
	s.log.Infow("Opening new http handler")
	// TODO make a struct for the payload that includes some service name/port

	// TODO Replace with new http proxy; the request should have some
	//		the request should have some destination service name or port

	p := proxy.NewHTTPProxy(":0", target, nil, s.log)
	go func() {
		p.Start()
	}()

	s.log.Infow("------", "hostport", p.ListenerHost())
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
	req.Reply(true, []byte(t.Addr().String()))
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
	s.log.Infow("Connection established", "user", conn.User)

	go s.routeRequests(reqs)

	logger := s.log
	// Service the incoming Channel channel.
	for newChannel := range chans {
		logger.Infow("New channel opened",
			"type", newChannel.ChannelType(),
			"data", string(newChannel.ExtraData()),
		)
		if newChannel.ChannelType() == "direct-tcpip" {
			logger.Info("Direct channel")
			var fwdData localForwardChannelData
			if err := ssh.Unmarshal(newChannel.ExtraData(), &fwdData); err != nil {
				logger.Error(err)
				continue
			}

			logger.Infow("Got forwarding data",
				"dest", fwdData.DestAddr,
				"destPort", fwdData.DestPort,
			)

			dest := net.JoinHostPort(fwdData.DestAddr, strconv.FormatInt(int64(fwdData.DestPort), 10))

			var dialer net.Dialer
			dconn, err := dialer.Dial("tcp", dest)
			if err != nil {
				newChannel.Reject(ssh.ConnectionFailed, err.Error())
				return nil, nil
			}
			logger.Info("Dialer started")
			ch, reqs, err := newChannel.Accept()
			if err != nil {
				dconn.Close()
				return nil, nil
			}
			go ssh.DiscardRequests(reqs)

			go func() {
				defer ch.Close()
				defer dconn.Close()
				io.Copy(ch, dconn)
			}()
			go func() {
				defer ch.Close()
				defer dconn.Close()
				io.Copy(dconn, ch)
			}()
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

		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
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

		term := terminal.NewTerminal(channel, "> ")

		go func() {
			defer channel.Close()
			for {
				line, err := term.ReadLine()
				if err != nil {
					break
				}
				fmt.Println(line)
			}
		}()
	}
	return nil, nil
}
