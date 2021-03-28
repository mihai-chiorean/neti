package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func readKeys() (map[string]bool, error) {
	// Public key authentication is done by comparing
	// the public key of a received connection
	// with the entries in the authorized_keys file.
	authorizedKeysBytes, err := ioutil.ReadFile("authorized_keys")
	if err != nil {
		//return nil, err
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return authorizedKeysMap, err
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	return authorizedKeysMap, nil
}

func main() {
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()
	logger.Info().Msg("hello world")

	_, err := readKeys()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed reading keys")

	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		// Remove to disable password auth.
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			logger.Info().
				Str("user", c.User()).
				Str("pass", string(pass)).
				Msg("Checking handshake")
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
		log.Fatal("Failed to load private key: ", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:8022")
	if err != nil {
		logger.Fatal().Err(err).Msg("Can't listen")
	}
	nConn, err := listener.Accept()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to accept incoming connection: ")
	}

	logger.Info().Str("port", "8022").Msg("SSH listening")
	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Fatal("failed to handshake: ", err)
	}
	log.Printf("logged in with key %v", conn.Permissions)

	// The incoming Request channel must be serviced.
	go func(in <-chan *ssh.Request) {
		for req := range in {
			logger.Info().Msg("Request received")
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
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
}
