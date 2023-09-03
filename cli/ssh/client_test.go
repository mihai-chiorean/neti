package ssh

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mihai-chiorean/neti/testdata"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

var (
	testPrivateKeys map[string]interface{}
	testSigners     map[string]ssh.Signer
	testPublicKeys  map[string]ssh.PublicKey
)

func init() {
	var err error

	n := len(testdata.PEMBytes)

	testPrivateKeys = make(map[string]interface{}, n)
	testSigners = make(map[string]ssh.Signer, n)
	testPublicKeys = make(map[string]ssh.PublicKey, n)
	for t, k := range testdata.PEMBytes {
		testPrivateKeys[t], err = ssh.ParseRawPrivateKey(k)
		if err != nil {
			panic(fmt.Sprintf("Unable to parse test key %s: %v", t, err))
		}
		testSigners[t], err = ssh.NewSignerFromKey(testPrivateKeys[t])
		if err != nil {
			panic(fmt.Sprintf("Unable to create signer for test key %s: %v", t, err))
		}
		testPublicKeys[t] = testSigners[t].PublicKey()
	}
}

func TestNewSSHClient(t *testing.T) {
	l := zap.NewNop()
	c := NewSSHClient(&ssh.ClientConfig{}, l.Sugar())
	assert.NotNil(t, c)
}

func TestDialBastion(t *testing.T) {
	cfg := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	cfg.AddHostKey(testSigners["rsa"])
	listener, err := net.Listen("tcp", ":0")
	assert.Nil(t, err)
	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	go func(ctx context.Context, listener net.Listener) {
		select {
		case <-ctx.Done():
			assert.Fail(t, "timeout")
		default:
			nConn, err := listener.Accept()
			assert.Nil(t, err)
			fmt.Println("listening!")
			conn, chanChan, reqChan, err := ssh.NewServerConn(nConn, cfg)
			assert.Nil(t, err)
			assert.NotNil(t, conn)
			fmt.Println(conn.User())
			for newChannel := range chanChan {
				switch newChannel.ChannelType() {
				case "session":
					{
						_, requests, err := newChannel.Accept()
						assert.Nil(t, err)

						// Sessions have out-of-band requests such as "shell",
						// "pty-req" and "env".  Here we handle only the
						// "shell" request.
						go func(in <-chan *ssh.Request) {
							for req := range in {
								req.Reply(req.Type == "shell", nil)
							}
						}(requests)
					}
				default:
					continue
				}
			}
			for req := range reqChan {
				req.Reply(req.Type == "shell", nil)
			}
		}

	}(ctx, listener)

	sshCliConfig := &ssh.ClientConfig{
		User: "testuser",
		// TODO what's up with this?
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //hostKeyCallback, //ssh.FixedHostKey(hostKey),
	}
	l := zap.NewNop()
	c := NewSSHClient(sshCliConfig, l.Sugar())
	assert.NotNil(t, c)

	assert.NoError(t, c.DialBastion(listener.Addr().String()))
}
