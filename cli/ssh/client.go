package ssh

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mihai-chiorean/neti/cli/logging"
	"github.com/mihai-chiorean/neti/gateway/api"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
)

// SSHClient is the client that connects to the gateway
type SSHClient struct {
	sshConfig *ssh.ClientConfig
	logger    *zap.SugaredLogger
	session   *ssh.Session
	client    *ssh.Client
	gwClient  *ssh.Client
	gwLogger  logging.GatewayLogger
}

// NewSSHClient -
func NewSSHClient(sshConfig *ssh.ClientConfig, logger *zap.SugaredLogger) *SSHClient {
	return &SSHClient{
		sshConfig: sshConfig,
		logger:    logger.Named("SSHClient"),
	}
}

// Dial connects starts an ssh session to the bastion
func (c *SSHClient) DialBastion(hostport string) error {
	// Dial your ssh server.
	c.logger.Infof("Connecting to gateway: %s", hostport)
	connAuth, err := ssh.Dial("tcp", hostport, c.sshConfig)
	if err != nil {
		return err
	}
	c.client = connAuth

	c.logger.Debug("Starting SSH session")

	// The session is only used to start the gateway
	// and basically get the port from the output of the gw

	// Perform the SSH handshake
	sshSession, err := connAuth.NewSession()
	if err != nil {
		return err
	}
	defer sshSession.Close()

	// Redirect the session's output to the local stdout
	sshSession.Stdout = os.Stdout
	sshSession.Stderr = os.Stderr

	c.session = sshSession
	return nil
}

func (c *SSHClient) StartGateway() (string, error) {
	outputScanner, err := c.sessionReadBuffer()
	if err != nil {
		return "", err
	}

	// TODO - is this needed if the force command is set up in the server ssh config?
	// Start the session and wait for the force command to be executed
	// Need this to be in a goroutine because it will block until the command is done
	go func() {
		c.logger.Debug("Starting the gateway")
		if err := c.session.Run("/bin/gateway "); err != nil {
			c.logger.Fatalf("Failed to execute command: %s", err)
		}
	}()

	c.logger.Info("Waiting for the gw to start listening... (2 sec timer)")

	ctxTimer, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	portChan := make(chan string)
	errChan := make(chan error)

	go func(ctx context.Context, cancelFunc context.CancelFunc, portChan chan string, errChan chan error) {
		for outputScanner.Scan() {
			select {
			case <-ctx.Done():
				errChan <- fmt.Errorf("doesn't look like the gateway started")
				return
			default:
				{
					line := outputScanner.Text()
					c.logger.Debugf("output line:", line)
					if strings.HasPrefix(line, "gateway listening hostport ") {
						postStr := strings.TrimPrefix(line, "gateway listening hostport ")
						_, serverPort, err := net.SplitHostPort(postStr)
						if err != nil {
							errChan <- err
							cancelFunc()
							return
						}
						portChan <- serverPort
						cancelFunc()
						return
					}
				}
			}
		}
	}(ctxTimer, cancel, portChan, errChan)

	select {
	case serverPort := <-portChan:
		if len(serverPort) <= 0 {
			return "", fmt.Errorf("empty server port found")
		}
		return serverPort, nil
	case err := <-errChan:
		return "", err
	}
}

func (c *SSHClient) CloseSession() error {
	c.client.Close()
	return c.session.Close()
}

func (c *SSHClient) sessionReadBuffer() (*bufio.Scanner, error) {
	outputPipe, err := c.session.StdoutPipe()
	if err != nil {
		return nil, err
	}
	outputScanner := bufio.NewScanner(outputPipe)
	return outputScanner, nil
}

func (c *SSHClient) DialGateway(gwHostport string) (*ssh.Client, error) {
	// Create a connection from server A to server B
	connAB, err := c.client.Dial("tcp", gwHostport)
	if err != nil {
		return nil, err
	}

	// Establish an SSH connection with the gw using the connection from the bastion
	connB, chans, reqs, err := ssh.NewClientConn(connAB, gwHostport, c.sshConfig)
	if err != nil {
		return nil, err
	}
	defer connB.Close()

	// Create an SSH client from the connection with server B
	clientB := ssh.NewClient(connB, chans, reqs)
	c.gwClient = clientB
	defer clientB.Close()

	// TODO At this point we need a gateway client struct and or interface for custome methods handled by
	// the gw.
	return clientB, nil
}

func (c *SSHClient) Handshake() error {
	handshake := api.HandshakeRequest{
		LoggerAddr: ":0",
	}
	// TODO handle error
	body, err := json.Marshal(&handshake)
	if err != nil {
		return err
	}

	// this is an "ssh request"; the body will likely expand with other things
	// TODO we need these api names - like Handshake - in some static form
	_, payload, err := c.gwClient.SendRequest("Handshake", true, body)
	if err != nil {
		return err
	}

	// this is the handshake response; it will expose the port logs come on
	var handshakeRes api.Handshake
	if err := json.Unmarshal(payload, &handshakeRes); err != nil {
		return err
	}
	c.logger.Debug("Handshake received", "payload", handshakeRes)

	c.initGwLogger(handshakeRes.LoggerListener)
	return nil
}

// CreateHTTPProxy create a new http proxy on the gateway side and return the hostport
// it's listening on
func (c *SSHClient) CreateHTTPProxy(hostport string) (string, error) {
	httpProxyReq := api.HTTPProxyRequest{
		ServiceHostPort: hostport,
	}

	body, err := json.Marshal(&httpProxyReq)
	if err != nil {
		return "", err
	}

	// this is another api that the gateway provides. At the moment there is no payload schema for it
	_, payload, err := c.gwClient.SendRequest("NewHTTPProxy", true, body)
	if err != nil {
		return "", err
	}

	c.logger.With("payload", string(payload)).Debug("Created http proxy")
	return string(payload), nil
}

func (c *SSHClient) initGwLogger(logListenHostport string) {
	c.gwLogger = logging.NewGatewayLogger(zapcore.InfoLevel, logListenHostport, c.logger.Desugar().Named("GATEWAY"))
	c.gwLogger.Start(c.gwClient)
}
