package logging

import (
	"io"
	"net"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type logDecoder interface {
	Decode(in io.Reader)
	Log([]byte)
}

type gwLogger struct {
	gwHostPort string
	level      zapcore.Level
	l          *zap.Logger
}

type dialer interface {
	Dial(n, addr string) (net.Conn, error)
}

// Start connects to the gateway and starts receuvubg logs
func (l *gwLogger) Start(conn dialer) error {
	// Dial the log listener port to get gateway logs
	ch, err := conn.Dial("tcp", l.gwHostPort)
	if err != nil {
		return err
	}
	l.l.Sugar().Debugw("TCP connection to the gateway Sink is open", "remote", ch.RemoteAddr().String())

	// adding a new reveiver for the logger. This is going to read and decode logs from the gateway
	go func(l logDecoder) {
		l.Decode(ch)
	}(NewLogReceiver(l.l.Named("GATEWAY")))

	return nil
}

// GatewayLogger is the interface used to control a gateway logger
type GatewayLogger interface {
	Start(dialer) error
}

// NewGatewayLogger creates a logger that displays logs from the gateway
func NewGatewayLogger(level zapcore.Level, hostport string, l *zap.Logger) GatewayLogger {

	return &gwLogger{
		hostport,
		level,
		l,
	}
}
