package ssh

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

func TestNewSSHClient(t *testing.T) {
	l := zap.NewNop()
	c := NewSSHClient(&ssh.ClientConfig{}, l.Sugar())
	assert.NotNil(t, c)
}
