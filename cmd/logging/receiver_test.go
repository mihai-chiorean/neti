package logging

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func newRecorderCore() (zap.Option, *observer.ObservedLogs) {
	core, recorder := observer.New(zap.DebugLevel)
	return zap.WrapCore(func(zapcore.Core) zapcore.Core {
		return core
	}), recorder
}

func Test_receiverInfo(t *testing.T) {
	coreOption, logs := newRecorderCore()
	raw := []byte(`
		{"caller":"gateway/server.go:138","level":"info","msg":"info message","ts":"2021-05-05T04:05:22.895Z", "field":"value"}
		`)
	input := strings.NewReader(string(raw))
	l, err := zap.NewDevelopment(coreOption)
	assert.NoError(t, err)

	l = l.WithOptions(coreOption)
	r := Receiver{
		L: l,
	}

	r.Decode(input)
	assert.Equal(t, 1, logs.Len())
	infos := logs.FilterMessage("info message").TakeAll()

	assert.Equal(t, 1, len(infos))

	theLog := infos[0]
	assert.Len(t, theLog.Context, 1)
	assert.Contains(t, theLog.Caller.File, "server")
	assert.Equal(t, 138, theLog.Caller.Line)
}
