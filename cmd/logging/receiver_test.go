package logging

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func Test_receiverInfo(t *testing.T) {
	raw := []byte(`{"caller":"gateway/server.go:138","level":"info","msg":"Opening new HTTP handler","ts":"2021-05-05T04:05:22.895Z", "field":"value"}`)
	l, err := zap.NewDevelopment()
	assert.NoError(t, err)

	r := Receiver{
		L: l.Sugar(),
	}

	r.log(raw)
}
