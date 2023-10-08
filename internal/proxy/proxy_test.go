package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewHTTPProxy(t *testing.T) {

	vr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "works!")
	}))
	defer vr.Close()

	dialer := func(ctx context.Context, n, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(context.Background(), "tcp", vr.Listener.Addr().String())
	}

	log, _ := zap.NewDevelopment()

	p, _ := NewHTTPProxy(":8085", vr.Listener.Addr().String(), dialer, log.Sugar())

	_, err := p.ListenAndServe()
	assert.NoError(t, err)
	res, err := http.Get("http://" + p.ListenerHost() + "/")
	assert.NoError(t, err)
	out, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.NoError(t, res.Body.Close())
	assert.Equal(t, "works!", string(out))
	p.Stop()
}
