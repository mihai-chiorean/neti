package proxy

import (
	"fmt"
	"io/ioutil"
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

	dialer := func(n string, addr string) (net.Conn, error) {
		return net.Dial("tcp", vr.Listener.Addr().String())
	}
	log := zap.NewNop()
	p := NewHTTPProxy(":0", vr.Listener.Addr().String(), dialer, log.Sugar())

	_, err := p.ListenAndServe()
	assert.NoError(t, err)
	res, err := http.Get("http://" + p.ListenerHost() + "/")
	assert.NoError(t, err)
	out, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.NoError(t, res.Body.Close())
	assert.Equal(t, "works!", string(out))
	p.Stop()
}
