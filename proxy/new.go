package proxy

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"time"
)

type keys struct {
	Cert, Key string
}

// Timeout is a time.Duration alias of a configuration option.
type Timeout time.Duration

// Parameter is an interface that helps define config options for the
// Proxy struct.
type Parameter interface {
	config(*Proxy)
}

func (k keys) config(p *Proxy) {
	p.key = k.Key
	p.cert = k.Cert
}
func (t Timeout) config(p *Proxy) {
	p.server.ReadTimeout = time.Duration(t)
	p.server.IdleTimeout = time.Duration(t)
	p.server.WriteTimeout = time.Duration(t)
	p.server.ReadHeaderTimeout = time.Duration(t)
}

// TLS creates a config paramater with the specified Key and Value file
// paths.
func TLS(cert, key string) Parameter {
	return &keys{Cert: cert, Key: key}
}

// New creates a new Proxy instance from the specified listen
// address and optional parameters.
func New(listen string, c ...Parameter) *Proxy {
	return NewContext(context.Background(), listen, c...)
}

// NewContext creates a new Proxy instance from the specified listen
// address and optional parameters. This function allows the caller to specify
// a context to specify when to shutdown the Proxy.
func NewContext(x context.Context, listen string, c ...Parameter) *Proxy {
	p := &Proxy{
		pool: &sync.Pool{
			New: func() interface{} {
				return &transfer{
					out:  new(bytes.Buffer),
					read: new(bytes.Buffer),
				}
			},
		},
		server: &http.Server{
			Addr:    listen,
			Handler: &http.ServeMux{},
		},
		secondary: make([]*Switch, 0),
	}
	p.server.BaseContext = p.context
	p.ctx, p.cancel = context.WithCancel(x)
	p.server.Handler.(*http.ServeMux).Handle("/", p)
	for i := range c {
		c[i].config(p)
	}
	if len(c) == 0 {
		p.server.ReadTimeout = DefaultTimeout
		p.server.IdleTimeout = DefaultTimeout
		p.server.WriteTimeout = DefaultTimeout
		p.server.ReadHeaderTimeout = DefaultTimeout
	}
	return p
}