package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	// DefaultTimeout is the default timeout value used when a Timeout is not
	// specified in NewProxy.
	DefaultTimeout = time.Second * time.Duration(15)
)

// Proxy is a struct that represents a stacked proxy that allows a forwarding proxy
// with secondary read only Switch connections that allow logging and storing the connection data.
type Proxy struct {
	key       string
	cert      string
	pool      *sync.Pool
	server    *http.Server
	primary   *Switch
	secondary []*Switch
}

// Start starts the Server listening loop and returns an error if the server could not be started.
// Only returns an error if any IO issues occur during operation.
func (p *Proxy) Start() error {
	if len(p.cert) > 0 && len(p.key) > 0 {
		return p.server.ListenAndServeTLS(p.cert, p.key)
	}
	return p.server.ListenAndServe()
}

// Primary sets the primary Proxy Switch context.
func (p *Proxy) Primary(s *Switch) {
	p.primary = s
}

// NewProxy creates a new Proxy struct from the supplied options.
func NewProxy(listen string) *Proxy {
	return NewProxyEx(DefaultTimeout, listen, "", "")
}
func (p *Proxy) putClear(b *bytes.Buffer) {
	b.Reset()
	p.pool.Put(b)
}

// AddSecondary adds an additional one-way Switch context.
func (p *Proxy) AddSecondary(s ...*Switch) {
	p.secondary = append(p.secondary, s...)
}

// ServeHTTP satisfies the http.Handler interface.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i := p.pool.Get().(*bytes.Buffer)
	defer p.putClear(i)
	defer r.Body.Close()
	if _, err := io.Copy(i, r.Body); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, http.StatusText(http.StatusInternalServerError))
		return
	}
	o := p.pool.Get().(*bytes.Buffer)
	defer p.putClear(o)
	if p.primary != nil {
		c, h, err := p.primary.process(r, i, o)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, http.StatusText(http.StatusInternalServerError))
		} else {
			for k, v := range h {
				w.Header()[k] = v
			}
			w.WriteHeader(c)
			if _, err := io.Copy(w, o); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, http.StatusText(http.StatusInternalServerError))
			}
		}
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, http.StatusText(http.StatusServiceUnavailable))
	}
	if len(p.secondary) > 0 {
		for n := range p.secondary {
			o.Reset()
			p.secondary[n].process(r, i, o)
		}
	}
}

// NewProxyEx creates a new Proxy struct from the supplied options.
// This function allows fos specifying TLS options.
func NewProxyEx(timeout time.Duration, listen, cert, key string) *Proxy {
	p := &Proxy{
		key:  key,
		cert: cert,
		pool: &sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		},
		server: &http.Server{
			Addr:              listen,
			Handler:           &http.ServeMux{},
			ReadTimeout:       timeout,
			IdleTimeout:       timeout,
			WriteTimeout:      timeout,
			ReadHeaderTimeout: timeout,
		},
		secondary: make([]*Switch, 0),
	}
	p.server.Handler.(*http.ServeMux).Handle("/", p)
	return p
}
