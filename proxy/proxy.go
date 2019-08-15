package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// Proxy is a struct that repersents a stacked proxy that allows a forwarding proxy
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
	return NewProxyEx(listen, "", "")
}
func (p *Proxy) putClear(b *bytes.Buffer) {
	b.Reset()
	p.pool.Put(b)
}

// AddSecondary adds an additional one-way Switch context.
func (p *Proxy) AddSecondary(s ...*Switch) {
	p.secondary = append(p.secondary, s...)
}

// NewProxyEx creates a new Proxy struct from the supplied options.
// This function allows fos specifying TLS options.
func NewProxyEx(listen, cert, key string) *Proxy {
	p := &Proxy{
		key:  key,
		cert: cert,
		pool: &sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		},
		server: &http.Server{
			Addr:    listen,
			Handler: &http.ServeMux{},
		},
		secondary: make([]*Switch, 0),
	}
	p.server.Handler.(*http.ServeMux).Handle("/", p)
	return p
}

// ServeHTTP satisifies the http.Hanndler interface.
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
	for n := range p.secondary {
		p.secondary[n].process(r, i, o)
		o.Reset()
	}
	if p.primary != nil {
		c, h, err := p.primary.process(r, i, o)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, http.StatusText(http.StatusInternalServerError))
			fmt.Fprintf(w, err.Error())
			return
		}
		for k, v := range h {
			w.Header()[k] = v
		}
		w.WriteHeader(c)
		if _, err := io.Copy(w, o); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, http.StatusText(http.StatusInternalServerError))
			fmt.Fprintf(w, err.Error())
			return
		}
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, http.StatusText(http.StatusServiceUnavailable))
		return
	}
}
