// Copyright (C) 2020 iDigitalFlame
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

package switchproxy

import (
	"bytes"
	"context"
	"io"
	"net"
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
	ctx       context.Context
	key       string
	cert      string
	pool      *sync.Pool
	server    *http.Server
	cancel    context.CancelFunc
	primary   *Switch
	secondary []*Switch
}
type transfer struct {
	in   *bytes.Reader
	out  *bytes.Buffer
	read *bytes.Buffer
	data []byte
}

// Stop attempts to gracefully close and Stop the proxy and all remaining connextions.
func (p *Proxy) Stop() error {
	p.cancel()
	return p.server.Close()
}

// Start starts the Server listening loop and returns an error if the server could not be started.
// Only returns an error if any IO issues occur during operation.
func (p *Proxy) Start() error {
	defer p.Stop()
	if len(p.cert) > 0 && len(p.key) > 0 {
		return p.server.ListenAndServeTLS(p.cert, p.key)
	}
	return p.server.ListenAndServe()
}

// Primary sets the primary Proxy Switch context.
func (p *Proxy) Primary(s *Switch) {
	p.primary = s
}
func (p *Proxy) clear(t *transfer) {
	t.in = nil
	t.data = nil
	t.out.Reset()
	t.read.Reset()
	p.pool.Put(t)
}

// AddSecondary adds an additional one-way Switch context.
func (p *Proxy) AddSecondary(s ...*Switch) {
	p.secondary = append(p.secondary, s...)
}
func (p *Proxy) context(_ net.Listener) context.Context {
	return p.ctx
}

// ServeHTTP satisfies the http.Handler interface.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t := p.pool.Get().(*transfer)
	defer p.clear(t)
	defer r.Body.Close()
	if _, err := io.Copy(t.read, r.Body); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	t.data = t.read.Bytes()
	t.in = bytes.NewReader(t.data)
	if p.primary != nil {
		if s, h, err := p.primary.process(p.ctx, r, t); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		} else {
			for k, v := range h {
				w.Header()[k] = v
			}
			w.WriteHeader(s)
			if _, err := io.Copy(w, t.out); err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}
	} else {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	}
	if len(p.secondary) > 0 {
		for i := range p.secondary {
			t.out.Reset()
			t.in.Seek(0, 0)
			p.secondary[i].process(p.ctx, r, t)
		}
	}
}
