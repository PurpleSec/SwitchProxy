// Copyright 2021 - 2022 PurpleSec Team
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
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// DefaultTimeout is the default timeout value used when a Timeout is not
// specified in NewProxy.
const DefaultTimeout = time.Second * time.Duration(15)

// Proxy is a struct that represents a stacked proxy that allows a forwarding proxy
// with secondary read only Switch connections that allow logging and storing
// the connection data.
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

// Close attempts to gracefully close and stop the proxy and all remaining
// connections.
func (p *Proxy) Close() error {
	p.cancel()
	return p.server.Close()
}

// Start starts the Server listening loop and returns an error if the server
// could not be started.
//
// Only returns an error if any IO issues occur during operation.
func (p *Proxy) Start() error {
	var err error
	if len(p.cert) > 0 && len(p.key) > 0 {
		p.server.TLSConfig = &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			CurvePreferences:         []tls.CurveID{tls.CurveP256, tls.X25519},
		}
		err = p.server.ListenAndServeTLS(p.cert, p.key)
	} else {
		err = p.server.ListenAndServe()
	}
	p.Close()
	return err
}

// Primary sets the primary Proxy Switch context.
func (p *Proxy) Primary(s *Switch) {
	p.primary = s
}
func (p *Proxy) clear(t *transfer) {
	t.in, t.data = nil, nil
	t.out.Reset()
	t.read.Reset()
	p.pool.Put(t)
}

// AddSecondary adds a one-way Switch context.
func (p *Proxy) AddSecondary(s ...*Switch) {
	p.secondary = append(p.secondary, s...)
}
func (p *Proxy) context(_ net.Listener) context.Context {
	return p.ctx
}

// ServeHTTP satisfies the http.Handler interface.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t := p.pool.Get().(*transfer)
	if _, err := io.Copy(t.read, r.Body); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		p.clear(t)
		r.Body.Close()
		return
	}
	t.data = t.read.Bytes()
	if t.in = bytes.NewReader(t.data); p.primary != nil {
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
	p.clear(t)
	r.Body.Close()
}
