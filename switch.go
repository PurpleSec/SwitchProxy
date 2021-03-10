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
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Result is a struct that contains the data of the resulting Switch
// operation to be passed to Handlers.
type Result struct {
	Headers http.Header `json:"headers"`
	IP      string      `json:"ip"`
	UUID    string      `json:"uuid"`
	Path    string      `json:"path"`
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Content []byte      `json:"content"`
	Status  uint16      `json:"status"`
}

// Switch is a struct that represents a connection between proxy services.
// This struct contains mapping and functions to capture input and output.
type Switch struct {
	Pre     Handler
	Post    Handler
	client  *http.Client
	rewrite map[string]string
	url.URL
	timeout time.Duration
}

// Handler is a function alias that can be passed a Result for processing.
type Handler func(Result)

// IsResponse is a function that returns true if the Result is for a response.
func (r Result) IsResponse() bool {
	return len(r.Method) > 0 && r.Status > 0
}

// Rewrite adds a URL rewrite from the Switch.
// If a URL starts with the 'from' paramater, it will be replaced with the 'to'
// paramater, only if starting with on the URL path.
func (s *Switch) Rewrite(from, to string) {
	s.rewrite[from] = to
}

// RemoveRewrite removes the URL rewrite from the Switch.
func (s *Switch) RemoveRewrite(from string) {
	delete(s.rewrite, from)
}

// NewSwitch creates a switching context that allows the connection to be proxied
// to the specified server.
func NewSwitch(target string) (*Switch, error) {
	return NewSwitchTimeout(target, DefaultTimeout)
}

// NewSwitchTimeout creates a switching context that allows the connection to be proxied
// to the specified server. This function will set the specified timeout.
func NewSwitchTimeout(target string, t time.Duration) (*Switch, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve URL: %w", err)
	}
	if !u.IsAbs() {
		u.Scheme = "http"
	}
	s := &Switch{
		URL: *u,
		client: &http.Client{
			Timeout: t,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   t,
					KeepAlive: t,
					DualStack: true,
				}).DialContext,
				IdleConnTimeout:       t,
				TLSHandshakeTimeout:   t,
				ExpectContinueTimeout: t,
				ResponseHeaderTimeout: t,
			},
		},
		timeout: t,
		rewrite: make(map[string]string),
	}
	return s, nil
}
func (s Switch) process(x context.Context, r *http.Request, t *transfer) (int, http.Header, error) {
	s.URL.Path = r.URL.Path
	s.URL.User = r.URL.User
	s.URL.Opaque = r.URL.Opaque
	s.URL.Fragment = r.URL.Fragment
	s.URL.RawQuery = r.URL.RawQuery
	s.URL.ForceQuery = r.URL.ForceQuery
	for k, v := range s.rewrite {
		if strings.HasPrefix(s.URL.Path, k) {
			s.URL.Path = path.Join(v, s.URL.Path[len(k):])
		}
	}
	if s.timeout > 0 {
		var f context.CancelFunc
		x, f = context.WithTimeout(x, s.timeout)
		defer f()
	}
	u := uuid.New().String()
	q, err := http.NewRequestWithContext(x, r.Method, s.URL.String(), t.in)
	if err != nil {
		return 0, nil, err
	}
	if s.Pre != nil {
		s.Pre(Result{
			IP:      r.RemoteAddr,
			URL:     s.URL.String(),
			UUID:    u,
			Path:    s.Path,
			Method:  r.Method,
			Content: t.data,
			Headers: r.Header,
		})
	}
	q.Header = r.Header
	q.Trailer = r.Trailer
	q.TransferEncoding = r.TransferEncoding
	o, err := s.client.Do(q)
	if err != nil {
		return 0, nil, err
	}
	defer o.Body.Close()
	if _, err := io.Copy(t.out, o.Body); err != nil {
		return 0, nil, err
	}
	if s.Post != nil {
		s.Post(Result{
			IP:      r.RemoteAddr,
			URL:     s.URL.String(),
			Path:    s.Path,
			UUID:    u,
			Status:  uint16(o.StatusCode),
			Method:  r.Method,
			Content: t.out.Bytes(),
			Headers: o.Header,
		})
	}
	return o.StatusCode, o.Header, nil
}
