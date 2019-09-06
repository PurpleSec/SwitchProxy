package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// Switch is a struct that represents a connection between proxy services.
// This struct contains mapping and functions to capture input and output.
type Switch struct {
	Pre  func(url string, path string, ip string, method string, headers http.Header, data []byte)
	Post func(url string, path string, ip string, method string, status int, headers http.Header, data []byte)

	target  *url.URL
	client  *http.Client
	timeout time.Duration
	rewrite map[string]string
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
func NewSwitch(base string, timeout time.Duration) (*Switch, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	if !u.IsAbs() {
		u.Scheme = "http"
	}
	s := &Switch{
		target:  u,
		timeout: timeout,
		rewrite: make(map[string]string),
	}
	if timeout > 0 {
		s.client = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Dial:                (&net.Dialer{Timeout: timeout}).Dial,
				TLSHandshakeTimeout: timeout,
			},
		}
	} else {
		s.client = &http.Client{}
	}
	return s, nil
}
func (s *Switch) process(r *http.Request, i, o *bytes.Buffer) (int, http.Header, error) {
	y := *(r.URL)
	u := &y
	for k, v := range s.rewrite {
		if strings.HasPrefix(u.Path, k) {
			u.Path = path.Join(v, u.Path[len(k):])
		}
	}
	u.Host = s.target.Host
	u.Scheme = s.target.Scheme
	x, err := http.NewRequest(r.Method, u.String(), i)
	if s.Pre != nil {
		s.Pre(x.URL.String(), x.URL.Path, r.RemoteAddr, r.Method, r.Header, i.Bytes())
	}
	x.Header = r.Header
	x.Trailer = r.Trailer
	x.TransferEncoding = r.TransferEncoding
	if err != nil {
		return 0, nil, err
	}
	if s.timeout > 0 {
		c, f := context.WithTimeout(r.Context(), s.timeout)
		x = x.WithContext(c)
		defer f()
	}
	p, err := s.client.Do(x)
	if err != nil {
		return 0, nil, err
	}
	defer p.Body.Close()
	if _, err := io.Copy(o, p.Body); err != nil {
		return 0, nil, err
	}
	if s.Post != nil {
		s.Post(u.String(), u.Path, r.RemoteAddr, r.Method, p.StatusCode, p.Header, o.Bytes())
	}
	return p.StatusCode, p.Header, nil
}
