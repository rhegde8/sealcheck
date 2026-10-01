package seal

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// Fixture models package proxy behaviors. Its routes are intentionally NOT
// Artifactory exploit paths and cannot substantiate CVE reproduction claims.
type Fixture struct {
	Observer *Observer
	// Resolver, when set, models a proxy that resolves destination names
	// before applying its policy (as destination-IP ACLs do). Only the leaky
	// configuration resolves. Set fields before serving.
	Resolver *net.Resolver
	// AuthToken, when set, requires a bearer credential on fixture routes.
	AuthToken string
	upstream  *url.URL
	leaky     atomic.Bool
}

func NewFixture(upstream string, leaky bool) (*Fixture, error) {
	if !httpURL(upstream) {
		return nil, errors.New("invalid fixture upstream")
	}
	u, _ := url.Parse(upstream)
	f := &Fixture{Observer: NewObserver("canary.test"), upstream: u}
	f.leaky.Store(leaky)
	return f, nil
}

func (f *Fixture) SetLeaky(value bool) { f.leaky.Store(value) }

func (f *Fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/packages/approved.txt" && !r.URL.IsAbs() {
		_, _ = io.WriteString(w, "sealcheck approved package fixture v1\n")
		return
	}
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT unsupported by fixture", 501)
		return
	}
	var target *url.URL
	var err error
	var body []byte
	canary := r.URL.Query().Get("canary")
	isRegistry := strings.HasPrefix(r.URL.Path, "/registry/") && !r.URL.IsAbs()
	if isRegistry {
		body, err = io.ReadAll(io.LimitReader(r.Body, 1025))
		if err != nil || len(body) > 1024 {
			http.Error(w, "body", 400)
			return
		}
		canary = string(body)
		u := *f.upstream
		u.Path = r.URL.Path
		target = &u
	} else if r.URL.IsAbs() {
		target = r.URL
	} else {
		switch r.URL.Path {
		case "/fixtures/terraform/module", "/fixtures/cargo/download", "/fixtures/ansible/archive":
		default:
			http.NotFound(w, r)
			return
		}
		if f.AuthToken != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+f.AuthToken)) != 1 {
			http.Error(w, "authentication required", 401)
			return
		}
		target, err = url.Parse(r.URL.Query().Get("url"))
		if err != nil {
			http.Error(w, "target", 400)
			return
		}
	}
	leaky := f.leaky.Load()
	if leaky && f.Resolver != nil && target != nil && net.ParseIP(target.Hostname()) == nil {
		// Resolving a denied name already sends its labels to the name's
		// authoritative server.
		lookup, cancel := context.WithTimeout(r.Context(), time.Second)
		_, _ = f.Resolver.LookupHost(lookup, target.Hostname())
		cancel()
	}
	event, valid := ParseCanary([]byte(canary))
	deny := func() {
		if valid {
			protocol := "http"
			if isRegistry {
				protocol = "registry"
			}
			f.Observer.Record(event, "denied", protocol, r.RemoteAddr)
		}
		http.Error(w, "fixture policy denied request", 403)
	}
	// Even the deliberately leaky fixture only contacts the configured lab origin.
	if !f.sameOrigin(target) {
		deny()
		return
	}
	allowed := func(u *url.URL) bool {
		return f.sameOrigin(u) && (leaky || u.Path == "/package/approved" || u.Path == "/redirect")
	}
	if (!leaky && isRegistry) || !allowed(target) {
		deny()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	blockedRedirect := false
	client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !allowed(req.URL) {
			blockedRedirect = true
			return errors.New("redirect denied")
		}
		return nil
	}}
	method := http.MethodGet
	if isRegistry {
		method = r.Method
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "request", 400)
		return
	}
	response, err := client.Do(req)
	if err != nil {
		if blockedRedirect {
			deny()
		} else {
			http.Error(w, "upstream failed", 502)
		}
		return
	}
	defer response.Body.Close()
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, 4096))
}

func (f *Fixture) sameOrigin(u *url.URL) bool {
	return u != nil && u.User == nil && u.Scheme == f.upstream.Scheme && u.Host == f.upstream.Host
}

// UDPResolver sends every lookup to one DNS server, ignoring system configuration.
func UDPResolver(address string) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", address)
	}}
}
