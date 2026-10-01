package seal

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxEvents = 10000

type Observer struct {
	mu       sync.Mutex
	instance string
	events   []Event
	overflow bool
	zone     string
	registry map[string][]byte
}

func NewObserver(zone string) *Observer {
	return &Observer{instance: RandomID(), zone: strings.TrimSuffix(zone, "."), events: []Event{}, registry: map[string][]byte{}}
}

func (o *Observer) Record(e Event, action, protocol, remote string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.events) >= maxEvents {
		o.overflow = true
		return
	}
	e.Action = action
	e.Protocol = protocol
	e.Remote = remote
	e.At = time.Now().UTC()
	o.events = append(o.events, e)
}

func (o *Observer) Snapshot(run string) Snapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := Snapshot{Instance: o.instance, At: time.Now().UTC(), Overflow: o.overflow, Events: []Event{}}
	for _, e := range o.events {
		if e.RunID == run {
			if len(s.Events) >= 1024 {
				s.Overflow = true
				break
			}
			s.Events = append(s.Events, e)
		}
	}
	return s
}

func (o *Observer) Management(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "read only", 405)
			return
		}
		if r.URL.Path != "/health" && r.URL.Path != "/events" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(o.Snapshot(r.URL.Query().Get("run_id")))
	})
}

func (o *Observer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/package/approved" {
		_, _ = io.WriteString(w, "sealcheck approved package fixture v1\n")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/registry/") {
		o.registryHTTP(w, r)
		return
	}
	if r.URL.Path == "/redirect" {
		// Redirect fixture remains on the same controlled origin and preserves the canary.
		u := *r.URL
		u.Path = "/canary"
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}
	if r.URL.Path != "/canary" && r.URL.Path != "/error" {
		http.NotFound(w, r)
		return
	}
	if e, ok := ParseCanary([]byte(r.URL.Query().Get("canary"))); ok {
		o.Record(e, "received", "http", r.RemoteAddr)
	} else {
		http.Error(w, "invalid canary", 400)
		return
	}
	if r.URL.Path == "/error" {
		http.Error(w, "intentional error after receiving canary", 500)
		return
	}
	w.WriteHeader(204)
}

func (o *Observer) registryHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		b, e := io.ReadAll(io.LimitReader(r.Body, 1025))
		if e != nil || len(b) > 1024 {
			http.Error(w, "invalid body", 400)
			return
		}
		event, ok := ParseCanary(b)
		if !ok || r.URL.Path != "/registry/"+event.RunID+"/"+event.ProbeID {
			http.Error(w, "invalid object", 400)
			return
		}
		o.mu.Lock()
		if len(o.registry) >= maxEvents {
			o.overflow = true
			o.mu.Unlock()
			http.Error(w, "full", 503)
			return
		}
		o.registry[r.URL.Path] = append([]byte(nil), b...)
		o.mu.Unlock()
		o.Record(event, "received", "registry", r.RemoteAddr)
		w.WriteHeader(201)
	case http.MethodGet:
		o.mu.Lock()
		b, ok := o.registry[r.URL.Path]
		b = append([]byte(nil), b...)
		o.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		event, _ := ParseCanary(b)
		o.Record(event, "retrieved", "registry", r.RemoteAddr)
		_, _ = w.Write(b)
	default:
		http.Error(w, "method", 405)
	}
}

func (o *Observer) ServeTCP(ctx context.Context, l net.Listener) error {
	connections := make(chan struct{}, 64)
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		c, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case connections <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-connections }()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			b, _ := bufio.NewReader(io.LimitReader(c, 256)).ReadBytes('\n')
			if e, ok := ParseCanary(b); ok {
				o.Record(e, "received", "tcp", c.RemoteAddr().String())
			}
		}()
	}
}

func (o *Observer) ServeUDP(ctx context.Context, c net.PacketConn, dns bool) error {
	go func() { <-ctx.Done(); _ = c.Close() }()
	b := make([]byte, 4096)
	for {
		n, addr, err := c.ReadFrom(b)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if dns {
			name, end, ok := parseDNS(b[:n])
			if !ok {
				continue
			}
			if e, ok := dnsCanary(name, o.zone); ok {
				o.Record(e, "received", "dns", addr.String())
			}
			// NXDOMAIN is intentional: a failed lookup can still leak its query labels.
			response := append([]byte(nil), b[:end]...)
			response[2] = 0x84
			response[3] = 3
			for i := 6; i < 12; i++ {
				response[i] = 0
			}
			_, _ = c.WriteTo(response, addr)
		} else if e, ok := ParseCanary(b[:n]); ok {
			o.Record(e, "received", "udp", addr.String())
		}
	}
}
