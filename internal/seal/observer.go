package seal

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	maxRunEvents  = 1024
	maxActiveRuns = 1024
	maxRunWindow  = 2 * time.Hour
)

// Observers retain evidence only for runs a trusted controller registered.
// Canary-shaped traffic for any other run is dropped, so a workload cannot
// exhaust storage that later runs depend on.
type Observer struct {
	mu       sync.Mutex
	instance string
	zone     string
	runs     map[string]*runState
}

type runState struct {
	expires  time.Time
	events   []Event
	overflow bool
	registry map[string][]byte
}

type Registration struct {
	RunID     string    `json:"run_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

var errRegistrationFull = errors.New("too many active runs")

func NewObserver(zone string) *Observer {
	return &Observer{instance: RandomID(), zone: strings.TrimSuffix(zone, "."), runs: map[string]*runState{}}
}

// Register is idempotent; it can extend but never shorten a run's retention.
func (o *Observer) Register(r Registration, now time.Time) error {
	if !randomHex.MatchString(r.RunID) || !r.ExpiresAt.After(now) || r.ExpiresAt.After(now.Add(maxRunWindow)) {
		return errors.New("invalid run registration")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.prune(now)
	if s, ok := o.runs[r.RunID]; ok {
		if r.ExpiresAt.After(s.expires) {
			s.expires = r.ExpiresAt
		}
		return nil
	}
	if len(o.runs) >= maxActiveRuns {
		return errRegistrationFull
	}
	o.runs[r.RunID] = &runState{expires: r.ExpiresAt, events: []Event{}, registry: map[string][]byte{}}
	return nil
}

// active must be called with o.mu held.
func (o *Observer) active(run string, now time.Time) *runState {
	o.prune(now)
	return o.runs[run]
}

func (o *Observer) prune(now time.Time) {
	for id, s := range o.runs {
		if !now.Before(s.expires) {
			delete(o.runs, id)
		}
	}
}

func (o *Observer) Record(e Event, action, protocol, remote string) {
	now := time.Now().UTC()
	o.mu.Lock()
	defer o.mu.Unlock()
	s := o.active(e.RunID, now)
	if s == nil {
		return
	}
	if len(s.events) >= maxRunEvents {
		s.overflow = true
		return
	}
	e.Action = action
	e.Protocol = protocol
	e.Remote = remote
	e.At = now
	s.events = append(s.events, e)
}

func (o *Observer) Snapshot(run string) Snapshot {
	now := time.Now().UTC()
	o.mu.Lock()
	defer o.mu.Unlock()
	snapshot := Snapshot{Instance: o.instance, At: now, Events: []Event{}}
	if s := o.active(run, now); s != nil {
		snapshot.Overflow = s.overflow
		snapshot.Events = append(snapshot.Events, s.events...)
	}
	return snapshot
}

func (o *Observer) Management(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.URL.Path == "/runs" {
			if r.Method != http.MethodPost {
				http.Error(w, "method", 405)
				return
			}
			var registration Registration
			if err := DecodeJSON(io.LimitReader(r.Body, 4096), &registration); err != nil {
				http.Error(w, "invalid registration", 400)
				return
			}
			if err := o.Register(registration, time.Now()); errors.Is(err, errRegistrationFull) {
				http.Error(w, "full", 503)
				return
			} else if err != nil {
				http.Error(w, "invalid registration", 400)
				return
			}
			w.WriteHeader(204)
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
		// Unregistered runs get the same response, so the sender learns
		// nothing about which runs the controller is measuring.
		o.mu.Lock()
		stored := false
		if s := o.active(event.RunID, time.Now().UTC()); s != nil {
			if _, exists := s.registry[r.URL.Path]; !exists && len(s.registry) >= maxRunEvents {
				s.overflow = true
			} else {
				s.registry[r.URL.Path] = append([]byte(nil), b...)
				stored = true
			}
		}
		o.mu.Unlock()
		if stored {
			o.Record(event, "received", "registry", r.RemoteAddr)
		}
		w.WriteHeader(201)
	case http.MethodGet:
		run, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/registry/"), "/")
		o.mu.Lock()
		var b []byte
		ok := false
		if s := o.active(run, time.Now().UTC()); s != nil {
			b, ok = s.registry[r.URL.Path]
			b = append([]byte(nil), b...)
		}
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
			// The lookup still fails for the probe: a negative answer does not
			// mean its query labels stayed inside the boundary.
			_, _ = c.WriteTo(dnsResponse(b[:end], name, o.zone), addr)
		} else if e, ok := ParseCanary(b[:n]); ok {
			o.Record(e, "received", "udp", addr.String())
		}
	}
}
