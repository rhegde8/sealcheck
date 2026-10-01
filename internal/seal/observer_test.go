package seal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func foreignCanary() Event {
	e, _ := ParseCanary([]byte("sc1:" + RandomID() + ":probe:" + RandomID()))
	return e
}

func registered(t *testing.T, o *Observer, ttl time.Duration) string {
	t.Helper()
	run := RandomID()
	if err := o.Register(Registration{RunID: run, ExpiresAt: time.Now().Add(ttl)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return run
}

func TestUnregisteredFloodCannotOverflowRegisteredRun(t *testing.T) {
	o := NewObserver("canary.test")
	run := registered(t, o, time.Minute)
	for i := 0; i < 10*maxRunEvents; i++ {
		o.Record(foreignCanary(), "denied", "http", "127.0.0.1")
	}
	e := foreignCanary()
	e.RunID = run
	o.Record(e, "received", "http", "127.0.0.1")
	s := o.Snapshot(run)
	if s.Overflow || len(s.Events) != 1 || len(o.runs) != 1 {
		t.Fatalf("foreign canaries affected a registered run: overflow=%v events=%d runs=%d", s.Overflow, len(s.Events), len(o.runs))
	}
	if h := o.Snapshot(""); h.Overflow || len(h.Events) != 0 {
		t.Fatal("health snapshot exposed events or overflow")
	}
}

func TestRunOverflowIsIsolated(t *testing.T) {
	o := NewObserver("canary.test")
	flooded, other := registered(t, o, time.Minute), registered(t, o, time.Minute)
	for i := 0; i <= maxRunEvents; i++ {
		e := foreignCanary()
		e.RunID = flooded
		o.Record(e, "received", "http", "127.0.0.1")
	}
	if s := o.Snapshot(flooded); !s.Overflow || len(s.Events) != maxRunEvents {
		t.Fatalf("per-run overflow not reported: %v %d", s.Overflow, len(s.Events))
	}
	if o.Snapshot(other).Overflow {
		t.Fatal("overflow leaked into another run")
	}
}

func TestRunRegistrationBounds(t *testing.T) {
	o := NewObserver("canary.test")
	now := time.Now()
	for name, r := range map[string]Registration{
		"bad id":       {RunID: "not-a-run", ExpiresAt: now.Add(time.Minute)},
		"expired":      {RunID: RandomID(), ExpiresAt: now.Add(-time.Second)},
		"too long":     {RunID: RandomID(), ExpiresAt: now.Add(maxRunWindow + time.Minute)},
		"zero expiry":  {RunID: RandomID()},
		"uppercase id": {RunID: strings.ToUpper(RandomID()), ExpiresAt: now.Add(time.Minute)},
	} {
		if o.Register(r, now) == nil {
			t.Fatalf("%s: accepted invalid registration", name)
		}
	}
	run := registered(t, o, time.Minute)
	if err := o.Register(Registration{RunID: run, ExpiresAt: now.Add(time.Second)}, now); err != nil || !o.runs[run].expires.After(now.Add(30*time.Second)) {
		t.Fatal("re-registration must be idempotent and never shorten retention")
	}
	for len(o.runs) < maxActiveRuns {
		registered(t, o, time.Minute)
	}
	if err := o.Register(Registration{RunID: RandomID(), ExpiresAt: now.Add(time.Minute)}, now); err != errRegistrationFull {
		t.Fatalf("active run cap not enforced: %v", err)
	}
	o.mu.Lock()
	o.prune(now.Add(2 * time.Minute))
	remaining := len(o.runs)
	o.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("expired runs were not pruned: %d", remaining)
	}
}

func TestRegistryStoresOnlyRegisteredRuns(t *testing.T) {
	o := NewObserver("canary.test")
	s := httptest.NewServer(o)
	defer s.Close()
	run := registered(t, o, time.Minute)
	put := func(run string) (int, int) {
		canary := "sc1:" + run + ":upload:" + RandomID()
		path := s.URL + "/registry/" + run + "/upload"
		req, _ := http.NewRequest(http.MethodPut, path, strings.NewReader(canary))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		get, err := http.Get(path)
		if err != nil {
			t.Fatal(err)
		}
		_ = get.Body.Close()
		return res.StatusCode, get.StatusCode
	}
	if putStatus, getStatus := put(RandomID()); putStatus != 201 || getStatus != 404 {
		t.Fatalf("unregistered upload: PUT %d GET %d", putStatus, getStatus)
	}
	if putStatus, getStatus := put(run); putStatus != 201 || getStatus != 200 {
		t.Fatalf("registered upload: PUT %d GET %d", putStatus, getStatus)
	}
}

func TestManagementRunRegistration(t *testing.T) {
	o := NewObserver("canary.test")
	s := httptest.NewServer(o.Management("management-secret"))
	defer s.Close()
	request := func(method, token, body string) int {
		req, _ := http.NewRequest(method, s.URL+"/runs", strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
	valid := `{"run_id":"` + RandomID() + `","expires_at":"` + time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano) + `"}`
	for _, tt := range []struct {
		method, token, body string
		want                int
	}{
		{http.MethodPost, "", valid, 401},
		{http.MethodPost, "wrong-secret-value", valid, 401},
		{http.MethodGet, "management-secret", "", 405},
		{http.MethodPost, "management-secret", `{"run_id":"x"}`, 400},
		{http.MethodPost, "management-secret", `{"run_id":"` + RandomID() + `","expires_at":"2000-01-01T00:00:00Z","extra":1}`, 400},
		{http.MethodPost, "management-secret", valid, 204},
		{http.MethodPost, "management-secret", valid, 204},
	} {
		if got := request(tt.method, tt.token, tt.body); got != tt.want {
			t.Fatalf("%s %q: want %d, got %d", tt.method, tt.body, tt.want, got)
		}
	}
	if len(o.runs) != 1 {
		t.Fatalf("want one registered run, got %d", len(o.runs))
	}
}
