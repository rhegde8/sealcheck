package seal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type proxyEnv struct {
	receiver, proxy *Services
	fixture         *Fixture
	tokenEnv        string
}

func startProxyEnv(t *testing.T, auth string) proxyEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	token := RandomID()
	env := proxyEnv{tokenEnv: "SEALCHECK_PROXY_TEST_TOKEN"}
	t.Setenv(env.tokenEnv, token)
	var err error
	env.receiver, err = StartReceiver(ctx, ReceiverOptions{HTTP: "127.0.0.1:0", Management: "127.0.0.1:0", TCP: "127.0.0.1:0", UDP: "127.0.0.1:0", DNS: "127.0.0.1:0", Zone: "canary.test", Token: token})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.receiver.Close)
	if env.fixture, err = NewFixture(env.receiver.HTTP, false); err != nil {
		t.Fatal(err)
	}
	env.fixture.Resolver = UDPResolver(env.receiver.DNS)
	env.fixture.AuthToken = auth
	if env.proxy, err = StartFixture(ctx, env.fixture, "127.0.0.1:0", "127.0.0.1:0", token); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.proxy.Close)
	return env
}

func (e proxyEnv) check(t *testing.T, probes ...Probe) (Report, []byte) {
	t.Helper()
	p := Policy{Version: 1, Name: "proxy-test", TimeoutMS: 1000, ObservationMS: 50, MaxAgeSeconds: 300, Probes: probes,
		Witnesses: []WitnessConfig{{ID: "receiver", URL: e.receiver.Management, TokenEnv: e.tokenEnv, Role: "receiver"}, {ID: "proxy", URL: e.proxy.Management, TokenEnv: e.tokenEnv, Role: "boundary"}}}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	r, err := Check(context.Background(), p, key, dir, RunProbes, nil)
	if err != nil {
		t.Fatal(err)
	}
	var written bytes.Buffer
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(path)
			written.Write(b)
		}
		return nil
	})
	return r, written.Bytes()
}

func TestProbeCarriesWorkloadCredential(t *testing.T) {
	const secret = "fixture-credential-value-1234"
	env := startProxyEnv(t, secret)
	env.fixture.SetLeaky(true)
	probe := Probe{ID: "auth-fetch", Kind: "proxy-fetch", Target: env.proxy.HTTP + "/fixtures/cargo/download", Callback: env.receiver.HTTP + "/canary", Expect: "deny", CredentialEnv: "WORKLOAD_REPO_CREDENTIAL"}
	for _, tt := range []struct {
		name, value, verdict, outcome string
		status                        int
	}{
		{"present", "Bearer " + secret, "FAIL", "success", 204},
		{"missing", "", "INCONCLUSIVE", "unsupported", 0},
		{"wrong", "Bearer wrong-credential-value", "INCONCLUSIVE", "error", 401},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("WORKLOAD_REPO_CREDENTIAL", tt.value)
			r, written := env.check(t, probe)
			got := r.Results.Probes[0]
			if r.Verdict != tt.verdict || got.Outcome != tt.outcome || got.HTTPStatus != tt.status {
				t.Fatalf("want %s/%s/%d, got %s/%s/%d", tt.verdict, tt.outcome, tt.status, r.Verdict, got.Outcome, got.HTTPStatus)
			}
			if bytes.Contains(written, []byte(secret)) || tt.value != "" && bytes.Contains(written, []byte(tt.value)) {
				t.Fatal("credential value reached report output")
			}
		})
	}
}

// A synthetic proxy whose handlers take the upstream URL in places the
// fixture does not: a path segment, or a header on a POST.
func TestTemplatedProxyFetchFindsInjectionPoints(t *testing.T) {
	env := startProxyEnv(t, "")
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var encoded string
		switch {
		case strings.HasPrefix(r.URL.EscapedPath(), "/remote/") && r.Method == http.MethodGet:
			encoded = strings.TrimSuffix(strings.TrimPrefix(r.URL.EscapedPath(), "/remote/"), "/fetch")
		case r.URL.Path == "/by-header" && r.Method == http.MethodPost:
			encoded = r.Header.Get("X-Upstream")
		default:
			http.Error(w, "unexpected request shape", 405)
			return
		}
		upstream, err := url.QueryUnescape(encoded)
		if err != nil {
			http.Error(w, "bad upstream", 400)
			return
		}
		res, err := http.Get(upstream)
		if err != nil {
			http.Error(w, "upstream failed", 502)
			return
		}
		_ = res.Body.Close()
		w.WriteHeader(res.StatusCode)
	}))
	defer proxy.Close()
	r, _ := env.check(t,
		Probe{ID: "path-template", Kind: "proxy-fetch", Target: proxy.URL + "/remote/{callback}/fetch", Callback: env.receiver.HTTP + "/canary", Expect: "deny"},
		Probe{ID: "header-template", Kind: "proxy-fetch", Target: proxy.URL + "/by-header?trace={canary}", Method: "POST", Headers: map[string]string{"X-Upstream": "{callback}"}, Callback: env.receiver.HTTP + "/canary", Expect: "deny"},
	)
	for _, f := range r.Findings {
		if f.Verdict != "FAIL" || !strings.Contains(f.Reason, "independent witness") {
			t.Fatalf("templated injection point not exercised: %+v", f)
		}
	}
}
