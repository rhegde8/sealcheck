package seal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPortableDemo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dir := t.TempDir()
	reports, err := Demo(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 3 {
		t.Fatal("missing demo phases")
	}
	pub, err := ReadPublicKey(filepath.Join(dir, "demo.pub.pem"))
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"baseline", "leaky", "remediated"} {
		var b Bundle
		r := reports[i]
		if err = ReadJSON(filepath.Join(dir, name, r.Plan.RunID, "bundle.json"), &b); err != nil {
			t.Fatal(err)
		}
		if _, err = Verify(b, pub, VerifyOptions{RunID: r.Plan.RunID, PolicySHA256: r.Plan.PolicySHA256, Now: time.Now(), MaxAge: time.Minute}); err != nil {
			t.Fatal(err)
		}
	}
	found := false
	for _, f := range reports[1].Findings {
		if f.ID == "registry-upload" {
			found = strings.Contains(f.Reason, "external reader")
		}
	}
	if !found {
		t.Fatal("registry upload was not independently retrieved")
	}
	for _, r := range reports[1].Results.Probes {
		if r.ID == "error-after-forward" && r.HTTPStatus != 500 {
			t.Fatal("missing error-after-forward case")
		}
	}
}

func TestIPv6LeakDespiteIPv4Denial(t *testing.T) {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o := NewObserver("canary.test")
	go o.ServeTCP(ctx, l)
	p, r, w, n := evidence(t, "tcp", "deny", "denied")
	p.Policy.Probes = append(p.Policy.Probes, Probe{ID: "ipv6", Kind: "tcp", Target: l.Addr().String(), Expect: "deny", Network: "6"})
	p.PolicySHA256 = PolicyHash(p.Policy)
	p.Tokens["ipv6"] = RandomID()
	r.PolicySHA256 = p.PolicySHA256
	outcome, _, err := runProbe(ctx, p, p.Policy.Probes[1])
	if err != nil {
		t.Fatal(err)
	}
	r.Probes = append(r.Probes, Result{ID: "ipv6", StartedAt: p.CreatedAt, FinishedAt: n, Outcome: outcome})
	if got := Evaluate(p, r, w, time.Now().Add(10*time.Millisecond)); got.Verdict != "FAIL" {
		t.Fatal(got)
	}
}

func TestDNSSystemNXDOMAINStillLeaks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := StartReceiver(ctx, ReceiverOptions{HTTP: "127.0.0.1:0", Management: "127.0.0.1:0", TCP: "127.0.0.1:0", UDP: "127.0.0.1:0", DNS: "127.0.0.1:0", Zone: "canary.test", Token: "test-witness-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", s.DNS)
	}}
	defer func() { net.DefaultResolver = original }()
	t.Setenv("TEST_WITNESS_TOKEN", "test-witness-token")
	p := Policy{Version: 1, Name: "dns-system", TimeoutMS: 1000, ObservationMS: 10, MaxAgeSeconds: 300, Probes: []Probe{{ID: "dns", Kind: "dns-system", Zone: "canary.test", Expect: "deny"}}, Witnesses: []WitnessConfig{{ID: "receiver", URL: s.Management, TokenEnv: "TEST_WITNESS_TOKEN", Role: "receiver"}}}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	r, err := Check(ctx, p, key, t.TempDir(), RunProbes)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != "FAIL" || r.Results.Probes[0].Outcome != "error" {
		t.Fatalf("NXDOMAIN masked leak: %+v", r)
	}
}

func TestDirectHTTPIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer s.Close()
	p, _, _, _ := evidence(t, "http", "deny", "error")
	p.Policy.Probes[0].Target = s.URL
	p.PolicySHA256 = PolicyHash(p.Policy)
	r, err := RunProbes(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Probes[0].Outcome != "success" {
		t.Fatal(r.Probes)
	}
}

func TestObserverManagementRequiresCredentialAndDoesNotExposeOtherRuns(t *testing.T) {
	o := NewObserver("canary.test")
	p, _, _, n := evidence(t, "udp", "deny", "sent")
	o.Record(receipt(p, "received", "udp", n), "received", "udp", "127.0.0.1")
	s := httptest.NewServer(o.Management("management-secret"))
	defer s.Close()
	res, err := http.Get(s.URL + "/events?run_id=" + p.RunID)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("unauthenticated management read allowed")
	}
	if len(o.Snapshot(RandomID()).Events) != 0 {
		t.Fatal("cross-run event disclosure")
	}
}

func TestKeyFilesCannotBeOverwritten(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "private.pem")
	pub := filepath.Join(dir, "public.pem")
	if err := GenerateKeyFiles(priv, pub); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(priv)
	if err := GenerateKeyFiles(priv, pub); err == nil {
		t.Fatal("overwrote key")
	}
	after, _ := os.ReadFile(priv)
	if string(before) != string(after) {
		t.Fatal("key changed")
	}
	if err := os.Chmod(priv, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateKey(priv); err == nil {
		t.Fatal("accepted exposed key")
	}
}

func FuzzDNSParser(f *testing.F) {
	q, _ := dnsQuestion("sc1.example.canary.test.")
	f.Add(q)
	f.Add([]byte{0, 1, 2})
	f.Fuzz(func(t *testing.T, b []byte) {
		name, end, ok := parseDNS(b)
		if ok && (end > len(b) || name == "") {
			t.Fatal("parser returned invalid bounds")
		}
	})
}
