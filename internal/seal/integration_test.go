package seal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
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

func TestDNSSystemNegativeAnswerStillLeaks(t *testing.T) {
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
		t.Fatalf("negative answer masked leak: %+v", r)
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
		if ok {
			if err := walkDNSResponse(dnsResponse(b[:end], name, "canary.test"), end); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// walkDNSResponse checks that every counted record is present and that the
// message ends exactly after the last one. Responses never use compression.
func walkDNSResponse(r []byte, questionEnd int) error {
	if len(r) < questionEnd || r[2]&0x80 == 0 {
		return errors.New("response missing header or question")
	}
	records := int(binary.BigEndian.Uint16(r[6:8])) + int(binary.BigEndian.Uint16(r[8:10])) + int(binary.BigEndian.Uint16(r[10:12]))
	i := questionEnd
	name := func() error {
		for i < len(r) {
			n := int(r[i])
			i++
			if n == 0 {
				return nil
			}
			if n > 63 {
				return errors.New("compressed or oversized label")
			}
			i += n
		}
		return errors.New("unterminated name")
	}
	for ; records > 0; records-- {
		if err := name(); err != nil {
			return err
		}
		if i+10 > len(r) {
			return errors.New("truncated record header")
		}
		i += 10 + int(binary.BigEndian.Uint16(r[i+8:i+10]))
	}
	if i != len(r) {
		return fmt.Errorf("response length %d, records end at %d", len(r), i)
	}
	return nil
}

func TestDNSResponsesKeepMinimizingResolversGoing(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		qtype                byte
		rcode                byte
		answers, authorities uint16
	}{
		{"abc.canary.test", 1, 0, 0, 1},
		{"canary.test", 1, 0, 0, 1},
		{"canary.test", dnsTypeSOA, 0, 1, 0},
		{"canary.test", dnsTypeNS, 0, 1, 0},
		{"example.com", 1, 5, 0, 0},
	} {
		q, err := dnsQuestion(tt.name + ".")
		if err != nil {
			t.Fatal(err)
		}
		q[len(q)-3] = tt.qtype
		_, end, _ := parseDNS(q)
		r := dnsResponse(q[:end], tt.name, "canary.test.")
		if err = walkDNSResponse(r, end); err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if r[3]&0x0f != tt.rcode || r[2]&0x04 == 0 || binary.BigEndian.Uint16(r[6:8]) != tt.answers || binary.BigEndian.Uint16(r[8:10]) != tt.authorities {
			t.Fatalf("%s type %d: unexpected header % x", tt.name, tt.qtype, r[:12])
		}
	}
}

// minimizingResolver models RFC 9156 QNAME minimization with the RFC 8020
// NXDOMAIN cut: it reveals one more label to the authority per query and
// stops as soon as the authority says a shorter name does not exist.
func minimizingResolver(t *testing.T, authority, zone string) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	rcode := func(name string) byte {
		q, err := dnsQuestion(name + ".")
		if err != nil {
			return 2
		}
		conn, err := net.Dial("udp", authority)
		if err != nil {
			return 2
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		b := make([]byte, 512)
		if _, err = conn.Write(q); err != nil {
			return 2
		}
		if n, err := conn.Read(b); err != nil || n < 12 {
			return 2
		}
		return b[3] & 0x0f
	}
	go func() {
		b := make([]byte, 512)
		for {
			n, addr, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			name, end, ok := parseDNS(b[:n])
			if !ok || !strings.HasSuffix(name, "."+zone) {
				continue
			}
			labels := strings.Split(strings.TrimSuffix(name, "."+zone), ".")
			result := byte(0)
			for i := len(labels) - 1; i >= 0 && result == 0; i-- {
				result = rcode(strings.Join(labels[i:], ".") + "." + zone)
			}
			response := append([]byte(nil), b[:end]...)
			response[2] = 0x81 // response, recursion desired
			response[3] = 0x80 | result
			for i := 6; i < 12; i++ {
				response[i] = 0
			}
			_, _ = c.WriteTo(response, addr)
		}
	}()
	return c.LocalAddr().String()
}

func TestDNSSystemThroughMinimizingResolver(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := StartReceiver(ctx, ReceiverOptions{HTTP: "127.0.0.1:0", Management: "127.0.0.1:0", TCP: "127.0.0.1:0", UDP: "127.0.0.1:0", DNS: "127.0.0.1:0", Zone: "canary.test", Token: "test-witness-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	recursive := minimizingResolver(t, s.DNS, "canary.test")
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", recursive)
	}}
	defer func() { net.DefaultResolver = original }()
	t.Setenv("TEST_WITNESS_TOKEN", "test-witness-token")
	p := Policy{Version: 1, Name: "dns-minimized", TimeoutMS: 2000, ObservationMS: 10, MaxAgeSeconds: 300, Probes: []Probe{{ID: "dns", Kind: "dns-system", Zone: "canary.test", Expect: "deny"}}, Witnesses: []WitnessConfig{{ID: "receiver", URL: s.Management, TokenEnv: "TEST_WITNESS_TOKEN", Role: "receiver"}}}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	r, err := Check(ctx, p, key, t.TempDir(), RunProbes)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != "FAIL" {
		t.Fatalf("minimizing resolver hid the leaked canary: %+v", r)
	}
}
