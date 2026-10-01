package seal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func evidence(t *testing.T, kind, expect, outcome string) (Plan, Results, []Witness, time.Time) {
	t.Helper()
	p := Policy{Version: 1, Name: "test", TimeoutMS: 100, ObservationMS: 1, MaxAgeSeconds: 300, Probes: []Probe{{ID: "probe", Kind: kind, Target: "127.0.0.1:9999", Expect: expect}}, Witnesses: []WitnessConfig{{ID: "receiver", URL: "http://127.0.0.1:1", TokenEnv: "TOKEN", Role: "receiver"}, {ID: "boundary", URL: "http://127.0.0.1:2", TokenEnv: "TOKEN", Role: "boundary"}}}
	if kind == "http" {
		p.Probes[0].Target = "http://127.0.0.1:9999/canary"
	}
	now := time.Now().UTC()
	plan, err := NewPlan(p, now)
	if err != nil {
		t.Fatal(err)
	}
	results := Results{Version: 1, RunID: plan.RunID, PolicySHA256: plan.PolicySHA256, Identity: CurrentIdentity(), Probes: []Result{{ID: "probe", StartedAt: now, FinishedAt: now.Add(time.Millisecond), Outcome: outcome}}}
	ws := []Witness{}
	for _, cfg := range p.Witnesses {
		ws = append(ws, Witness{ID: cfg.ID, Role: cfg.Role, HealthyBefore: true, HealthyAfter: true, Before: now.Add(-time.Millisecond), After: now.Add(2 * time.Millisecond), Snapshot: Snapshot{Instance: "instance", At: now.Add(2 * time.Millisecond), Events: []Event{}}})
	}
	return plan, results, ws, now.Add(3 * time.Millisecond)
}

func receipt(p Plan, action, protocol string, now time.Time) Event {
	return Event{RunID: p.RunID, ProbeID: "probe", Token: p.Tokens["probe"], Action: action, Protocol: protocol, At: now, PayloadSHA256: Hash([]byte(Canary(p, "probe")))}
}

func TestEvaluationEvidencePrecedence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(Plan, *Results, []Witness, time.Time)
		want   string
	}{
		{"timeout is inconclusive", func(_ Plan, _ *Results, _ []Witness, _ time.Time) {}, "INCONCLUSIVE"},
		{"explicit kernel denial", func(_ Plan, r *Results, _ []Witness, _ time.Time) { r.Probes[0].Outcome = "denied" }, "PASS"},
		{"independent boundary denial", func(p Plan, _ *Results, w []Witness, n time.Time) {
			w[1].Snapshot.Events = append(w[1].Snapshot.Events, receipt(p, "denied", "http", n))
		}, "PASS"},
		{"receiver cannot claim boundary denial", func(p Plan, _ *Results, w []Witness, n time.Time) {
			w[0].Snapshot.Events = append(w[0].Snapshot.Events, receipt(p, "denied", "http", n))
		}, "INCONCLUSIVE"},
		{"500 after delivery is a leak", func(p Plan, r *Results, w []Witness, n time.Time) {
			r.Probes[0].HTTPStatus = 500
			w[0].Snapshot.Events = append(w[0].Snapshot.Events, receipt(p, "received", "http", n))
		}, "FAIL"},
		{"leak overrides denial", func(p Plan, r *Results, w []Witness, n time.Time) {
			r.Probes[0].Outcome = "denied"
			w[0].Snapshot.Events = append(w[0].Snapshot.Events, receipt(p, "received", "http", n))
		}, "FAIL"},
		{"outage cannot pass", func(_ Plan, r *Results, w []Witness, _ time.Time) {
			r.Probes[0].Outcome = "denied"
			w[0].HealthyAfter = false
		}, "INCONCLUSIVE"},
		{"overflow cannot pass", func(_ Plan, r *Results, w []Witness, _ time.Time) {
			r.Probes[0].Outcome = "denied"
			w[0].Snapshot.Overflow = true
		}, "INCONCLUSIVE"},
		{"missing result cannot pass", func(p Plan, r *Results, w []Witness, n time.Time) {
			r.Probes = nil
			w[1].Snapshot.Events = append(w[1].Snapshot.Events, receipt(p, "denied", "http", n))
		}, "INCONCLUSIVE"},
		{"duplicate result cannot pass", func(_ Plan, r *Results, _ []Witness, _ time.Time) {
			r.Probes[0].Outcome = "denied"
			r.Probes = append(r.Probes, r.Probes[0])
		}, "INCONCLUSIVE"},
		{"wrong run cannot pass", func(_ Plan, r *Results, _ []Witness, _ time.Time) {
			r.RunID = RandomID()
			r.Probes[0].Outcome = "denied"
		}, "INCONCLUSIVE"},
		{"unmatched canary ignored", func(p Plan, _ *Results, w []Witness, n time.Time) {
			e := receipt(p, "denied", "http", n)
			e.Token = RandomID()
			w[1].Snapshot.Events = append(w[1].Snapshot.Events, e)
		}, "INCONCLUSIVE"},
		{"stale evidence ignored", func(p Plan, _ *Results, w []Witness, n time.Time) {
			w[1].Snapshot.Events = append(w[1].Snapshot.Events, receipt(p, "denied", "http", n.Add(-time.Hour)))
		}, "INCONCLUSIVE"},
		{"wrong protocol ignored", func(p Plan, _ *Results, w []Witness, n time.Time) {
			w[1].Snapshot.Events = append(w[1].Snapshot.Events, receipt(p, "denied", "udp", n))
		}, "INCONCLUSIVE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, r, w, n := evidence(t, "http", "deny", "error")
			tt.mutate(p, &r, w, n)
			got := Evaluate(p, r, w, n)
			if got.Verdict != tt.want {
				t.Fatalf("want %s, got %s: %+v", tt.want, got.Verdict, got)
			}
		})
	}
}

func TestUDPNeedsExternalReceipt(t *testing.T) {
	p, r, w, n := evidence(t, "udp", "deny", "sent")
	if got := Evaluate(p, r, w, n); got.Verdict != "INCONCLUSIVE" {
		t.Fatal(got.Verdict)
	}
	w[0].Snapshot.Events = append(w[0].Snapshot.Events, receipt(p, "received", "udp", n))
	if got := Evaluate(p, r, w, n); got.Verdict != "FAIL" {
		t.Fatal(got.Verdict)
	}
}

func TestSignedReportBindingAndTampering(t *testing.T) {
	p, r, w, n := evidence(t, "http", "deny", "denied")
	report := Evaluate(p, r, w, n)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bundle, err := Sign(report, priv)
	if err != nil {
		t.Fatal(err)
	}
	opts := VerifyOptions{RunID: p.RunID, PolicySHA256: p.PolicySHA256, Now: n, MaxAge: time.Minute}
	if _, err = Verify(bundle, pub, opts); err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err = Verify(bundle, other, opts); err == nil {
		t.Fatal("accepted wrong key")
	}
	for _, name := range []string{"payload", "signature", "run", "policy", "stale", "missing binding"} {
		t.Run(name, func(t *testing.T) {
			b := bundle
			o := opts
			switch name {
			case "payload":
				raw, _ := base64.StdEncoding.DecodeString(b.Payload)
				raw[len(raw)/2] ^= 1
				b.Payload = base64.StdEncoding.EncodeToString(raw)
			case "signature":
				raw, _ := base64.StdEncoding.DecodeString(b.Signature)
				raw[0] ^= 1
				b.Signature = base64.StdEncoding.EncodeToString(raw)
			case "run":
				o.RunID = RandomID()
			case "policy":
				o.PolicySHA256 = "wrong"
			case "stale":
				o.Now = n.Add(time.Hour)
			case "missing binding":
				o.RunID = ""
			}
			if _, err := Verify(b, pub, o); err == nil {
				t.Fatal("invalid report accepted")
			}
		})
	}
	report.Verdict = "FAIL"
	b, _ := Sign(report, priv)
	if _, err = Verify(b, pub, opts); err == nil {
		t.Fatal("inconsistent signed verdict accepted")
	}
	if _, err = Verify(bundle, pub, VerifyOptions{Historical: true}); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyRejectsAmbiguousInputs(t *testing.T) {
	p, _, _, _ := evidence(t, "tcp", "deny", "error")
	for _, name := range []string{"duplicate", "all optional", "hostname target", "unknown kind", "embedded credential", "bad window"} {
		t.Run(name, func(t *testing.T) {
			q := p.Policy
			q.Probes = append([]Probe(nil), q.Probes...)
			switch name {
			case "duplicate":
				q.Probes = append(q.Probes, q.Probes[0])
			case "all optional":
				q.Probes[0].Optional = true
			case "hostname target":
				q.Probes[0].Target = "example.com:443"
			case "unknown kind":
				q.Probes[0].Kind = "oracle"
			case "embedded credential":
				q.Probes[0].Kind = "http"
				q.Probes[0].Target = "http://user:password@example.com"
			case "bad window":
				q.TimeoutMS = 0
			}
			if q.Validate() == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}
