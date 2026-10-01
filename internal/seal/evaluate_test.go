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
	return evidenceWith(t, kind, expect, outcome, nil)
}

func evidenceWith(t *testing.T, kind, expect, outcome string, mutate func(*Policy)) (Plan, Results, []Witness, time.Time) {
	t.Helper()
	p := Policy{Version: 1, Name: "test", TimeoutMS: 100, ObservationMS: 1, MaxAgeSeconds: 300, Probes: []Probe{{ID: "probe", Kind: kind, Target: "127.0.0.1:9999", Expect: expect}}, Witnesses: []WitnessConfig{{ID: "receiver", URL: "http://127.0.0.1:1", TokenEnv: "TOKEN", Role: "receiver"}, {ID: "boundary", URL: "http://127.0.0.1:2", TokenEnv: "TOKEN", Role: "boundary"}}}
	if kind == "http" {
		p.Probes[0].Target = "http://127.0.0.1:9999/canary"
	}
	if kind == "http-proxy" {
		p.Probes[0].Target, p.Probes[0].Proxy = "http://127.0.0.1:9999/canary", "http://127.0.0.1:9998"
	}
	if mutate != nil {
		mutate(&p)
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
			got := Evaluate(p, r, w, nil, n)
			if got.Verdict != tt.want {
				t.Fatalf("want %s, got %s: %+v", tt.want, got.Verdict, got)
			}
		})
	}
}

func TestUDPNeedsExternalReceipt(t *testing.T) {
	p, r, w, n := evidence(t, "udp", "deny", "sent")
	if got := Evaluate(p, r, w, nil, n); got.Verdict != "INCONCLUSIVE" {
		t.Fatal(got.Verdict)
	}
	w[0].Snapshot.Events = append(w[0].Snapshot.Events, receipt(p, "received", "udp", n))
	if got := Evaluate(p, r, w, nil, n); got.Verdict != "FAIL" {
		t.Fatal(got.Verdict)
	}
}

func TestSignedReportBindingAndTampering(t *testing.T) {
	p, r, w, n := evidence(t, "http", "deny", "denied")
	report := Evaluate(p, r, w, nil, n)
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

func optIn(p *Policy) { p.MinDenyEvidence, p.ObservationMS = "non-receipt", 100 }

// reference builds a positive control for the main plan with one delivery.
func reference(t *testing.T, p Plan, protocol string, n time.Time) *Reference {
	t.Helper()
	q := p.Policy
	optIn(&q)
	main := p
	main.Policy = q
	rp, ok, err := NewReferencePlan(main, p.CreatedAt.Add(time.Millisecond))
	if err != nil || !ok {
		t.Fatalf("reference plan not created: %v", err)
	}
	receipt := Event{RunID: rp.RunID, ProbeID: "probe", Token: rp.Tokens["probe"], Action: "received", Protocol: protocol, At: n, PayloadSHA256: Hash([]byte(Canary(rp, "probe")))}
	return &Reference{Plan: rp, Snapshots: map[string]Snapshot{
		"receiver": {Instance: "instance", At: n, Events: []Event{receipt}},
		"boundary": {Instance: "instance", At: n, Events: []Event{}},
	}}
}

func TestNonReceiptEvidence(t *testing.T) {
	tests := []struct {
		name, kind, outcome string
		policy              func(*Policy)
		mutate              func(Plan, *Reference, []Witness, time.Time) *Reference
		want, grade         string
	}{
		{"reference proves live target", "tcp", "error", optIn, nil, "PASS", "non-receipt"},
		{"udp send can rest on non-receipt", "udp", "sent", optIn, nil, "PASS", "non-receipt"},
		{"policy did not opt in", "tcp", "error", nil, nil, "INCONCLUSIVE", ""},
		{"missing reference", "tcp", "error", optIn, func(Plan, *Reference, []Witness, time.Time) *Reference { return nil }, "INCONCLUSIVE", ""},
		{"reference to another target", "tcp", "error", optIn, func(_ Plan, r *Reference, _ []Witness, _ time.Time) *Reference {
			r.Plan.Policy.Probes[0].Target = "127.0.0.1:1"
			r.Plan.PolicySHA256 = PolicyHash(r.Plan.Policy)
			return r
		}, "INCONCLUSIVE", ""},
		{"reference seen by another witness instance", "tcp", "error", optIn, func(_ Plan, r *Reference, _ []Witness, _ time.Time) *Reference {
			s := r.Snapshots["receiver"]
			s.Instance = "restarted"
			r.Snapshots["receiver"] = s
			return r
		}, "INCONCLUSIVE", ""},
		{"overflowed reference snapshot", "tcp", "error", optIn, func(_ Plan, r *Reference, _ []Witness, _ time.Time) *Reference {
			s := r.Snapshots["receiver"]
			s.Overflow = true
			r.Snapshots["receiver"] = s
			return r
		}, "INCONCLUSIVE", ""},
		{"reference before the measured run", "tcp", "error", optIn, func(p Plan, r *Reference, _ []Witness, _ time.Time) *Reference {
			r.Plan.CreatedAt = p.CreatedAt.Add(-time.Second)
			return r
		}, "INCONCLUSIVE", ""},
		{"reference on wrong protocol", "tcp", "error", optIn, func(_ Plan, r *Reference, _ []Witness, _ time.Time) *Reference {
			r.Snapshots["receiver"].Events[0].Protocol = "udp"
			return r
		}, "INCONCLUSIVE", ""},
		{"probe never ran", "tcp", "unsupported", optIn, nil, "INCONCLUSIVE", ""},
		{"leak still fails", "tcp", "error", optIn, func(p Plan, r *Reference, w []Witness, n time.Time) *Reference {
			w[0].Snapshot.Events = append(w[0].Snapshot.Events, receipt(p, "received", "tcp", n))
			return r
		}, "FAIL", ""},
		{"explicit denial needs no grade", "tcp", "denied", optIn, nil, "PASS", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, r, w, n := evidenceWith(t, tt.kind, "deny", tt.outcome, tt.policy)
			ref := reference(t, p, tt.kind, n)
			if tt.mutate != nil {
				ref = tt.mutate(p, ref, w, n)
			}
			got := Evaluate(p, r, w, ref, n)
			if got.Verdict != tt.want || got.Findings[0].Grade != tt.grade {
				t.Fatalf("want %s/%q, got %s/%q: %+v", tt.want, tt.grade, got.Verdict, got.Findings[0].Grade, got.Findings[0])
			}
		})
	}
}

func TestProxyKindsCannotRestOnNonReceipt(t *testing.T) {
	p, r, w, n := evidenceWith(t, "http-proxy", "deny", "error", optIn)
	if _, ok, _ := NewReferencePlan(p, n); ok {
		t.Fatal("reference plan included a proxy probe")
	}
	// Even a hand-built reference for the proxy probe must not be accepted.
	q := p.Policy
	q.Name, q.MinDenyEvidence = "forged-reference", ""
	q.Probes = []Probe{p.Policy.Probes[0]}
	q.Probes[0].Expect = "allow"
	rp, err := NewPlan(q, p.CreatedAt.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	e := Event{RunID: rp.RunID, ProbeID: "probe", Token: rp.Tokens["probe"], Action: "received", Protocol: "http", At: n, PayloadSHA256: Hash([]byte(Canary(rp, "probe")))}
	ref := &Reference{Plan: rp, Snapshots: map[string]Snapshot{"receiver": {Instance: "instance", At: n, Events: []Event{e}}}}
	if got := Evaluate(p, r, w, ref, n); got.Verdict != "INCONCLUSIVE" {
		t.Fatalf("proxy probe passed on non-receipt: %+v", got.Findings)
	}
}

func TestSignedNonReceiptGradeIsBound(t *testing.T) {
	p, r, w, n := evidenceWith(t, "tcp", "deny", "error", optIn)
	report := Evaluate(p, r, w, reference(t, p, "tcp", n), n)
	if report.Verdict != "PASS" || report.Findings[0].Grade != "non-receipt" {
		t.Fatalf("setup: %+v", report.Findings)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	opts := VerifyOptions{RunID: p.RunID, PolicySHA256: p.PolicySHA256, Now: n, MaxAge: time.Minute}
	bundle, _ := Sign(report, priv)
	if _, err := Verify(bundle, pub, opts); err != nil {
		t.Fatal(err)
	}
	for name, tamper := range map[string]func(*Report){
		"grade removed":     func(r *Report) { r.Findings[0].Grade = "" },
		"reference dropped": func(r *Report) { r.Reference = nil },
	} {
		forged := report
		forged.Findings = append([]Finding(nil), report.Findings...)
		tamper(&forged)
		b, _ := Sign(forged, priv)
		if _, err := Verify(b, pub, opts); err == nil {
			t.Fatalf("%s: inconsistent signed grade accepted", name)
		}
	}
}
