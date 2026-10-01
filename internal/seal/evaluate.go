package seal

import (
	"fmt"
	"reflect"
	"time"
)

const ToolVersion = "0.2.0"

func Evaluate(plan Plan, results Results, witnesses []Witness, reference *Reference, now time.Time) Report {
	report := Report{Version: Version, ToolVersion: ToolVersion, IssuedAt: now.UTC(), Plan: plan, Results: results, Witnesses: witnesses, Reference: reference, Findings: []Finding{}, Verdict: "PASS", Limitations: []string{
		"Evidence applies only to this probe set, identity, destinations, and observation window.",
		"The launcher, host, controller, and configured witnesses are trusted; runner identity is self-reported.",
		"A signature authenticates the report, not the integrity of a compromised runtime. Periodic checks sample behavior.",
		"Proxy fixtures do not establish coverage of real Artifactory versions or incident request paths.",
	}}
	addError := func(s string) { report.Errors = append(report.Errors, s) }
	if err := plan.Validate(); err != nil {
		addError("invalid plan: " + err.Error())
	}
	if plan.CreatedAt.After(now.Add(2*time.Second)) || now.After(plan.Deadline) {
		addError("evaluation outside the plan validity window")
	}
	if now.Sub(plan.CreatedAt) > time.Duration(plan.Policy.MaxAgeSeconds)*time.Second {
		addError("run exceeded the policy maximum age before evaluation")
	}
	if results.Version != Version || results.RunID != plan.RunID || results.PolicySHA256 != plan.PolicySHA256 {
		addError("runner result binding mismatch")
	}
	resultMap := map[string]Result{}
	known := map[string]Probe{}
	for _, p := range plan.Policy.Probes {
		known[p.ID] = p
	}
	for _, r := range results.Probes {
		if _, ok := known[r.ID]; !ok {
			addError("unexpected result: " + r.ID)
		}
		if _, ok := resultMap[r.ID]; ok {
			addError("duplicate result: " + r.ID)
		}
		if r.StartedAt.Before(plan.CreatedAt.Add(-2*time.Second)) || r.FinishedAt.Before(r.StartedAt) || r.FinishedAt.After(now.Add(2*time.Second)) {
			addError("invalid result timestamps: " + r.ID)
		}
		switch r.Outcome {
		case "success", "sent", "denied", "error", "unsupported":
		default:
			addError("invalid result outcome: " + r.ID)
		}
		resultMap[r.ID] = r
	}
	witnessMap := map[string]Witness{}
	for _, w := range witnesses {
		if _, ok := witnessMap[w.ID]; ok {
			addError("duplicate witness: " + w.ID)
		}
		witnessMap[w.ID] = w
	}
	if len(witnesses) != len(plan.Policy.Witnesses) {
		addError("witness count mismatch")
	}
	for _, cfg := range plan.Policy.Witnesses {
		w, ok := witnessMap[cfg.ID]
		if !ok || w.Role != cfg.Role || !w.HealthyBefore || !w.HealthyAfter || w.Snapshot.Overflow || w.Snapshot.Instance == "" {
			addError("witness unavailable or incomplete: " + cfg.ID)
		}
		if w.Before.After(plan.CreatedAt) || w.Before.Before(plan.CreatedAt.Add(-30*time.Second)) || w.After.Before(plan.CreatedAt) || w.After.After(now.Add(2*time.Second)) || w.Snapshot.At.Before(w.After.Add(-5*time.Second)) || w.Snapshot.At.After(now.Add(2*time.Second)) {
			addError("invalid witness observation window: " + cfg.ID)
		}
	}
	for _, q := range plan.Policy.Probes {
		f := Finding{ID: q.ID, Verdict: "INCONCLUSIVE", Reason: "no corroborated delivery or denial", Evidence: []string{}}
		r, hasResult := resultMap[q.ID]
		received, denied, retrieved := false, false, false
		for _, cfg := range plan.Policy.Witnesses {
			w := witnessMap[cfg.ID]
			for i, e := range w.Snapshot.Events {
				if e.RunID != plan.RunID || e.ProbeID != q.ID || e.Token != plan.Tokens[q.ID] || e.PayloadSHA256 != Hash([]byte(Canary(plan, q.ID))) || e.At.Before(plan.CreatedAt.Add(-2*time.Second)) || e.At.After(now.Add(2*time.Second)) {
					continue
				}
				if !eventProtocolMatches(q, e.Protocol) {
					continue
				}
				if e.Action == "received" {
					received = true
				} else if e.Action == "retrieved" && q.Kind == "registry-upload" {
					received = true
				} else if e.Action == "denied" && cfg.Role == "boundary" {
					denied = true
				} else {
					continue
				}
				f.Evidence = append(f.Evidence, fmt.Sprintf("witnesses/%s/events/%d", w.ID, i))
			}
			for i, readback := range w.Readbacks {
				if cfg.RegistryURL != "" && q.Kind == "registry-upload" && readback.ProbeID == q.ID && readback.PayloadSHA256 == Hash([]byte(Canary(plan, q.ID))) && !readback.At.Before(plan.CreatedAt) && !readback.At.After(now.Add(2*time.Second)) {
					received = true
					retrieved = true
					f.Evidence = append(f.Evidence, fmt.Sprintf("witnesses/%s/readbacks/%d", w.ID, i))
				}
			}
		}
		// Successful UDP send and resolver responses are deliberately insufficient.
		succeeded := hasResult && r.Outcome == "success" && q.Kind != "udp" && q.Kind != "dns" && q.Kind != "dns-system"
		if hasResult && r.Outcome == "denied" {
			denied = true
			f.Evidence = append(f.Evidence, "runner/"+q.ID+"/kernel-denial")
		}
		if q.Expect == "deny" && (received || succeeded) {
			f.Verdict = "FAIL"
			f.Reason = "forbidden operation succeeded from the measured context"
			if received {
				f.Reason = "independent witness observed forbidden canary delivery"
			}
			if retrieved {
				f.Reason = "external reader retrieved the synthetic registry upload"
			}
			if succeeded {
				f.Evidence = append(f.Evidence, "runner/"+q.ID+"/success")
			}
		} else if !hasResult {
			f.Reason = "required runner result missing"
		} else if q.Expect == "deny" && denied {
			f.Verdict = "PASS"
			f.Reason = "explicit denial corroborates the expected policy"
		} else if q.Expect == "deny" && plan.Policy.MinDenyEvidence == "non-receipt" && (r.Outcome == "error" || r.Outcome == "sent") {
			if ref, ok := referenceReceipt(plan, q, witnessMap, reference, now); ok {
				f.Verdict, f.Grade = "PASS", "non-receipt"
				f.Reason = "reference delivery proved the target live; no canary arrived from the measured context"
				f.Evidence = append(f.Evidence, ref)
			} else {
				f.Reason = "no corroborated denial and no reference delivery to support non-receipt"
			}
		} else if q.Expect == "allow" && (received || succeeded) {
			f.Verdict = "PASS"
			f.Reason = "allowed control operation succeeded"
			if succeeded {
				f.Evidence = append(f.Evidence, "runner/"+q.ID+"/success")
			}
		} else if q.Expect == "allow" && denied {
			f.Reason = "allowed control was denied"
		}
		if q.Optional && f.Verdict == "INCONCLUSIVE" {
			f.Verdict = "SKIP"
			f.Reason = "optional coverage unavailable: " + f.Reason
		}
		report.Findings = append(report.Findings, f)
		if f.Verdict == "FAIL" {
			report.Verdict = "FAIL"
		} else if f.Verdict == "INCONCLUSIVE" && report.Verdict != "FAIL" {
			report.Verdict = "INCONCLUSIVE"
		}
	}
	for _, f := range report.Findings {
		if f.Grade == "non-receipt" {
			report.Limitations = append(report.Limitations, "Non-receipt findings show the target was live from a reference context and no canary arrived from the measured context; they do not identify why delivery failed.")
			break
		}
	}
	if len(report.Errors) > 0 && report.Verdict != "FAIL" {
		report.Verdict = "INCONCLUSIVE"
	}
	return report
}

// referenceReceipt finds a reference delivery for q's exact target, observed
// by the same witness instance that watched the measured run.
func referenceReceipt(plan Plan, q Probe, witnesses map[string]Witness, ref *Reference, now time.Time) (string, bool) {
	if ref == nil || !nonReceiptKind(q.Kind) || ref.Plan.Validate() != nil || ref.Plan.RunID == plan.RunID ||
		ref.Plan.CreatedAt.Before(plan.CreatedAt) || ref.Plan.CreatedAt.After(now.Add(2*time.Second)) {
		return "", false
	}
	same := false
	for _, rq := range ref.Plan.Policy.Probes {
		if rq.ID == q.ID {
			a, b := rq, q
			a.Expect, a.Optional, b.Expect, b.Optional = "", false, "", false
			same = reflect.DeepEqual(a, b)
		}
	}
	if !same {
		return "", false
	}
	payload := Hash([]byte(Canary(ref.Plan, q.ID)))
	for _, cfg := range plan.Policy.Witnesses {
		s, ok := ref.Snapshots[cfg.ID]
		if !ok || s.Overflow || s.Instance == "" || s.Instance != witnesses[cfg.ID].Snapshot.Instance {
			continue
		}
		for i, e := range s.Events {
			if e.Action == "received" && e.RunID == ref.Plan.RunID && e.ProbeID == q.ID && e.Token == ref.Plan.Tokens[q.ID] &&
				e.PayloadSHA256 == payload && eventProtocolMatches(q, e.Protocol) &&
				!e.At.Before(ref.Plan.CreatedAt.Add(-2*time.Second)) && !e.At.After(now.Add(2*time.Second)) {
				return fmt.Sprintf("reference/witnesses/%s/events/%d", cfg.ID, i), true
			}
		}
	}
	return "", false
}

// A hostname-borne canary leaks through resolution, so DNS receipts count.
func eventProtocolMatches(q Probe, protocol string) bool {
	if protocol == "dns" && usesCanaryHost(q) {
		return true
	}
	switch q.Kind {
	case "tcp", "udp":
		return q.Kind == protocol
	case "dns", "dns-system":
		return protocol == "dns"
	case "registry-upload":
		return protocol == "registry"
	default:
		return protocol == "http"
	}
}
