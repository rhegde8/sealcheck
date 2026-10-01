package seal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type LaunchFunc func(context.Context, Plan) (Results, error)

func fetchSnapshot(ctx context.Context, cfg WitnessConfig, path, run string) (Snapshot, error) {
	var s Snapshot
	token := os.Getenv(cfg.TokenEnv)
	if len(token) < 16 {
		return s, fmt.Errorf("%s requires a management token of at least 16 characters", cfg.ID)
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return s, err
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	q := u.Query()
	q.Set("run_id", run)
	u.RawQuery = q.Encode()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return s, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return s, errors.New("management endpoint unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return s, fmt.Errorf("management endpoint returned %d", res.StatusCode)
	}
	if err = DecodeJSON(res.Body, &s); err != nil {
		return s, errors.New("invalid witness snapshot")
	}
	if s.Instance == "" || s.Overflow {
		return s, errors.New("witness restarted or event storage overflowed")
	}
	return s, nil
}

// Check is the trusted control path. launch must enter the workload's actual
// security context; the local demo's launcher intentionally offers no isolation.
func Check(ctx context.Context, p Policy, key ed25519.PrivateKey, out string, launch LaunchFunc) (Report, error) {
	if err := p.Validate(); err != nil {
		return Report{}, err
	}
	if err := os.MkdirAll(out, 0700); err != nil {
		return Report{}, err
	}
	witnesses := make([]Witness, len(p.Witnesses))
	for i, cfg := range p.Witnesses {
		s, err := fetchSnapshot(ctx, cfg, "/health", "")
		w := Witness{ID: cfg.ID, Role: cfg.Role, Before: time.Now().UTC(), HealthyBefore: err == nil, Snapshot: s}
		if err != nil {
			w.Error = err.Error()
		}
		witnesses[i] = w
	}
	plan, err := NewPlan(p, time.Now())
	if err != nil {
		return Report{}, err
	}
	runDir := filepath.Join(out, plan.RunID)
	if err = os.Mkdir(runDir, 0700); err != nil {
		return Report{}, err
	}
	if err = WriteJSON(filepath.Join(runDir, "plan.json"), plan); err != nil {
		return Report{}, err
	}
	runCtx, cancel := context.WithDeadline(ctx, plan.Deadline)
	defer cancel()
	results, launchErr := launch(runCtx, plan)
	// Complete evidence collection after probe failures. Observed leaks take precedence.
	timer := time.NewTimer(time.Duration(p.ObservationMS) * time.Millisecond)
	select {
	case <-ctx.Done():
		timer.Stop()
	case <-timer.C:
	}
	for i, cfg := range p.Witnesses {
		if cfg.RegistryURL != "" {
			witnesses[i].Readbacks = readRegistry(ctx, cfg.RegistryURL, plan)
		}
		s, err := fetchSnapshot(ctx, cfg, "/events", plan.RunID)
		w := &witnesses[i]
		w.After = time.Now().UTC()
		w.HealthyAfter = err == nil && s.Instance == w.Snapshot.Instance
		if err != nil {
			w.Error = err.Error()
		} else if !w.HealthyAfter {
			w.Error = "witness instance changed during run"
		}
		w.Snapshot = s
	}
	report := Evaluate(plan, results, witnesses, time.Now())
	if launchErr != nil {
		report.Errors = append(report.Errors, "launcher failed or returned invalid output")
		if report.Verdict != "FAIL" {
			report.Verdict = "INCONCLUSIVE"
		}
	}
	if ctx.Err() != nil {
		report.Errors = append(report.Errors, "controller interrupted")
		if report.Verdict != "FAIL" {
			report.Verdict = "INCONCLUSIVE"
		}
	}
	if err = SaveReport(runDir, report, key); err != nil {
		return report, err
	}
	// latest.json is convenience only; verifiers must obtain the run ID independently.
	if err = WriteJSON(filepath.Join(out, "latest.json"), map[string]string{"run_id": plan.RunID, "verdict": report.Verdict, "directory": runDir}); err != nil {
		return report, err
	}
	return report, nil
}

// Readback runs outside the sandbox and checks the exact synthetic bytes.
func readRegistry(ctx context.Context, base string, plan Plan) []Readback {
	readbacks := []Readback{}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	for _, p := range plan.Policy.Probes {
		if p.Kind != "registry-upload" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+"/"+plan.RunID+"/"+p.ID, nil)
		if err != nil {
			continue
		}
		res, err := client.Do(req)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(res.Body, 1025))
		_ = res.Body.Close()
		if err == nil && res.StatusCode == 200 && string(b) == Canary(plan, p.ID) {
			readbacks = append(readbacks, Readback{ProbeID: p.ID, At: time.Now().UTC(), PayloadSHA256: Hash(b)})
		}
	}
	return readbacks
}

func SaveReport(dir string, report Report, key ed25519.PrivateKey) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	bundle, err := Sign(report, key)
	if err != nil {
		return err
	}
	if err = WriteJSON(filepath.Join(dir, "report.json"), report); err != nil {
		return err
	}
	if err = WriteJSON(filepath.Join(dir, "bundle.json"), bundle); err != nil {
		return err
	}
	return WriteAtomic(filepath.Join(dir, "summary.txt"), []byte(Summary(report)), 0600)
}

func Summary(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s — %s\nRun: %s\nPolicy SHA-256: %s\nObserved: %s to %s\nIdentity: uid=%d euid=%d (%s)\n", r.Verdict, r.Plan.Policy.Name, r.Plan.RunID, r.Plan.PolicySHA256, r.Plan.CreatedAt.Format(time.RFC3339), r.IssuedAt.Format(time.RFC3339), r.Results.Identity.UID, r.Results.Identity.EUID, r.Results.Identity.Source)
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  %-12s %-24s %s\n", f.Verdict, f.ID, f.Reason)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "  ERROR: %s\n", e)
	}
	fmt.Fprintln(&b, "Coverage is bounded to this profile and time window. See report.json for evidence and limitations.")
	return b.String()
}

// CommandLauncher passes the plan over stdin, never shell-interpolates it, and
// removes witness credentials from the environment given to the probe process.
func CommandLauncher(command []string, p Policy) LaunchFunc {
	return func(ctx context.Context, plan Plan) (Results, error) {
		var results Results
		if len(command) == 0 {
			return results, errors.New("launcher command required after --")
		}
		cmd := exec.CommandContext(ctx, command[0], command[1:]...)
		b, _ := json.Marshal(plan)
		cmd.Stdin = bytes.NewReader(b)
		secretNames := map[string]bool{}
		for _, w := range p.Witnesses {
			secretNames[w.TokenEnv] = true
		}
		for _, env := range os.Environ() {
			name, _, _ := strings.Cut(env, "=")
			if !secretNames[name] {
				cmd.Env = append(cmd.Env, env)
			}
		}
		var output boundedBuffer
		cmd.Stdout = &output
		cmd.Stderr = io.Discard
		cmd.WaitDelay = 2 * time.Second
		if err := cmd.Run(); err != nil {
			return results, errors.New("probe launcher failed")
		}
		if output.overflow {
			return results, errors.New("probe output exceeded limit")
		}
		if err := DecodeJSON(bytes.NewReader(output.Bytes()), &results); err != nil {
			return Results{}, err
		}
		return results, nil
	}
}

type boundedBuffer struct {
	bytes.Buffer
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len()+n > 4<<20 {
		b.overflow = true
		return n, nil
	}
	_, err := b.Buffer.Write(p)
	return n, err
}
