package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhegde8/sealcheck/internal/seal"
)

const failureTokenEnv = "SEALCHECK_FAILURE_WITNESS_TOKEN"

// Re-execute the race-instrumented test binary as the actual CLI. Only the
// launcher helper injects faults; controller and witness commands use main.
func TestFailureProcess(t *testing.T) {
	if os.Getenv("SEALCHECK_FAILURE_HELPER") != "1" {
		return
	}
	args := flag.Args()
	if len(args) == 0 {
		os.Exit(90)
	}
	if args[0] == "failure-probe" {
		if err := failureProbe(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(91)
		}
		os.Exit(0)
	}
	if args[0] == "deadline-check" {
		duration, err := time.ParseDuration(args[1])
		if err != nil {
			os.Exit(92)
		}
		// Exercise the CLI controller with a caller deadline without waiting
		// for the production plan's 30-second launcher allowance.
		ctx, cancel := context.WithTimeout(context.Background(), duration)
		defer cancel()
		code, err := run(ctx, args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			code = 2
		}
		os.Exit(code)
	}
	os.Args = append([]string{"sealcheck"}, args...)
	main()
}

func failureProbe(args []string) error {
	if len(args) != 2 || os.Getenv(failureTokenEnv) != "" {
		return errors.New("invalid helper arguments or witness credential reached runner")
	}
	mode, gate := args[0], args[1]
	var plan seal.Plan
	if err := seal.DecodeJSON(os.Stdin, &plan); err != nil {
		return err
	}
	if mode == "crash" {
		os.Exit(42)
	}
	if mode == "malformed" {
		_, err := io.WriteString(os.Stdout, "{incomplete runner JSON")
		return err
	}
	if mode == "oversized" {
		_, err := io.WriteString(os.Stdout, strings.Repeat("x", (4<<20)+1))
		return err
	}
	notify := func() error {
		client := &http.Client{Timeout: 10 * time.Second}
		res, err := client.Post(gate, "text/plain", nil)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNoContent {
			return fmt.Errorf("fault gate returned %d", res.StatusCode)
		}
		return nil
	}
	if mode == "gate-before" || mode == "stall" {
		if err := notify(); err != nil {
			return err
		}
	}
	if mode == "stall" {
		time.Sleep(time.Hour) // The controller must terminate this launcher.
	}
	results, err := seal.RunProbes(context.Background(), plan)
	if err != nil {
		return err
	}
	if mode == "flood" {
		// The first real probe recorded one receipt. Exceed the witness's 1,024
		// events per snapshot through its HTTP listener, without forged JSON.
		u, err := url.Parse(plan.Policy.Probes[0].Target)
		if err != nil {
			return err
		}
		q := u.Query()
		q.Set("canary", seal.Canary(plan, plan.Policy.Probes[0].ID))
		u.RawQuery = q.Encode()
		transport := &http.Transport{Proxy: nil}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: time.Second}
		for i := 0; i < 1024; i++ {
			res, err := client.Get(u.String())
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			if res.StatusCode != http.StatusNoContent {
				return fmt.Errorf("receipt flood returned %d", res.StatusCode)
			}
		}
	}
	if mode == "gate-after" || mode == "stall-after" {
		if err := notify(); err != nil {
			return err
		}
	}
	if mode == "stall-after" {
		time.Sleep(time.Hour)
	}
	if mode == "leak-crash" {
		os.Exit(42) // Independent receipts must survive loss of runner JSON.
	}
	return json.NewEncoder(os.Stdout).Encode(results)
}

func failureCommand(ctx context.Context, token string, args ...string) *exec.Cmd {
	command := append([]string{"-test.run=^TestFailureProcess$", "--"}, args...)
	cmd := exec.CommandContext(ctx, os.Args[0], command...)
	cmd.Env = append(os.Environ(), "SEALCHECK_FAILURE_HELPER=1", failureTokenEnv+"="+token,
		"GORACE=atexit_sleep_ms=0")
	return cmd
}

type failureWitness struct {
	services seal.Services
	cmd      *exec.Cmd
	stopped  bool
}

func startFailureWitness(t *testing.T, token, management string) *failureWitness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	cmd := failureCommand(ctx, token, "receiver", "--http", "127.0.0.1:0",
		"--management", management, "--tcp", "127.0.0.1:0", "--udp", "127.0.0.1:0",
		"--dns", "127.0.0.1:0", "--token-env", failureTokenEnv)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	w := &failureWitness{cmd: cmd}
	t.Cleanup(func() { w.stop(); cancel() })
	ready := make(chan error, 1)
	go func() { ready <- json.NewDecoder(stdout).Decode(&w.services) }()
	select {
	case err = <-ready:
	case <-time.After(5 * time.Second):
		err = errors.New("witness did not publish its listener addresses")
		w.stop()
		<-ready
	}
	if err != nil {
		w.stop()
		t.Fatalf("start witness: %v; %s", err, stderr.String())
	}
	return w
}

func (w *failureWitness) stop() {
	if !w.stopped {
		_ = w.cmd.Process.Kill()
		_ = w.cmd.Wait()
		w.stopped = true
	}
}

type failureFixture struct {
	token, controllerToken string
	witness                *failureWitness
	policy                 seal.Policy
	dir                    string
	checkTimeout           time.Duration
}

func newFailureFixture(t *testing.T) *failureFixture {
	t.Helper()
	const token = "failure-test-management-token"
	w := startFailureWitness(t, token, "127.0.0.1:0")
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(control.Close)
	f := &failureFixture{token: token, controllerToken: token, witness: w, dir: t.TempDir()}
	f.policy = seal.Policy{Version: 1, Name: "failure-handling", TimeoutMS: 1000,
		ObservationMS: 10, MaxAgeSeconds: 300,
		Probes: []seal.Probe{{ID: "control", Kind: "http", Target: control.URL, Expect: "allow"}},
		Witnesses: []seal.WitnessConfig{{ID: "receiver", URL: w.services.Management,
			TokenEnv: failureTokenEnv, Role: "receiver"}}}
	if err := seal.GenerateKeyFiles(filepath.Join(f.dir, "controller.key.pem"), filepath.Join(f.dir, "controller.pub.pem")); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *failureFixture) addLeak() {
	f.policy.Probes = append(f.policy.Probes, seal.Probe{ID: "leak", Kind: "http",
		Target: f.witness.services.HTTP + "/error", Expect: "deny"})
}

func (f *failureFixture) check(t *testing.T, mode, verdict string, onGate func(*exec.Cmd)) seal.Report {
	t.Helper()
	policyPath := filepath.Join(f.dir, "policy.json")
	if err := seal.WriteJSON(policyPath, f.policy); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}, 1), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
			w.WriteHeader(http.StatusNoContent)
		case <-req.Context().Done():
		}
	}))
	defer func() { unblock(); gate.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out := filepath.Join(f.dir, "reports")
	args := []string{"check", "--policy", policyPath,
		"--private-key", filepath.Join(f.dir, "controller.key.pem"), "--out", out, "--",
		os.Args[0], "-test.run=^TestFailureProcess$", "--", "failure-probe", mode, gate.URL}
	if f.checkTimeout != 0 {
		args = append([]string{"deadline-check", f.checkTimeout.String()}, args...)
	}
	cmd := failureCommand(ctx, f.controllerToken, args...)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(done) }()
	defer func() { cancel(); <-done }()
	if onGate != nil {
		select {
		case <-entered:
			onGate(cmd)
			unblock()
		case <-done:
			t.Fatalf("controller exited before fault injection: %v; %s", waitErr, output.String())
		case <-ctx.Done():
			t.Fatal("controller never reached the fault gate")
		}
	}
	<-done
	err := waitErr
	if ctx.Err() != nil {
		t.Fatalf("controller did not complete within the test deadline: %s", output.String())
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	if code != seal.ExitCode(verdict) {
		t.Fatalf("want %s exit %d, got %d: %s", verdict, seal.ExitCode(verdict), code, output.String())
	}
	var latest struct {
		RunID     string `json:"run_id"`
		Verdict   string `json:"verdict"`
		Directory string `json:"directory"`
	}
	if err := seal.ReadJSON(filepath.Join(out, "latest.json"), &latest); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(out, latest.RunID)
	var report seal.Report
	if err := seal.ReadJSON(filepath.Join(runDir, "report.json"), &report); err != nil {
		t.Fatal(err)
	}
	if latest.Verdict != verdict || report.Verdict != verdict || latest.Directory != runDir {
		t.Fatalf("exit, report, and latest index disagree: %+v %+v", latest, report)
	}
	// Exercise the actual verifier with pinned policy/key and the controller's
	// run ID. A valid INCONCLUSIVE or FAIL bundle must retain its nonzero exit.
	verify := failureCommand(ctx, f.controllerToken, "verify", "--bundle", filepath.Join(runDir, "bundle.json"),
		"--public-key", filepath.Join(f.dir, "controller.pub.pem"), "--policy", policyPath, "--run-id", latest.RunID)
	verified, err := verify.CombinedOutput()
	verifyCode := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		verifyCode = exit.ExitCode()
	}
	if verifyCode != code || !strings.HasPrefix(string(verified), verdict+" —") {
		t.Fatalf("signed report did not verify with %s exit: %d %s", verdict, verifyCode, verified)
	}
	if bytes.Contains(output.Bytes(), []byte(f.token)) || bytes.Contains(verified, []byte(f.token)) {
		t.Fatal("management credential appeared in CLI output")
	}
	return report
}

func TestCheckFailureHandling(t *testing.T) {
	for _, fault := range []string{"healthy", "witness-offline", "wrong-token", "witness-dies", "witness-restarts",
		"runner-crash", "runner-malformed", "runner-oversized", "probe-timeout", "udp-no-receipt",
		"witness-overflow", "leak-runner-crash", "leak-witness-offline", "interrupted-runner", "leak-interrupted-runner",
		"runner-deadline", "leak-runner-deadline"} {
		t.Run(fault, func(t *testing.T) {
			f := newFailureFixture(t)
			mode, verdict := "normal", "INCONCLUSIVE"
			var onGate func(*exec.Cmd)
			switch fault {
			case "healthy":
				verdict = "PASS"
			case "witness-offline":
				f.witness.stop()
			case "wrong-token":
				f.controllerToken = "incorrect-management-token"
			case "witness-dies", "witness-restarts":
				mode = "gate-before"
				onGate = func(_ *exec.Cmd) {
					f.witness.stop()
					if fault == "witness-restarts" {
						u, err := url.Parse(f.witness.services.Management)
						if err != nil {
							t.Fatal(err)
						}
						startFailureWitness(t, f.token, u.Host)
					}
				}
			case "runner-crash":
				mode = "crash"
			case "runner-malformed":
				mode = "malformed"
			case "runner-oversized":
				mode = "oversized"
			case "probe-timeout":
				f.policy.TimeoutMS = 100
				silent := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
					<-req.Context().Done()
				}))
				t.Cleanup(silent.Close)
				f.policy.Probes = append(f.policy.Probes, seal.Probe{ID: "timeout", Kind: "http", Target: silent.URL, Expect: "deny"})
			case "udp-no-receipt":
				sink, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = sink.Close() })
				f.policy.Probes = append(f.policy.Probes, seal.Probe{ID: "udp", Kind: "udp", Network: "4", Target: sink.LocalAddr().String(), Expect: "deny"})
			case "witness-overflow":
				mode = "flood"
				f.policy.Probes[0].Target = f.witness.services.HTTP + "/canary"
			case "leak-runner-crash":
				mode, verdict = "leak-crash", "FAIL"
				f.addLeak()
			case "leak-witness-offline":
				verdict = "FAIL"
				f.addLeak()
				other := startFailureWitness(t, f.token, "127.0.0.1:0")
				f.policy.Witnesses = append(f.policy.Witnesses, seal.WitnessConfig{ID: "offline", URL: other.services.Management, TokenEnv: failureTokenEnv, Role: "receiver"})
				other.stop()
			case "interrupted-runner", "leak-interrupted-runner":
				mode = "stall"
				if fault == "leak-interrupted-runner" {
					mode, verdict = "gate-after", "FAIL"
					f.addLeak()
				}
				onGate = func(cmd *exec.Cmd) {
					if err := cmd.Process.Signal(os.Interrupt); err != nil {
						t.Fatal(err)
					}
				}
			case "runner-deadline", "leak-runner-deadline":
				f.checkTimeout, mode = 2*time.Second, "stall"
				onGate = func(_ *exec.Cmd) {} // Confirm the runner is live before expiry.
				if fault == "leak-runner-deadline" {
					mode, verdict = "stall-after", "FAIL"
					f.addLeak()
				}
			}
			report := f.check(t, mode, verdict, onGate)
			w := report.Witnesses[0]
			switch fault {
			case "witness-offline", "wrong-token":
				if w.HealthyBefore || w.HealthyAfter || report.Results.Probes[0].Outcome != "success" {
					t.Fatalf("witness failure was not exercised with a successful control: %+v", report)
				}
			case "witness-dies", "witness-restarts":
				if !w.HealthyBefore || w.HealthyAfter || report.Results.Probes[0].Outcome != "success" {
					t.Fatalf("mid-run witness failure was not exercised: %+v", report)
				}
				if fault == "witness-restarts" && w.Error != "witness instance changed during run" {
					t.Fatalf("restart did not invalidate instance continuity: %+v", w)
				}
			case "runner-crash", "runner-malformed", "runner-oversized", "interrupted-runner", "runner-deadline":
				if len(report.Results.Probes) != 0 || !strings.Contains(strings.Join(report.Errors, ";"), "launcher failed") {
					t.Fatalf("failed launcher did not invalidate results: %+v", report)
				}
			case "probe-timeout":
				if r := report.Results.Probes[1]; r.Outcome != "error" || !strings.Contains(r.Detail, "timeout is not evidence of denial") {
					t.Fatalf("timeout was not exercised: %+v", r)
				}
			case "udp-no-receipt":
				if report.Results.Probes[1].Outcome != "sent" || len(w.Snapshot.Events) != 0 {
					t.Fatalf("UDP send without a receipt was not exercised: %+v", report)
				}
			case "witness-overflow":
				if !w.HealthyBefore || w.HealthyAfter || !w.Snapshot.Overflow || report.Results.Probes[0].Outcome != "success" {
					t.Fatalf("real witness overflow was not exercised: %+v", report)
				}
			}
			if strings.Contains(fault, "interrupted-runner") || strings.Contains(fault, "runner-deadline") {
				if !w.HealthyBefore || !w.HealthyAfter || !strings.Contains(strings.Join(report.Errors, ";"), "controller interrupted") {
					t.Fatalf("cancellation lost final witness collection or interruption evidence: %+v", report)
				}
			}
			if strings.HasPrefix(fault, "leak-") {
				if report.Findings[1].Verdict != "FAIL" || !strings.Contains(report.Findings[1].Reason, "independent witness") || len(w.Snapshot.Events) == 0 {
					t.Fatalf("FAIL was not supported by independent receipts: %+v", report)
				}
			}
		})
	}
}
