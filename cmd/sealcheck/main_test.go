package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhegde8/sealcheck/internal/seal"
)

// A real subprocess validates the JSON launcher interface and secret scrubbing.
func TestProbeProcess(t *testing.T) {
	if os.Getenv("SEALCHECK_TEST_HELPER") != "1" {
		return
	}
	if os.Getenv("SEALCHECK_TEST_WITNESS_TOKEN") != "" {
		os.Exit(10)
	}
	if delay := os.Getenv("SEALCHECK_TEST_DELAY"); delay != "" {
		d, _ := time.ParseDuration(delay)
		time.Sleep(d)
	}
	var plan seal.Plan
	if err := seal.DecodeJSON(os.Stdin, &plan); err != nil {
		os.Exit(11)
	}
	results, err := seal.RunProbes(context.Background(), plan)
	if err != nil {
		os.Exit(12)
	}
	if err = json.NewEncoder(os.Stdout).Encode(results); err != nil {
		os.Exit(13)
	}
	os.Exit(0)
}

func cliFixture(t *testing.T, switchOnSecond bool) (string, string, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	const token = "cli-test-management-token"
	t.Setenv("SEALCHECK_TEST_WITNESS_TOKEN", token)
	t.Setenv("SEALCHECK_TEST_HELPER", "1")
	r, err := seal.StartReceiver(ctx, seal.ReceiverOptions{HTTP: "127.0.0.1:0", Management: "127.0.0.1:0", TCP: "127.0.0.1:0", UDP: "127.0.0.1:0", DNS: "127.0.0.1:0", Zone: "canary.test", Token: token})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	f, err := seal.NewFixture(r.HTTP, false)
	if err != nil {
		t.Fatal(err)
	}
	var iterations atomic.Int32
	data := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/packages/approved.txt" && switchOnSecond && iterations.Add(1) == 2 {
			f.SetLeaky(true)
		}
		f.ServeHTTP(w, req)
	}))
	t.Cleanup(data.Close)
	mgmt := httptest.NewServer(f.Observer.Management(token))
	t.Cleanup(mgmt.Close)
	p := seal.DemoPolicy(r, &seal.Services{HTTP: data.URL, Management: mgmt.URL}, "SEALCHECK_TEST_WITNESS_TOKEN")
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.json")
	key := filepath.Join(dir, "controller.key.pem")
	if err = seal.WriteJSON(policy, p); err != nil {
		t.Fatal(err)
	}
	if err = seal.GenerateKeyFiles(key, filepath.Join(dir, "controller.pub.pem")); err != nil {
		t.Fatal(err)
	}
	return policy, key, filepath.Join(dir, "reports")
}

func TestWatchDetectsDriftAndExitsFail(t *testing.T) {
	policy, key, out := cliFixture(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code, err := run(ctx, []string{"watch", "--policy", policy, "--private-key", key, "--out", out, "--interval", "2s", "--count", "3", "--", os.Args[0], "-test.run=^TestProbeProcess$"})
	if err != nil || code != 1 {
		t.Fatalf("want FAIL exit, got %d %v", code, err)
	}
	var latest map[string]string
	if err = seal.ReadJSON(filepath.Join(out, "latest.json"), &latest); err != nil {
		t.Fatal(err)
	}
	var diff struct {
		PreviousRunID string              `json:"previous_run_id"`
		RunID         string              `json:"run_id"`
		Changes       []map[string]string `json:"changes"`
	}
	if err = seal.ReadJSON(filepath.Join(out, latest["run_id"], "diff.json"), &diff); err != nil {
		t.Fatal(err)
	}
	if len(diff.Changes) == 0 || diff.PreviousRunID == diff.RunID {
		t.Fatal("missing drift evidence")
	}
	code, err = run(ctx, []string{"verify", "--bundle", filepath.Join(out, latest["run_id"], "bundle.json"), "--public-key", filepath.Join(filepath.Dir(key), "controller.pub.pem"), "--run-id", latest["run_id"], "--policy", policy})
	if err != nil || code != 1 {
		t.Fatalf("verified FAIL must retain failing exit: %d %v", code, err)
	}
}

func TestWatchOverdueDoesNotContinue(t *testing.T) {
	policy, key, out := cliFixture(t, false)
	t.Setenv("SEALCHECK_TEST_DELAY", "1100ms")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code, err := run(ctx, []string{"watch", "--policy", policy, "--private-key", key, "--out", out, "--interval", "1s", "--", os.Args[0], "-test.run=^TestProbeProcess$"})
	if code != 2 || err == nil || !strings.Contains(err.Error(), "overdue") {
		t.Fatalf("overdue watcher should exit 2: %d %v", code, err)
	}
}

func TestCLIRejectsMissingAndUnknownInputs(t *testing.T) {
	for _, args := range [][]string{{"verify"}, {"check"}, {"unknown"}, {"probe", "--wrong"}} {
		if code, err := run(context.Background(), args); code != 2 || err == nil {
			t.Fatalf("accepted bad arguments %v", args)
		}
	}
}
