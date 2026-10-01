package seal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// DemoPolicy explicitly allows transport controls. This demo verifies fixture
// behavior, not operating-system isolation; the Linux lab uses a deny profile.
func DemoPolicy(receiver, proxy *Services, tokenEnv string) Policy {
	p := Policy{Version: 1, Name: "portable-proxy-fixture-demo", TimeoutMS: 500, ObservationMS: 100, MaxAgeSeconds: 300,
		Witnesses: []WitnessConfig{{ID: "receiver", URL: receiver.Management, TokenEnv: tokenEnv, Role: "receiver", RegistryURL: receiver.HTTP + "/registry"}, {ID: "proxy", URL: proxy.Management, TokenEnv: tokenEnv, Role: "boundary"}},
		Probes: []Probe{
			{ID: "tcp-control", Kind: "tcp", Target: receiver.TCP, Expect: "allow", Network: "4"},
			{ID: "udp-control", Kind: "udp", Target: receiver.UDP, Expect: "allow", Network: "4"},
			{ID: "dns-control", Kind: "dns", Target: receiver.DNS, Zone: "canary.test", Expect: "allow"},
			{ID: "allowed-package", Kind: "http", Target: proxy.HTTP + "/packages/approved.txt", Expect: "allow"},
			{ID: "forward-proxy", Kind: "http-proxy", Target: receiver.HTTP + "/canary", Proxy: proxy.HTTP, Expect: "deny"},
			{ID: "terraform-fixture", Kind: "proxy-fetch", Target: proxy.HTTP + "/fixtures/terraform/module", Callback: receiver.HTTP + "/canary", Expect: "deny"},
			{ID: "cargo-fixture", Kind: "proxy-fetch", Target: proxy.HTTP + "/fixtures/cargo/download", Callback: receiver.HTTP + "/canary", Expect: "deny"},
			{ID: "ansible-fixture", Kind: "proxy-fetch", Target: proxy.HTTP + "/fixtures/ansible/archive", Callback: receiver.HTTP + "/canary", Expect: "deny"},
			{ID: "redirect-fixture", Kind: "proxy-fetch", Target: proxy.HTTP + "/fixtures/terraform/module", Callback: receiver.HTTP + "/redirect", Expect: "deny"},
			{ID: "error-after-forward", Kind: "proxy-fetch", Target: proxy.HTTP + "/fixtures/cargo/download", Callback: receiver.HTTP + "/error", Expect: "deny"},
			{ID: "registry-upload", Kind: "registry-upload", Target: proxy.HTTP + "/registry", Expect: "deny"},
			{ID: "proxy-dns-forward", Kind: "http-proxy", Target: "http://{canary_host}/canary", Proxy: proxy.HTTP, Zone: "canary.test", Expect: "deny"},
			{ID: "proxy-dns-callback", Kind: "proxy-fetch", Target: proxy.HTTP + "/fixtures/terraform/module", Callback: "http://{canary_host}/canary", Zone: "canary.test", Expect: "deny"},
		}}
	return p
}

func Demo(ctx context.Context, out string) ([]Report, error) {
	if err := os.MkdirAll(out, 0700); err != nil {
		return nil, err
	}
	privatePath := filepath.Join(out, "demo.key.pem")
	publicPath := filepath.Join(out, "demo.pub.pem")
	if _, err := os.Stat(privatePath); os.IsNotExist(err) {
		if err = GenerateKeyFiles(privatePath, publicPath); err != nil {
			return nil, err
		}
	}
	key, err := ReadPrivateKey(privatePath)
	if err != nil {
		return nil, err
	}
	token := RandomID()
	envName := "SEALCHECK_DEMO_" + RandomID()
	_ = os.Setenv(envName, token)
	defer os.Unsetenv(envName)
	r, err := StartReceiver(ctx, ReceiverOptions{HTTP: "127.0.0.1:0", Management: "127.0.0.1:0", TCP: "127.0.0.1:0", UDP: "127.0.0.1:0", DNS: "127.0.0.1:0", Zone: "canary.test", Token: token})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	f, err := NewFixture(r.HTTP, false)
	if err != nil {
		return nil, err
	}
	f.Resolver = UDPResolver(r.DNS)
	proxy, err := StartFixture(ctx, f, "127.0.0.1:0", "127.0.0.1:0", token)
	if err != nil {
		return nil, err
	}
	defer proxy.Close()
	p := DemoPolicy(r, proxy, envName)
	if err = WriteJSON(filepath.Join(out, "policy.json"), p); err != nil {
		return nil, err
	}
	reports := []Report{}
	for _, phase := range []struct {
		name  string
		leaky bool
		want  string
	}{{"baseline", false, "PASS"}, {"leaky", true, "FAIL"}, {"remediated", false, "PASS"}} {
		f.SetLeaky(phase.leaky)
		// This in-process launcher is for a fixture demonstration only.
		report, err := Check(ctx, p, key, filepath.Join(out, phase.name), RunProbes, nil)
		if err != nil {
			return reports, err
		}
		reports = append(reports, report)
		if report.Verdict != phase.want {
			return reports, fmt.Errorf("demo %s: expected %s, got %s", phase.name, phase.want, report.Verdict)
		}
	}
	index := map[string]string{"baseline": reports[0].Plan.RunID, "leaky": reports[1].Plan.RunID, "remediated": reports[2].Plan.RunID}
	return reports, WriteJSON(filepath.Join(out, "demo.json"), index)
}
