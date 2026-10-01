package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rhegde8/sealcheck/internal/seal"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code, err := run(ctx, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "sealcheck:", err)
		code = 2
	}
	os.Exit(code)
}

const usage = `Sealcheck — evidence-based egress verification

Commands:
  keygen    Create an external Ed25519 signing identity
  receiver  Serve controlled TCP/UDP/DNS/HTTP canary receivers
  fixture   Serve a controlled package proxy fixture
  plan      Create a run-bound probe plan
  probe     Run a plan inside the workload's security context
  check     Launch probes, collect independent evidence, and sign a report
  evaluate  Evaluate collected plan/results/witness JSON and sign a report
  verify    Verify a pinned signing key, run, policy, and freshness
  watch     Schedule checks and stop on failure or incomplete evidence
  demo      Run the portable fixture pass -> leak -> fix demonstration
  version   Print version

Use <command> -h for flags. Evaluation exits: 0 PASS, 1 FAIL, 2 INCONCLUSIVE/error.
`

func flags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	return f
}
func parse(f *flag.FlagSet, args []string) error { return f.Parse(args) }
func required(values ...string) error {
	for _, v := range values {
		if v == "" {
			return errors.New("missing required flag; use -h for usage")
		}
	}
	return nil
}
func loadPolicy(path string) (seal.Policy, error) {
	var p seal.Policy
	if e := seal.ReadJSON(path, &p); e != nil {
		return p, e
	}
	return p, p.Validate()
}

func run(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		fmt.Print(usage)
		return 0, nil
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(usage)
		return 0, nil
	case "version":
		fmt.Println(seal.ToolVersion)
		return 0, nil
	case "keygen":
		f := flags("keygen")
		private := f.String("private-key", "", "required private PEM output (never put in sandbox)")
		public := f.String("public-key", "", "required public PEM output")
		if e := parse(f, args[1:]); e != nil {
			return flagResult(e)
		}
		if e := required(*private, *public); e != nil {
			return 2, e
		}
		return 0, seal.GenerateKeyFiles(*private, *public)
	case "plan":
		f := flags("plan")
		policy := f.String("policy", "", "required policy JSON")
		out := f.String("out", "", "required plan JSON output")
		if e := parse(f, args[1:]); e != nil {
			return flagResult(e)
		}
		if e := required(*policy, *out); e != nil {
			return 2, e
		}
		p, e := loadPolicy(*policy)
		if e != nil {
			return 2, e
		}
		plan, e := seal.NewPlan(p, time.Now())
		if e != nil {
			return 2, e
		}
		if e = seal.WriteJSON(*out, plan); e != nil {
			return 2, e
		}
		fmt.Println(plan.RunID)
		return 0, nil
	case "probe":
		return probeCommand(ctx, args[1:])
	case "check", "watch":
		return checkCommand(ctx, args[0], args[1:])
	case "evaluate":
		return evaluateCommand(args[1:])
	case "verify":
		return verifyCommand(args[1:])
	case "receiver", "fixture":
		return serveCommand(ctx, args[0], args[1:])
	case "demo":
		f := flags("demo")
		out := f.String("out", "out/demo", "output directory")
		if e := parse(f, args[1:]); e != nil {
			return flagResult(e)
		}
		fmt.Println("Portable fixture demonstration. Transport controls are allowed; this does not attest OS sandbox isolation.")
		reports, e := seal.Demo(ctx, *out)
		for _, r := range reports {
			fmt.Print(seal.Summary(r))
		}
		if e != nil {
			return 2, e
		}
		fmt.Println("Evidence and public verification key:", *out)
		return 0, nil
	default:
		return 2, fmt.Errorf("unknown command %q", args[0])
	}
}

func flagResult(err error) (int, error) {
	if errors.Is(err, flag.ErrHelp) {
		return 0, nil
	}
	return 2, err
}

func probeCommand(ctx context.Context, args []string) (int, error) {
	f := flags("probe")
	planPath := f.String("plan", "-", "plan JSON or - for stdin")
	out := f.String("out", "-", "results JSON or - for stdout")
	if e := parse(f, args); e != nil {
		return flagResult(e)
	}
	var plan seal.Plan
	var e error
	if *planPath == "-" {
		e = seal.DecodeJSON(os.Stdin, &plan)
	} else {
		e = seal.ReadJSON(*planPath, &plan)
	}
	if e != nil {
		return 2, e
	}
	results, e := seal.RunProbes(ctx, plan)
	if e != nil {
		return 2, e
	}
	if *out == "-" {
		e = json.NewEncoder(os.Stdout).Encode(results)
	} else {
		e = seal.WriteJSON(*out, results)
	}
	// The runner never issues a verdict; the external controller owns evaluation.
	return 0, e
}

func checkCommand(ctx context.Context, name string, args []string) (int, error) {
	f := flags(name)
	policy := f.String("policy", "", "required policy JSON")
	private := f.String("private-key", "", "required external private PEM")
	out := f.String("out", "out/checks", "report directory")
	interval := f.Duration("interval", 5*time.Minute, "watch interval, measured between start times")
	count := f.Int("count", 0, "watch check limit; 0 runs until interrupted")
	if e := parse(f, args); e != nil {
		return flagResult(e)
	}
	if e := required(*policy, *private); e != nil {
		return 2, e
	}
	if len(f.Args()) == 0 {
		return 2, errors.New("provide launcher after --, for example -- docker exec -i -u 10001 sandbox sealcheck probe")
	}
	if *interval < time.Second || *count < 0 {
		return 2, errors.New("invalid interval or count")
	}
	p, e := loadPolicy(*policy)
	if e != nil {
		return 2, e
	}
	key, e := seal.ReadPrivateKey(*private)
	if e != nil {
		return 2, e
	}
	launch := seal.CommandLauncher(f.Args(), p)
	var previous *seal.Report
	for n := 0; ; n++ {
		start := time.Now()
		r, e := seal.Check(ctx, p, key, *out, launch)
		if e != nil {
			return 2, e
		}
		fmt.Print(seal.Summary(r))
		if previous != nil {
			diff := reportDiff(*previous, r)
			if e = seal.WriteJSON(filepath.Join(*out, r.Plan.RunID, "diff.json"), diff); e != nil {
				return 2, e
			}
		}
		if name == "check" || r.Verdict != "PASS" || (*count > 0 && n+1 >= *count) {
			return seal.ExitCode(r.Verdict), nil
		}
		previous = &r
		remaining := time.Until(start.Add(*interval))
		if remaining <= 0 {
			return 2, errors.New("periodic check overdue; interval shorter than completed check")
		}
		if e = seal.WriteJSON(filepath.Join(*out, "schedule.json"), map[string]any{"last_run_id": r.Plan.RunID, "next_due_at": start.Add(*interval).UTC(), "interval_seconds": interval.Seconds()}); e != nil {
			return 2, e
		}
		timer := time.NewTimer(remaining)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 2, errors.New("periodic checking interrupted; no continuing coverage")
		case <-timer.C:
		}
	}
}

func reportDiff(before, after seal.Report) map[string]any {
	old := map[string]string{}
	for _, f := range before.Findings {
		old[f.ID] = f.Verdict
	}
	changes := []map[string]string{}
	for _, f := range after.Findings {
		if old[f.ID] != f.Verdict {
			changes = append(changes, map[string]string{"probe_id": f.ID, "before": old[f.ID], "after": f.Verdict})
		}
	}
	return map[string]any{"previous_run_id": before.Plan.RunID, "run_id": after.Plan.RunID, "changes": changes}
}

func evaluateCommand(args []string) (int, error) {
	f := flags("evaluate")
	planPath := f.String("plan", "", "required plan JSON")
	resultsPath := f.String("results", "", "required runner results JSON")
	witnessPath := f.String("witnesses", "", "required controller-collected witness array JSON")
	private := f.String("private-key", "", "required external private PEM")
	out := f.String("out", "out/evaluation", "output directory")
	if e := parse(f, args); e != nil {
		return flagResult(e)
	}
	if e := required(*planPath, *resultsPath, *witnessPath, *private); e != nil {
		return 2, e
	}
	var plan seal.Plan
	var results seal.Results
	var witnesses []seal.Witness
	if e := seal.ReadJSON(*planPath, &plan); e != nil {
		return 2, e
	}
	if e := seal.ReadJSON(*resultsPath, &results); e != nil {
		return 2, e
	}
	if e := seal.ReadJSON(*witnessPath, &witnesses); e != nil {
		return 2, e
	}
	key, e := seal.ReadPrivateKey(*private)
	if e != nil {
		return 2, e
	}
	r := seal.Evaluate(plan, results, witnesses, time.Now())
	if e = seal.SaveReport(*out, r, key); e != nil {
		return 2, e
	}
	fmt.Print(seal.Summary(r))
	return seal.ExitCode(r.Verdict), nil
}

func verifyCommand(args []string) (int, error) {
	f := flags("verify")
	bundlePath := f.String("bundle", "", "required signed bundle JSON")
	public := f.String("public-key", "", "required independently trusted public PEM")
	runID := f.String("run-id", "", "expected run ID from controller")
	policy := f.String("policy", "", "expected policy JSON")
	age := f.Duration("max-age", 5*time.Minute, "maximum run age")
	historical := f.Bool("historical", false, "verify archived signature and consistency; does not authorize an evaluation")
	if e := parse(f, args); e != nil {
		return flagResult(e)
	}
	if e := required(*bundlePath, *public); e != nil {
		return 2, e
	}
	if !*historical {
		if e := required(*runID, *policy); e != nil {
			return 2, e
		}
	}
	var bundle seal.Bundle
	if e := seal.ReadJSON(*bundlePath, &bundle); e != nil {
		return 2, e
	}
	key, e := seal.ReadPublicKey(*public)
	if e != nil {
		return 2, e
	}
	hash := ""
	if *policy != "" {
		p, e := loadPolicy(*policy)
		if e != nil {
			return 2, e
		}
		hash = seal.PolicyHash(p)
	}
	r, e := seal.Verify(bundle, key, seal.VerifyOptions{RunID: *runID, PolicySHA256: hash, Now: time.Now(), MaxAge: *age, Historical: *historical})
	if e != nil {
		return 2, e
	}
	if *historical {
		fmt.Printf("VALID HISTORICAL SIGNATURE — recorded verdict %s; no current freshness or run authorization\n", r.Verdict)
		return 0, nil
	}
	fmt.Print(seal.Summary(r))
	return seal.ExitCode(r.Verdict), nil
}

func serveCommand(ctx context.Context, name string, args []string) (int, error) {
	f := flags(name)
	listen := f.String("http", "127.0.0.1:8080", "HTTP data listener")
	management := f.String("management", "127.0.0.1:8081", "management listener; keep outside sandbox reach")
	tokenEnv := f.String("token-env", "SEALCHECK_WITNESS_TOKEN", "management token environment variable")
	tcp := f.String("tcp", "127.0.0.1:9000", "TCP receiver")
	udp := f.String("udp", "127.0.0.1:9001", "UDP receiver")
	dns := f.String("dns", "127.0.0.1:5353", "authoritative DNS receiver")
	zone := f.String("zone", "canary.test", "controlled DNS zone")
	upstream := f.String("upstream", "", "fixture's required controlled receiver origin")
	leaky := f.Bool("leaky", false, "enable deliberately leaky fixture behavior")
	resolver := f.String("resolver", "", "fixture's DNS server for names it resolves when leaky")
	authEnv := f.String("auth-token-env", "", "environment variable holding a bearer token fixture routes require")
	if e := parse(f, args); e != nil {
		return flagResult(e)
	}
	var s *seal.Services
	var e error
	if name == "receiver" {
		s, e = seal.StartReceiver(ctx, seal.ReceiverOptions{HTTP: *listen, Management: *management, TCP: *tcp, UDP: *udp, DNS: *dns, Zone: *zone, Token: os.Getenv(*tokenEnv)})
	} else {
		var fixture *seal.Fixture
		fixture, e = seal.NewFixture(*upstream, *leaky)
		if e == nil && *resolver != "" {
			fixture.Resolver = seal.UDPResolver(*resolver)
		}
		if e == nil && *authEnv != "" {
			if fixture.AuthToken = os.Getenv(*authEnv); fixture.AuthToken == "" {
				e = errors.New("fixture auth token variable is empty")
			}
		}
		if e == nil {
			s, e = seal.StartFixture(ctx, fixture, *listen, *management, os.Getenv(*tokenEnv))
		}
	}
	if e != nil {
		return 2, e
	}
	defer s.Close()
	if e = json.NewEncoder(os.Stdout).Encode(s); e != nil {
		return 2, e
	}
	return 0, s.Wait(ctx)
}
