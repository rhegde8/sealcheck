package seal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

func CurrentIdentity() Identity {
	host, _ := os.Hostname()
	i := Identity{UID: os.Getuid(), EUID: os.Geteuid(), GID: os.Getgid(), Hostname: host, Source: "runner-reported", Namespaces: map[string]string{}, ProcessStatus: map[string]string{}}
	for _, n := range []string{"net", "user", "mnt", "pid"} {
		if v, e := os.Readlink("/proc/self/ns/" + n); e == nil {
			i.Namespaces[n] = v
		}
	}
	if b, e := os.ReadFile("/proc/self/status"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if ok && (k == "CapEff" || k == "NoNewPrivs" || k == "Seccomp") {
				i.ProcessStatus[k] = strings.TrimSpace(v)
			}
		}
	}
	return i
}

func RunProbes(ctx context.Context, plan Plan) (Results, error) {
	if e := plan.Validate(); e != nil {
		return Results{}, e
	}
	if time.Now().After(plan.Deadline) || plan.CreatedAt.After(time.Now().Add(30*time.Second)) {
		return Results{}, errors.New("plan is expired or from the future")
	}
	ctx, cancel := context.WithDeadline(ctx, plan.Deadline)
	defer cancel()
	r := Results{Version: Version, RunID: plan.RunID, PolicySHA256: plan.PolicySHA256, Identity: CurrentIdentity(), Probes: []Result{}}
	for _, q := range plan.Policy.Probes {
		start := time.Now().UTC()
		probeCtx, stop := context.WithTimeout(ctx, time.Duration(plan.Policy.TimeoutMS)*time.Millisecond)
		outcome, status, err := runProbe(probeCtx, plan, q)
		stop()
		result := Result{ID: q.ID, StartedAt: start, FinishedAt: time.Now().UTC(), Outcome: outcome, HTTPStatus: status}
		if err != nil {
			// Do not serialize error strings: HTTP errors can contain credentials or URLs.
			result.Outcome = "error"
			result.Detail = "operation failed; no denial established"
			if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
				result.Outcome = "denied"
				result.Detail = "kernel returned EACCES or EPERM"
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
				result.Detail = "deadline exceeded; a timeout is not evidence of denial"
			}
		}
		r.Probes = append(r.Probes, result)
	}
	return r, nil
}

func runProbe(ctx context.Context, plan Plan, q Probe) (string, int, error) {
	canary := Canary(plan, q.ID)
	switch q.Kind {
	case "tcp", "udp":
		network := q.Kind + q.Network
		c, e := (&net.Dialer{}).DialContext(ctx, network, q.Target)
		if e != nil {
			return "error", 0, e
		}
		defer c.Close()
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(deadline)
		}
		_, e = io.WriteString(c, canary+"\n")
		// A successful TCP handshake already demonstrates reachability even if the write fails.
		if q.Kind == "tcp" {
			return "success", 0, nil
		}
		return "sent", 0, e // UDP send success alone does not establish delivery.
	case "dns", "dns-system":
		name := "sc1." + plan.RunID + "." + q.ID + "." + plan.Tokens[q.ID] + "." + strings.TrimSuffix(q.Zone, ".") + "."
		if q.Kind == "dns-system" {
			_, e := net.DefaultResolver.LookupHost(ctx, name)
			return "sent", 0, e
		}
		packet, e := dnsQuestion(name)
		if e != nil {
			return "error", 0, e
		}
		c, e := (&net.Dialer{}).DialContext(ctx, "udp"+q.Network, q.Target)
		if e != nil {
			return "error", 0, e
		}
		defer c.Close()
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(deadline)
		}
		_, e = c.Write(packet)
		if e != nil {
			return "error", 0, e
		}
		buf := make([]byte, 512)
		_, e = c.Read(buf)
		return "sent", 0, e // A DNS answer is not proof that the authoritative receiver saw the query.
	case "http", "http-proxy", "proxy-fetch", "registry-upload":
		target, e := url.Parse(q.Target)
		if e != nil {
			return "error", 0, e
		}
		method := http.MethodGet
		var body io.Reader
		if q.Kind == "proxy-fetch" {
			callback, _ := url.Parse(q.Callback)
			params := callback.Query()
			params.Set("canary", canary)
			callback.RawQuery = params.Encode()
			params = target.Query()
			params.Set("url", callback.String())
			params.Set("canary", canary)
			target.RawQuery = params.Encode()
		} else if q.Kind == "registry-upload" {
			method = http.MethodPut
			body = strings.NewReader(canary)
			target.Path = strings.TrimSuffix(target.Path, "/") + "/" + plan.RunID + "/" + q.ID
		} else {
			params := target.Query()
			params.Set("canary", canary)
			target.RawQuery = params.Encode()
		}
		transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{}).DialContext, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		if q.Kind == "http-proxy" {
			proxy, _ := url.Parse(q.Proxy)
			transport.Proxy = http.ProxyURL(proxy)
		}
		client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		req, e := http.NewRequestWithContext(ctx, method, target.String(), body)
		if e != nil {
			return "error", 0, e
		}
		req.Header.Set("User-Agent", "sealcheck/0.1")
		res, e := client.Do(req)
		if e != nil {
			return "error", 0, e
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return "success", res.StatusCode, nil
		}
		// A 403/500 can occur after forwarding; only independent evidence establishes denial.
		return "error", res.StatusCode, nil
	default:
		return "unsupported", 0, fmt.Errorf("unsupported kind")
	}
}
