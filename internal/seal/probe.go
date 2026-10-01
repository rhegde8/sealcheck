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
	"sync"
	"syscall"
	"time"
)

const datagramCopies = 3

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
			if errors.Is(err, errCredentialUnavailable) {
				result.Outcome = "unsupported"
				result.Detail = "credential environment variable unset"
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
		// Repeat datagrams so one lost packet cannot hide a delivery path.
		for i := 1; i < datagramCopies && e == nil; i++ {
			_, e = io.WriteString(c, canary+"\n")
		}
		return "sent", 0, e // UDP send success alone does not establish delivery.
	case "dns", "dns-system":
		name := "sc1." + plan.RunID + "." + q.ID + "." + plan.Tokens[q.ID] + "." + strings.TrimSuffix(q.Zone, ".") + "."
		if q.Kind == "dns-system" {
			// Go normally strips syscall errors when creating DNSError. Track
			// dial failures without classifying text like "permission denied".
			var mu sync.Mutex
			attempts, denials := 0, 0
			originalDial := net.DefaultResolver.Dial
			resolver := &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var c net.Conn
				var err error
				if originalDial != nil {
					c, err = originalDial(ctx, network, address)
				} else {
					c, err = (&net.Dialer{}).DialContext(ctx, network, address)
				}
				mu.Lock()
				attempts++
				if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
					denials++
				}
				mu.Unlock()
				return c, err
			}}
			_, e := resolver.LookupHost(ctx, name)
			mu.Lock()
			allDenied := attempts > 0 && attempts == denials
			mu.Unlock()
			if e != nil && allDenied {
				return "denied", 0, syscall.EACCES
			}
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
		for i := 0; i < datagramCopies && e == nil; i++ {
			_, e = c.Write(packet)
		}
		if e != nil {
			return "error", 0, e
		}
		buf := make([]byte, 512)
		_, e = c.Read(buf)
		return "sent", 0, e // A DNS answer is not proof that the authoritative receiver saw the query.
	case "http", "http-proxy", "proxy-fetch", "registry-upload":
		return httpProbe(ctx, plan, q, canary)
	default:
		return "unsupported", 0, fmt.Errorf("unsupported kind")
	}
}

func httpProbe(ctx context.Context, plan Plan, q Probe, canary string) (string, int, error) {
	rawTarget, callback, e := probeURLs(q, plan.RunID, plan.Tokens[q.ID])
	if e != nil {
		return "error", 0, e
	}
	target, e := url.Parse(rawTarget)
	if e != nil {
		return "error", 0, e
	}
	method := http.MethodGet
	var body io.Reader
	switch {
	case fetchTemplate(q):
		// The policy placed {callback} where the handler reads its upstream.
		if q.Method != "" {
			method = q.Method
		}
	case q.Kind == "proxy-fetch":
		params := target.Query()
		params.Set("url", callback)
		params.Set("canary", canary)
		target.RawQuery = params.Encode()
	case q.Kind == "registry-upload":
		method = http.MethodPut
		body = strings.NewReader(canary)
		target.Path = strings.TrimSuffix(target.Path, "/") + "/" + plan.RunID + "/" + q.ID
	default:
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
	headers, e := headerValues(q, canary, callback)
	if e != nil {
		return "error", 0, e
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if q.CredentialEnv != "" {
		value := os.Getenv(q.CredentialEnv)
		if value == "" {
			return "unsupported", 0, errCredentialUnavailable
		}
		name := credentialHeader(q)
		if q.Kind == "http-proxy" && strings.EqualFold(name, "Proxy-Authorization") && target.Scheme == "https" {
			// Only the CONNECT request may carry proxy credentials; request
			// headers travel inside the tunnel to the origin.
			transport.ProxyConnectHeader = http.Header{name: {value}}
		} else {
			req.Header.Set(name, value)
		}
	}
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
}
