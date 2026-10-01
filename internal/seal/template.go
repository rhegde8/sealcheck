package seal

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Placeholders let a policy describe where a proxy handler takes its upstream
// URL without the repository shipping vendor-specific request shapes.
const (
	phCanary     = "{canary}"
	phCallback   = "{callback}"
	phCanaryHost = "{canary_host}"
)

var (
	placeholder = regexp.MustCompile(`\{[^{}]*\}`)
	headerName  = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	envName     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	dummyHex    = strings.Repeat("0", 32)
)

var errCredentialUnavailable = errors.New("credential environment variable unset")

// expandTemplate substitutes the placeholders present in vars. Any other
// placeholder or stray brace is an error.
func expandTemplate(s string, vars map[string]string) (string, error) {
	var err error
	out := placeholder.ReplaceAllStringFunc(s, func(m string) string {
		v, ok := vars[m]
		if !ok && err == nil {
			err = fmt.Errorf("unsupported placeholder %s", m)
		}
		return v
	})
	if err == nil && strings.ContainsAny(out, "{}") {
		err = errors.New("unbalanced placeholder brace")
	}
	return out, err
}

func isTemplate(s string) bool { return strings.ContainsAny(s, "{}") }

// fetchTemplate reports whether a proxy-fetch probe places its callback
// itself, in the target or a header, instead of the legacy url= parameter.
func fetchTemplate(q Probe) bool {
	if q.Kind != "proxy-fetch" {
		return false
	}
	return isTemplate(q.Target) || headersContain(q, phCallback)
}

func usesCanaryHost(q Probe) bool {
	return strings.Contains(q.Target, phCanaryHost) || strings.Contains(q.Callback, phCanaryHost)
}

func canaryHost(run, id, token, zone string) string {
	return "sc1." + run + "." + id + "." + token + "." + strings.TrimSuffix(zone, ".")
}

// probeURLs expands a probe's target and callback for one run. The callback
// always carries the canary as a query parameter so receivers can record it.
func probeURLs(q Probe, run, token string) (target, callback string, err error) {
	vars := map[string]string{phCanary: "sc1:" + run + ":" + q.ID + ":" + token}
	if q.Zone != "" {
		vars[phCanaryHost] = canaryHost(run, q.ID, token, q.Zone)
	}
	if q.Kind == "proxy-fetch" {
		raw, err := expandTemplate(q.Callback, map[string]string{phCanaryHost: vars[phCanaryHost]})
		if err != nil {
			return "", "", err
		}
		u, err := url.Parse(raw)
		if err != nil {
			return "", "", err
		}
		params := u.Query()
		params.Set("canary", vars[phCanary])
		u.RawQuery = params.Encode()
		callback = u.String()
		vars[phCallback] = url.QueryEscape(callback)
	}
	allowed := map[string]string{}
	switch {
	case q.Kind == "proxy-fetch":
		allowed[phCallback], allowed[phCanary] = vars[phCallback], vars[phCanary]
	case q.Kind == "http" || q.Kind == "http-proxy":
		if v, ok := vars[phCanaryHost]; ok {
			allowed[phCanaryHost] = v
		}
	}
	target, err = expandTemplate(q.Target, allowed)
	return target, callback, err
}

// headerValues expands header templates; only proxy-fetch has a callback.
func headerValues(q Probe, canary, callback string) (map[string]string, error) {
	vars := map[string]string{phCanary: canary}
	if q.Kind == "proxy-fetch" {
		vars[phCallback] = url.QueryEscape(callback)
	}
	out := map[string]string{}
	for k, v := range q.Headers {
		expanded, err := expandTemplate(v, vars)
		if err != nil {
			return nil, err
		}
		out[k] = expanded
	}
	return out, nil
}

func credentialHeader(q Probe) string {
	if q.CredentialHeader != "" {
		return q.CredentialHeader
	}
	if q.Kind == "http-proxy" {
		return "Proxy-Authorization"
	}
	return "Authorization"
}

// Framing and connection headers would let a policy desynchronize requests;
// credentials belong in credential_env, never in a signed policy.
func forbiddenHeader(name string, credential bool) bool {
	n := strings.ToLower(name)
	switch n {
	case "host", "content-length", "transfer-encoding", "connection", "te", "upgrade", "trailer", "keep-alive":
		return true
	case "authorization", "cookie", "proxy-authorization":
		return !credential
	}
	return !credential && strings.HasPrefix(n, "proxy-")
}

// validateHTTPTemplates checks the template-related probe fields with
// placeholder values standing in for the run's identifiers.
func validateHTTPTemplates(q Probe, tokenEnvs map[string]bool) error {
	if usesCanaryHost(q) && !validZone(q.Zone) {
		return errors.New("{canary_host} requires a valid zone")
	}
	if q.Kind == "registry-upload" && isTemplate(q.Target) {
		return errors.New("registry-upload targets do not take placeholders")
	}
	if q.Kind != "proxy-fetch" && isTemplate(q.Callback) {
		return errors.New("callback placeholders require proxy-fetch")
	}
	template := fetchTemplate(q)
	if template && !strings.Contains(q.Target, phCallback) && !headersContain(q, phCallback) {
		return errors.New("templated proxy-fetch must place {callback} in the target or a header")
	}
	if q.Method != "" {
		if !template {
			return errors.New("method requires a templated proxy-fetch")
		}
		switch q.Method {
		case "GET", "HEAD", "POST", "PUT":
		default:
			return errors.New("method must be GET, HEAD, POST, or PUT")
		}
	}
	target, callback, err := probeURLs(q, dummyHex, dummyHex)
	if err != nil {
		return err
	}
	dummyHost := canaryHost(dummyHex, q.ID, dummyHex, q.Zone)
	for _, c := range []struct{ raw, expanded string }{{q.Target, target}, {q.Callback, callback}} {
		if c.raw == "" {
			continue
		}
		if !httpURL(c.expanded) {
			return errors.New("URL must be HTTP(S) without credentials after placeholder expansion")
		}
		if strings.Contains(c.raw, phCanaryHost) {
			u, _ := url.Parse(c.expanded)
			if u.Hostname() != dummyHost || strings.Count(c.raw, phCanaryHost) != 1 {
				return errors.New("{canary_host} must be the whole URL host")
			}
		}
	}
	if len(q.Headers) > 16 {
		return errors.New("at most 16 headers")
	}
	for k, v := range q.Headers {
		if !headerName.MatchString(k) || forbiddenHeader(k, false) || strings.EqualFold(k, credentialHeader(q)) && q.CredentialEnv != "" {
			return fmt.Errorf("header %q is not allowed", k)
		}
		if len(v) > 1024 || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("header %q has an invalid value", k)
		}
	}
	if _, err := headerValues(q, "sc1:"+dummyHex+":"+q.ID+":"+dummyHex, callback); err != nil {
		return err
	}
	if q.CredentialHeader != "" && q.CredentialEnv == "" {
		return errors.New("credential_header requires credential_env")
	}
	if q.CredentialEnv != "" {
		if !envName.MatchString(q.CredentialEnv) || tokenEnvs[q.CredentialEnv] {
			return errors.New("credential_env must name a workload variable, never a witness token")
		}
		if h := credentialHeader(q); !headerName.MatchString(h) || forbiddenHeader(h, true) {
			return fmt.Errorf("credential header %q is not allowed", h)
		}
	}
	return nil
}

func headersContain(q Probe, ph string) bool {
	for _, v := range q.Headers {
		if strings.Contains(v, ph) {
			return true
		}
	}
	return false
}
