package seal

import (
	"strings"
	"testing"
)

func TestExpandTemplate(t *testing.T) {
	vars := map[string]string{phCanary: "sc1:a:b:c"}
	if got, err := expandTemplate("/x/{canary}/y", vars); err != nil || got != "/x/sc1:a:b:c/y" {
		t.Fatalf("got %q %v", got, err)
	}
	for _, bad := range []string{"/{callback}", "/{", "/}", "/{canary"} {
		if _, err := expandTemplate(bad, vars); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestTemplatedProbeValidation(t *testing.T) {
	base := func() Policy {
		p, _, _, _ := evidence(t, "http", "deny", "error")
		return p.Policy
	}
	valid := map[string]Probe{
		"hostname canary through proxy": {Kind: "http-proxy", Target: "http://{canary_host}/x", Proxy: "http://127.0.0.1:1", Zone: "canary.test"},
		"direct hostname canary":        {Kind: "http", Target: "https://{canary_host}:8443/", Zone: "canary.test"},
		"callback in query":             {Kind: "proxy-fetch", Target: "http://p/api?u={callback}", Callback: "http://r/canary", Method: "POST"},
		"callback in path":              {Kind: "proxy-fetch", Target: "http://p/remote/{callback}/x", Callback: "http://{canary_host}/c", Zone: "canary.test"},
		"callback in header":            {Kind: "proxy-fetch", Target: "http://p/api", Callback: "http://r/c", Headers: map[string]string{"X-Upstream": "{callback}"}},
		"workload credential":           {Kind: "proxy-fetch", Target: "http://p/api", Callback: "http://r/c", CredentialEnv: "REPO_TOKEN", CredentialHeader: "X-JFrog-Art-Api"},
		"proxy credential":              {Kind: "http-proxy", Target: "https://r/c", Proxy: "http://p", CredentialEnv: "PROXY_AUTH"},
	}
	invalid := map[string]Probe{
		"unknown placeholder":       {Kind: "proxy-fetch", Target: "http://p/{nope}?u={callback}", Callback: "http://r/c"},
		"stray brace":               {Kind: "proxy-fetch", Target: "http://p/{?u={callback}", Callback: "http://r/c"},
		"canary_host without zone":  {Kind: "http-proxy", Target: "http://{canary_host}/", Proxy: "http://p"},
		"canary_host partial host":  {Kind: "http", Target: "http://a{canary_host}/", Zone: "canary.test"},
		"canary_host in path":       {Kind: "http", Target: "http://h/{canary_host}", Zone: "canary.test"},
		"canary in direct target":   {Kind: "http", Target: "http://h/{canary}"},
		"template without callback": {Kind: "proxy-fetch", Target: "http://p/{canary}", Callback: "http://r/c"},
		"method on legacy fetch":    {Kind: "proxy-fetch", Target: "http://p/api", Callback: "http://r/c", Method: "POST"},
		"unsupported method":        {Kind: "proxy-fetch", Target: "http://p/{callback}", Callback: "http://r/c", Method: "DELETE"},
		"host header":               {Kind: "http", Target: "http://h/", Headers: map[string]string{"Host": "x"}},
		"static credential":         {Kind: "http", Target: "http://h/", Headers: map[string]string{"Authorization": "Bearer x"}},
		"proxy header":              {Kind: "http", Target: "http://h/", Headers: map[string]string{"Proxy-Authorization": "x"}},
		"header injection":          {Kind: "http", Target: "http://h/", Headers: map[string]string{"X-A": "a\r\nX-B: b"}},
		"callback header on http":   {Kind: "http", Target: "http://h/", Headers: map[string]string{"X-A": "{callback}"}},
		"witness token credential":  {Kind: "http", Target: "http://h/", CredentialEnv: "TOKEN"},
		"credential header alone":   {Kind: "http", Target: "http://h/", CredentialHeader: "X-Key"},
		"framing credential header": {Kind: "http", Target: "http://h/", CredentialEnv: "KEY", CredentialHeader: "Content-Length"},
		"duplicate credential":      {Kind: "http", Target: "http://h/", CredentialEnv: "KEY", Headers: map[string]string{"authorization": "x"}},
		"registry placeholder":      {Kind: "registry-upload", Target: "http://h/{canary}"},
		"tcp headers":               {Kind: "tcp", Target: "127.0.0.1:1", Headers: map[string]string{"X-A": "b"}},
		"tcp credential":            {Kind: "tcp", Target: "127.0.0.1:1", CredentialEnv: "KEY"},
	}
	many := map[string]string{}
	for i := 0; i < 17; i++ {
		many["X-H"+strings.Repeat("a", i)] = "v"
	}
	invalid["too many headers"] = Probe{Kind: "http", Target: "http://h/", Headers: many}
	check := func(name string, q Probe, wantErr bool) {
		p := base()
		q.ID, q.Expect = "probe", "deny"
		p.Probes = []Probe{q}
		if err := p.Validate(); (err != nil) != wantErr {
			t.Fatalf("%s: want error %v, got %v", name, wantErr, err)
		}
	}
	for name, q := range valid {
		check(name, q, false)
	}
	for name, q := range invalid {
		check(name, q, true)
	}
}
