// Package seal implements bounded, evidence-based sandbox egress checks.
package seal

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"time"
)

const Version = 1

type Probe struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	Target        string `json:"target"`
	Expect        string `json:"expect"`
	Optional      bool   `json:"optional,omitempty"`
	Network       string `json:"network,omitempty"`
	Proxy         string `json:"proxy,omitempty"`
	Callback      string `json:"callback,omitempty"`
	Zone          string `json:"zone,omitempty"`
	IdentityLabel string `json:"identity_label,omitempty"`
	// Method applies to templated proxy-fetch targets.
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	// CredentialEnv names a variable the runner reads inside the sandbox, so
	// the probe carries the workload's own identity. Values are never recorded.
	CredentialEnv    string `json:"credential_env,omitempty"`
	CredentialHeader string `json:"credential_header,omitempty"`
}

// Witness management endpoints are read by the controller, never by a probe.
// TokenEnv names an environment variable, not a credential value.
type WitnessConfig struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	TokenEnv    string `json:"token_env"`
	Role        string `json:"role"`                   // receiver or boundary
	RegistryURL string `json:"registry_url,omitempty"` // external reader's controlled registry endpoint
}

type Policy struct {
	Version       int             `json:"version"`
	Name          string          `json:"name"`
	TimeoutMS     int             `json:"timeout_ms"`
	ObservationMS int             `json:"observation_ms"`
	MaxAgeSeconds int             `json:"max_age_seconds"`
	Probes        []Probe         `json:"probes"`
	Witnesses     []WitnessConfig `json:"witnesses"`
}

type Plan struct {
	Version      int               `json:"version"`
	RunID        string            `json:"run_id"`
	Nonce        string            `json:"nonce"`
	CreatedAt    time.Time         `json:"created_at"`
	Deadline     time.Time         `json:"deadline"`
	PolicySHA256 string            `json:"policy_sha256"`
	Policy       Policy            `json:"policy"`
	Tokens       map[string]string `json:"tokens"`
}

type Identity struct {
	UID           int               `json:"uid"`
	EUID          int               `json:"euid"`
	GID           int               `json:"gid"`
	Hostname      string            `json:"hostname"`
	Namespaces    map[string]string `json:"namespaces,omitempty"`
	ProcessStatus map[string]string `json:"process_status,omitempty"`
	Source        string            `json:"source"`
}

type Result struct {
	ID         string    `json:"id"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Outcome    string    `json:"outcome"` // success, denied, error, unsupported
	Detail     string    `json:"detail,omitempty"`
	HTTPStatus int       `json:"http_status,omitempty"`
}

type Results struct {
	Version      int      `json:"version"`
	RunID        string   `json:"run_id"`
	PolicySHA256 string   `json:"policy_sha256"`
	Identity     Identity `json:"identity"`
	Probes       []Result `json:"probes"`
}

type Event struct {
	RunID         string    `json:"run_id"`
	ProbeID       string    `json:"probe_id"`
	Token         string    `json:"token"`
	Action        string    `json:"action"` // received, denied, retrieved
	Protocol      string    `json:"protocol"`
	Remote        string    `json:"remote"`
	At            time.Time `json:"at"`
	PayloadSHA256 string    `json:"payload_sha256"`
}

type Snapshot struct {
	Instance string    `json:"instance"`
	At       time.Time `json:"at"`
	Overflow bool      `json:"overflow"`
	Events   []Event   `json:"events"`
}

type Witness struct {
	ID            string     `json:"id"`
	Role          string     `json:"role"`
	HealthyBefore bool       `json:"healthy_before"`
	HealthyAfter  bool       `json:"healthy_after"`
	Before        time.Time  `json:"before"`
	After         time.Time  `json:"after"`
	Snapshot      Snapshot   `json:"snapshot"`
	Error         string     `json:"error,omitempty"`
	Readbacks     []Readback `json:"readbacks,omitempty"`
}

type Readback struct {
	ProbeID       string    `json:"probe_id"`
	At            time.Time `json:"at"`
	PayloadSHA256 string    `json:"payload_sha256"`
}

type Finding struct {
	ID       string   `json:"id"`
	Verdict  string   `json:"verdict"`
	Reason   string   `json:"reason"`
	Evidence []string `json:"evidence"`
}

type Report struct {
	Version     int       `json:"version"`
	ToolVersion string    `json:"tool_version"`
	IssuedAt    time.Time `json:"issued_at"`
	Plan        Plan      `json:"plan"`
	Results     Results   `json:"results"`
	Witnesses   []Witness `json:"witnesses"`
	Findings    []Finding `json:"findings"`
	Verdict     string    `json:"verdict"`
	Errors      []string  `json:"errors,omitempty"`
	Limitations []string  `json:"limitations"`
}

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
var randomHex = regexp.MustCompile(`^[0-9a-f]{32}$`)

func RandomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func Hash(b []byte) string       { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func PolicyHash(p Policy) string { b, _ := json.Marshal(p); return Hash(b) }

func ReadJSON(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return DecodeJSON(f, dst)
}

func DecodeJSON(r io.Reader, dst any) error {
	const limit = 8 << 20
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if len(data) > limit {
		return errors.New("JSON input exceeds 8 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("expected exactly one JSON document")
	}
	return nil
}

func WriteJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(path, append(b, '\n'), 0600)
}

func WriteAtomic(path string, b []byte, mode os.FileMode) error {
	// Temp file and rename prevent interrupted writes from producing valid-looking reports.
	return writeAtomic(path, b, mode)
}

func httpURL(s string) bool {
	u, e := url.Parse(s)
	return len(s) <= 2048 && e == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}

func (p Policy) Validate() error {
	if p.Version != Version || p.Name == "" {
		return errors.New("policy requires version 1 and a name")
	}
	if p.TimeoutMS < 10 || p.TimeoutMS > 30000 || p.ObservationMS < 0 || p.ObservationMS > 30000 || p.MaxAgeSeconds < 1 || p.MaxAgeSeconds > 86400 {
		return errors.New("invalid timeout, observation window, or maximum age")
	}
	if len(p.Probes) == 0 || len(p.Probes) > 128 {
		return errors.New("policy requires 1–128 probes")
	}
	tokenEnvs := map[string]bool{}
	for _, w := range p.Witnesses {
		tokenEnvs[w.TokenEnv] = true
	}
	seen := map[string]bool{}
	requiredCount := 0
	for _, q := range p.Probes {
		if !q.Optional {
			requiredCount++
		}
		if !identifier.MatchString(q.ID) || seen[q.ID] {
			return fmt.Errorf("invalid or duplicate probe id %q", q.ID)
		}
		seen[q.ID] = true
		if q.Expect != "allow" && q.Expect != "deny" {
			return fmt.Errorf("%s: expect must be allow or deny", q.ID)
		}
		if q.Network != "" && q.Network != "4" && q.Network != "6" {
			return fmt.Errorf("%s: network must be 4 or 6", q.ID)
		}
		httpKind := q.Kind == "http" || q.Kind == "http-proxy" || q.Kind == "proxy-fetch" || q.Kind == "registry-upload"
		if !httpKind && (q.Method != "" || len(q.Headers) > 0 || q.CredentialEnv != "" || q.CredentialHeader != "") {
			return fmt.Errorf("%s: method, headers, and credentials require an HTTP probe", q.ID)
		}
		switch q.Kind {
		case "tcp", "udp", "dns":
			host, _, e := net.SplitHostPort(q.Target)
			if e != nil || net.ParseIP(host) == nil {
				return fmt.Errorf("%s: target requires host:port", q.ID)
			}
		case "dns-system":
			if q.Target != "" {
				return fmt.Errorf("%s: system resolver probe uses zone, not target", q.ID)
			}
		case "http", "http-proxy", "proxy-fetch", "registry-upload":
			if q.Target == "" {
				return fmt.Errorf("%s: target must be an HTTP(S) URL without credentials", q.ID)
			}
			if q.Kind == "http-proxy" && !httpURL(q.Proxy) {
				return fmt.Errorf("%s: proxy URL required", q.ID)
			}
			if q.Kind == "proxy-fetch" && q.Callback == "" {
				return fmt.Errorf("%s: callback URL required", q.ID)
			}
			if e := validateHTTPTemplates(q, tokenEnvs); e != nil {
				return fmt.Errorf("%s: %w", q.ID, e)
			}
		default:
			return fmt.Errorf("%s: unsupported probe kind %q", q.ID, q.Kind)
		}
		if q.Kind == "dns" || q.Kind == "dns-system" {
			if !validZone(q.Zone) {
				return fmt.Errorf("%s: invalid DNS zone", q.ID)
			}
		}
	}
	if requiredCount == 0 {
		return errors.New("at least one probe must be required")
	}
	if len(p.Witnesses) < 1 || len(p.Witnesses) > 8 {
		return errors.New("policy requires 1–8 witnesses")
	}
	seen = map[string]bool{}
	for _, w := range p.Witnesses {
		if !identifier.MatchString(w.ID) || seen[w.ID] || !httpURL(w.URL) || w.TokenEnv == "" || (w.Role != "receiver" && w.Role != "boundary") {
			return fmt.Errorf("invalid witness %q", w.ID)
		}
		seen[w.ID] = true
		if w.RegistryURL != "" && (w.Role != "receiver" || !httpURL(w.RegistryURL)) {
			return fmt.Errorf("invalid registry reader endpoint for %s", w.ID)
		}
	}
	return nil
}

func NewPlan(p Policy, now time.Time) (Plan, error) {
	if e := p.Validate(); e != nil {
		return Plan{}, e
	}
	tokens := map[string]string{}
	for _, q := range p.Probes {
		tokens[q.ID] = RandomID()
	}
	duration := time.Duration(len(p.Probes)*p.TimeoutMS+p.ObservationMS)*time.Millisecond + 30*time.Second
	return Plan{Version, RandomID(), RandomID(), now.UTC(), now.Add(duration).UTC(), PolicyHash(p), p, tokens}, nil
}

func (p Plan) Validate() error {
	if e := p.Policy.Validate(); e != nil {
		return e
	}
	if p.Version != Version || !randomHex.MatchString(p.RunID) || !randomHex.MatchString(p.Nonce) || p.PolicySHA256 != PolicyHash(p.Policy) || !p.Deadline.After(p.CreatedAt) {
		return errors.New("invalid plan binding")
	}
	if len(p.Tokens) != len(p.Policy.Probes) {
		return errors.New("invalid token count")
	}
	seen := map[string]bool{}
	for _, q := range p.Policy.Probes {
		t := p.Tokens[q.ID]
		if !randomHex.MatchString(t) || seen[t] {
			return errors.New("invalid or reused probe token")
		}
		seen[t] = true
	}
	return nil
}

func Canary(p Plan, id string) string { return "sc1:" + p.RunID + ":" + id + ":" + p.Tokens[id] }

func ParseCanary(b []byte) (Event, bool) {
	parts := bytes.Split(bytes.TrimSpace(b), []byte(":"))
	if len(parts) != 4 || string(parts[0]) != "sc1" || !randomHex.Match(parts[1]) || !identifier.Match(parts[2]) || !randomHex.Match(parts[3]) {
		return Event{}, false
	}
	return Event{RunID: string(parts[1]), ProbeID: string(parts[2]), Token: string(parts[3]), PayloadSHA256: Hash(bytes.TrimSpace(b))}, true
}

func ExitCode(verdict string) int {
	if verdict == "PASS" {
		return 0
	}
	if verdict == "FAIL" {
		return 1
	}
	return 2
}
