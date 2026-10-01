package seal

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"time"
)

// Payload is base64 encoded so JSON formatters cannot change signed bytes.
type Bundle struct {
	Version   int    `json:"version"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func signingBytes(b []byte) []byte { return append([]byte("sealcheck/report/v1\x00"), b...) }

func GenerateKeyFiles(privatePath, publicPath string) error {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	priv, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	pub, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return err
	}
	// O_EXCL protects existing signing identities from accidental replacement.
	if err = writeExclusive(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), 0600); err != nil {
		return err
	}
	if err = writeExclusive(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0644); err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	return nil
}

func writeExclusive(path string, b []byte, mode os.FileMode) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	closeErr := f.Close()
	if e != nil {
		_ = os.Remove(path)
		return e
	}
	return closeErr
}

func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private key must not be group/world accessible")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid PEM private key")
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	k, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("Ed25519 private key required")
	}
	return k, nil
}

func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid PEM public key")
	}
	key, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	k, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("Ed25519 public key required")
	}
	return k, nil
}

func Sign(report Report, key ed25519.PrivateKey) (Bundle, error) {
	b, e := json.Marshal(report)
	if e != nil {
		return Bundle{}, e
	}
	if len(b) > 4<<20 {
		return Bundle{}, errors.New("report exceeds 4 MiB evidence limit")
	}
	sig := ed25519.Sign(key, signingBytes(b))
	pub := key.Public().(ed25519.PublicKey)
	return Bundle{Version: Version, KeyID: Hash(pub), Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

type VerifyOptions struct {
	RunID        string
	PolicySHA256 string
	Now          time.Time
	MaxAge       time.Duration
	Historical   bool
}

func Verify(bundle Bundle, public ed25519.PublicKey, opts VerifyOptions) (Report, error) {
	var report Report
	if bundle.Version != Version || bundle.KeyID != Hash(public) {
		return report, errors.New("wrong bundle version or signing key")
	}
	b, e := base64.StdEncoding.DecodeString(bundle.Payload)
	if e != nil {
		return report, e
	}
	sig, e := base64.StdEncoding.DecodeString(bundle.Signature)
	if e != nil || !ed25519.Verify(public, signingBytes(b), sig) {
		return report, errors.New("signature verification failed")
	}
	if e = json.Unmarshal(b, &report); e != nil {
		return report, e
	}
	if report.Version != Version {
		return report, errors.New("unsupported report version")
	}
	if e = report.Plan.Validate(); e != nil {
		return report, e
	}
	if !opts.Historical {
		if opts.RunID == "" || opts.PolicySHA256 == "" {
			return report, errors.New("verification requires an independently supplied run id and policy hash")
		}
		if report.Plan.RunID != opts.RunID || report.Plan.PolicySHA256 != opts.PolicySHA256 {
			return report, errors.New("run or policy binding mismatch")
		}
		maxAge := opts.MaxAge
		policyAge := time.Duration(report.Plan.Policy.MaxAgeSeconds) * time.Second
		if maxAge <= 0 || policyAge < maxAge {
			maxAge = policyAge
		}
		if report.IssuedAt.After(opts.Now.Add(30*time.Second)) || report.Plan.CreatedAt.Before(opts.Now.Add(-maxAge)) || report.IssuedAt.Before(report.Plan.CreatedAt) {
			return report, errors.New("report expired or has invalid timestamps")
		}
	}
	// Even a valid signature must not mask a malformed/inconsistent verdict.
	expected := Evaluate(report.Plan, report.Results, report.Witnesses, report.Reference, report.IssuedAt)
	// Controller interruption can conservatively downgrade a complete probe set.
	if expected.Verdict == "PASS" && len(report.Errors) > 0 {
		expected.Verdict = "INCONCLUSIVE"
	}
	a, _ := json.Marshal(expected.Findings)
	bFindings, _ := json.Marshal(report.Findings)
	if expected.Verdict != report.Verdict || string(a) != string(bFindings) {
		return report, errors.New("report verdict is inconsistent with its evidence")
	}
	return report, nil
}
