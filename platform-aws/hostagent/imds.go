package hostagent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// IMDSCredentials reads the parent instance's role credentials with
// IMDSv2 (token PUT, then the security-credentials path). UNTESTED: no
// EC2 instance was available.
func IMDSCredentials(ctx context.Context) (Credentials, error) {
	const base = "http://169.254.169.254/latest"
	c := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, base+"/api/token", nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "300")
	resp, err := c.Do(req)
	if err != nil {
		return Credentials{}, err
	}
	tok, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	get := func(path string) ([]byte, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		req.Header.Set("X-aws-ec2-metadata-token", string(tok))
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("imds %s: %s", path, resp.Status)
		}
		return io.ReadAll(resp.Body)
	}
	role, err := get("/meta-data/iam/security-credentials/")
	if err != nil {
		return Credentials{}, err
	}
	body, err := get("/meta-data/iam/security-credentials/" + strings.TrimSpace(strings.SplitN(string(role), "\n", 2)[0]))
	if err != nil {
		return Credentials{}, err
	}
	var r struct {
		AccessKeyID     string    `json:"AccessKeyId"`
		SecretAccessKey string    `json:"SecretAccessKey"`
		Token           string    `json:"Token"`
		Expiration      time.Time `json:"Expiration"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return Credentials{}, err
	}
	return Credentials{AccessKeyID: r.AccessKeyID, SecretAccessKey: r.SecretAccessKey, SessionToken: r.Token, Expiration: r.Expiration}, nil
}
