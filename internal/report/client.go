package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Wearden/proto/wire"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Client struct {
	endpoint, token string
	http            *http.Client
}

var taskResultEndpoint = regexp.MustCompile(`^tasks/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/results$`)

// Request shares the report transport guards with agent lifecycle requests.
func (c *Client) Request(ctx context.Context, method, path string, body any, status, limit int) ([]byte, error) {
	if path != "enroll" && path != "heartbeat" && path != "config" && path != "ruleset" && path != "tasks" && !taskResultEndpoint.MatchString(path) {
		return nil, errors.New("unsupported agent endpoint")
	}
	var input io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		input = bytes.NewReader(data)
	}
	endpoint := strings.TrimSuffix(c.endpoint, "reports") + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, input)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("core request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != status {
		return nil, fmt.Errorf("core rejected %s: HTTP %d", path, res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, int64(limit)+1))
	if err != nil {
		return nil, errors.New("cannot read core response")
	}
	if len(data) > limit {
		return nil, errors.New("core response too large")
	}
	return data, nil
}

func NewClient(base, token string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, errors.New("invalid core URL")
	}
	if u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("core URL must be an origin without credentials, query or path")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("TLS required except for literal loopback addresses")
		}
	}
	if strings.TrimSpace(token) == "" || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("agent token is required")
	}
	return &Client{endpoint: strings.TrimRight(base, "/") + "/api/agent/v1/reports", token: token, http: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Submit(ctx context.Context, report wire.Report) error {
	if err := report.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if len(body) > 8*1024*1024 {
		return errors.New("report exceeds 8 MiB")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	res, err := c.http.Do(req)
	if err != nil {
		return errors.New("core request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return fmt.Errorf("core rejected report: HTTP %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil {
		return errors.New("cannot read core receipt")
	}
	if len(data) > 65536 {
		return errors.New("core receipt too large")
	}
	var receipt wire.Receipt
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&receipt); err != nil {
		return errors.New("invalid core receipt")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("invalid trailing receipt data")
	}
	if !receipt.Accepted || receipt.ReportID != report.ReportID {
		return errors.New("core did not acknowledge this report")
	}
	return nil
}
