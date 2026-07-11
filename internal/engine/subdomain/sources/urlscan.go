package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type URLScan struct{}

func NewURLScan() Source          { return &URLScan{} }
func (s *URLScan) Name() string   { return "urlscan" }
func (s *URLScan) NeedsKey() bool { return false }

func (s *URLScan) Query(ctx context.Context, domain string, session *Session) (chan string, error) {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=10000", domain)
	data, err := session.Client.Get(url)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
			Task struct {
				Domain string `json:"domain"`
			} `json:"task"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	results := make(chan string)
	go func() {
		defer close(results)
		seen := make(map[string]struct{})
		for _, entry := range resp.Results {
			for _, d := range []string{entry.Page.Domain, entry.Task.Domain} {
				d = strings.TrimSpace(strings.ToLower(d))
				if d == "" || !strings.Contains(d, domain) {
					continue
				}
				if _, ok := seen[d]; ok {
					continue
				}
				seen[d] = struct{}{}
				select {
				case results <- d:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return results, nil
}
