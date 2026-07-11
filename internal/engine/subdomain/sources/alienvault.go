package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type AlienVault struct{}

func NewAlienVault() Source          { return &AlienVault{} }
func (s *AlienVault) Name() string   { return "alienvault" }
func (s *AlienVault) NeedsKey() bool { return false }

func (s *AlienVault) Query(ctx context.Context, domain string, session *Session) (chan string, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	data, err := session.Client.Get(url)
	if err != nil {
		return nil, err
	}
	var resp struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	results := make(chan string)
	go func() {
		defer close(results)
		seen := make(map[string]struct{})
		for _, entry := range resp.PassiveDNS {
			hostname := strings.TrimSpace(strings.ToLower(entry.Hostname))
			if hostname == "" || !strings.Contains(hostname, domain) {
				continue
			}
			if _, ok := seen[hostname]; ok {
				continue
			}
			seen[hostname] = struct{}{}
			select {
			case results <- hostname:
			case <-ctx.Done():
				return
			}
		}
	}()
	return results, nil
}
