package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type ThreatCrowd struct{}

func NewThreatCrowd() Source          { return &ThreatCrowd{} }
func (s *ThreatCrowd) Name() string   { return "threatcrowd" }
func (s *ThreatCrowd) NeedsKey() bool { return false }

func (s *ThreatCrowd) Query(ctx context.Context, domain string, session *Session) (chan string, error) {
	url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)
	data, err := session.Client.Get(url)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	results := make(chan string)
	go func() {
		defer close(results)
		seen := make(map[string]struct{})
		for _, sub := range resp.Subdomains {
			sub = strings.TrimSpace(strings.ToLower(sub))
			if sub == "" || !strings.Contains(sub, domain) {
				continue
			}
			if _, ok := seen[sub]; ok {
				continue
			}
			seen[sub] = struct{}{}
			select {
			case results <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()
	return results, nil
}
