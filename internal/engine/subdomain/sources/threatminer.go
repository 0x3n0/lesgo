package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type ThreatMiner struct{}

func NewThreatMiner() Source          { return &ThreatMiner{} }
func (s *ThreatMiner) Name() string   { return "threatminer" }
func (s *ThreatMiner) NeedsKey() bool { return false }

func (s *ThreatMiner) Query(ctx context.Context, domain string, session *Session) (chan string, error) {
	url := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain)
	data, err := session.Client.Get(url)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Results []string `json:"results"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	results := make(chan string)
	go func() {
		defer close(results)
		seen := make(map[string]struct{})
		for _, sub := range resp.Results {
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
