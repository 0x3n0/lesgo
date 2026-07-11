package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type Anubis struct{}

func NewAnubis() Source          { return &Anubis{} }
func (s *Anubis) Name() string   { return "anubis" }
func (s *Anubis) NeedsKey() bool { return false }

func (s *Anubis) Query(ctx context.Context, domain string, session *Session) (chan string, error) {
	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
	data, err := session.Client.Get(url)
	if err != nil {
		return nil, err
	}
	var subdomains []string
	if err := json.Unmarshal(data, &subdomains); err != nil {
		return nil, err
	}
	results := make(chan string)
	go func() {
		defer close(results)
		seen := make(map[string]struct{})
		for _, sub := range subdomains {
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
