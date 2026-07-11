package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type CertSpotter struct{}

func NewCertSpotter() Source          { return &CertSpotter{} }
func (s *CertSpotter) Name() string   { return "certspotter" }
func (s *CertSpotter) NeedsKey() bool { return false }

func (s *CertSpotter) Query(ctx context.Context, domain string, session *Session) (chan string, error) {
	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
	data, err := session.Client.Get(url)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	results := make(chan string)
	go func() {
		defer close(results)
		seen := make(map[string]struct{})
		for _, entry := range entries {
			for _, name := range entry.DNSNames {
				name = strings.TrimSpace(strings.ToLower(name))
				name = strings.TrimPrefix(name, "*.")
				if name == "" || !strings.Contains(name, domain) {
					continue
				}
				if _, ok := seen[name]; ok {
					continue
				}
				seen[name] = struct{}{}
				select {
				case results <- name:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return results, nil
}
