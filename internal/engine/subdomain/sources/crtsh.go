package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type Crtsh struct{}

func NewCrtsh() Source          { return &Crtsh{} }
func (s *Crtsh) Name() string   { return "crtsh" }
func (s *Crtsh) NeedsKey() bool { return false }

func (s *Crtsh) Query(ctx context.Context, domain string, session *Session) (chan string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	data, err := session.Client.Get(url)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	results := make(chan string)
	go func() {
		defer close(results)
		seen := make(map[string]struct{})
		for _, entry := range entries {
			for _, name := range strings.Split(entry.NameValue, "\n") {
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
