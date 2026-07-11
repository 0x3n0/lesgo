package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type Riddler struct{}

func NewRiddler() Source          { return &Riddler{} }
func (s *Riddler) Name() string   { return "riddler" }
func (s *Riddler) NeedsKey() bool { return false }

func (s *Riddler) Query(ctx context.Context, domain string, session *Session) (chan string, error) {
	url := fmt.Sprintf("https://riddler.io/search/exportcsv?q=pld:%s", domain)
	data, err := session.Client.Get(url)
	if err != nil {
		return nil, err
	}
	results := make(chan string)
	go func() {
		defer close(results)
		body := string(data)
		seen := make(map[string]struct{})
		if strings.HasPrefix(strings.TrimSpace(body), "[") {
			var entries []struct {
				Host string `json:"host"`
			}
			if err := json.Unmarshal(data, &entries); err == nil {
				for _, entry := range entries {
					host := strings.TrimSpace(strings.ToLower(entry.Host))
					if host == "" || !strings.Contains(host, domain) {
						continue
					}
					if _, ok := seen[host]; ok {
						continue
					}
					seen[host] = struct{}{}
					select {
					case results <- host:
					case <-ctx.Done():
						return
					}
				}
			}
		} else {
			for _, line := range strings.Split(body, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				host := strings.TrimSpace(strings.ToLower(line))
				if host == "" || !strings.Contains(host, domain) {
					continue
				}
				if _, ok := seen[host]; ok {
					continue
				}
				seen[host] = struct{}{}
				select {
				case results <- host:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return results, nil
}
