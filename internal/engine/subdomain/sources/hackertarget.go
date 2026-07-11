package sources

import (
	"context"
	"fmt"
	"strings"
)

type HackerTarget struct{}

func NewHackerTarget() Source          { return &HackerTarget{} }
func (s *HackerTarget) Name() string   { return "hackertarget" }
func (s *HackerTarget) NeedsKey() bool { return false }

func (s *HackerTarget) Query(ctx context.Context, domain string, session *Session) (chan string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	data, err := session.Client.Get(url)
	if err != nil {
		return nil, err
	}
	results := make(chan string)
	go func() {
		defer close(results)
		seen := make(map[string]struct{})
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Split(line, ",")
			if len(parts) == 0 {
				continue
			}
			name := strings.TrimSpace(strings.ToLower(parts[0]))
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
	}()
	return results, nil
}
