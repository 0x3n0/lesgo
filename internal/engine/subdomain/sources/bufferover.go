package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type BufferOver struct{}

func NewBufferOver() Source          { return &BufferOver{} }
func (s *BufferOver) Name() string   { return "bufferover" }
func (s *BufferOver) NeedsKey() bool { return false }

func (s *BufferOver) Query(ctx context.Context, domain string, session *Session) (chan string, error) {
	url := fmt.Sprintf("https://tls.bufferover.run/dns?q=.%s", domain)
	data, err := session.Client.Get(url)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Results []string `json:"Results"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	results := make(chan string)
	go func() {
		defer close(results)
		seen := make(map[string]struct{})
		for _, entry := range resp.Results {
			parts := strings.SplitN(entry, ",", 2)
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
