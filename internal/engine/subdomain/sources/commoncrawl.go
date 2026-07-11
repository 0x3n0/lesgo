package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type CommonCrawl struct{}

func NewCommonCrawl() Source          { return &CommonCrawl{} }
func (s *CommonCrawl) Name() string   { return "commoncrawl" }
func (s *CommonCrawl) NeedsKey() bool { return false }

func (s *CommonCrawl) Query(ctx context.Context, domain string, session *Session) (chan string, error) {
	indexURL := "https://index.commoncrawl.org/collinfo.json"
	data, err := session.Client.Get(indexURL)
	if err != nil {
		return nil, err
	}
	var indexes []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &indexes); err != nil {
		return nil, err
	}
	results := make(chan string)
	go func() {
		defer close(results)
		seen := make(map[string]struct{})
		maxIdx := 3
		if len(indexes) < maxIdx {
			maxIdx = len(indexes)
		}
		for i := 0; i < maxIdx; i++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			searchURL := fmt.Sprintf("https://index.commoncrawl.org/%s-index?url=*.%s/*&output=json&fl=url", indexes[i].ID, domain)
			respData, err := session.Client.Get(searchURL)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(respData), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var entry struct {
					URL string `json:"url"`
				}
				if err := json.Unmarshal([]byte(line), &entry); err != nil {
					continue
				}
				host := strings.TrimPrefix(entry.URL, "http://")
				host = strings.TrimPrefix(host, "https://")
				if idx := strings.Index(host, "/"); idx != -1 {
					host = host[:idx]
				}
				host = strings.TrimSpace(strings.ToLower(host))
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
