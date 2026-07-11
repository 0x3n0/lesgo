package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type WaybackArchive struct{}

func NewWaybackArchive() Source          { return &WaybackArchive{} }
func (s *WaybackArchive) Name() string   { return "waybackarchive" }
func (s *WaybackArchive) NeedsKey() bool { return false }

func (s *WaybackArchive) Query(ctx context.Context, domain string, session *Session) (chan string, error) {
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", domain)
	data, err := session.Client.Get(url)
	if err != nil {
		return nil, err
	}
	var entries [][]string
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	results := make(chan string)
	go func() {
		defer close(results)
		seen := make(map[string]struct{})
		for i, entry := range entries {
			if i == 0 || len(entry) == 0 {
				continue
			}
			raw := strings.TrimSpace(entry[0])
			raw = strings.TrimPrefix(raw, "http://")
			raw = strings.TrimPrefix(raw, "https://")
			if idx := strings.Index(raw, "/"); idx != -1 {
				raw = raw[:idx]
			}
			raw = strings.TrimSpace(strings.ToLower(raw))
			if raw == "" || !strings.Contains(raw, domain) {
				continue
			}
			if _, ok := seen[raw]; ok {
				continue
			}
			seen[raw] = struct{}{}
			select {
			case results <- raw:
			case <-ctx.Done():
				return
			}
		}
	}()
	return results, nil
}
