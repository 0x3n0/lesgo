package sources

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

type RapidDNS struct{}

func NewRapidDNS() Source          { return &RapidDNS{} }
func (s *RapidDNS) Name() string   { return "rapiddns" }
func (s *RapidDNS) NeedsKey() bool { return false }

func (s *RapidDNS) Query(ctx context.Context, domain string, session *Session) (chan string, error) {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
	data, err := session.Client.Get(url)
	if err != nil {
		return nil, err
	}
	results := make(chan string)
	go func() {
		defer close(results)
		body := string(data)
		re := regexp.MustCompile(`([a-zA-Z0-9][-a-zA-Z0-9]*\.` + regexp.QuoteMeta(domain) + `)`)
		matches := re.FindAllString(body, -1)
		seen := make(map[string]struct{})
		for _, match := range matches {
			match = strings.TrimSpace(strings.ToLower(match))
			if match == "" {
				continue
			}
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}
			select {
			case results <- match:
			case <-ctx.Done():
				return
			}
		}
	}()
	return results, nil
}
