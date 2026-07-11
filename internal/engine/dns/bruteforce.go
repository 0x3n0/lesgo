package dns

import (
	"fmt"
	"strings"
	"sync"
)

// BruteResult holds bruteforce results.
type BruteResult struct {
	Found []string
	Total int
}

// BruteForce performs subdomain bruteforce: wordlist × domain.
func (e *Engine) BruteForce(domain string, wordlist []string, threads int) *BruteResult {
	result := &BruteResult{}
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")

	if len(wordlist) == 0 {
		return result
	}

	if threads <= 0 {
		threads = 10
	}

	jobs := make(chan string, len(wordlist))
	results := make(chan string, 100)
	var wg sync.WaitGroup

	// Workers
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				host := fmt.Sprintf("%s.%s", strings.TrimSpace(word), domain)
				if e.opts.RateLimiter != nil {
					e.opts.RateLimiter.Take()
				}
				res := e.Query(host)
				if res != nil && len(res.A) > 0 {
					results <- host
				}
			}
		}()
	}

	// Send jobs
	go func() {
		for _, word := range wordlist {
			word = strings.TrimSpace(word)
			if word == "" {
				continue
			}
			jobs <- word
		}
		close(jobs)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		result.Found = append(result.Found, r)
	}

	result.Total = len(wordlist)
	return result
}
