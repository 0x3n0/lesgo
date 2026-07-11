package http

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// ExtractTitle extracts the <title> from an HTML body.
func ExtractTitle(body string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return ""
	}
	title := strings.TrimSpace(doc.Find("title").First().Text())
	return title
}

// ExtractWithRegex extracts content matching a regex pattern.
func ExtractWithRegex(body, pattern string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	matches := re.FindAllString(body, -1)
	// Deduplicate
	seen := make(map[string]struct{})
	var result []string
	for _, m := range matches {
		if _, ok := seen[m]; !ok {
			seen[m] = struct{}{}
			result = append(result, m)
		}
	}
	return result
}

// ExtractMail extracts email addresses from text.
func ExtractMail(body string) []string {
	re := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	return dedupStrings(re.FindAllString(body, -1))
}

// ExtractURL extracts URLs from text.
func ExtractURL(body string) []string {
	re := regexp.MustCompile(`https?://[^\s"'<>]+`)
	return dedupStrings(re.FindAllString(body, -1))
}

// ExtractIPv4 extracts IPv4 addresses from text.
func ExtractIPv4(body string) []string {
	re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	return dedupStrings(re.FindAllString(body, -1))
}

// PresetExtract applies a preset extraction.
var PresetExtractors = map[string]func(string) []string{
	"mail": ExtractMail,
	"url":  ExtractURL,
	"ipv4": ExtractIPv4,
}

// detectTech performs basic technology detection.
func detectTech(resp *http.Response, body string) []string {
	var tech []string

	// Server header
	server := resp.Header.Get("Server")
	if server != "" {
		tech = append(tech, "Server:"+server)
	}

	// X-Powered-By
	xpb := resp.Header.Get("X-Powered-By")
	if xpb != "" {
		tech = append(tech, "X-Powered-By:"+xpb)
	}

	// Common technologies
	checks := map[string]string{
		"jquery":             `jquery[.-]?\d+\.\d+\.\d+`,
		"bootstrap":          `bootstrap[.-]?\d+\.\d+\.\d+`,
		"react":              `react[.-]?\d+\.\d+\.\d+`,
		"vue.js":             `vue[.-]?\d+\.\d+\.\d+`,
		"angular":            `angular[.-]?\d+\.\d+\.\d+`,
		"wordpress":          `wp-content`,
		"drupal":             `drupal`,
		"joomla":             `joomla`,
		"laravel":            `laravel`,
		"django":             `django`,
		"ruby on rails":      `rails`,
		"express":            `express`,
		"nginx":              `nginx`,
		"apache":             `apache`,
		"iis":                `iis`,
		"cloudflare":         `cloudflare`,
		"google analytics":   `google-analytics`,
		"google tag manager": `googletagmanager`,
		"font awesome":       `font-?awesome`,
	}

	for name, pattern := range checks {
		re := regexp.MustCompile("(?i)" + pattern)
		if re.MatchString(body) || re.MatchString(strings.Join(resp.Header.Values("Set-Cookie"), " ")) {
			tech = append(tech, name)
		}
	}

	return dedupStrings(tech)
}

func dedupStrings(items []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, item := range items {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
