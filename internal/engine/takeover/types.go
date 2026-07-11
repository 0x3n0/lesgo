package takeover

import "time"

// Result holds subdomain takeover detection results.
type Result struct {
	Host       string    `json:"host"`
	CNAME      []string  `json:"cname,omitempty"`
	A          []string  `json:"a,omitempty"`
	NS         []string  `json:"ns,omitempty"`
	Vulnerable bool      `json:"vulnerable"`
	Service    string    `json:"service,omitempty"`
	Evidence   string    `json:"evidence,omitempty"`
	StatusCode int       `json:"status_code,omitempty"`
	Response   string    `json:"response,omitempty"`
	Error      string    `json:"error,omitempty"`
	IsCDN      bool      `json:"is_cdn,omitempty"`
	CDNName    string    `json:"cdn_name,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// Options configures the takeover engine.
type Options struct {
	Threads     int
	Timeout     int
	AllServices bool
	CheckCNAME  bool
	CheckNS     bool
	CheckHTTP   bool
	DNSServers  []string
	HTTPClient  interface{} // optional shared HTTP client
}

// ServiceFingerprint defines a known vulnerable service pattern.
type ServiceFingerprint struct {
	Name          string
	Provider      string
	CNAMEPatterns []string
	NSPatterns    []string
	HTTPPatterns  []FingerprintMatch
}

// FingerprintMatch describes an HTTP response pattern for takeover detection.
type FingerprintMatch struct {
	StatusCode     int
	BodyContains   []string
	HeaderContains map[string]string
	BodyRegex      []string
}
