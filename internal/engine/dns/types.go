package dns

import "time"

// Result holds DNS query results.
type Result struct {
	Host       string     `json:"host,omitempty"`
	Timestamp  time.Time  `json:"timestamp,omitempty"`
	A          []string   `json:"a,omitempty"`
	AAAA       []string   `json:"aaaa,omitempty"`
	CNAME      []string   `json:"cname,omitempty"`
	MX         []string   `json:"mx,omitempty"`
	NS         []string   `json:"ns,omitempty"`
	TXT        []string   `json:"txt,omitempty"`
	SOA        []string   `json:"soa,omitempty"`
	PTR        []string   `json:"ptr,omitempty"`
	CAA        []string   `json:"caa,omitempty"`
	SRV        []string   `json:"srv,omitempty"`
	RCode      string     `json:"rcode,omitempty"`
	StatusCode int        `json:"status_code,omitempty"`
	Raw        string     `json:"raw,omitempty"`
	TraceData  *TraceData `json:"trace,omitempty"`
	CDNName    string     `json:"cdn_name,omitempty"`
	IsCDN      bool       `json:"is_cdn,omitempty"`
	ASN        *ASNResult `json:"asn,omitempty"`
	HostsFile  bool       `json:"hosts_file,omitempty"`
}

// ASNResult holds ASN lookup results.
type ASNResult struct {
	AsNumber  string   `json:"as_number,omitempty"`
	AsName    string   `json:"as_name,omitempty"`
	AsCountry string   `json:"as_country,omitempty"`
	AsRange   []string `json:"as_range,omitempty"`
}

// TraceData holds DNS trace information.
type TraceData struct {
	Host    string        `json:"host,omitempty"`
	Servers []TraceServer `json:"servers,omitempty"`
}

// TraceServer represents a server in the DNS trace.
type TraceServer struct {
	Server    string `json:"server,omitempty"`
	QueryType string `json:"query_type,omitempty"`
	Response  string `json:"response,omitempty"`
}

// Options configures the DNS engine.
type Options struct {
	RecordTypes        []string
	Resolvers          []string
	Retries            int
	Timeout            time.Duration
	HostsFile          bool
	Trace              bool
	TraceMaxRecursion  int
	WildcardThreshold  int
	WildcardDomain     string
	Raw                bool
	Resp               bool
	RespOnly           bool
	RCode              string
	ResponseTypeFilter string
	CDN                bool
	ASN                bool
	RateLimiter        interface{ Take() }
}
