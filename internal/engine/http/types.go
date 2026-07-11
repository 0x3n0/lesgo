package http

import (
	"time"

	"github.com/0x3n0/lesgo/internal/shared"
)

// Result holds HTTP probe results.
type Result struct {
	Input         string              `json:"input,omitempty"`
	URL           string              `json:"url,omitempty"`
	Host          string              `json:"host,omitempty"`
	IP            string              `json:"ip,omitempty"`
	IPs           []string            `json:"ips,omitempty"`
	CNAMEs        []string            `json:"cnames,omitempty"`
	StatusCode    int                 `json:"status_code,omitempty"`
	ContentLength int                 `json:"content_length,omitempty"`
	ContentType   string              `json:"content_type,omitempty"`
	Title         string              `json:"title,omitempty"`
	Server        string              `json:"server,omitempty"`
	Location      string              `json:"location,omitempty"`
	ResponseTime  string              `json:"response_time,omitempty"`
	Lines         int                 `json:"lines,omitempty"`
	Words         int                 `json:"words,omitempty"`
	Method        string              `json:"method,omitempty"`
	ProbeStatus   bool                `json:"probe_status,omitempty"`
	FavIconMMH3   string              `json:"favicon_mmh3,omitempty"`
	WebSocket     bool                `json:"websocket,omitempty"`
	HTTP2         bool                `json:"http2,omitempty"`
	Pipeline      bool                `json:"pipeline,omitempty"`
	VHost         bool                `json:"vhost,omitempty"`
	TechDetect    []string            `json:"tech,omitempty"`
	CDNName       string              `json:"cdn_name,omitempty"`
	IsCDN         bool                `json:"is_cdn,omitempty"`
	Body          string              `json:"body,omitempty"`
	Headers       map[string][]string `json:"headers,omitempty"`
	RawRequest    string              `json:"raw_request,omitempty"`
	RawResponse   string              `json:"raw_response,omitempty"`
	Extracts      map[string][]string `json:"extracts,omitempty"`
	Hashes        map[string]string   `json:"hashes,omitempty"`
	JARM          string              `json:"jarm,omitempty"`
	TLSData       *TLSData            `json:"tls,omitempty"`
	Chain         []ChainItem         `json:"chain,omitempty"`
	Err           error               `json:"-"`
}

// TLSData holds TLS certificate information from probes.
type TLSData struct {
	SubjectCN string   `json:"subject_cn,omitempty"`
	SubjectAN []string `json:"subject_an,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
	Version   string   `json:"version,omitempty"`
}

// ChainItem represents an item in the redirect chain.
type ChainItem struct {
	URL        string `json:"url,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Location   string `json:"location,omitempty"`
}

// Options configures the HTTP engine.
type Options struct {
	Threads             int
	Timeout             int
	Retries             int
	Proxy               string
	CustomHeaders       map[string]string
	RandomAgent         bool
	AutoReferer         bool
	Unsafe              bool
	NoFallback          bool
	NoFallbackScheme    bool
	TLSGrab             bool
	TLSProbe            bool
	CSPProbe            bool
	VHost               bool
	Pipeline            bool
	HTTP2Probe          bool
	SniName             string
	FollowRedirects     bool
	MaxRedirects        int
	FollowHostRedirects bool
	NoDecode            bool
	LeaveDefaultPorts   bool
	Favicon             bool
	JARM                bool
	RequestMethods      string
	RequestBody         string
	RequestPaths        string
	CustomPorts         string
	Delay               time.Duration
	RateLimiter         *shared.RateLimiter
	BodyPreviewSize     int
	OutputCDN           string
	Hashes              string
	ExtractRegex        []string
	ExtractPreset       []string
	Probe               bool
}
