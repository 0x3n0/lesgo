package runner

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Result holds the output of any engine scan.
type Result struct {
	// Common fields
	Timestamp time.Time `json:"timestamp,omitempty" csv:"timestamp"`
	Input     string    `json:"input,omitempty" csv:"input"`
	URL       string    `json:"url,omitempty" csv:"url"`
	Host      string    `json:"host,omitempty" csv:"host"`
	IP        string    `json:"ip,omitempty" csv:"ip"`
	Err       error     `json:"-" csv:"-"`
	ErrorStr  string    `json:"error,omitempty" csv:"error"`
	Failed    bool      `json:"failed,omitempty" csv:"failed"`

	// DNS fields
	DNSRecords    map[string][]string `json:"dns,omitempty" csv:"-"`
	A             []string            `json:"a,omitempty" csv:"-"`
	AAAA          []string            `json:"aaaa,omitempty" csv:"-"`
	CNAME         []string            `json:"cname,omitempty" csv:"-"`
	MX            []string            `json:"mx,omitempty" csv:"-"`
	NS            []string            `json:"ns,omitempty" csv:"-"`
	TXT           []string            `json:"txt,omitempty" csv:"-"`
	SOA           []string            `json:"soa,omitempty" csv:"-"`
	PTR           []string            `json:"ptr,omitempty" csv:"-"`
	CAA           []string            `json:"caa,omitempty" csv:"-"`
	SRV           []string            `json:"srv,omitempty" csv:"-"`
	StatusCodeRaw int                 `json:"status_code,omitempty" csv:"status_code"`
	RCode         string              `json:"rcode,omitempty" csv:"rcode"`
	RawDNS        string              `json:"raw_dns,omitempty" csv:"-"`
	IsCDN         bool                `json:"is_cdn,omitempty" csv:"is_cdn"`
	CDNName       string              `json:"cdn_name,omitempty" csv:"cdn_name"`
	ASN           *ASNInfo            `json:"asn,omitempty" csv:"-"`
		TraceData	*TraceInfo	`json:"trace,omitempty" csv:"-"`

	// HTTP fields
	StatusCode     int                 `json:"http_status_code,omitempty" csv:"http_status_code"`
	ContentLength  int                 `json:"content_length,omitempty" csv:"content_length"`
	ContentType    string              `json:"content_type,omitempty" csv:"content_type"`
	Title          string              `json:"title,omitempty" csv:"title"`
	Server         string              `json:"server,omitempty" csv:"server"`
	Location       string              `json:"location,omitempty" csv:"location"`
	ResponseTime   string              `json:"response_time,omitempty" csv:"response_time"`
	Lines          int                 `json:"lines,omitempty" csv:"lines"`
	Words          int                 `json:"words,omitempty" csv:"words"`
	FavIconMMH3    string              `json:"favicon_mmh3,omitempty" csv:"favicon_mmh3"`
	Hash           map[string]string   `json:"hash,omitempty" csv:"-"`
	JARM           string              `json:"jarm,omitempty" csv:"jarm"`
	WebSocket      bool                `json:"websocket,omitempty" csv:"websocket"`
	HTTP2          bool                `json:"http2,omitempty" csv:"http2"`
	Pipeline       bool                `json:"pipeline,omitempty" csv:"pipeline"`
	VHost          bool                `json:"vhost,omitempty" csv:"vhost"`
	Method         string              `json:"method,omitempty" csv:"method"`
	ProbeStatus    bool                `json:"probe_status,omitempty" csv:"probe_status"`
	TechDetect     []string            `json:"tech,omitempty" csv:"-"`
	Extracts       map[string][]string `json:"extracts,omitempty" csv:"-"`
	BodyPreview    string              `json:"body_preview,omitempty" csv:"-"`
	ResponseBody   string              `json:"-" csv:"-"`
	ResponseHeader string              `json:"response_header,omitempty" csv:"-"`
	RawHTTP        string              `json:"raw_http,omitempty" csv:"-"`
	TLSData        *TLSInfo            `json:"tls,omitempty" csv:"-"`

	// Takeover fields
	Vulnerable bool   `json:"takeover_vulnerable,omitempty" csv:"takeover_vulnerable"`
	Service    string `json:"takeover_service,omitempty" csv:"takeover_service"`
	Evidence   string `json:"takeover_evidence,omitempty" csv:"takeover_evidence"`

	// Internal
	str string
}

// ASNInfo holds ASN information.
type ASNInfo struct {
	AsNumber  string   `json:"as_number,omitempty" csv:"as_number"`
	AsName    string   `json:"as_name,omitempty" csv:"as_name"`
	AsCountry string   `json:"as_country,omitempty" csv:"as_country"`
	AsRange   []string `json:"as_range,omitempty" csv:"-"`
}


// TraceInfo holds DNS trace information.
type TraceInfo struct {
	Host    string        `json:"host,omitempty"`
	Servers []TraceServer `json:"servers,omitempty"`
}

// TraceServer represents a server in the DNS trace.
type TraceServer struct {
	Server    string `json:"server,omitempty"`
	QueryType string `json:"query_type,omitempty"`
	Response  string `json:"response,omitempty"`
}
func (a *ASNInfo) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("[%s] [%s]", a.AsNumber, a.AsName)
}

// TLSInfo holds TLS certificate information.
type TLSInfo struct {
	SubjectCN string   `json:"subject_cn,omitempty"`
	SubjectAN []string `json:"subject_an,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
}

// SetStr sets the string representation of the result.
func (r *Result) SetStr(s string) {
	r.str = s
}

// Str returns the string representation.
func (r *Result) Str() string {
	return r.str
}

// JSON returns the result as JSON.
func (r *Result) JSON() string {
	// Make a copy without the error
	cp := *r
	cp.Err = nil
	if r.Err != nil {
		cp.ErrorStr = r.Err.Error()
	}
	data, err := json.Marshal(cp)
	if err != nil {
		return ""
	}
	return string(data)
}

// CSVHeader returns CSV headers.
func (r Result) CSVHeader() string {
	return "timestamp,input,host,url,ip,a_record,aaaa_record,cname,mx,ns,txt,cdn_name,http_status_code,content_length,content_type,title,server,location,response_time,lines,words,websocket,http2,failed,error"
}

// CSVRow returns the result as a CSV row.
func (r *Result) CSVRow() string {
	errStr := ""
	if r.Err != nil {
		errStr = r.Err.Error()
	}
	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write([]string{
		r.Timestamp.Format(time.RFC3339),
		r.Input,
		r.Host,
		r.URL,
		r.IP,
		strings.Join(r.A, ";"),
		strings.Join(r.AAAA, ";"),
		strings.Join(r.CNAME, ";"),
		strings.Join(r.MX, ";"),
		strings.Join(r.NS, ";"),
		strings.Join(r.TXT, ";"),
		r.CDNName,
		strconv.Itoa(r.StatusCode),
		strconv.Itoa(r.ContentLength),
		r.ContentType,
		r.Title,
		r.Server,
		r.Location,
		r.ResponseTime,
		strconv.Itoa(r.Lines),
		strconv.Itoa(r.Words),
		strconv.FormatBool(r.WebSocket),
		strconv.FormatBool(r.HTTP2),
		strconv.FormatBool(r.Failed),
		errStr,
	})
	w.Flush()
	return strings.TrimRight(b.String(), "\n")
}

// MarkdownHeader returns the markdown table header.
func (r *Result) MarkdownHeader() string {
	return "| URL | Status | Title | Server | Content-Type | Content-Length | IP | CDN | Time |\n" +
		"|-----|--------|-------|--------|-------------|---------------|----|-----|------|\n"
}

// MarkdownRow returns a markdown table row.
func (r *Result) MarkdownRow() string {
	return fmt.Sprintf("| %s | %d | %s | %s | %s | %d | %s | %s | %s |\n",
		markdownCell(r.URL), r.StatusCode, markdownCell(r.Title), markdownCell(r.Server),
		markdownCell(r.ContentType), r.ContentLength, markdownCell(r.IP), markdownCell(r.CDNName),
		markdownCell(r.ResponseTime))
}

func markdownCell(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}
