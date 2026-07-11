package runner

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
	updateutils "github.com/projectdiscovery/utils/update"
)

const (
	defaultThreads    = 50
	defaultRateLimit  = 150
	DefaultResumeFile = "resume_lesgo.cfg"
)

// Engine selection: auto-detected from flags used.
// Default (no engine flags): subdomain discovery + HTTP probing.
// DNS runs when DNS record type flags are present.
// Takeover runs when takeover flags or -dt are set.
// All engines compose: e.g. -d domain -a -sc runs subdomain discovery + DNS + HTTP.

// Options holds all CLI configuration.
type Options struct {
	// Input
	InputFile    string
	Domains      goflags.StringSlice
	WordList     string
	InputTargets goflags.StringSlice
	Stdin        bool

	// Output
	OutputFile    string
	JSONOutput    bool
	CSVOutput     bool
	Markdown      bool
	Silent        bool
	Verbose       bool
	NoColor       bool
	Version       bool
	ShowStats     bool
	StatsInterval int
	HealthCheck   bool
	Stream        bool

	// Rate limit
	Threads         int
	RateLimit       int
	RateLimitMinute int

	// DNS options
	A                 bool
	AAAA              bool
	CNAME             bool
	NS                bool
	TXT               bool
	SRV               bool
	PTR               bool
	MX                bool
	SOA               bool
	ANY               bool
	AXFR              bool
	CAA               bool
	QueryAll          bool
	ExcludeType       goflags.StringSlice
	Resp              bool
	RespOnly          bool
	RCode             string
	RespTypeFilter    string
	CDN               bool
	ASN               bool
	DNSRaw            bool
	DNSTrace          bool
	TraceMaxRecursion int
	WildcardThreshold int
	WildcardDomain    string
	HostsFile         bool
	DNSRetry          int
	DNSTimeout        time.Duration

	// HTTP options
	StatusCode             bool
	ContentLength          bool
	ContentType            bool
	Location               bool
	Favicon                bool
	Hashes                 string
	JARM                   bool
	ResponseTime           bool
	LineCount              bool
	WordCount              bool
	ExtractTitle           bool
	BodyPreview            int
	WebServer              bool
	TechDetect             bool
	OutputIP               bool
	OutputCName            bool
	OutputCDN              string
	ProbeStatus            bool
	HTTPMethod             bool
	WebSocket              bool
	FollowRedirects        bool
	MaxRedirects           int
	FollowHostRedirects    bool
	CustomHeaders          goflags.StringSlice
	CustomPorts            string
	RequestPaths           string
	RequestMethods         string
	RequestBody            string
	RandomAgent            bool
	AutoReferer            bool
	HTTPProxy              string
	Unsafe                 bool
	NoFallback             bool
	NoFallbackScheme       bool
	TLSGrab                bool
	TLSProbe               bool
	CSPProbe               bool
	VHost                  bool
	Pipeline               bool
	HTTP2Probe             bool
	SniName                string
	HTTPTimeout            int
	HTTPRetries            int
	Delay                  time.Duration
	HTTPRateLimit          int
	HTTPRateLimitMinute    int
	NoDecode               bool
	LeaveDefaultPorts      bool
	ResponseBodySizeToSave int
	ResponseBodySizeToRead int

	// HTTP Matchers
	MatchStatusCode    string
	MatchContentLength string
	MatchString        goflags.StringSlice
	MatchRegex         goflags.StringSlice
	MatchCDN           goflags.StringSlice
	MatchResponseTime  string
	MatchCondition     string

	// HTTP Filters
	FilterStatusCode    string
	FilterContentLength string
	FilterString        goflags.StringSlice
	FilterRegex         goflags.StringSlice
	FilterCDN           goflags.StringSlice
	FilterResponseTime  string
	FilterCondition     string
	FilterDuplicates    bool

	// Extractors
	ExtractRegex  goflags.StringSlice
	ExtractPreset goflags.StringSlice

	// Subdomain options
	Sources          goflags.StringSlice
	ExcludeSources   goflags.StringSlice
	OnlyRecursive    bool
	AllSources       bool
	ActiveSubdomain  bool
	ListSources      bool
	CaptureSources   bool
	SubdomainTimeout int
	MaxEnumTime      int
	ExcludeIPs       bool
	MatchSubdomain   goflags.StringSlice
	FilterSubdomain  goflags.StringSlice

	// Takeover options
	Takeover           bool
	TakeoverAll        bool
	TakeoverCheckCNAME bool
	TakeoverCheckNS    bool
	TakeoverCheckHTTP  bool
	DiscoverTakeover   bool

	// Configs
	Resolvers          goflags.StringSlice
	Proxy              string
	Resume             bool
	SkipDedupe         bool
	DisableUpdateCheck bool
	ConfigFile         string
}

// ParseOptions parses CLI flags and returns Options.
func ParseOptions() *Options {
	opts := &Options{}
	var cfgFile string

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`lesgo is a fast and multi-purpose reconnaissance toolkit combining DNS, HTTP, Subdomain discovery, and Takeover detection.

Input modes:
  lesgo domain.com [flags]
  cat targets.txt | lesgo [flags]
  lesgo -l targets.txt [flags]

Default behavior:
  input automatically runs subdomain discovery + HTTP probing.
  use -sc / -td / -title / etc. to control what fields to display.
  DNS runs only with DNS flags (-a, -cname, etc.), takeover with -tk / -dt.

Supports positional domain arguments (like httpx): lesgo domain.com [flags]`)

	// ---- INPUT ----
	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&opts.InputFile, "list", "l", "", "file containing target domains/hosts to process"),
		flagSet.StringSliceVarP(&opts.Domains, "domain", "d", nil, "domain(s) for discovery or DNS bruteforce root with -w", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&opts.WordList, "wordlist", "w", "", "wordlist for DNS bruteforce (file or comma separated)"),
		flagSet.StringSliceVarP(&opts.InputTargets, "target", "u", nil, "target host(s)/URL(s) to probe directly (skips subdomain discovery)", goflags.CommaSeparatedStringSliceOptions),
	)

	// ---- DNS ----
	flagSet.CreateGroup("dns", "DNS",
		flagSet.BoolVar(&opts.A, "a", false, "query A record (default)"),
		flagSet.BoolVar(&opts.AAAA, "aaaa", false, "query AAAA record"),
		flagSet.BoolVar(&opts.CNAME, "cname", false, "query CNAME record"),
		flagSet.BoolVar(&opts.NS, "ns", false, "query NS record"),
		flagSet.BoolVar(&opts.TXT, "txt", false, "query TXT record"),
		flagSet.BoolVar(&opts.SRV, "srv", false, "query SRV record"),
		flagSet.BoolVar(&opts.PTR, "ptr", false, "query PTR record"),
		flagSet.BoolVar(&opts.MX, "mx", false, "query MX record"),
		flagSet.BoolVar(&opts.SOA, "soa", false, "query SOA record"),
		flagSet.BoolVar(&opts.ANY, "any", false, "query ANY record"),
		flagSet.BoolVar(&opts.AXFR, "axfr", false, "query AXFR"),
		flagSet.BoolVar(&opts.CAA, "caa", false, "query CAA record"),
		flagSet.BoolVarP(&opts.QueryAll, "recon", "all", false, "query all DNS record types"),
		flagSet.StringSliceVarP(&opts.ExcludeType, "exclude-type", "e", nil, "DNS query type to exclude (a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&opts.Resp, "resp", "re", false, "display DNS response"),
		flagSet.BoolVarP(&opts.RespOnly, "resp-only", "ro", false, "display DNS response only"),
		flagSet.StringVarP(&opts.RCode, "rcode", "rc", "", "filter by DNS status code (e.g., noerror,servfail,refused)"),
		flagSet.StringVarP(&opts.RespTypeFilter, "response-type-filter", "rtf", "", "filter entries by record type (e.g., a,cname)"),
		flagSet.BoolVar(&opts.CDN, "cdn", false, "display CDN name"),
		flagSet.BoolVar(&opts.ASN, "asn", false, "display host ASN information"),
		flagSet.BoolVarP(&opts.DNSRaw, "raw", "debug", false, "display raw DNS response"),
		flagSet.BoolVar(&opts.DNSTrace, "trace", false, "perform DNS tracing"),
		flagSet.IntVar(&opts.TraceMaxRecursion, "trace-max-recursion", 255, "max recursion for DNS trace"),
		flagSet.IntVarP(&opts.WildcardThreshold, "wildcard-threshold", "wt", 5, "wildcard filter threshold"),
		flagSet.StringVarP(&opts.WildcardDomain, "wildcard-domain", "wd", "", "domain name for manual wildcard filtering"),
		flagSet.BoolVarP(&opts.HostsFile, "hostsfile", "hf", false, "use system hosts file"),
		flagSet.IntVar(&opts.DNSRetry, "retry", 2, "number of DNS attempts (must be at least 1)"),
		flagSet.DurationVar(&opts.DNSTimeout, "timeout", 3*time.Second, "maximum DNS query wait time"),
	)

	// ---- HTTP PROBES ----
	flagSet.CreateGroup("http-probes", "HTTP Probes",
		flagSet.BoolVarP(&opts.StatusCode, "status-code", "sc", false, "display response status-code"),
		flagSet.BoolVarP(&opts.ContentLength, "content-length", "cl", false, "display response content-length"),
		flagSet.BoolVarP(&opts.ContentType, "content-type", "ct", false, "display response content-type"),
		flagSet.BoolVar(&opts.Location, "location", false, "display response redirect location"),
		flagSet.BoolVar(&opts.Favicon, "favicon", false, "display mmh3 hash for '/favicon.ico' file"),
		flagSet.StringVar(&opts.Hashes, "hash", "", "display response body hash (supported: md5,mmh3,simhash,sha1,sha256,sha512)"),
		flagSet.BoolVar(&opts.JARM, "jarm", false, "display jarm fingerprint hash"),
		flagSet.BoolVarP(&opts.ResponseTime, "response-time", "rt", false, "display response time"),
		flagSet.BoolVarP(&opts.LineCount, "line-count", "lc", false, "display response body line count"),
		flagSet.BoolVarP(&opts.WordCount, "word-count", "wc", false, "display response body word count"),
		flagSet.BoolVar(&opts.ExtractTitle, "title", false, "display page title"),
		flagSet.IntVarP(&opts.BodyPreview, "body-preview", "bp", 0, "display first N characters of response body (use = syntax: -bp=200 or --body-preview=200)"),
		flagSet.BoolVarP(&opts.WebServer, "web-server", "server", false, "display server name"),
		flagSet.BoolVarP(&opts.TechDetect, "tech-detect", "td", false, "display technology in use based on wappalyzer dataset"),
		flagSet.BoolVar(&opts.HTTPMethod, "method", false, "display http request method"),
		flagSet.BoolVarP(&opts.WebSocket, "websocket", "ws", false, "display server using websocket"),
		flagSet.BoolVar(&opts.OutputIP, "ip", false, "display host ip"),
		// Note: HTTP CNAME data is always available in JSON/CSV output (use -json or -csv)
		flagSet.BoolVar(&opts.ProbeStatus, "probe", false, "display probe status"),
	)

	// ---- HTTP MATCHERS ----
	flagSet.CreateGroup("http-matchers", "HTTP Matchers",
		flagSet.StringVarP(&opts.MatchStatusCode, "match-code", "mc", "", "match response with specified status code (-mc 200,302)"),
		flagSet.StringVarP(&opts.MatchContentLength, "match-length", "ml", "", "match response with specified content length (-ml 100,102)"),
		flagSet.StringSliceVarP(&opts.MatchString, "match-string", "ms", nil, "match response with specified string (-ms admin)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.MatchRegex, "match-regex", "mr", nil, "match response with specified regex (-mr admin)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.MatchCDN, "match-cdn", "mcdn", nil, "match host with specified cdn provider", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&opts.MatchResponseTime, "match-response-time", "mrt", "", "match response with specified response time in seconds (-mrt '< 1')"),
		flagSet.StringVarP(&opts.MatchCondition, "match-condition", "mdc", "", "match response with dsl expression condition"),
	)

	// ---- HTTP FILTERS ----
	flagSet.CreateGroup("http-filters", "HTTP Filters",
		flagSet.StringVarP(&opts.FilterStatusCode, "filter-code", "fc", "", "filter response with specified status code (-fc 403,401)"),
		flagSet.StringVarP(&opts.FilterContentLength, "filter-length", "fl", "", "filter response with specified content length (-fl 23,33)"),
		flagSet.StringSliceVarP(&opts.FilterString, "filter-string", "fs", nil, "filter response with specified string (-fs admin)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.FilterRegex, "filter-regex", "fe", nil, "filter response with specified regex (-fe admin)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.FilterCDN, "filter-cdn", "fcdn", nil, "filter host with specified cdn provider", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&opts.FilterResponseTime, "filter-response-time", "frt", "", "filter response with specified response time in seconds (-frt '> 1')"),
		flagSet.StringVarP(&opts.FilterCondition, "filter-condition", "fdc", "", "filter response with dsl expression condition"),
		flagSet.BoolVarP(&opts.FilterDuplicates, "filter-duplicates", "fd", false, "filter out near-duplicate responses"),
	)

	// ---- HTTP EXTRACTORS ----
	flagSet.CreateGroup("http-extractors", "HTTP Extractors",
		flagSet.StringSliceVarP(&opts.ExtractRegex, "extract-regex", "er", nil, "display response content with matched regex", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.ExtractPreset, "extract-preset", "ep", nil, "display response content matched by a pre-defined regex (mail,url,ipv4)", goflags.NormalizedStringSliceOptions),
	)

	// ---- HTTP ADVANCED ----
	flagSet.CreateGroup("http-advanced", "HTTP Advanced",
		flagSet.StringVarP(&opts.CustomPorts, "ports", "p", "", "ports to probe (nmap syntax: eg http:1,2-10,11,https:80)"),
		flagSet.StringVar(&opts.RequestPaths, "path", "", "path or list of paths to probe (comma-separated, file)"),
		flagSet.StringVar(&opts.RequestMethods, "x", "", "request methods to probe (use 'all' for all HTTP methods)"),
		flagSet.StringVar(&opts.RequestBody, "body", "", "post body to include in http request"),
		flagSet.BoolVar(&opts.TLSProbe, "tls-probe", false, "send http probes on extracted TLS domains (dns_name)"),
		flagSet.BoolVar(&opts.CSPProbe, "csp-probe", false, "send http probes on extracted CSP domains"),
		flagSet.BoolVar(&opts.TLSGrab, "tls-grab", false, "perform TLS(SSL) data grabbing"),
		flagSet.BoolVar(&opts.Pipeline, "pipeline", false, "probe and display server supporting HTTP1.1 pipeline"),
		flagSet.BoolVar(&opts.HTTP2Probe, "http2", false, "probe and display server supporting HTTP2"),
		flagSet.BoolVar(&opts.VHost, "vhost", false, "probe and display server supporting VHOST"),
	)

	// ---- HTTP CONFIGS ----
	flagSet.CreateGroup("http-configs", "HTTP Configurations",
		flagSet.StringSliceVarP(&opts.CustomHeaders, "header", "H", nil, "custom http headers to send with request", goflags.StringSliceOptions),
		flagSet.BoolVar(&opts.RandomAgent, "random-agent", true, "enable Random User-Agent to use"),
		flagSet.BoolVar(&opts.AutoReferer, "auto-referer", false, "set the Referer header to the current URL"),
		flagSet.StringVar(&opts.HTTPProxy, "http-proxy", "", "HTTP/SOCKS proxy (eg http://127.0.0.1:8080)"),
		flagSet.BoolVar(&opts.Unsafe, "unsafe", false, "send raw requests skipping golang normalization"),
		flagSet.BoolVarP(&opts.NoFallback, "no-fallback", "nf", false, "display both probed protocol (HTTPS and HTTP)"),
		flagSet.BoolVarP(&opts.NoFallbackScheme, "no-fallback-scheme", "nfs", false, "probe with protocol scheme specified in input"),
		flagSet.StringVarP(&opts.SniName, "sni-name", "sni", "", "custom TLS SNI name"),
		flagSet.BoolVarP(&opts.FollowRedirects, "follow-redirects", "fr", false, "follow http redirects"),
		flagSet.IntVarP(&opts.MaxRedirects, "max-redirects", "maxr", 10, "max number of redirects to follow per host"),
		flagSet.BoolVarP(&opts.FollowHostRedirects, "follow-host-redirects", "fhr", false, "follow redirects on the same host"),
		flagSet.BoolVar(&opts.NoDecode, "no-decode", false, "avoid decoding body"),
		flagSet.BoolVarP(&opts.LeaveDefaultPorts, "leave-default-ports", "ldp", false, "leave default http/https ports in host header"),
		flagSet.IntVar(&opts.HTTPTimeout, "http-timeout", 10, "timeout in seconds for HTTP requests"),
		flagSet.IntVar(&opts.HTTPRetries, "http-retries", 0, "number of HTTP retries"),
		flagSet.DurationVar(&opts.Delay, "delay", -1, "duration between each http request (eg: 200ms, 1s)"),
	)

	// ---- SUBDOMAIN ----
	flagSet.CreateGroup("subdomain", "Subdomain Discovery",
		flagSet.StringSliceVarP(&opts.Sources, "sources", "", nil, "specific sources to use for discovery", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.ExcludeSources, "exclude-sources", "es", nil, "sources to exclude from enumeration (-es alienvault)", goflags.NormalizedStringSliceOptions),
		flagSet.BoolVar(&opts.OnlyRecursive, "recursive", false, "use only sources that can handle subdomains recursively"),
		flagSet.BoolVar(&opts.AllSources, "all-sources", false, "use all sources for discovery (already default when discovery runs)"),
		flagSet.BoolVarP(&opts.ActiveSubdomain, "active", "nW", false, "display active subdomains only (resolve discovered subs)"),
		flagSet.BoolVarP(&opts.ListSources, "list-sources", "ls", false, "list all available sources"),
		flagSet.BoolVarP(&opts.CaptureSources, "collect-sources", "cs", false, "include all sources in the output (-json only)"),
		flagSet.IntVar(&opts.SubdomainTimeout, "sd-timeout", 30, "seconds to wait before timing out sources"),
		flagSet.IntVar(&opts.MaxEnumTime, "max-time", 10, "minutes to wait for enumeration results"),
		flagSet.BoolVarP(&opts.ExcludeIPs, "exclude-ip", "ei", false, "exclude IPs from the list of domains"),
		flagSet.StringSliceVarP(&opts.MatchSubdomain, "match", "m", nil, "subdomain(s) to match (file or comma separated)", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.FilterSubdomain, "filter", "f", nil, "subdomain(s) to filter (file or comma separated)", goflags.FileNormalizedStringSliceOptions),
	)

	// ---- TAKEOVER ----
	flagSet.CreateGroup("takeover", "Subdomain Takeover",
		flagSet.BoolVarP(&opts.DiscoverTakeover, "discover-takeover", "dt", false, "discover subdomains with all sources, then run takeover checks"),
		flagSet.BoolVarP(&opts.Takeover, "takeover", "tk", false, "run takeover checks on supplied targets only"),
		flagSet.BoolVar(&opts.TakeoverAll, "takeover-all", false, "run all takeover checks on supplied targets (CNAME + NS + HTTP)"),
		flagSet.BoolVar(&opts.TakeoverCheckCNAME, "tk-cname", false, "check CNAME takeover (dangling DNS)"),
		flagSet.BoolVar(&opts.TakeoverCheckNS, "tk-ns", false, "check NS takeover (dangling delegation)"),
		flagSet.BoolVar(&opts.TakeoverCheckHTTP, "tk-http", false, "check HTTP takeover (service fingerprints)"),
	)

	// ---- RATE-LIMIT ----
	flagSet.CreateGroup("rate-limit", "Rate-Limit",
		flagSet.IntVarP(&opts.Threads, "threads", "t", defaultThreads, "number of concurrent threads to use"),
		flagSet.IntVarP(&opts.RateLimit, "rate-limit", "rl", 0, "maximum requests per second (0 = unlimited)"),
		flagSet.IntVarP(&opts.RateLimitMinute, "rate-limit-minute", "rlm", 0, "maximum requests per minute"),
	)

	// ---- UPDATE ----
	flagSet.CreateGroup("update", "Update",
		flagSet.CallbackVarP(GetUpdateCallback(), "update", "up", "update lesgo to latest version"),
		flagSet.BoolVarP(&opts.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic update check"),
	)

	// ---- OUTPUT ----
	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&opts.OutputFile, "output", "o", "", "file to write output results"),
		flagSet.BoolVarP(&opts.JSONOutput, "json", "j", false, "store output in JSONL(ines) format"),
		flagSet.BoolVar(&opts.CSVOutput, "csv", false, "store output in CSV format"),
		flagSet.BoolVarP(&opts.Markdown, "markdown", "md", false, "store output in Markdown table format"),
	)

	// ---- DEBUG ----
	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVarP(&opts.HealthCheck, "hc", "health-check", false, "run diagnostic check up"),
		flagSet.BoolVar(&opts.Silent, "silent", false, "display only results in the output"),
		flagSet.BoolVarP(&opts.Verbose, "verbose", "v", false, "display verbose output"),
		flagSet.BoolVar(&opts.Version, "version", false, "display lesgo version"),
		flagSet.BoolVar(&opts.ShowStats, "stats", false, "display scan statistics"),
		flagSet.IntVarP(&opts.StatsInterval, "stats-interval", "si", 5, "seconds between statistics updates"),
		flagSet.BoolVarP(&opts.NoColor, "no-color", "nc", false, "disable color in CLI output"),
		flagSet.BoolVarP(&opts.Stream, "stream", "s", false, "stream mode - process targets as they arrive"),
	)

	// ---- CONFIGS ----
	flagSet.CreateGroup("configurations", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "path to configuration file"),
		flagSet.StringSliceVarP(&opts.Resolvers, "resolver", "r", nil, "list of custom resolvers (file or comma separated)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVar(&opts.Proxy, "proxy", "", "proxy to use (eg socks5://127.0.0.1:8080 or http://127.0.0.1:8080)"),
		flagSet.BoolVar(&opts.Resume, "resume", false, "resume scan using resume file"),
		flagSet.BoolVarP(&opts.SkipDedupe, "skip-dedupe", "sd", false, "disable deduplication of input items"),
	)

	// Support bare positional domains at the start of args (like httpx).
	// Scan leading args: non-flag items at the beginning are domains.
	// ./lesgo example.com -td  →  Domains=["example.com"], parse -td as flag.
	// Must extract BEFORE flagSet.Parse() because Go 1.26+ flag parsing
	// stops at the first non-flag arg, leaving subsequent flags unparsed.
	var argIdx int
	for argIdx = 1; argIdx < len(os.Args); argIdx++ {
		if strings.HasPrefix(os.Args[argIdx], "-") {
			break
		}
		opts.Domains = append(opts.Domains, os.Args[argIdx])
	}
	if argIdx > 1 {
		// Remove extracted domain args from os.Args so goflags can parse the rest.
		os.Args = append([]string{os.Args[0]}, os.Args[argIdx:]...)
	}

	_ = flagSet.Parse()

	// Collect any remaining positional args after flag parsing as domains.
	// Filter out items starting with "-" that Go 1.26+ left unparsed.
	if args := flagSet.CommandLine.Args(); len(args) > 0 {
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				opts.Domains = append(opts.Domains, a)
			}
		}
	}

	// Merge config file if provided
	if cfgFile != "" {
		if !fileutil.FileExists(cfgFile) {
			gologger.Fatal().Msgf("given config file '%s' does not exist", cfgFile)
		}
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}

	// Configure logging levels
	opts.configureOutput()

	// Show banner (skip in silent mode)
	if !opts.Silent {
		showBanner()
	}

	if opts.Version {
		fmt.Fprintf(os.Stderr, "Current Version: %s\n", Version)
		os.Exit(0)
	}

	if opts.ListSources {
		listAvailableSources()
		os.Exit(0)
	}

	if opts.HealthCheck {
		gologger.Print().Msgf("lesgo health check: OK\n")
		os.Exit(0)
	}

	if !opts.DisableUpdateCheck && !opts.Silent {
		latestVersion, err := updateutils.GetToolVersionCallback("lesgo", Version)()
		if err == nil {
			gologger.Info().Msgf("Current lesgo version %v %v", Version, updateutils.GetVersionDescription(Version, latestVersion))
		}
	}

	// Validate options
	opts.validateOptions()

	return opts
}

// hasDNSFlags returns true if any DNS-specific flags are explicitly set.
func (o *Options) hasDNSFlags() bool {
	return o.A || o.AAAA || o.CNAME || o.NS || o.TXT || o.SRV || o.PTR ||
		o.MX || o.SOA || o.ANY || o.AXFR || o.CAA || o.QueryAll ||
		o.Resp || o.RespOnly || o.RCode != "" || o.RespTypeFilter != "" ||
		o.DNSTrace || o.WildcardDomain != "" || o.HostsFile ||
		len(o.ExcludeType) > 0 || o.CDN || o.ASN || o.DNSRaw ||
		o.WordList != ""
}

// hasHTTPBehaviorFlags returns true if any HTTP behavior flag is explicitly set.
func (o *Options) hasHTTPBehaviorFlags() bool {
	return o.StatusCode || o.ContentLength || o.ContentType || o.Location ||
		o.Favicon || o.Hashes != "" || o.JARM || o.ResponseTime ||
		o.LineCount || o.WordCount || o.ExtractTitle || o.BodyPreview > 0 ||
		o.WebServer || o.TechDetect || o.OutputIP || o.OutputCName ||
		o.OutputCDN != "" || o.ProbeStatus || o.HTTPMethod || o.WebSocket ||
		o.FollowRedirects || o.FollowHostRedirects ||
		o.TLSGrab || o.TLSProbe || o.CSPProbe ||
		o.VHost || o.Pipeline || o.HTTP2Probe ||
		o.MatchStatusCode != "" || o.MatchContentLength != "" ||
		len(o.MatchString) > 0 || len(o.MatchRegex) > 0 ||
		len(o.MatchCDN) > 0 || o.MatchResponseTime != "" || o.MatchCondition != "" ||
		o.FilterStatusCode != "" || o.FilterContentLength != "" ||
		len(o.FilterString) > 0 || len(o.FilterRegex) > 0 ||
		len(o.FilterCDN) > 0 || o.FilterResponseTime != "" ||
		o.FilterCondition != "" || o.FilterDuplicates ||
		len(o.ExtractRegex) > 0 || len(o.ExtractPreset) > 0 ||
		o.CustomPorts != "" || o.RequestPaths != "" || o.RequestMethods != "" ||
		o.RequestBody != "" || len(o.CustomHeaders) > 0 ||
		o.SniName != "" || o.Unsafe || o.NoFallback || o.NoFallbackScheme ||
		o.AutoReferer || o.LeaveDefaultPorts || o.NoDecode ||
		o.HTTPProxy != "" || o.HTTPRetries > 0 || o.Delay > 0 ||
		o.HTTPRateLimit > 0 || o.HTTPRateLimitMinute > 0
}

// hasHTTPFlags returns true if explicit HTTP behavior flags are set.
func (o *Options) hasHTTPFlags() bool {
	return o.hasHTTPBehaviorFlags()
}

// hasSubFlags returns true if any subdomain-specific flags are set.
func (o *Options) hasSubFlags() bool {
	return len(o.Sources) > 0 || o.AllSources || o.OnlyRecursive ||
		o.ActiveSubdomain || o.CaptureSources || o.ExcludeIPs ||
		len(o.MatchSubdomain) > 0 || len(o.FilterSubdomain) > 0
}

// hasTakeoverFlags returns true if any takeover flags are set.
func (o *Options) hasTakeoverFlags() bool {
	return o.Takeover || o.TakeoverAll || o.TakeoverCheckCNAME || o.TakeoverCheckNS || o.TakeoverCheckHTTP
}

func (o *Options) hasInput() bool {
	return len(o.Domains) > 0 || len(o.InputTargets) > 0 || o.InputFile != "" || o.Stdin
}

func (o *Options) hasExplicitEngineFlags() bool {
	return o.hasDNSFlags() || o.hasHTTPBehaviorFlags() || o.hasSubFlags() || o.hasTakeoverFlags() || o.DiscoverTakeover
}

func (o *Options) defaultDiscovery() bool {
	return o.hasInput() && !o.hasExplicitEngineFlags()
}

// RunDNS returns true if DNS engine should run (auto-detected from flags).
func (o *Options) RunDNS() bool {
	return o.hasDNSFlags()
}

// hasDomainInput returns true when domain-type input (not -u targets) is provided,
// which is suitable for subdomain discovery.
func (o *Options) hasDomainInput() bool {
	return len(o.Domains) > 0 || o.InputFile != "" || o.Stdin
}

// RunHTTP returns true if HTTP engine should run.
// By default, HTTP runs for all input (like httpx), showing basic status code.
// DNS-only or takeover-only mode without HTTP flags skips HTTP.
func (o *Options) RunHTTP() bool {
	if !o.hasInput() {
		return o.hasHTTPBehaviorFlags()
	}
	// Skip HTTP in DNS-only or takeover-only mode (unless HTTP flags explicitly set)
	if (o.hasDNSFlags() || o.hasTakeoverFlags() || o.DiscoverTakeover) && !o.hasHTTPBehaviorFlags() {
		return false
	}
	return true
}

// RunSubdomain returns true if subdomain discovery should run.
// By default, subdomain discovery runs for domain-type input (-d, -l, stdin).
// -u (direct targets) or DNS-only mode skip subdomain discovery.
func (o *Options) RunSubdomain() bool {
	if !o.hasInput() {
		return false
	}
	// DiscoverTakeover always runs subdomain discovery regardless of input type
	if o.DiscoverTakeover {
		return true
	}
	// Only run subdomain discovery for domain-type input, not direct -u targets
	if !o.hasDomainInput() {
		return false
	}
	// DNS-only: skip subdomain discovery
	if o.hasDNSFlags() && !o.hasHTTPBehaviorFlags() && !o.hasTakeoverFlags() {
		return false
	}
	// Takeover-only (without -dt): user provides targets directly
	if o.hasTakeoverFlags() && !o.hasHTTPBehaviorFlags() {
		return false
	}
	return true
}

// RunTakeover returns true if takeover engine should run.
func (o *Options) RunTakeover() bool {
	return o.hasTakeoverFlags() || o.DiscoverTakeover
}

// configureOutput configures logging levels.
func (o *Options) configureOutput() {
	if o.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if o.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if o.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

// validateOptions checks for incompatible flags.
func (o *Options) validateOptions() {
	if o.Silent && (o.Verbose) {
		gologger.Fatal().Msg("silent and verbose flags are incompatible")
	}

	// Check for stdin before engine selection.
	o.Stdin = fileutil.HasStdin()

	if !o.hasInput() && !o.ListSources && !o.Version && !o.HealthCheck {
		gologger.Fatal().Msg("no input provided: use -u target, -l file, -d domain, or pipe targets via stdin")
	}

	// Ensure at least some DNS type is enabled when DNS engine runs
	if o.RunDNS() && !o.QueryAll && !o.A && !o.AAAA && !o.CNAME && !o.NS && !o.TXT &&
		!o.SRV && !o.PTR && !o.MX && !o.SOA && !o.ANY && !o.AXFR && !o.CAA {
		// Default to A record
		o.A = true
	}

	// If QueryAll is set, enable all types
	if o.QueryAll {
		o.A = true
		o.AAAA = true
		o.CNAME = true
		o.NS = true
		o.TXT = true
		o.SRV = true
		o.PTR = true
		o.MX = true
		o.SOA = true
		o.CAA = true
		o.Resp = true
	}

	// Handle excludes
	for _, et := range o.ExcludeType {
		switch strings.ToLower(strings.TrimSpace(et)) {
		case "a":
			o.A = false
		case "aaaa":
			o.AAAA = false
		case "cname":
			o.CNAME = false
		case "ns":
			o.NS = false
		case "txt":
			o.TXT = false
		case "srv":
			o.SRV = false
		case "ptr":
			o.PTR = false
		case "mx":
			o.MX = false
		case "soa":
			o.SOA = false
		case "axfr":
			o.AXFR = false
		case "caa":
			o.CAA = false
		case "any":
			o.ANY = false
		}
	}

	// Set DNS timeout
	if o.DNSTimeout == 0 {
		o.DNSTimeout = 3 * time.Second
	}

	// If any CDN matching/filtering is specified, enable CDN output
	if len(o.MatchCDN) > 0 || len(o.FilterCDN) > 0 {
		o.OutputCDN = "true"
	}

	// If response time match/filter is specified, enable response time
	if o.MatchResponseTime != "" || o.FilterResponseTime != "" {
		o.ResponseTime = true
	}

	// Validate numeric fields
	if o.Threads <= 0 {
		if o.Threads < 0 {
			gologger.Fatal().Msgf("threads must be positive, got %d", o.Threads)
		}
		o.Threads = defaultThreads
	}

	if o.HTTPRetries < 0 {
		gologger.Fatal().Msgf("http-retries must be non-negative, got %d", o.HTTPRetries)
	}

	if o.HTTPTimeout <= 0 {
		gologger.Fatal().Msgf("http-timeout must be positive, got %d", o.HTTPTimeout)
	}

	if o.MaxRedirects < 0 {
		gologger.Fatal().Msgf("max-redirects must be non-negative, got %d", o.MaxRedirects)
	}

	if o.StatsInterval <= 0 {
		gologger.Fatal().Msgf("stats-interval must be positive, got %d", o.StatsInterval)
	}

	if o.RateLimit < 0 {
		gologger.Fatal().Msgf("rate-limit must be non-negative, got %d", o.RateLimit)
	}

	if o.RateLimitMinute < 0 {
		gologger.Fatal().Msgf("rate-limit-minute must be non-negative, got %d", o.RateLimitMinute)
	}

	if o.RunSubdomain() && len(o.Sources) == 0 {
		o.AllSources = true
	}

	// Stream mode incompatible with some features
	if o.Stream {
		if o.WordList != "" {
			gologger.Fatal().Msg("wordlist not supported in stream mode")
		}
		if o.Resume {
			gologger.Fatal().Msg("resume not supported in stream mode")
		}
	}
}

// GetUpdateCallback returns the update handler.
func GetUpdateCallback() func() {
	return func() {
		latestVersion, err := updateutils.GetToolVersionCallback("lesgo", Version)()
		if err != nil {
			gologger.Fatal().Msgf("Could not check for updates: %s\n", err)
		}
		if latestVersion != Version {
			gologger.Info().Msgf("New version available: %s (current: %s). Run: go install github.com/0x3n0/lesgo@latest\n", latestVersion, Version)
		} else {
			gologger.Info().Msgf("lesgo is up to date (%s)\n", Version)
		}
		os.Exit(0)
	}
}

// DNSRecordTypes returns the list of enabled DNS record type strings.
func (o *Options) hasRecordType(rtype string) bool {
	switch rtype {
	case "A":
		return o.A
	case "AAAA":
		return o.AAAA
	case "CNAME":
		return o.CNAME
	case "NS":
		return o.NS
	case "TXT":
		return o.TXT
	case "SRV":
		return o.SRV
	case "PTR":
		return o.PTR
	case "MX":
		return o.MX
	case "SOA":
		return o.SOA
	case "ANY":
		return o.ANY
	case "AXFR":
		return o.AXFR
	case "CAA":
		return o.CAA
	}
	return false
}

func (o *Options) DNSRecordTypes() []string {
	var types []string
	if o.A {
		types = append(types, "A")
	}
	if o.AAAA {
		types = append(types, "AAAA")
	}
	if o.CNAME {
		types = append(types, "CNAME")
	}
	if o.NS {
		types = append(types, "NS")
	}
	if o.TXT {
		types = append(types, "TXT")
	}
	if o.SRV {
		types = append(types, "SRV")
	}
	if o.PTR {
		types = append(types, "PTR")
	}
	if o.MX {
		types = append(types, "MX")
	}
	if o.SOA {
		types = append(types, "SOA")
	}
	if o.ANY {
		types = append(types, "ANY")
	}
	if o.AXFR {
		types = append(types, "AXFR")
	}
	if o.CAA {
		types = append(types, "CAA")
	}
	return types
}

// HasProbes returns true if any HTTP probe was requested.
func (o *Options) HasProbes() bool {
	return o.StatusCode || o.ContentLength || o.ContentType || o.Location ||
		o.Favicon || o.Hashes != "" || o.JARM || o.ResponseTime ||
		o.LineCount || o.WordCount || o.ExtractTitle || o.BodyPreview > 0 ||
		o.WebServer || o.TechDetect || o.OutputIP || o.OutputCName ||
		o.OutputCDN != "" || o.WebSocket || o.VHost || o.Pipeline || o.HTTP2Probe
}

// Custom headers as map
func (o *Options) GetCustomHeadersMap() map[string]string {
	result := make(map[string]string)
	for _, h := range o.CustomHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

func (o *Options) ShouldStoreResponse() bool {
	return o.BodyPreview > 0 || o.WebServer || o.ExtractTitle ||
		o.LineCount || o.WordCount || o.TechDetect || o.Favicon ||
		o.Hashes != "" || len(o.ExtractRegex) > 0 || len(o.ExtractPreset) > 0
}

// GetProxy returns the unified proxy (checks HTTP proxy first, then generic proxy).
func (o *Options) GetProxy() string {
	if o.HTTPProxy != "" {
		return o.HTTPProxy
	}
	return o.Proxy
}

// HasMatcherFilter reports whether any matcher or filter is set.
func (o *Options) HasMatcherFilter() bool {
	return !stringsutil.EqualFoldAny(o.MatchStatusCode, "") ||
		!stringsutil.EqualFoldAny(o.MatchContentLength, "") ||
		!stringsutil.EqualFoldAny(o.FilterStatusCode, "") ||
		!stringsutil.EqualFoldAny(o.FilterContentLength, "") ||
		len(o.MatchString) > 0 ||
		len(o.FilterString) > 0 ||
		len(o.MatchRegex) > 0 ||
		len(o.FilterRegex) > 0 ||
		len(o.MatchCDN) > 0 ||
		len(o.FilterCDN) > 0 ||
		o.MatchCondition != "" ||
		o.FilterCondition != "" ||
		o.MatchResponseTime != "" ||
		o.FilterResponseTime != ""
}
