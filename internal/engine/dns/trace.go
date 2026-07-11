package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Trace performs DNS tracing for a host, following the delegation chain.
func (e *Engine) Trace(host string) (*TraceData, error) {
	// Set an overall deadline for the entire trace
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	host = strings.TrimSuffix(strings.TrimSpace(host), ".")

	// Start with root servers
	rootServers := []string{
		"198.41.0.4:53",    // a.root-servers.net
		"199.9.14.201:53",  // b.root-servers.net
	}

	trace := &TraceData{
		Host: host,
	}

	// Create a tracing client
	client := &dns.Client{
		Timeout: e.opts.Timeout,
	}

	currentServers := rootServers
	maxRecursion := e.opts.TraceMaxRecursion
	if maxRecursion <= 0 {
		maxRecursion = 255
	}

	for i := 0; i < maxRecursion; i++ {
		// Query each server at the current level
		var nextNS []string
		var found bool

		// Check overall context timeout
		select {
		case <-ctx.Done():
			return trace, nil
		default:
		}

		// Query the first responsive server at this level for delegation info
		for _, server := range currentServers {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(host), dns.TypeA)
			m.RecursionDesired = false

			resp, _, err := client.Exchange(m, server)
			if err != nil {
				continue
			}

			ts := TraceServer{
				Server:    server,
				QueryType: "A",
				Response:  dns.RcodeToString[resp.Rcode],
			}
			trace.Servers = append(trace.Servers, ts)

			// If we got an answer, we're done
			if len(resp.Answer) > 0 {
				for _, ans := range resp.Answer {
					if a, ok := ans.(*dns.A); ok {
						ts.Response = fmt.Sprintf("ANSWER: %s", a.A.String())
					}
				}
				found = true
				break
			}

			// Collect NS records from authority section for next iteration
			for _, ns := range resp.Ns {
				if nsRec, ok := ns.(*dns.NS); ok {
					nextNS = append(nextNS, nsRec.Ns)
				}
			}

			// Also check additional section for glue records
			for _, extra := range resp.Extra {
				switch r := extra.(type) {
				case *dns.A:
					nextNS = append(nextNS, r.A.String())
				case *dns.AAAA:
					nextNS = append(nextNS, r.AAAA.String())
				}
			}

			// Got delegation info — proceed to next level
			break
		}

		if found {
			break
		}

		if len(nextNS) == 0 {
			break
		}

		// Resolve NS names to IPs for the next iteration
		var resolvedNS []string
		select {
		case <-ctx.Done():
			return trace, nil
		default:
		}

		for _, ns := range nextNS {
			ns = strings.TrimSuffix(ns, ".")
			// Check if this is already an IP address (glue record)
			if ip := net.ParseIP(ns); ip != nil {
				resolvedNS = append(resolvedNS, ip.String()+":53")
				continue
			}
			ips := e.LookupIP(ns)
			for _, ip := range ips {
				resolvedNS = append(resolvedNS, ip.String()+":53")
			}
		}

		if len(resolvedNS) == 0 {
			break
		}

		currentServers = resolvedNS
	}

	return trace, nil
}
