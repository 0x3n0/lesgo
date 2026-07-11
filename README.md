<p align="center">
  <img src="lesgo.png" alt="lesgo" width="600"/>
</p>

Unified reconnaissance toolkit - **DNS**, **HTTP**, **Subdomain Discovery**, and **Takeover**.

> **Full methodology:** [docs/guideline.md](docs/guideline.md)

## Install

```bash
go install github.com/0x3n0/lesgo/cmd/lesgo@latest
```

## Default Behavior

Default (no engine flags): **subdomain discovery + HTTP probing**.

| Input | Engines |
|---|---|
| `lesgo domain.com` (positional) | Subdomain discovery + HTTP probing |
| `cat domains.txt \| lesgo` | Subdomain discovery + HTTP probing |
| `lesgo -l targets.txt` | Subdomain discovery + HTTP probing |
| `lesgo -u https://target.com` | HTTP probing only (no subdomain discovery) |

Use HTTP probe flags to control displayed fields:
- `-sc` → show status code
- `-td` → show tech-detect
- `-title` → show page title
- `-server` → show server header
- Combine any: `-sc -td -title -server -cl`

## Engines

| Mode | How to trigger |
|---|---|
| **Subdomain + HTTP** (default) | Positional domain, stdin, `-l`, or `-d` |
| **DNS only** | `-a`, `-mx`, `-ns`, `-cname`, `-txt`, etc. |
| **Takeover only** | `-tk`, `--takeover-all` |
| **Discovery + Takeover** | `-dt` |

| Flag Category | Example Flags |
|---|---|
| DNS record types | `-a`, `-aaaa`, `-mx`, `-ns`, `-cname`, `-txt`, `-srv`, `-soa`, `-caa`, `-any`, `-recon` |
| HTTP probes | `-sc`, `-td`, `-title`, `-server`, `-cl`, `-ct`, `-ip`, `-rt`, `-lc`, `-wc`, `-favicon`, `-jarm`, `-hash`, `-method`, `-probe` |
| HTTP matchers | `-mc`, `-ml`, `-ms`, `-mr`, `-mcdn`, `-mrt`, `-mdc` |
| HTTP filters | `-fc`, `-fl`, `-fs`, `-fe`, `-fcdn`, `-frt`, `-fdc`, `-fd` |
| HTTP extractors | `-er regex`, `-ep mail,url,ipv4` |
| HTTP advanced | `-tls-grab`, `-tls-probe`, `-csp-probe`, `-p ports`, `-path`, `-x method`, `-pipeline`, `-http2`, `-vhost` |
| HTTP configs | `-H header`, `-http-proxy`, `-fr`, `-fhr`, `-sni`, `-unsafe`, `-no-decode`, `-delay` |
| Subdomain discovery | `-sources`, `-es`, `-nW`, `-cs`, `-ls`, `-m sub`, `-f sub` |
| Takeover | `-dt`, `-tk`, `-tk-cname`, `-tk-ns`, `-tk-html` |
| Output | `-o file`, `-json`, `-csv`, `-md`, `-silent`, `-stats` |
| Speed | `-t N`, `-rl N`, `-delay`, `-http-timeout` |
| Configs | `-r resolvers`, `-config`, `-resume` |

## Quick Examples

```bash
# Default: subdomain discovery + HTTP probing
lesgo example.com -silent
lesgo example.com -sc -td -title -silent
cat domains.txt | lesgo -sc -silent

# DNS - all record types
lesgo example.com -a -mx -ns -cname -txt -cdn -asn -re

# HTTP - tech fingerprinting
lesgo -u hackerone.com -sc -title -server -td -ip -rt

# Takeover
lesgo -u mta-sts.wearehackerone.com -tk -silent

# Discovery, then takeover
lesgo example.com -dt -silent

# One command - everything
lesgo example.com -dt \
      -a -aaaa -cname -ns -txt -mx -caa -cdn -asn -re \
      -sc -title -server -td -ip -rt \
      --takeover-all -silent -json -o full_recon.json
```

## Workflows

```bash
# Quick (~2 min): discover -> HTTP probe
lesgo example.com -sc -td -silent > http.txt

# Standard (~5 min): + takeover
lesgo example.com -dt -silent -json > takeover.json

# Deep (~10 min): + all records + extracts + TLS
lesgo example.com -dt -recon -cdn -asn -re \
      -sc -title -td -server -ip -rt -tls-grab -hash md5,sha256 \
      -ep mail,url \
      --takeover-all -silent -json -o deep_recon.json

# Full probe (~15 min): favicon + jarm + TLS SANs + CSP + pipeline + vhost
lesgo -l subs.txt -favicon -jarm -method -probe \
      -http2 -pipeline -vhost -tls-probe -csp-probe \
      -silent -json -o probes.json

# Through proxy (Burp/ZAP)
lesgo -l targets.txt -sc -title -server -ip -http-proxy http://127.0.0.1:8080 -duc
```

## Flags

| Category | Flags |
|---|---|
| **Input** | positional domain, `-l file`, stdin, `-d domain`, `-u target`, `-w wordlist` |
| **DNS** | `-a`, `-aaaa`, `-cname`, `-mx`, `-ns`, `-txt`, `-srv`, `-ptr`, `-soa`, `-caa`, `-any`, `-recon`, `-cdn`, `-asn`, `-re`, `-ro`, `-trace`, `-raw`, `-rcode` |
| **HTTP Probe** | `-sc`, `-title`, `-server`, `-td`, `-ip`, `-cl`, `-ct`, `-location`, `-rt`, `-lc`, `-wc`, `-favicon`, `-hash`, `-jarm`, `-body-preview=N`, `-ws`, `-probe`, `-method` |
| **HTTP Match** | `-mc`, `-ml`, `-ms`, `-mr`, `-mcdn`, `-mrt`, `-mdc` |
| **HTTP Filter** | `-fc`, `-fl`, `-fs`, `-fe`, `-fcdn`, `-frt`, `-fdc`, `-fd` |
| **HTTP Extract** | `-er regex`, `-ep mail,url,ipv4` |
| **HTTP Advanced** | `-tls-grab`, `-tls-probe`, `-csp-probe`, `-p ports`, `-path`, `-x method`, `-body`, `-pipeline`, `-http2`, `-vhost` |
| **HTTP Config** | `-H header`, `-http-proxy`, `-proxy`, `-fr`, `-fhr`, `-maxr`, `-unsafe`, `-sni`, `-nf`, `-nfs`, `-no-decode`, `-auto-referer`, `-random-agent`, `-delay`, `-http-retries` |
| **Subdomain** | `-sources`, `-es`, `-nW`, `-cs`, `-ls`, `-ei`, `-m`, `-f` |
| **Takeover** | `-dt`, `-tk`, `--takeover-all`, `-tk-cname`, `-tk-ns`, `-tk-http` |
| **Output** | `-o file`, `-json`, `-csv`, `-md`, `-silent`, `-stats`, `-nc` |
| **Speed** | `-t N`, `-rl N`, `-rlm N`, `-delay`, `-http-timeout`, `-stream` |
| **Debug** | `-v`, `-version`, `-health-check`, `-si N`, `-resume`, `-sd` |
| **Other** | `-r resolvers`, `-config`, `-duc` |

> NOTE: Use `=` for value flags: `--body-preview=200` OK | `--body-preview 200` no
