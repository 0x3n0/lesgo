package runner

import (
	"fmt"
	"os"

	"github.com/projectdiscovery/gologger"
)

// Version is the current version of lesgo.
const Version = "1.2.1"

// Banner is the ASCII banner for lesgo.
const Banner = `
▜
▐ █▌▛▘▛▌▛▌
▐▖▙▖▄▌▙▌▙▌
      ▄▌
`

func listAvailableSources() {
	sources := []struct {
		name     string
		needsKey bool
	}{
		{"crtsh", false},
		{"alienvault", false},
		{"urlscan", false},
		{"certspotter", false},
		{"hackertarget", false},
		{"threatcrowd", false},
		{"waybackarchive", false},
		{"commoncrawl", false},
		{"anubis", false},
		{"bufferover", false},
		{"dnsdumpster", false},
		{"rapiddns", false},
		{"riddler", false},
		{"sitedossier", false},
		{"threatminer", false},
	}

	gologger.Info().Msgf("Available subdomain sources: [%d]\n", len(sources))
	for _, s := range sources {
		key := ""
		if s.needsKey {
			key = " *"
		}
		gologger.Silent().Msgf("%s%s\n", s.name, key)
	}
	gologger.Info().Msgf("\nSources marked with * require API keys.\n")
}

func showBanner() {
	fmt.Fprintf(os.Stderr, "%s\n", Banner)
	fmt.Fprintf(os.Stderr, "      v%s\n\n", Version)
}
