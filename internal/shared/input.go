package shared

import (
	"bufio"
	"os"
	"strings"

	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/mapcidr/asn"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
)

// ReadTargets reads targets from file, stdin, or inline comma-separated string.
func ReadTargets(inputFile string, inputTargets []string, stdinMarker string) (chan string, error) {
	out := make(chan string)

	go func() {
		defer close(out)

		// Input from file
		if inputFile != "" && fileutil.FileExists(inputFile) {
			ch, err := fileutil.ReadFile(inputFile)
			if err == nil {
				for line := range ch {
					emitTarget(line, out)
				}
			}
		}

		// Input from command line targets
		for _, target := range inputTargets {
			emitTarget(target, out)
		}

		// Input from stdin (only when no file input and no command-line targets)
		if inputFile == "" && len(inputTargets) == 0 && fileutil.HasStdin() {
			ch, err := fileutil.ReadFileWithReader(os.Stdin)
			if err == nil {
				for line := range ch {
					emitTarget(line, out)
				}
			}
		}
	}()

	return out, nil
}

// emitTarget expands CIDR/ASN and sends individual targets.
func emitTarget(target string, out chan string) {
	target = strings.TrimSpace(target)
	if target == "" {
		return
	}

	switch {
	case iputil.IsCIDR(target):
		ch, err := mapcidr.IPAddressesAsStream(target)
		if err != nil {
			out <- target
			return
		}
		for ip := range ch {
			out <- ip
		}
	case asn.IsASN(target):
		ch, err := asn.GetIPAddressesAsStream(target)
		if err != nil {
			out <- target
			return
		}
		for ip := range ch {
			out <- ip
		}
	default:
		out <- target
	}
}

// ReadLinesFromFile reads all lines from a file into a channel.
func ReadLinesFromFile(filename string) (chan string, error) {
	out := make(chan string)

	go func() {
		defer close(out)
		file, err := os.Open(filename)
		if err != nil {
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				out <- line
			}
		}
	}()

	return out, nil
}
