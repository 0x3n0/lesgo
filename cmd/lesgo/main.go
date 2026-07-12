package main

import (
	"github.com/projectdiscovery/gologger"

	"github.com/0x3n0/lesgo/internal/runner"
)

func main() {
	// Parse the command line flags
	options := runner.ParseOptions()

	// Create the runner
	mr, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	defer mr.Close()

	// Run enumeration
	if err := mr.Run(); err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
}
