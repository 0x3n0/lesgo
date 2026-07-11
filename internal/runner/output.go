package runner

import (
	"bufio"
	"os"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// OutputWriter handles writing results to files and stdout.
type OutputWriter struct {
	options   *Options
	plainFile *os.File
	jsonFile  *os.File
	csvFile   *os.File
	mdFile    *os.File
	mu        sync.Mutex
	mdWritten bool
}

// NewOutputWriter creates a new output writer.
func NewOutputWriter(opts *Options) (*OutputWriter, error) {
	w := &OutputWriter{options: opts}

	if opts.OutputFile != "" {
		var err error

		// Plain text file
		if !opts.JSONOutput && !opts.CSVOutput && !opts.Markdown {
			w.plainFile, err = os.OpenFile(opts.OutputFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				return nil, err
			}
		}

		// JSON file
		if opts.JSONOutput {
			w.jsonFile, err = os.OpenFile(opts.OutputFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				return nil, err
			}
		}

		// CSV file
		if opts.CSVOutput {
			w.csvFile, err = os.OpenFile(opts.OutputFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				return nil, err
			}
			header := Result{}.CSVHeader()
			w.csvFile.WriteString(header + "\n")
		}

		// Markdown file
		if opts.Markdown {
			w.mdFile, err = os.OpenFile(opts.OutputFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				return nil, err
			}
		}
	}

	return w, nil
}

// Write writes a result to the appropriate outputs.
func (w *OutputWriter) Write(result *Result) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if result == nil {
		return
	}

	// Print to stdout — gologger.Silent bypasses level filters
	if w.options.JSONOutput && w.options.OutputFile == "" {
		gologger.Silent().Msgf("%s\n", result.JSON())
	} else if w.options.CSVOutput && w.options.OutputFile == "" {
		gologger.Silent().Msgf("%s\n", result.CSVRow())
	} else if result.Str() != "" {
		gologger.Silent().Msgf("%s\n", result.Str())
	}

	// Markdown to stdout if no output file
	if w.options.Markdown && w.options.OutputFile == "" {
		if !w.mdWritten {
			gologger.Silent().Msgf("%s", result.MarkdownHeader())
			w.mdWritten = true
		}
		gologger.Silent().Msgf("%s", result.MarkdownRow())
	}

	// Write to files
	if w.plainFile != nil && result.Str() != "" {
		w.plainFile.WriteString(result.Str() + "\n")
	}

	if w.jsonFile != nil {
		w.jsonFile.WriteString(result.JSON() + "\n")
	}

	if w.csvFile != nil {
		w.csvFile.WriteString(result.CSVRow() + "\n")
	}

	if w.mdFile != nil {
		if !w.mdWritten {
			w.mdFile.WriteString(result.MarkdownHeader())
			w.mdWritten = true
		}
		w.mdFile.WriteString(result.MarkdownRow())
	}
}

// Close closes all open files.
func (w *OutputWriter) Close() {
	if w.plainFile != nil {
		w.plainFile.Close()
	}
	if w.jsonFile != nil {
		w.jsonFile.Close()
	}
	if w.csvFile != nil {
		w.csvFile.Close()
	}
	if w.mdFile != nil {
		w.mdFile.Close()
	}
}

// WriteToFile writes a single line to a buffered file.
func WriteToFile(f *os.File, w *bufio.Writer, data string) {
	if f != nil && w != nil {
		w.WriteString(data + "\n")
	}
}

// FlushFile flushes the buffered writer.
func FlushFile(f *os.File, w *bufio.Writer) {
	if w != nil {
		w.Flush()
	}
}
