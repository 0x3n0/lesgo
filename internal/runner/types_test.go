package runner

import (
	"strings"
	"testing"
	"time"

	enginehttp "github.com/0x3n0/lesgo/internal/engine/http"
)

func TestCSVRowEscapesFields(t *testing.T) {
	result := &Result{
		Timestamp: time.Unix(0, 0).UTC(),
		URL:       "https://example.com",
		Title:     "alpha,beta\nnext",
		Server:    "unit",
	}

	row := result.CSVRow()
	if !strings.Contains(row, "\"alpha,beta\nnext\"") {
		t.Fatalf("CSV row did not quote comma/newline field: %q", row)
	}
}

func TestMarkdownRowEscapesPipesAndNewlines(t *testing.T) {
	result := &Result{
		URL:   "https://example.com/a|b",
		Title: "line1\nline2|x",
	}

	row := result.MarkdownRow()
	if strings.Contains(row, "line1\nline2") {
		t.Fatalf("markdown row contains raw newline: %q", row)
	}
	if !strings.Contains(row, `a\|b`) || !strings.Contains(row, `line2\|x`) {
		t.Fatalf("markdown row did not escape pipes: %q", row)
	}
}

func TestHTTPResultJSONUsesPreviewAndOmitsFullBody(t *testing.T) {
	runner := &Runner{options: &Options{BodyPreview: 6}}
	result := runner.convertHTTPResult(&enginehttp.Result{
		URL:        "https://example.com",
		Host:       "example.com",
		Body:       "secret-full-body",
		StatusCode: 200,
	})

	data := result.JSON()
	if strings.Contains(data, "response_body") || strings.Contains(data, "secret-full-body") {
		t.Fatalf("JSON leaked full response body: %s", data)
	}
	if !strings.Contains(data, `"body_preview":"secret"`) {
		t.Fatalf("JSON did not include expected body preview: %s", data)
	}
}
