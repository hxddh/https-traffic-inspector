package main

import (
	"net/http"
	"sort"

	"github.com/hxddh/https-traffic-inspector/v2/internal/textsafe"
)

// showSecrets turns off masking in terminal and JSON output (--show-secrets).
// redactCaptures turns it on for --record and --har as well (--redact).
var (
	showSecrets    bool
	redactCaptures bool
)

// displayHeaders and displayURL apply masking for terminal and JSON output.
func displayHeaders(h http.Header) http.Header {
	if showSecrets {
		return h
	}
	return textsafe.MaskHeaders(h)
}

func displayURL(u string) string {
	if showSecrets {
		return u
	}
	return textsafe.MaskURL(u)
}

// captureHeaders and captureURL apply masking for --record and --har, which
// keep credentials unless --redact is set: replay needs them.
func captureHeaders(h http.Header) http.Header {
	if redactCaptures {
		return textsafe.MaskHeaders(h)
	}
	return h
}

func captureURL(u string) string {
	if redactCaptures {
		return textsafe.MaskURL(u)
	}
	return u
}

// sortedKeys returns the header names in h in a stable order, so output does
// not reshuffle between runs or, in the TUI, between redraws.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
