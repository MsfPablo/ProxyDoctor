package commands

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestCompleteCheckFiltersReturnsIDsCategoriesAndAll guards #22: tab-completing
// --checks offers the default check IDs, their categories, and the literal
// "all" — not file completion. The default registry is the common case; plugins
// add more but are opt-in.
func TestCompleteCheckFiltersReturnsIDsCategoriesAndAll(t *testing.T) {
	got, dir := completeCheckFilters(nil, nil, "")
	if dir != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("got directive %v, want NoFileComp", dir)
	}
	for _, want := range []string{"all", "public_ip", "dns_resolve"} {
		if !contains(got, want) {
			t.Errorf("check-filter completions missing %q; got %v", want, got)
		}
	}
	// At least one category must be offered alongside the IDs.
	if !sort.StringsAreSorted(got) {
		t.Errorf("expected sorted completions for stable shell display, got %v", got)
	}
}

// TestCompleteCheckFiltersPrefixFilters verifies the helper narrows to the
// segment the cursor is on.
func TestCompleteCheckFiltersPrefixFilters(t *testing.T) {
	got, _ := completeCheckFilters(nil, nil, "dns")
	for _, c := range got {
		if !strings.HasPrefix(c, "dns") {
			t.Errorf("prefix-filter leaked non-matching candidate %q", c)
		}
	}
	if !contains(got, "dns_resolve") {
		t.Errorf("expected dns_resolve in prefix-filtered results, got %v", got)
	}
	if contains(got, "public_ip") {
		t.Errorf("public_ip should not match prefix \"dns\", got %v", got)
	}
}

// TestCompleteCheckFiltersCommaSeparated completes only the final segment of a
// comma-separated --checks value, preserving the already-typed prefix.
func TestCompleteCheckFiltersCommaSeparated(t *testing.T) {
	got, _ := completeCheckFilters(nil, nil, "public_ip,dns")
	for _, c := range got {
		if !strings.HasPrefix(c, "public_ip,dns") {
			t.Errorf("comma completion dropped the typed prefix: %q", c)
		}
	}
	if !contains(got, "public_ip,dns_resolve") {
		t.Errorf("expected public_ip,dns_resolve, got %v", got)
	}
}

// TestCompleteExportFormat enumerates the four supported formats.
func TestCompleteExportFormat(t *testing.T) {
	got, dir := completeExportFormat(nil, nil, "")
	if dir != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("got directive %v, want NoFileComp", dir)
	}
	for _, want := range []string{"text", "json", "html", "markdown"} {
		if !contains(got, want) {
			t.Errorf("export completions missing %q, got %v", want, got)
		}
	}
}

// TestCompleteProxyType enumerates the five accepted proxy types.
func TestCompleteProxyType(t *testing.T) {
	got, dir := completeProxyType(nil, nil, "")
	if dir != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("got directive %v, want NoFileComp", dir)
	}
	for _, want := range []string{"auto", "http", "https", "socks4", "socks5"} {
		if !contains(got, want) {
			t.Errorf("proxy-type completions missing %q, got %v", want, got)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}