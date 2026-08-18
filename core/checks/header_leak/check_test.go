package headerleak

import (
	"net/netip"
	"testing"

	"github.com/francomano/proxydoctor/core/check"
)

func TestExtractRoutableIPs(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{"single public ipv4", "203.0.113.5", []string{"203.0.113.5"}},
		{"comma separated", "203.0.113.5, 198.51.100.1", []string{"203.0.113.5", "198.51.100.1"}},
		{"forwarded for syntax", "for=203.0.113.5;for=198.51.100.1", []string{"203.0.113.5", "198.51.100.1"}},
		{"quoted in brackets", "[2001:db8::1]", []string{"2001:db8::1"}},
		{"private only", "10.0.0.1, 192.168.1.1", nil},
		{"loopback only", "127.0.0.1, ::1", nil},
		{"link local only", "169.254.1.1", nil},
		{"empty", "", nil},
		{"garbage", "not-an-ip, , ;", nil},
		{"dedupes", "203.0.113.5, 203.0.113.5", []string{"203.0.113.5"}},
	}
	for _, tt := range tests {
		got := extractRoutableIPs(tt.value)
		if !equalSlices(got, tt.want) {
			t.Errorf("%s: extractRoutableIPs(%q) = %v, want %v", tt.name, tt.value, got, tt.want)
		}
	}
}

func TestIsRoutablePublic(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":     true,
		"203.0.113.5": true,
		"2001:db8::1": true,
		"10.0.0.1":    false,
		"192.168.1.1": false,
		"127.0.0.1":   false,
		"::1":         false,
		"169.254.1.1": false,
		"224.0.0.1":   false,
		"0.0.0.0":     false,
	}
	for ip, want := range cases {
		addr := mustParseAddr(t, ip)
		if got := isRoutablePublic(addr); got != want {
			t.Errorf("isRoutablePublic(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestLookupHeaderCaseInsensitive(t *testing.T) {
	headers := map[string]string{
		"X-Forwarded-For": "203.0.113.5",
		"HOST":            "httpbin.org",
	}
	if v, ok := lookupHeader(headers, "x-forwarded-for"); !ok || v != "203.0.113.5" {
		t.Fatalf("case-insensitive lookup of x-forwarded-for failed: %q ok=%v", v, ok)
	}
	if v, ok := lookupHeader(headers, "host"); !ok || v != "httpbin.org" {
		t.Fatalf("case-insensitive lookup of host failed: %q ok=%v", v, ok)
	}
	if _, ok := lookupHeader(headers, "via"); ok {
		t.Fatal("lookup of missing header should return false")
	}
}

func TestEvaluateHeaderLeakClean(t *testing.T) {
	headers := map[string]string{
		"Host":       "httpbin.org",
		"User-Agent": "ProxyDoctor/0.1",
	}
	v := evaluateHeaderLeak(headers, "203.0.113.99")
	if v.status != check.StatusPassed {
		t.Fatalf("expected passed, got %s: %s", v.status, v.explanation)
	}
}

func TestEvaluateHeaderLeakIgnoresExitIP(t *testing.T) {
	headers := map[string]string{
		"Host":            "httpbin.org",
		"X-Forwarded-For": "203.0.113.99",
	}
	v := evaluateHeaderLeak(headers, "203.0.113.99")
	if v.status != check.StatusPassed {
		t.Fatalf("X-Forwarded-For matching exit IP should not be a leak, got %s: %s", v.status, v.explanation)
	}
}

func TestEvaluateHeaderLeakDetectsClientIP(t *testing.T) {
	headers := map[string]string{
		"Host":            "httpbin.org",
		"X-Forwarded-For": "198.51.100.7",
	}
	v := evaluateHeaderLeak(headers, "203.0.113.99")
	if v.status != check.StatusFailed {
		t.Fatalf("expected failed, got %s", v.status)
	}
	if v.severity != check.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", v.severity)
	}
	if !containsStr(v.explanation, "x-forwarded-for=198.51.100.7") {
		t.Errorf("explanation should name the leaking header: %q", v.explanation)
	}
	if len(v.causes) == 0 || len(v.actions) == 0 {
		t.Errorf("expected causes and actions for a leak verdict, got causes=%v actions=%v", v.causes, v.actions)
	}
}

func TestEvaluateHeaderLeakNoExitIPFlagsAnyRoutableIP(t *testing.T) {
	// Without an exit IP to compare against, a routable IP in a leak header is
	// itself the leak signal.
	headers := map[string]string{
		"Host": "httpbin.org",
		"Via":  "1.1 203.0.113.5",
	}
	v := evaluateHeaderLeak(headers, "")
	if v.status != check.StatusFailed {
		t.Fatalf("expected failed when exit IP unknown, got %s", v.status)
	}
}

func TestEvaluateHeaderLeakInternalHostMetadata(t *testing.T) {
	headers := map[string]string{
		"Host": "10.0.0.5:8080",
		"Via":  "1.1 proxy",
	}
	v := evaluateHeaderLeak(headers, "203.0.113.99")
	if v.status != check.StatusFailed {
		t.Fatalf("expected failed, got %s", v.status)
	}
	if !containsStr(v.explanation, "Host=") {
		t.Errorf("explanation should mention Host leak: %q", v.explanation)
	}
}

func TestRevealsInternalNetwork(t *testing.T) {
	cases := map[string]bool{
		"localhost":          true,
		"localhost:8080":     true,
		"file:///etc/passwd": true,
		"10.0.0.5":           true,
		"127.0.0.1":          true,
		"192.168.1.1:443":    true,
		"httpbin.org":        false,
		"93.184.216.34":      false,
		"":                   false,
	}
	for value, want := range cases {
		if got := revealsInternalNetwork(value); got != want {
			t.Errorf("revealsInternalNetwork(%q) = %v, want %v", value, got, want)
		}
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsStr(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func mustParseAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("netip.ParseAddr(%s): %v", s, err)
	}
	return a
}
