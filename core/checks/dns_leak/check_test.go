package dnsleak

import (
	"reflect"
	"testing"

	"github.com/francomano/proxydoctor/core/check"
)

func TestNormalizeAndSort(t *testing.T) {
	got := normalizeAndSort([]string{
		"203.0.113.5",
		"203.0.113.3",
		"203.0.113.5",
		"invalid",
		"198.51.100.1",
	})
	want := []string{"198.51.100.1", "203.0.113.3", "203.0.113.5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestNormalizeAndSortEmpty(t *testing.T) {
	got := normalizeAndSort(nil)
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestStringSlicesEqual(t *testing.T) {
	tests := []struct {
		a, b []string
		want bool
	}{
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a", "b"}, []string{"b", "a"}, false},
		{[]string{"a"}, []string{"a", "b"}, false},
		{nil, nil, true},
	}
	for _, tt := range tests {
		if got := stringSlicesEqual(tt.a, tt.b); got != tt.want {
			t.Errorf("stringSlicesEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestContainsIP(t *testing.T) {
	ips := []string{"10.0.0.1", "192.168.1.1", "2001:db8::1"}
	if !containsIP(ips, "10.0.0.1") {
		t.Fatal("expected to find 10.0.0.1")
	}
	if !containsIP(ips, "2001:db8::1") {
		t.Fatal("expected to find 2001:db8::1")
	}
	if containsIP(ips, "8.8.8.8") {
		t.Fatal("should not find 8.8.8.8")
	}
	if containsIP(ips, "not-an-ip") {
		t.Fatal("should not match invalid IP")
	}
}

func TestIsDirectIPBogonLoopback(t *testing.T) {
	if !isDirectIPBogon([]string{"127.0.0.1"}, "", "") {
		t.Fatal("127.0.0.1 should be bogon")
	}
}

func TestIsDirectIPBogonLinkLocal(t *testing.T) {
	if !isDirectIPBogon([]string{"169.254.1.1"}, "", "") {
		t.Fatal("169.254.1.1 should be bogon")
	}
}

func TestIsDirectIPBogonMatchesPublicIP(t *testing.T) {
	if !isDirectIPBogon([]string{"203.0.113.10"}, "", "203.0.113.10") {
		t.Fatal("direct IP matching public IP should be bogon")
	}
}

func TestIsDirectIPBogonMatchesProxyHost(t *testing.T) {
	if !isDirectIPBogon([]string{"10.0.0.5"}, "10.0.0.5", "") {
		t.Fatal("direct IP matching proxy host should be bogon")
	}
}

func TestIsDirectIPBogonPublicRoutable(t *testing.T) {
	if isDirectIPBogon([]string{"93.184.216.34"}, "10.0.0.1", "203.0.113.10") {
		t.Fatal("distinct public IP should not be bogon")
	}
}

func TestEvaluateDNSLeakBothFail(t *testing.T) {
	v := evaluateDNSLeak("example.com", nil, nil,
		fmtError("direct failed"), fmtError("proxy failed"), "", "")
	if v.status != check.StatusError {
		t.Fatalf("expected error status, got %+v", v)
	}
}

func TestEvaluateDNSLeakProxyFailsDirectOk(t *testing.T) {
	v := evaluateDNSLeak("example.com", nil, []string{"93.184.216.34"},
		fmtError("proxy failed"), nil, "203.0.113.10", "10.0.0.1")
	if v.status != check.StatusError {
		t.Fatalf("expected error, got %+v", v)
	}
}

func TestEvaluateDNSLeakNoProxyRecords(t *testing.T) {
	v := evaluateDNSLeak("example.com", []string{}, []string{"93.184.216.34"},
		nil, nil, "203.0.113.10", "10.0.0.1")
	if v.status != check.StatusFailed {
		t.Fatalf("expected failed, got %+v", v)
	}
}

func TestEvaluateDNSLeakSameIPsLeaking(t *testing.T) {
	v := evaluateDNSLeak("example.com",
		[]string{"93.184.216.34"}, []string{"93.184.216.34"},
		nil, nil, "203.0.113.10", "10.0.0.1")
	if v.status != check.StatusFailed || v.severity != check.SeverityCritical {
		t.Fatalf("expected failed+critical, got %+v", v)
	}
	if len(v.causes) == 0 || len(v.actions) == 0 {
		t.Fatalf("expected causes and actions")
	}
}

func TestEvaluateDNSLeakSameBogonIPsNoLeak(t *testing.T) {
	v := evaluateDNSLeak("example.com",
		[]string{"127.0.0.53"}, []string{"127.0.0.53"},
		nil, nil, "203.0.113.10", "10.0.0.1")
	if v.status != check.StatusPassed {
		t.Fatalf("expected passed, got %+v", v)
	}
}

func TestEvaluateDNSLeakDifferentIPsNoLeak(t *testing.T) {
	v := evaluateDNSLeak("example.com",
		[]string{"10.0.0.100"}, []string{"93.184.216.34"},
		nil, nil, "203.0.113.10", "10.0.0.1")
	if v.status != check.StatusPassed || v.severity != check.SeverityInfo {
		t.Fatalf("expected passed+info, got %+v", v)
	}
}

func TestEvaluateDNSLeakProxyResolvesToPublicIP(t *testing.T) {
	v := evaluateDNSLeak("example.com",
		[]string{"203.0.113.10"}, []string{"93.184.216.34"},
		nil, nil, "203.0.113.10", "10.0.0.1")
	if v.status != check.StatusFailed || v.severity != check.SeverityCritical {
		t.Fatalf("expected failed+critical for public IP match, got %+v", v)
	}
}

func TestEvaluateDNSLeakDirectFailsProxyOk(t *testing.T) {
	v := evaluateDNSLeak("example.com",
		[]string{"93.184.216.34"}, nil,
		nil, fmtError("direct failed"), "203.0.113.10", "10.0.0.1")
	if v.status != check.StatusPassed {
		t.Fatalf("expected passed (direct failure is ok when proxied), got %+v", v)
	}
}

type errStr string

func (e errStr) Error() string { return string(e) }

func fmtError(s string) error { return errStr(s) }
