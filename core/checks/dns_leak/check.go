package dnsleak

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"time"

	"github.com/francomano/proxydoctor/core/check"
)

type DNSLeakCheck struct{}

func NewDNSLeakCheck() check.Checker { return &DNSLeakCheck{} }

func (c *DNSLeakCheck) ID() string   { return "dns_leak" }
func (c *DNSLeakCheck) Name() string { return "DNS Leak Detection" }
func (c *DNSLeakCheck) Description() string {
	return "Compares DNS resolution through direct and proxied paths to detect potential DNS leaks"
}
func (c *DNSLeakCheck) Category() check.CheckCategory { return check.CategoryLeakDetection }
func (c *DNSLeakCheck) DependsOn() []string           { return []string{"dns_resolve", "public_ip"} }

func (c *DNSLeakCheck) Execute(ctx check.ExecutionContext) check.CheckResult {
	result := check.NewCheckResult(c.ID(), c.Category())
	startTime := time.Now()

	if ctx.GetProxyConfig().Type == check.ProxyTypeDirect {
		result.SetExecutionTime(time.Since(startTime))
		return *result.WithStatus(check.StatusSkipped, check.SeverityInfo).
			WithExplanation("No proxy configured; DNS leak detection only applies when using a proxy/tunnel").
			WithConfidence(0)
	}

	parsed, err := url.Parse(ctx.GetURL())
	if err != nil {
		result.SetExecutionTime(time.Since(startTime))
		return *result.WithStatus(check.StatusError, check.SeverityCritical).
			WithExplanation(fmt.Sprintf("Invalid URL: %v", err)).
			WithConfidence(0)
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		result.SetExecutionTime(time.Since(startTime))
		return *result.WithStatus(check.StatusError, check.SeverityCritical).
			WithExplanation("Invalid URL: missing hostname").
			WithConfidence(0)
	}

	proxyIPs, proxyErr := ctx.GetProxyAdapter().ResolveDNS(hostname)
	directIPs, directErr := ctx.GetDirectAdapter().ResolveDNS(hostname)

	proxyIPSet := normalizeAndSort(proxyIPs)
	directIPSet := normalizeAndSort(directIPs)

	result.AddEvidence("hostname", hostname).
		AddEvidence("proxy_dns_results", proxyIPSet).
		AddEvidence("direct_dns_results", directIPSet).
		AddEvidence("proxy_dns_error", errorString(proxyErr)).
		AddEvidence("direct_dns_error", errorString(directErr))

	publicIP, _ := ctx.GetSharedData("public_ip").(string)
	proxyHost := ctx.GetProxyConfig().Host
	if proxyHost != "" {
		result.AddEvidence("proxy_host", proxyHost)
	}
	result.AddEvidence("public_ip", publicIP)

	verdict := evaluateDNSLeak(hostname, proxyIPSet, directIPSet, proxyErr, directErr, publicIP, proxyHost)
	result.SetExecutionTime(time.Since(startTime))

	result.WithStatus(verdict.status, verdict.severity).
		WithExplanation(verdict.explanation).
		WithConfidence(verdict.confidence)
	for _, cause := range verdict.causes {
		result.AddProbableCause(cause)
	}
	for _, action := range verdict.actions {
		result.AddSuggestedAction(action)
	}

	return *result
}

type leakVerdict struct {
	status      check.Status
	severity    check.Severity
	explanation string
	confidence  float64
	causes      []string
	actions     []string
}

func evaluateDNSLeak(
	hostname string,
	proxyIPs, directIPs []string,
	proxyErr, directErr error,
	publicIP, proxyHost string,
) leakVerdict {
	if proxyErr != nil && directErr != nil {
		return leakVerdict{
			status:      check.StatusError,
			severity:    check.SeverityWarning,
			explanation: fmt.Sprintf("DNS resolution failed through both direct and proxy paths for %s", hostname),
			confidence:  0,
		}
	}

	if proxyErr != nil {
		return leakVerdict{
			status:      check.StatusError,
			severity:    check.SeverityWarning,
			explanation: fmt.Sprintf("DNS resolution failed through the proxy for %s: %v", hostname, proxyErr),
			confidence:  0.5,
		}
	}

	if directErr != nil {
		return leakVerdict{
			status:      check.StatusPassed,
			severity:    check.SeverityInfo,
			explanation: fmt.Sprintf("DNS resolution through direct path failed (expected when all traffic is tunneled); proxy resolved %s successfully", hostname),
			confidence:  0.7,
		}
	}

	if len(proxyIPs) == 0 {
		return leakVerdict{
			status:      check.StatusFailed,
			severity:    check.SeverityCritical,
			explanation: fmt.Sprintf("No DNS records found through the proxy for %s", hostname),
			confidence:  0.9,
		}
	}

	ipsMatch := stringSlicesEqual(proxyIPs, directIPs)

	if ipsMatch && !isDirectIPBogon(directIPs, proxyHost, publicIP) {
		return leakVerdict{
			status:      check.StatusFailed,
			severity:    check.SeverityCritical,
			explanation: fmt.Sprintf(
				"DNS leak detected: the proxy and direct adapters resolved %s to the same IP(s) %v, suggesting DNS queries are bypassing the proxy and being resolved locally",
				hostname, proxyIPs,
			),
			confidence: 0.85,
			causes: []string{
				"The proxy client is not routing DNS queries through the tunnel",
				"The system is configured to use local/resolver DNS that is not proxied",
				"The proxy protocol does not support remote DNS resolution",
			},
			actions: []string{
				"Configure the proxy client to route DNS queries through the tunnel",
				"Use a proxy protocol that supports remote DNS resolution (e.g., SOCKS5 with remote DNS)",
				"Disable local DNS resolvers and force all DNS through the proxy",
			},
		}
	}

	if ipsMatch && isDirectIPBogon(directIPs, proxyHost, publicIP) {
		return leakVerdict{
			status:      check.StatusPassed,
			severity:    check.SeverityInfo,
			explanation: fmt.Sprintf(
				"No DNS leak detected: both paths resolved %s to %v, but these appear to be private/reserved addresses consistent with local resolution behind the proxy",
				hostname, proxyIPs,
			),
			confidence: 0.75,
		}
	}

	proxyIsDirect := !ipsMatch && publicIP != "" && containsIP(proxyIPs, publicIP)
	if proxyIsDirect {
		return leakVerdict{
			status:      check.StatusFailed,
			severity:    check.SeverityCritical,
			explanation: fmt.Sprintf(
				"DNS leak detected: the proxy adapter resolved %s to %v which matches the public IP %s, indicating DNS is resolved through the local network and not the proxy tunnel",
				hostname, proxyIPs, publicIP,
			),
			confidence: 0.9,
			causes: []string{
				"The proxy is forwarding DNS queries to the local network instead of its own resolver",
				"DNS queries are leaking outside the encrypted tunnel",
			},
			actions: []string{
				"Force DNS resolution through the proxy's internal resolver",
				"Use a different proxy configuration that supports tunnel DNS resolution",
			},
		}
	}

	return leakVerdict{
		status:      check.StatusPassed,
		severity:    check.SeverityInfo,
		explanation: fmt.Sprintf(
			"No DNS leak detected: the proxy resolved %s to %v while direct resolution returned %v, indicating DNS queries are routed through the proxy",
			hostname, proxyIPs, directIPs,
		),
		confidence: 0.8,
	}
}

func normalizeAndSort(ips []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(ips))
	for _, raw := range ips {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		s := addr.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}

func stringSlicesEqual(a, b []string) bool {
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

func containsIP(ips []string, target string) bool {
	addr, err := netip.ParseAddr(target)
	if err != nil {
		return false
	}
	for _, raw := range ips {
		parsed, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if parsed == addr {
			return true
		}
	}
	return false
}

func isDirectIPBogon(ips []string, proxyHost, publicIP string) bool {
	proxyAddr, _ := netip.ParseAddr(proxyHost)
	for _, raw := range ips {
		parsed, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
			return true
		}
		if proxyAddr.IsValid() && parsed == proxyAddr {
			return true
		}
		if publicIP != "" {
			pubAddr, err := netip.ParseAddr(publicIP)
			if err == nil && parsed == pubAddr {
				return true
			}
		}
	}
	return false
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
