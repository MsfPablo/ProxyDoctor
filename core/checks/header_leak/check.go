package headerleak

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/francomano/proxydoctor/core/check"
)

const (
	// headersEndpoint echoes back the request headers exactly as the upstream
	// service received them, including any forwarded client-identifying headers.
	headersEndpoint = "https://httpbin.org/headers"
	// ipEndpoint reports the origin (source) IP of the connection, which for a
	// correctly configured proxy is the proxy's exit IP and therefore the
	// address the destination should attribute the request to.
	ipEndpoint = "https://httpbin.org/ip"
)

// leakHeaderNames are the hop-by-hop / forwarded headers that commonly carry
// the client's real IP or internal network metadata when a proxy fails to
// strip them. Lookups are case-insensitive.
var leakHeaderNames = []string{
	"x-forwarded-for",
	"x-real-ip",
	"forwarded",
	"via",
	"x-forwarded-proto",
}

// HeaderLeakCheck detects whether the configured proxy leaks the client's real
// IP address or internal network metadata through forwarded HTTP headers.
type HeaderLeakCheck struct{}

// NewHeaderLeakCheck creates a new HTTP header leak detection check.
func NewHeaderLeakCheck() check.Checker { return &HeaderLeakCheck{} }

func (c *HeaderLeakCheck) ID() string { return "header_leak" }

func (c *HeaderLeakCheck) Name() string { return "HTTP Header Leak Detection" }

func (c *HeaderLeakCheck) Description() string {
	return "Detects whether the configured proxy leaks the client's real IP address or internal network metadata through forwarded HTTP headers like X-Forwarded-For, X-Real-IP, Forwarded and Via"
}

func (c *HeaderLeakCheck) Category() check.CheckCategory { return check.CategoryLeakDetection }

func (c *HeaderLeakCheck) DependsOn() []string { return []string{} }

func (c *HeaderLeakCheck) Execute(ctx check.ExecutionContext) check.CheckResult {
	result := check.NewCheckResult(c.ID(), c.Category())
	startTime := time.Now()

	if ctx.GetProxyConfig().Type == check.ProxyTypeDirect {
		result.SetExecutionTime(time.Since(startTime))
		return *result.WithStatus(check.StatusSkipped, check.SeverityInfo).
			WithExplanation("No proxy or tunnel is configured; header leak detection only applies when traffic is expected to be tunneled").
			WithConfidence(0)
	}

	adapter := ctx.GetProxyAdapter()

	headers, headersErr := fetchEchoHeaders(adapter)
	exitIP, ipErr := fetchExitIP(adapter)

	result.AddEvidence("headers_endpoint", headersEndpoint)
	if headersErr != nil {
		result.AddEvidence("headers_error", headersErr.Error())
	}
	if ipErr != nil {
		result.AddEvidence("ip_endpoint_error", ipErr.Error())
	}

	if headersErr != nil {
		result.SetExecutionTime(time.Since(startTime))
		return *result.WithStatus(check.StatusError, check.SeverityCritical).
			WithExplanation(fmt.Sprintf("Unable to reach the header echo service: %v", headersErr)).
			WithConfidence(0).
			AddProbableCause("Network connectivity issues").
			AddProbableCause("The echo service (httpbin.org) is unreachable through the configured proxy")
	}

	result.AddEvidence("observed_headers", headers)
	if exitIP != "" {
		result.AddEvidence("proxy_exit_ip", exitIP)
	}

	verdict := evaluateHeaderLeak(headers, exitIP)
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

// headerLeakVerdict is the pure, testable outcome of the header leak decision.
type headerLeakVerdict struct {
	status      check.Status
	severity    check.Severity
	explanation string
	confidence  float64
	causes      []string
	actions     []string
}

// evaluateHeaderLeak decides whether the observed forwarded headers expose the
// client's real IP or internal network metadata. exitIP is the proxy's exit
// address as reported by the echo service; when empty, any routable IP found
// in a leak-prone header is treated as a leak (an anonymising proxy should
// strip these headers regardless).
func evaluateHeaderLeak(headers map[string]string, exitIP string) headerLeakVerdict {
	type leak struct {
		header string
		ip     string
	}
	var leaks []leak
	seen := map[string]struct{}{}

	for _, name := range leakHeaderNames {
		val, ok := lookupHeader(headers, name)
		if !ok {
			continue
		}
		for _, ip := range extractRoutableIPs(val) {
			if exitIP != "" && ip == exitIP {
				continue
			}
			key := name + "\x00" + ip
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			leaks = append(leaks, leak{name, ip})
		}
	}

	internalLeaks := internalNetworkLeaks(headers)

	if len(leaks) == 0 && len(internalLeaks) == 0 {
		return headerLeakVerdict{
			status:      check.StatusPassed,
			severity:    check.SeverityInfo,
			explanation: "No client IP or internal network metadata detected in forwarded HTTP headers; the proxy appears to strip or withhold leak-prone headers",
			confidence:  0.8,
		}
	}

	explanation := "The configured proxy exposes identifying information through forwarded HTTP headers"
	severity := check.SeverityWarning
	causes := []string{}
	actions := []string{}

	if len(leaks) > 0 {
		severity = check.SeverityCritical
		pairs := make([]string, len(leaks))
		for i, l := range leaks {
			pairs[i] = fmt.Sprintf("%s=%s", l.header, l.ip)
		}
		explanation = fmt.Sprintf("%s; the following headers carry a non-proxy IP (%s)", explanation, strings.Join(pairs, ", "))
		causes = append(causes,
			"The proxy does not strip or rewrite X-Forwarded-For/X-Real-IP/Forwarded headers before forwarding to the destination",
			"The proxy appends the client's real IP to a hop-by-hop header that the upstream service can read",
		)
		actions = append(actions,
			"Configure the proxy to strip or overwrite X-Forwarded-For, X-Real-IP and Forwarded headers for non-trusted upstreams",
			"Use a proxy that performs header sanitisation at the egress edge",
		)
	}

	if len(internalLeaks) > 0 {
		explanation = fmt.Sprintf("%s; internal network metadata leaked via %s", explanation, strings.Join(internalLeaks, ", "))
		causes = append(causes, "The proxy forwards the original Host or Referer header without rewriting it to the egress origin")
		actions = append(actions, "Rewrite the Host header to the destination origin and suppress or sanitise the Referer header")
	}

	return headerLeakVerdict{
		status:      check.StatusFailed,
		severity:    severity,
		explanation: explanation,
		confidence:  0.85,
		causes:      causes,
		actions:     actions,
	}
}

// fetchEchoHeaders requests the header echo service through the adapter and
// returns the headers exactly as the upstream saw them.
func fetchEchoHeaders(adapter check.NetworkAdapter) (map[string]string, error) {
	resp, err := adapter.ExecuteHTTPRequest(&check.HTTPRequest{
		Method: "GET",
		URL:    headersEndpoint,
		Headers: map[string]string{
			"User-Agent": "ProxyDoctor/0.1",
			"Accept":     "application/json",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", headersEndpoint, err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s returned HTTP %d", headersEndpoint, resp.StatusCode)
	}
	var parsed struct {
		Headers map[string]string `json:"headers"`
	}
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return nil, fmt.Errorf("decode headers response: %w", err)
	}
	return parsed.Headers, nil
}

// fetchExitIP requests the IP echo service through the adapter and returns the
// connection's origin IP (the proxy's exit address). Missing or unparseable
// origins yield an empty string so the caller can fall back to the conservative
// "any routable IP in a leak header is a leak" heuristic.
func fetchExitIP(adapter check.NetworkAdapter) (string, error) {
	resp, err := adapter.ExecuteHTTPRequest(&check.HTTPRequest{
		Method: "GET",
		URL:    ipEndpoint,
		Headers: map[string]string{
			"User-Agent": "ProxyDoctor/0.1",
			"Accept":     "application/json",
		},
	})
	if err != nil {
		return "", fmt.Errorf("request to %s failed: %w", ipEndpoint, err)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s returned HTTP %d", ipEndpoint, resp.StatusCode)
	}
	var parsed struct {
		Origin string `json:"origin"`
	}
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return "", fmt.Errorf("decode ip response: %w", err)
	}
	// Origin may be a comma-separated chain (X-Forwarded-For style); the first
	// entry is the address the echo service attributes the connection to.
	origin := strings.TrimSpace(strings.Split(parsed.Origin, ",")[0])
	if origin == "" {
		return "", nil
	}
	addr, err := netip.ParseAddr(origin)
	if err != nil {
		return "", nil
	}
	return addr.String(), nil
}

// extractRoutableIPs pulls globally routable, non-private IP addresses out of
// a header value. It tolerates comma/semicolon/space-separated lists and the
// "for=<ip>" syntax used by the Forwarded header (RFC 7239).
func extractRoutableIPs(value string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, token := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	}) {
		token = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(token), "for="))
		token = strings.Trim(token, "\"'[] ")
		addr, err := netip.ParseAddr(token)
		if err != nil {
			continue
		}
		if !isRoutablePublic(addr) {
			continue
		}
		s := addr.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// isRoutablePublic reports whether addr is a globally routable public IP,
// excluding loopback, private, link-local, multicast and unspecified ranges.
func isRoutablePublic(addr netip.Addr) bool {
	return addr.IsValid() &&
		!addr.IsLoopback() &&
		!addr.IsPrivate() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast() &&
		!addr.IsMulticast() &&
		!addr.IsUnspecified()
}

// lookupHeader performs a case-insensitive lookup against a header map whose
// keys may use arbitrary casing (echo services canonicalise differently).
func lookupHeader(headers map[string]string, name string) (string, bool) {
	lower := strings.ToLower(name)
	for k, v := range headers {
		if strings.ToLower(k) == lower {
			return v, true
		}
	}
	return "", false
}

// internalNetworkLeaks inspects the Host and Referer headers for values that
// reveal internal network information (private/loopback IPs, localhost, or
// file:// URIs).
func internalNetworkLeaks(headers map[string]string) []string {
	var leaks []string
	if host, ok := lookupHeader(headers, "host"); ok && host != "" && revealsInternalNetwork(host) {
		leaks = append(leaks, "Host="+host)
	}
	if referer, ok := lookupHeader(headers, "referer"); ok && referer != "" && revealsInternalNetwork(referer) {
		leaks = append(leaks, "Referer="+referer)
	}
	return leaks
}

// revealsInternalNetwork reports whether the value contains an internal
// network signal: a file:// URI, a localhost reference, or a non-routable IP.
func revealsInternalNetwork(value string) bool {
	if strings.HasPrefix(strings.ToLower(value), "file://") {
		return true
	}
	if strings.EqualFold(value, "localhost") || strings.HasPrefix(strings.ToLower(value), "localhost:") {
		return true
	}
	for _, token := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '/' || r == ':' || r == '@' || r == '='
	}) {
		addr, err := netip.ParseAddr(token)
		if err != nil {
			continue
		}
		if !isRoutablePublic(addr) {
			return true
		}
	}
	return false
}
