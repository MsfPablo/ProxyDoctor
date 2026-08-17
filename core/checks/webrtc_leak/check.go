package webrtcleak

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/francomano/proxydoctor/core/check"
)

const (
	stunBindingRequest uint16 = 0x0001
	stunAttrXORMapped uint16 = 0x0020
	stunAttrMapped    uint16 = 0x0001
	magicCookie       uint32 = 0x2112A442
)

type stunServer struct {
	Name string
	Addr string
}

var defaultSTUNServers = []stunServer{
	{Name: "Google", Addr: "stun.l.google.com:19302"},
	{Name: "Twilio", Addr: "stun1.l.google.com:19302"},
	{Name: "Numb", Addr: "numb.viagenie.ca:3478"},
}

type WebRTCLeakCheck struct{}

func NewWebRTCLeakCheck() check.Checker { return &WebRTCLeakCheck{} }

func (c *WebRTCLeakCheck) ID() string   { return "webrtc_leak" }
func (c *WebRTCLeakCheck) Name() string { return "WebRTC Leak Detection" }
func (c *WebRTCLeakCheck) Description() string {
	return "Probes STUN servers to detect whether WebRTC ICE gathering could expose the real IP address while a proxy is in use"
}
func (c *WebRTCLeakCheck) Category() check.CheckCategory { return check.CategoryLeakDetection }
func (c *WebRTCLeakCheck) DependsOn() []string           { return []string{"public_ip"} }

func (c *WebRTCLeakCheck) Execute(ctx check.ExecutionContext) check.CheckResult {
	result := check.NewCheckResult(c.ID(), c.Category())
	startTime := time.Now()

	if ctx.GetProxyConfig().Type == check.ProxyTypeDirect {
		result.SetExecutionTime(time.Since(startTime))
		return *result.WithStatus(check.StatusSkipped, check.SeverityInfo).
			WithExplanation("No proxy configured; WebRTC leak detection only applies when using a proxy/tunnel").
			WithConfidence(0)
	}

	proxyPublicIP, _ := ctx.GetSharedData("public_ip").(string)
	if proxyPublicIP == "" {
		proxyPublicIP, _ = ctx.GetProxyAdapter().GetPublicIP()
	}
	result.AddEvidence("proxy_public_ip", proxyPublicIP)

	timeout := ctx.GetTimeout()
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	stunTimeout := timeout / 2
	if stunTimeout > 5*time.Second {
		stunTimeout = 5 * time.Second
	}

	discoveredIPs, probeErrors := probeSTUNServers(stunTimeout)
	result.AddEvidence("stun_discovered_ips", discoveredIPs).
		AddEvidence("stun_probe_errors", probeErrors)

	directPublicIP, directErr := ctx.GetDirectAdapter().GetPublicIP()
	if directErr == nil {
		result.AddEvidence("direct_public_ip", directPublicIP)
	} else {
		result.AddEvidence("direct_public_ip_error", directErr.Error())
	}

	localIPv4, localIPv6 := detectLocalCandidates(timeout)
	result.AddEvidence("local_ipv4_candidates", localIPv4).
		AddEvidence("local_ipv6_candidates", localIPv6)

	verdict := evaluateWebRTCLeak(proxyPublicIP, directPublicIP, discoveredIPs, localIPv4, localIPv6)
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
	for _, ref := range verdict.refs {
		result.AddReference(ref)
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
	refs        []string
}

func evaluateWebRTCLeak(proxyPublicIP, directPublicIP string, stunIPs, localIPv4, localIPv6 []string) leakVerdict {
	proxyAddr, proxyErr := netip.ParseAddr(proxyPublicIP)
	directAddr, directErr := netip.ParseAddr(directPublicIP)
	proxyOK := proxyErr == nil
	directOK := directErr == nil

	if proxyOK && directOK && proxyAddr == directAddr {
		return leakVerdict{
			status:      check.StatusPassed,
			severity:    check.SeverityInfo,
			explanation: "Proxy and direct public IPs match; no WebRTC leak concern detected at the IP level",
			confidence:  0.7,
		}
	}

	if !proxyOK && !directOK {
		return leakVerdict{
			status:      check.StatusError,
			severity:    check.SeverityWarning,
			explanation: "Could not determine public IPs to compare for WebRTC leak analysis",
			confidence:  0,
		}
	}

	stunMatchesDirect := false
	for _, raw := range stunIPs {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if directOK && addr == directAddr {
			stunMatchesDirect = true
			break
		}
	}

	if stunMatchesDirect {
		return leakVerdict{
			status:   check.StatusFailed,
			severity: check.SeverityCritical,
			explanation: fmt.Sprintf(
				"WebRTC leak detected: STUN probing discovered %s which matches the direct public IP (not the proxy IP %s). WebRTC ICE gathering would expose the real IP address",
				directPublicIP, proxyPublicIP,
			),
			confidence: 0.9,
			causes: []string{
				"WebRTC ICE gathering uses STUN over UDP which bypasses most TCP-based proxies",
				"The browser or system allows direct UDP traffic to STUN servers outside the proxy tunnel",
			},
			actions: []string{
				"Disable WebRTC in the browser or use a browser extension that blocks WebRTC leaks",
				"Configure the proxy/tunnel to also forward UDP traffic (e.g., SOCKS5 with UDP associate)",
				"Use a firewall rule to block outbound STUN traffic (UDP port 3478) when the proxy is active",
			},
			refs: []string{
				"https://github.com/nicedoc/webRTC-leak",
				"https://www.whatsmyip.org/webrtc-leak/",
			},
		}
	}

	hasLocalPrivate := false
	for _, raw := range localIPv4 {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsPrivate() {
			hasLocalPrivate = true
			break
		}
	}
	if hasLocalPrivate {
		return leakVerdict{
			status:   check.StatusFailed,
			severity: check.SeverityWarning,
			explanation: fmt.Sprintf(
				"Potential WebRTC leak: local network candidates %v discovered; WebRTC may expose internal network topology through ICE gathering",
				localIPv4,
			),
			confidence: 0.75,
			causes: []string{
				"WebRTC ICE includes local network interface IPs as candidates",
				"These local IPs can reveal internal network topology to remote peers",
			},
			actions: []string{
				"Disable WebRTC or configure it to only use relay (TURN) candidates",
				"Use a browser extension to restrict ICE candidates to relay-only",
			},
		}
	}

	stunIPList := make([]string, 0, len(stunIPs))
	for _, raw := range stunIPs {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		stunIPList = append(stunIPList, addr.String())
	}

	return leakVerdict{
		status:   check.StatusPassed,
		severity: check.SeverityInfo,
		explanation: fmt.Sprintf(
			"No WebRTC IP leak detected: STUN probing found %v (proxy IP: %s, direct IP: %s); WebRTC ICE gathering would not expose the real IP",
			stunIPList, proxyPublicIP, directPublicIP,
		),
		confidence: 0.8,
		refs: []string{
			"https://github.com/nicedoc/webRTC-leak",
		},
	}
}

func probeSTUNServers(timeout time.Duration) ([]string, map[string]string) {
	var discoveredIPs []string
	seen := make(map[string]struct{})
	probeErrors := make(map[string]string)

	for _, server := range defaultSTUNServers {
		ip, err := stunBindingRequestTo(server.Addr, timeout)
		if err != nil {
			probeErrors[server.Name] = err.Error()
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		discoveredIPs = append(discoveredIPs, ip)
	}

	return discoveredIPs, probeErrors
}

func stunBindingRequestTo(addr string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := new(net.Dialer)
	conn, err := dialer.DialContext(ctx, "udp4", addr)
	if err != nil {
		return "", fmt.Errorf("UDP dial to %s failed: %w", addr, err)
	}
	defer conn.Close()

	msg := buildSTUNBindingRequest()
	if _, err := conn.Write(msg); err != nil {
		return "", fmt.Errorf("STUN send to %s failed: %w", addr, err)
	}

	conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("STUN recv from %s failed: %w", addr, err)
	}

	ip, err := parseSTUNResponse(buf[:n])
	if err != nil {
		return "", fmt.Errorf("STUN parse from %s failed: %w", addr, err)
	}

	return ip, nil
}

func buildSTUNBindingRequest() []byte {
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint32(msg[4:8], magicCookie)
	for i := 8; i < 20; i++ {
		msg[i] = byte(rand.Intn(256))
	}
	return msg
}

var magicCookieBytes = []byte{0x21, 0x12, 0xa4, 0x42}

func parseSTUNResponse(data []byte) (string, error) {
	if len(data) < 20 {
		return "", fmt.Errorf("response too short: %d bytes", len(data))
	}

	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != 0x0101 {
		return "", fmt.Errorf("unexpected message type: 0x%04X", msgType)
	}

	cookie := binary.BigEndian.Uint32(data[4:8])
	if cookie != magicCookie {
		return "", fmt.Errorf("invalid magic cookie: 0x%08X", cookie)
	}

	attrs := data[20:]
	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := binary.BigEndian.Uint16(attrs[2:4])
		attrData := attrs[4 : 4+int(attrLen)]

		if attrType == stunAttrXORMapped || attrType == stunAttrMapped {
			ip, err := parseSTUNAddress(attrType, attrData, data[8:20])
			if err != nil {
				return "", err
			}
			return ip, nil
		}

		padded := int(attrLen) + (4-int(attrLen)%4)%4
		if padded > len(attrs) {
			break
		}
		attrs = attrs[padded:]
	}

	return "", fmt.Errorf("no mapped address attribute found in response")
}

func parseSTUNAddress(attrType uint16, data, transactionID []byte) (string, error) {
	if len(data) < 4 {
		return "", fmt.Errorf("address attribute too short")
	}

	port := binary.BigEndian.Uint16(data[2:4])

	if attrType == stunAttrXORMapped {
		xorPort := port ^ uint16(magicCookie>>16)
		family := data[1]
		if family == 1 && len(data) >= 8 {
			ipBytes := make([]byte, 4)
			for i := 0; i < 4; i++ {
				ipBytes[i] = data[4+i] ^ magicCookieBytes[i]
			}
			addr := netip.AddrFrom4([4]byte(ipBytes))
			_ = xorPort
			return addr.String(), nil
		}
		if family == 2 && len(data) >= 20 {
			ipBytes := make([]byte, 16)
			for i := 0; i < 12; i++ {
				ipBytes[i] = data[4+i] ^ transactionID[i]
			}
			for i := 0; i < 4; i++ {
				ipBytes[12+i] = data[16+i] ^ magicCookieBytes[i]
			}
			addr := netip.AddrFrom16([16]byte(ipBytes))
			_ = xorPort
			return addr.String(), nil
		}
	}

	if attrType == stunAttrMapped {
		family := data[1]
		if family == 1 && len(data) >= 8 {
			ipBytes := [4]byte{data[4], data[5], data[6], data[7]}
			addr := netip.AddrFrom4(ipBytes)
			return addr.String(), nil
		}
		if family == 2 && len(data) >= 20 {
			var ipBytes [16]byte
			copy(ipBytes[:], data[8:24])
			addr := netip.AddrFrom16(ipBytes)
			return addr.String(), nil
		}
	}

	return "", fmt.Errorf("unsupported address family")
}

func detectLocalCandidates(_ time.Duration) ([]string, []string) {
	var ipv4Candidates, ipv6Candidates []string

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, nil
	}

	for _, addr := range addrs {
		parsed, err := netip.ParseAddr(addr.String())
		if err != nil {
			continue
		}
		parsed = parsed.Unmap()

		if parsed.Is4() {
			ipv4Candidates = append(ipv4Candidates, parsed.String())
		} else if parsed.Is6() {
			ipv6Candidates = append(ipv6Candidates, parsed.String())
		}
	}

	return ipv4Candidates, ipv6Candidates
}
