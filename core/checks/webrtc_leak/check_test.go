package webrtcleak

import (
	"encoding/binary"
	"testing"

	"github.com/francomano/proxydoctor/core/check"
)

func TestBuildSTUNBindingRequestLength(t *testing.T) {
	msg := buildSTUNBindingRequest()
	if len(msg) != 20 {
		t.Fatalf("expected 20 bytes, got %d", len(msg))
	}
}

func TestBuildSTUNBindingRequestMessageType(t *testing.T) {
	msg := buildSTUNBindingRequest()
	msgType := uint16(msg[0])<<8 | uint16(msg[1])
	if msgType != stunBindingRequest {
		t.Fatalf("expected 0x%04X, got 0x%04X", stunBindingRequest, msgType)
	}
}

func TestBuildSTUNBindingRequestMagicCookie(t *testing.T) {
	msg := buildSTUNBindingRequest()
	cookie := uint32(msg[4])<<24 | uint32(msg[5])<<16 | uint32(msg[6])<<8 | uint32(msg[7])
	if cookie != magicCookie {
		t.Fatalf("expected magic cookie 0x%08X, got 0x%08X", magicCookie, cookie)
	}
}

func TestParseSTUNResponseTooShort(t *testing.T) {
	_, err := parseSTUNResponse([]byte{0, 0})
	if err == nil {
		t.Fatal("expected error for short response")
	}
}

func TestParseSTUNResponseWrongMessageType(t *testing.T) {
	data := make([]byte, 20)
	data[0] = 0x00
	data[1] = 0x02
	_, err := parseSTUNResponse(data)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
}

func TestParseSTUNResponseNoMappedAttribute(t *testing.T) {
	data := make([]byte, 20)
	data[0] = 0x01
	data[1] = 0x01
	copy(data[4:8], magicCookieBytes)
	_, err := parseSTUNResponse(data)
	if err == nil {
		t.Fatal("expected error when no mapped address present")
	}
}

func TestParseSTUNResponseXORMappedIPv4(t *testing.T) {
	resp := make([]byte, 20+4+8)
	resp[0] = 0x01
	resp[1] = 0x01
	binary.BigEndian.PutUint16(resp[2:4], 12)
	copy(resp[4:8], magicCookieBytes)

	binary.BigEndian.PutUint16(resp[20:22], stunAttrXORMapped)
	binary.BigEndian.PutUint16(resp[22:24], 8)

	resp[24] = 0
	resp[25] = 1
	binary.BigEndian.PutUint16(resp[26:28], 0)

	ip := [4]byte{93, 184, 216, 34}
	for i := 0; i < 4; i++ {
		resp[28+i] = ip[i] ^ magicCookieBytes[i]
	}

	got, err := parseSTUNResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "93.184.216.34" {
		t.Fatalf("got %q, want 93.184.216.34", got)
	}
}

func TestParseSTUNResponseMappedIPv4(t *testing.T) {
	resp := make([]byte, 20+4+8)
	resp[0] = 0x01
	resp[1] = 0x01
	binary.BigEndian.PutUint16(resp[2:4], 12)
	copy(resp[4:8], magicCookieBytes)

	binary.BigEndian.PutUint16(resp[20:22], stunAttrMapped)
	binary.BigEndian.PutUint16(resp[22:24], 8)

	resp[24] = 0
	resp[25] = 1
	binary.BigEndian.PutUint16(resp[26:28], 0)
	copy(resp[28:32], []byte{10, 0, 0, 1})

	got, err := parseSTUNResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "10.0.0.1" {
		t.Fatalf("got %q, want 10.0.0.1", got)
	}
}

func TestParseSTUNResponseXORMappedIPv6(t *testing.T) {
	resp := make([]byte, 20+4+20)
	resp[0] = 0x01
	resp[1] = 0x01
	binary.BigEndian.PutUint16(resp[2:4], 24)
	copy(resp[4:8], magicCookieBytes)

	binary.BigEndian.PutUint16(resp[20:22], stunAttrXORMapped)
	binary.BigEndian.PutUint16(resp[22:24], 20)

	resp[24] = 0
	resp[25] = 2
	binary.BigEndian.PutUint16(resp[26:28], 0)

	txID := resp[8:20]
	ipv6 := [16]byte{
		0x20, 0x01, 0x0d, 0xb8,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}
	for i := 0; i < 12; i++ {
		resp[28+i] = ipv6[i] ^ txID[i]
	}
	for i := 0; i < 4; i++ {
		resp[40+i] = ipv6[12+i] ^ magicCookieBytes[i]
	}

	got, err := parseSTUNResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "2001:db8::1" {
		t.Fatalf("got %q, want 2001:db8::1", got)
	}
}

func TestEvaluateWebRTCLeakSameIP(t *testing.T) {
	v := evaluateWebRTCLeak("203.0.113.10", "203.0.113.10", nil, nil, nil)
	if v.status != check.StatusPassed {
		t.Fatalf("expected passed, got %+v", v)
	}
}

func TestEvaluateWebRTCLeakNoPublicIPs(t *testing.T) {
	v := evaluateWebRTCLeak("", "", nil, nil, nil)
	if v.status != check.StatusError {
		t.Fatalf("expected error, got %+v", v)
	}
}

func TestEvaluateWebRTCLeakSTUNMatchesDirect(t *testing.T) {
	v := evaluateWebRTCLeak(
		"203.0.113.10", "93.184.216.34",
		[]string{"93.184.216.34"},
		nil, nil,
	)
	if v.status != check.StatusFailed || v.severity != check.SeverityCritical {
		t.Fatalf("expected failed+critical, got %+v", v)
	}
	if len(v.causes) == 0 || len(v.actions) == 0 {
		t.Fatalf("expected causes and actions")
	}
}

func TestEvaluateWebRTCLeakSTUNMatchesProxy(t *testing.T) {
	v := evaluateWebRTCLeak(
		"203.0.113.10", "93.184.216.34",
		[]string{"203.0.113.10"},
		nil, nil,
	)
	if v.status != check.StatusPassed {
		t.Fatalf("expected passed (STUN only sees proxy IP), got %+v", v)
	}
}

func TestEvaluateWebRTCLeakSTUNMatchesNeither(t *testing.T) {
	v := evaluateWebRTCLeak(
		"203.0.113.10", "93.184.216.34",
		[]string{"8.8.8.8"},
		nil, nil,
	)
	if v.status != check.StatusPassed {
		t.Fatalf("expected passed (STUN sees different IP), got %+v", v)
	}
}

func TestEvaluateWebRTCLeakSTUNMatchesDirectWithLocal(t *testing.T) {
	v := evaluateWebRTCLeak(
		"203.0.113.10", "93.184.216.34",
		[]string{"93.184.216.34"},
		[]string{"192.168.1.100"},
		nil,
	)
	if v.status != check.StatusFailed {
		t.Fatalf("expected failed (STUN matches direct), got %+v", v)
	}
}

func TestEvaluateWebRTCLeakLocalCandidatesOnly(t *testing.T) {
	v := evaluateWebRTCLeak(
		"203.0.113.10", "93.184.216.34",
		[]string{"203.0.113.10"},
		[]string{"192.168.1.100"},
		nil,
	)
	if v.status != check.StatusFailed || v.severity != check.SeverityWarning {
		t.Fatalf("expected failed+warning (local candidates), got %+v", v)
	}
}

func TestEvaluateWebRTCLeakLocalOnlyNoCandidates(t *testing.T) {
	v := evaluateWebRTCLeak(
		"203.0.113.10", "93.184.216.34",
		[]string{"203.0.113.10"},
		nil,
		nil,
	)
	if v.status != check.StatusPassed {
		t.Fatalf("expected passed (no local candidates, STUN matches proxy), got %+v", v)
	}
}

func TestEvaluateWebRTCLeakOnlyPublicLocal(t *testing.T) {
	v := evaluateWebRTCLeak(
		"203.0.113.10", "93.184.216.34",
		[]string{"203.0.113.10"},
		[]string{"8.8.8.8"},
		nil,
	)
	if v.status != check.StatusPassed {
		t.Fatalf("expected passed (no private local candidates), got %+v", v)
	}
}

func TestSTUNBindingRequestBuilds(t *testing.T) {
	msg := buildSTUNBindingRequest()
	if len(msg) != 20 {
		t.Fatalf("expected 20 bytes, got %d", len(msg))
	}
	if msg[0] != 0x00 || msg[1] != 0x01 {
		t.Fatalf("unexpected message type bytes: %02x %02x", msg[0], msg[1])
	}
}
