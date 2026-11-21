package pwntools

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ServiceProbeResult is the outcome of one probe against one endpoint.
type ServiceProbeResult struct {
	Service  string `json:"service"`
	Target   string `json:"target"`
	Port     int    `json:"port"`
	Outcome  string `json:"outcome"` // exposed, protected, no_answer, error
	Detail   string `json:"detail,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

const serviceProbeTimeout = 4 * time.Second

// probeService runs the probe for service against host:port.
func probeService(ctx context.Context, service, host string, port int) ServiceProbeResult {
	result := ServiceProbeResult{Service: service, Target: host, Port: port}
	ctx, cancel := context.WithTimeout(ctx, serviceProbeTimeout)
	defer cancel()
	address := net.JoinHostPort(host, strconv.Itoa(port))
	var err error
	switch service {
	case "telnet":
		err = probeTelnet(ctx, address, &result)
	case "rdp":
		err = probeRDP(ctx, address, &result)
	case "redis":
		err = probeRedis(ctx, address, &result)
	case "elasticsearch":
		err = probeElasticsearch(ctx, address, &result)
	case "mongodb":
		err = probeMongoDB(ctx, address, &result)
	case "snmp":
		err = probeSNMP(ctx, address, &result)
	case "ipmi":
		err = probeIPMI(ctx, address, &result)
	default:
		err = fmt.Errorf("unknown service %s", service)
	}
	if err != nil && result.Outcome == "" {
		result.Outcome, result.Detail = "error", classifyProbeError(ctx, err)
	}
	return result
}

func dialTCP(ctx context.Context, address string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
}

// printable keeps a short, single-line, printable excerpt of a reply.
func printable(data []byte, limit int) string {
	text := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, string(data))
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > limit {
		text = text[:limit]
	}
	return text
}

// probeTelnet records that a Telnet service answers; the banner excerpt
// often names the device.
func probeTelnet(ctx context.Context, address string, result *ServiceProbeResult) error {
	conn, err := dialTCP(ctx, address)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 512)
	n, _ := conn.Read(buffer)
	// Telnet option negotiation (IAC sequences) is not text.
	var text []byte
	for index := 0; index < n; index++ {
		if buffer[index] == 0xff && index+2 < n {
			index += 2
			continue
		}
		text = append(text, buffer[index])
	}
	result.Outcome, result.Detail, result.Evidence = "exposed", "Telnet answered; credentials cross the network in clear text", printable(text, 120)
	return nil
}

// probeRDP checks whether an RDP server requires Network Level
// Authentication. It first asks for standard RDP security only; a server that
// insists on TLS is then asked for TLS without CredSSP. A server that accepts
// either does not require NLA, so it shows a logon screen before any
// credentials are checked.
func probeRDP(ctx context.Context, address string, result *ServiceProbeResult) error {
	kind, value, err := rdpNegotiate(ctx, address, 0)
	if err != nil {
		return err
	}
	switch {
	case kind == 0 || kind == 0x02 && value == 0:
		result.Outcome, result.Detail = "exposed", "the server accepted standard RDP security; Network Level Authentication is not required"
		return nil
	case kind == 0x03 && value == 1: // TLS required: ask for TLS only
		kind, value, err = rdpNegotiate(ctx, address, 1)
		if err != nil {
			return err
		}
		if kind == 0x02 && value == 1 {
			result.Outcome, result.Detail = "exposed", "the server accepted TLS without CredSSP; Network Level Authentication is not required"
			return nil
		}
	}
	if kind == 0x02 {
		result.Outcome, result.Detail = "protected", fmt.Sprintf("the server selected protocol %d", value)
		return nil
	}
	reasons := map[uint32]string{1: "TLS required", 2: "TLS not allowed", 3: "no certificate", 4: "inconsistent flags", 5: "Network Level Authentication required", 6: "RDSTLS required"}
	result.Outcome, result.Detail = "protected", fallbackText(reasons[value], fmt.Sprintf("negotiation failure %d", value))
	return nil
}

// rdpNegotiate sends an X.224 Connection Request with RDP_NEG_REQ for the
// requested protocols and returns the response type (2 = selected protocol,
// 3 = failure code, 0 = no negotiation response) and its value.
func rdpNegotiate(ctx context.Context, address string, requested uint32) (byte, uint32, error) {
	conn, err := dialTCP(ctx, address)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	request := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(request[15:], requested)
	if _, err := conn.Write(request); err != nil {
		return 0, 0, err
	}
	reply := make([]byte, 64)
	n, err := io.ReadAtLeast(conn, reply, 11)
	if err != nil {
		return 0, 0, err
	}
	reply = reply[:n]
	if n < 19 || reply[11] != 0x02 && reply[11] != 0x03 {
		return 0, 0, nil
	}
	return reply[11], binary.LittleEndian.Uint32(reply[15:19]), nil
}

// probeRedis sends INFO server; without requirepass Redis answers it.
func probeRedis(ctx context.Context, address string, result *ServiceProbeResult) error {
	conn, err := dialTCP(ctx, address)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	first, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	switch {
	case strings.HasPrefix(first, "-NOAUTH"), strings.Contains(strings.ToUpper(first), "AUTHENTICATION REQUIRED"):
		result.Outcome, result.Detail = "protected", "authentication required"
	case strings.HasPrefix(first, "$"):
		body := make([]byte, 2048)
		n, _ := reader.Read(body)
		version := ""
		for _, line := range strings.Split(string(body[:n]), "\n") {
			if strings.HasPrefix(line, "redis_version:") {
				version = strings.TrimSpace(strings.TrimPrefix(line, "redis_version:"))
			}
		}
		result.Outcome, result.Detail, result.Evidence = "exposed", "INFO answered without authentication", "redis_version "+fallbackText(version, "unknown")
	default:
		result.Outcome, result.Detail = "protected", "unexpected reply: "+printable([]byte(first), 60)
	}
	return nil
}

// probeElasticsearch requests the cluster banner, which security-enabled
// clusters refuse with 401.
func probeElasticsearch(ctx context.Context, address string, result *ServiceProbeResult) error {
	for _, scheme := range []string{"http", "https"} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+address+"/", nil)
		if err != nil {
			return err
		}
		client := http.Client{Transport: insecureTransport(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.Do(request)
		if err != nil {
			if scheme == "https" {
				return err
			}
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		response.Body.Close()
		switch {
		case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
			result.Outcome, result.Detail = "protected", fmt.Sprintf("%s %d", strings.ToUpper(scheme), response.StatusCode)
			return nil
		case response.StatusCode == http.StatusOK && bytes.Contains(body, []byte(`"cluster_name"`)):
			result.Outcome, result.Detail, result.Evidence = "exposed", "the cluster answered without authentication over "+strings.ToUpper(scheme), printable([]byte(string(jsonField(body, "cluster_name"))+" "+string(jsonField(body, "number"))), 80)
			return nil
		case scheme == "http" && response.StatusCode == http.StatusBadRequest:
			continue // TLS-only cluster answering plain HTTP
		default:
			result.Outcome, result.Detail = "protected", fmt.Sprintf("%s %d without an Elasticsearch banner", strings.ToUpper(scheme), response.StatusCode)
			return nil
		}
	}
	result.Outcome, result.Detail = "no_answer", "no HTTP answer"
	return nil
}

// insecureTransport skips certificate checks: the probe only asks whether the
// service answers without credentials and sends nothing secret.
func insecureTransport() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
}

func jsonField(body []byte, name string) []byte {
	index := bytes.Index(body, []byte(`"`+name+`"`))
	if index < 0 {
		return nil
	}
	rest := body[index+len(name)+2:]
	start := bytes.IndexByte(rest, '"')
	if start < 0 {
		return nil
	}
	end := bytes.IndexByte(rest[start+1:], '"')
	if end < 0 {
		return nil
	}
	return rest[start+1 : start+1+end]
}

// probeMongoDB runs listDatabases, which an instance without access control
// answers for anyone.
func probeMongoDB(ctx context.Context, address string, result *ServiceProbeResult) error {
	conn, err := dialTCP(ctx, address)
	if err != nil {
		return err
	}
	defer conn.Close()
	var document bytes.Buffer
	document.Write([]byte{0, 0, 0, 0})
	document.WriteByte(0x10)
	document.WriteString("listDatabases\x00")
	binary.Write(&document, binary.LittleEndian, int32(1))
	document.WriteByte(0x08)
	document.WriteString("nameOnly\x00")
	document.WriteByte(1)
	document.WriteByte(0x02)
	document.WriteString("$db\x00")
	binary.Write(&document, binary.LittleEndian, int32(len("admin")+1))
	document.WriteString("admin\x00")
	document.WriteByte(0)
	bson := document.Bytes()
	binary.LittleEndian.PutUint32(bson, uint32(len(bson)))
	var message bytes.Buffer
	binary.Write(&message, binary.LittleEndian, int32(16+4+1+len(bson)))
	binary.Write(&message, binary.LittleEndian, int32(1))    // requestID
	binary.Write(&message, binary.LittleEndian, int32(0))    // responseTo
	binary.Write(&message, binary.LittleEndian, int32(2013)) // OP_MSG
	binary.Write(&message, binary.LittleEndian, uint32(0))   // flagBits
	message.WriteByte(0)                                     // section kind 0
	message.Write(bson)
	if _, err := conn.Write(message.Bytes()); err != nil {
		return err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	length := int(binary.LittleEndian.Uint32(header))
	if length < 16 || length > 1<<20 {
		return fmt.Errorf("unexpected MongoDB reply length %d", length)
	}
	reply := make([]byte, length-4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	switch {
	case bytes.Contains(reply, []byte("requires authentication")), bytes.Contains(reply, []byte("Unauthorized")), bytes.Contains(reply, []byte("not authorized")):
		result.Outcome, result.Detail = "protected", "authentication required"
	case bytes.Contains(reply, []byte("databases")):
		result.Outcome, result.Detail, result.Evidence = "exposed", "listDatabases answered without authentication", fmt.Sprintf("%d database name(s) returned", bytes.Count(reply, []byte("name\x00")))
	default:
		result.Outcome, result.Detail = "protected", "listDatabases was not answered"
	}
	return nil
}

// probeSNMP sends one SNMPv2c GET for sysDescr.0 with the community
// strings public and then private. Only reads are attempted.
func probeSNMP(ctx context.Context, address string, result *ServiceProbeResult) error {
	answered := false
	for _, community := range []string{"public", "private"} {
		reply, err := udpExchange(ctx, address, snmpGetRequest(community), 1500*time.Millisecond)
		if err != nil {
			continue
		}
		answered = true
		if text, ok := snmpOctetString(reply); ok {
			result.Outcome, result.Detail, result.Evidence = "exposed", "SNMPv2c answered to the community string \""+community+"\"", printable([]byte(text), 120)
			return nil
		}
	}
	if answered {
		result.Outcome, result.Detail = "protected", "SNMP answered but refused the default community strings"
	} else {
		result.Outcome = "no_answer"
	}
	return nil
}

func snmpGetRequest(community string) []byte {
	ber := func(tag byte, content []byte) []byte {
		return append([]byte{tag, byte(len(content))}, content...)
	}
	oid := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00} // 1.3.6.1.2.1.1.1.0
	varbind := ber(0x30, append(ber(0x06, oid), 0x05, 0x00))
	pdu := ber(0xa0, append(append(append(ber(0x02, []byte{0x01}), ber(0x02, []byte{0x00})...), ber(0x02, []byte{0x00})...), ber(0x30, varbind)...))
	message := append(append(ber(0x02, []byte{0x01}), ber(0x04, []byte(community))...), pdu...) // version 1 = v2c
	return ber(0x30, message)
}

// snmpOctetString returns the first OCTET STRING after the OID in a reply.
func snmpOctetString(reply []byte) (string, bool) {
	oid := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	index := bytes.Index(reply, oid)
	if index < 0 || index+len(oid)+2 > len(reply) || reply[index+len(oid)] != 0x04 {
		return "", false
	}
	position := index + len(oid) + 1
	length := int(reply[position])
	position++
	if length&0x80 != 0 {
		bytesOfLength := length & 0x7f
		if bytesOfLength > 2 || position+bytesOfLength > len(reply) {
			return "", false
		}
		length = 0
		for _, b := range reply[position : position+bytesOfLength] {
			length = length<<8 | int(b)
		}
		position += bytesOfLength
	}
	if position+length > len(reply) {
		return "", false
	}
	return string(reply[position : position+length]), true
}

// probeIPMI asks for the channel authentication capabilities, which BMCs
// answer before any login and which state whether anonymous and null-user
// logins are enabled.
func probeIPMI(ctx context.Context, address string, result *ServiceProbeResult) error {
	request := []byte{0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb5}
	reply, err := udpExchange(ctx, address, request, 2*time.Second)
	if err != nil {
		result.Outcome = "no_answer"
		return nil
	}
	// RMCP(4) + session header(10) + message: rsAddr netFn rsLUN... ; the
	// response data starts after 6 message bytes: completion code, channel,
	// auth type support, status flags.
	if len(reply) < 25 || reply[20] != 0x00 {
		result.Outcome, result.Detail = "exposed", "a BMC answered the IPMI capabilities request"
		return nil
	}
	flags := reply[23]
	var notes []string
	if flags&0x04 != 0 {
		notes = append(notes, "anonymous login enabled")
	}
	if flags&0x02 != 0 {
		notes = append(notes, "null user names enabled")
	}
	if reply[22]&0x80 != 0 {
		notes = append(notes, "IPMI v2.0 (RAKP)")
	}
	result.Outcome, result.Detail, result.Evidence = "exposed", "a BMC answered the IPMI capabilities request", strings.Join(notes, ", ")
	return nil
}

func udpExchange(ctx context.Context, address string, request []byte, wait time.Duration) ([]byte, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(wait))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	reply := make([]byte, 2048)
	n, err := conn.Read(reply)
	if err != nil {
		return nil, err
	}
	return reply[:n], nil
}

func classifyProbeError(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return "timed out"
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "refused"):
		return "connection refused"
	case strings.Contains(text, "timeout"), strings.Contains(text, "deadline"):
		return "timed out"
	case strings.Contains(text, "eof"), strings.Contains(text, "reset"):
		return "connection closed"
	default:
		return "probe failed"
	}
}

func fallbackText(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
